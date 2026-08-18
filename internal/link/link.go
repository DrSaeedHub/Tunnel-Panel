// Package link is the system interaction layer for network interfaces (§8.1).
//
// It defines LinkManager, the one interface through which the rest of the panel
// observes and changes kernel link state, and three implementations of it:
//
//   - netlink, the primary path, which spawns no process and returns typed
//     errors rather than text that has to be parsed;
//   - the `ip -j` command fallback, needed because netlink library coverage of
//     the IPv6 GRE variants and of newer attributes is incomplete, and useful as
//     a diagnostic escape hatch;
//   - a fake, which records what it was asked to do without touching anything,
//     and which powers the preview endpoint and every hermetic test.
//
// Nothing above this package parses command output or builds netlink messages.
package link

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Tunnel kinds, spelled as the kernel and iproute2 spell them.
const (
	KindGRE       = "gre"
	KindGRETAP    = "gretap"
	KindIP6GRE    = "ip6gre"
	KindIP6GRETAP = "ip6gretap"
)

// Manager implementation names, reported through /system/capabilities.
const (
	ManagerNetlink = "netlink"
	ManagerIP      = "ip_command"
	ManagerFake    = "fake"
)

// Sentinel errors. Callers switch on these rather than on message text.
var (
	// ErrNotFound means the interface does not exist.
	ErrNotFound = errors.New("link: no such interface")
	// ErrExists means an interface of that name is already present.
	ErrExists = errors.New("link: interface already exists")
	// ErrUnsupported means this implementation cannot serve the request. It is
	// the signal that makes the fallback manager retry through `ip` (§8.1).
	ErrUnsupported = errors.New("link: unsupported by this link manager")
)

// TunnelKinds lists every tunnel kind the panel understands, in a stable order.
func TunnelKinds() []string {
	return []string{KindGRE, KindGRETAP, KindIP6GRE, KindIP6GRETAP}
}

// IsTunnelKind reports whether a kind names a tunnel this panel manages.
func IsTunnelKind(kind string) bool {
	switch kind {
	case KindGRE, KindGRETAP, KindIP6GRE, KindIP6GRETAP:
		return true
	}
	return false
}

// IsIPv6Kind reports whether a kind carries its underlay over IPv6, which
// decides both the endpoint address family and the encapsulation overhead.
func IsIPv6Kind(kind string) bool {
	return kind == KindIP6GRE || kind == KindIP6GRETAP
}

// Address is one address on an interface.
type Address struct {
	Address      string `json:"address"`
	PrefixLength int    `json:"prefix_length"`
	// Peer is the far-side address of a point-to-point assignment. Empty for an
	// ordinary subnet assignment, which is what tunnels here normally use.
	Peer string `json:"peer,omitempty"`
	// Family is model.AddressFamilyIPv4 or model.AddressFamilyIPv6 as a plain
	// string, so this package stays free of a dependency on the data model.
	Family string `json:"family"`
	Scope  string `json:"scope,omitempty"`
	Label  string `json:"label,omitempty"`
}

// Address families, spelled the way this package reports them.
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

// String renders the address in CIDR form.
func (a Address) String() string { return fmt.Sprintf("%s/%d", a.Address, a.PrefixLength) }

// Prefix parses the address into a netip.Prefix.
func (a Address) Prefix() (netip.Prefix, error) {
	addr, err := netip.ParseAddr(a.Address)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("address %q is not an IP address: %w", a.Address, err)
	}
	if a.PrefixLength < 0 || a.PrefixLength > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("prefix length /%d is out of range for %s", a.PrefixLength, a.Address)
	}
	return netip.PrefixFrom(addr, a.PrefixLength), nil
}

// NeedsExplicitPeer reports whether the peer has to be stated in the command
// that assigns this address.
//
// On a /30 or a /31 the peer is inside the subnet, so assigning the address
// alone gives the kernel a connected route covering both ends — which is what
// the tunnels this panel adopts already look like. Naming the peer explicitly
// there would instead produce a host address plus a route, a different layout
// for no gain. Only a host address genuinely needs the peer spelled out.
func (a Address) NeedsExplicitPeer() bool {
	if a.Peer == "" {
		return false
	}
	addr, err := netip.ParseAddr(a.Address)
	if err != nil {
		return true
	}
	if addr.Unmap().Is4() {
		return a.PrefixLength == 32
	}
	return a.PrefixLength == 128
}

// Equal compares two assignments by address, prefix length and peer, ignoring
// the reported scope and label, which the kernel fills in itself.
func (a Address) Equal(b Address) bool {
	return a.Address == b.Address && a.PrefixLength == b.PrefixLength && a.Peer == b.Peer
}

// FamilyOf reports the family constant for a parsed address.
func FamilyOf(addr netip.Addr) string {
	if addr.Is4() || addr.Is4In6() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// TunnelAttrs are the tunnel-specific attributes of a link. Every field is
// read back from the kernel after apply and compared against what was asked
// for, which is how §9.3 verification catches a tunnel that came up wrong.
type TunnelAttrs struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Ttl    int    `json:"ttl"`
	Tos    string `json:"tos"`
	// IKey and OKey are the GRE keys as integers. iproute2 prints them in
	// dotted-quad form; the panel always presents the integer (§2).
	IKey *uint32 `json:"ikey"`
	OKey *uint32 `json:"okey"`

	HasInputChecksum  bool `json:"has_input_checksum"`
	HasOutputChecksum bool `json:"has_output_checksum"`
	HasInputSequence  bool `json:"has_input_sequence"`
	HasOutputSequence bool `json:"has_output_sequence"`

	IsPathMtuDiscovery bool `json:"is_path_mtu_discovery"`
	IsIgnoreDf         bool `json:"is_ignore_df"`

	// BindDevice is the underlay interface the tunnel is bound to, if any.
	BindDevice string `json:"bind_device,omitempty"`
	FwMark     *uint32
	// IPv6 tunnel modes only.
	HopLimit     *int   `json:"hop_limit,omitempty"`
	EncapLimit   *int   `json:"encap_limit,omitempty"`
	TrafficClass string `json:"traffic_class,omitempty"`
	FlowLabel    string `json:"flow_label,omitempty"`
}

// Statistics are the interface counters (§11.2, §13.3).
type Statistics struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

// Link is the observed state of one interface.
type Link struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	MTU   int    `json:"mtu"`
	// Kind is the interface type: a tunnel kind, "bridge", "device" for a plain
	// NIC, "loopback", or whatever else the kernel reports.
	Kind         string `json:"kind"`
	HardwareAddr string `json:"hardware_addr,omitempty"`
	TxQueueLen   int    `json:"tx_queue_length"`

	// OperState is the kernel's operational state. A healthy GRE tunnel reports
	// UNKNOWN; treating that as failure is a bug, so nothing in this codebase
	// decides health from this field (§2, §9.3).
	OperState string   `json:"oper_state"`
	Flags     []string `json:"flags"`
	IsUp      bool     `json:"is_up"`
	IsLowerUp bool     `json:"is_lower_up"`
	IsRunning bool     `json:"is_running"`
	// MasterIndex is the index of the bridge or bond this interface is enslaved
	// to, or zero. A non-zero value means something else owns this interface.
	MasterIndex int `json:"master_index,omitempty"`

	Tunnel     *TunnelAttrs `json:"tunnel,omitempty"`
	Addresses  []Address    `json:"addresses,omitempty"`
	Statistics *Statistics  `json:"statistics,omitempty"`
}

// IsTunnel reports whether this link is a tunnel kind the panel manages.
func (l Link) IsTunnel() bool { return IsTunnelKind(l.Kind) }

// IsLoopback reports whether this is the loopback interface.
func (l Link) IsLoopback() bool {
	return l.Kind == "loopback" || l.Name == "lo" || hasFlag(l.Flags, "LOOPBACK")
}

// IsBridge reports whether this link is a bridge, which the panel must never
// touch (§17.1).
func (l Link) IsBridge() bool { return l.Kind == "bridge" || l.Kind == "bond" }

// IsPhysical reports whether this link looks like real hardware. A NIC has no
// virtual kind of its own; netlink calls that "device" and `ip` reports no
// info_kind at all, which this normalises to "device".
func (l Link) IsPhysical() bool {
	if l.IsLoopback() || l.IsTunnel() || l.IsBridge() {
		return false
	}
	switch l.Kind {
	case "device", "", "ether":
		return true
	}
	return false
}

// HasAddress reports whether the link carries the given address, comparing the
// address and prefix length only.
func (l Link) HasAddress(a Address) bool {
	for _, existing := range l.Addresses {
		if existing.Address == a.Address && existing.PrefixLength == a.PrefixLength {
			return true
		}
	}
	return false
}

func hasFlag(flags []string, name string) bool {
	for _, f := range flags {
		if f == name {
			return true
		}
	}
	return false
}

// TunnelSpec is everything needed to create a tunnel. It is the plan's view of
// a tunnel, deliberately independent of the database row so that the fake, the
// preview and the real path all take the same input.
type TunnelSpec struct {
	Name   string
	Kind   string
	Local  string
	Remote string
	Ttl    int
	Tos    string
	IKey   *uint32
	OKey   *uint32

	HasInputChecksum  bool
	HasOutputChecksum bool
	HasInputSequence  bool
	HasOutputSequence bool

	IsPathMtuDiscovery bool
	IsIgnoreDf         bool

	BindDevice    string
	FwMark        *uint32
	Mtu           int
	TxQueueLength *int

	HopLimit     *int
	EncapLimit   *int
	TrafficClass string
	FlowLabel    string
}

// Route is one entry of the kernel routing table. The panel reads routes to
// detect subnet overlap (§7.4) and to identify the default-route interface,
// which it must never touch (§17.1).
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Device      string `json:"device,omitempty"`
	// IsDefault marks a default route, whose device carries this host's
	// connectivity.
	IsDefault bool   `json:"is_default"`
	Source    string `json:"source,omitempty"`
	Table     string `json:"table,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Metric    int    `json:"metric,omitempty"`
}

// EventKind classifies a netlink link notification.
type EventKind string

const (
	EventAdded   EventKind = "added"
	EventRemoved EventKind = "removed"
	EventChanged EventKind = "changed"
)

// Event is one link notification. Subscribing to these is what makes interface
// appearance and disappearance event-driven rather than polled (§8.1, §10.3).
type Event struct {
	Kind EventKind `json:"kind"`
	Link Link      `json:"link"`
}

// TypeSupport reports whether one tunnel type can be served, and by which
// implementation, so the frontend can disable what this kernel or this build
// cannot do (§8.1).
type TypeSupport struct {
	Supported bool   `json:"supported"`
	Manager   string `json:"manager"`
	Note      string `json:"note,omitempty"`
}

// Capabilities describes one link manager.
type Capabilities struct {
	Name        string                 `json:"name"`
	Available   bool                   `json:"available"`
	Detail      string                 `json:"detail,omitempty"`
	TunnelTypes map[string]TypeSupport `json:"tunnel_types"`
	Events      bool                   `json:"events"`
	Statistics  bool                   `json:"statistics"`
}

// LinkManager is the whole contract between the panel and kernel link state.
//
// Implementations must be safe for concurrent use: read paths are called from
// request handlers and from the monitor while the apply pipeline is running.
// Serialisation of mutations is the caller's job, through the global mutation
// lock (§16).
type LinkManager interface {
	// Name identifies the implementation, e.g. "netlink".
	Name() string
	// Capabilities reports what this implementation can do here and now.
	Capabilities() Capabilities

	// List returns every interface with its addresses and statistics.
	List(ctx context.Context) ([]Link, error)
	// Get returns one interface, or ErrNotFound.
	Get(ctx context.Context, name string) (Link, error)
	// Routes returns the routing table.
	Routes(ctx context.Context) ([]Route, error)
	// Statistics returns the counters for one interface.
	Statistics(ctx context.Context, name string) (Statistics, error)

	// Create adds a tunnel interface. It does not bring it up or address it.
	Create(ctx context.Context, spec TunnelSpec) error
	// Delete removes an interface. It is not an error if it is already gone.
	Delete(ctx context.Context, name string) error
	// SetMTU changes the MTU in place.
	SetMTU(ctx context.Context, name string, mtu int) error
	// SetTxQueueLength changes the transmit queue length in place.
	SetTxQueueLength(ctx context.Context, name string, length int) error
	// SetUp and SetDown change the administrative state.
	SetUp(ctx context.Context, name string) error
	SetDown(ctx context.Context, name string) error
	// AddAddress and RemoveAddress manage addresses on an interface.
	AddAddress(ctx context.Context, name string, addr Address) error
	RemoveAddress(ctx context.Context, name string, addr Address) error

	// Subscribe streams link notifications until the context is cancelled.
	// An implementation that cannot subscribe returns ErrUnsupported.
	Subscribe(ctx context.Context) (<-chan Event, error)
}

// ByName indexes links by interface name.
func ByName(links []Link) map[string]Link {
	out := make(map[string]Link, len(links))
	for _, l := range links {
		out[l.Name] = l
	}
	return out
}

// Names returns the interface names in sorted order.
func Names(links []Link) []string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		out = append(out, l.Name)
	}
	sort.Strings(out)
	return out
}

// DefaultRouteDevices returns the set of interfaces carrying a default route.
// The panel must never touch one (§17.1).
func DefaultRouteDevices(routes []Route) map[string]bool {
	out := map[string]bool{}
	for _, r := range routes {
		if r.IsDefault && r.Device != "" {
			out[r.Device] = true
		}
	}
	return out
}

// KeyToDotted renders a GRE key in the dotted-quad form iproute2 prints, so
// 2749365187 becomes "163.223.251.195" (§2).
func KeyToDotted(key uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(key>>24), byte(key>>16), byte(key>>8), byte(key))
}

// KeyFromDotted parses a GRE key. It accepts both the dotted-quad form iproute2
// prints and a plain integer, because the same field is read back from `ip -j`
// output and typed by an operator.
func KeyFromDotted(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("empty GRE key")
	}
	if !strings.Contains(s, ".") {
		var n uint64
		if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
			return 0, fmt.Errorf("%q is not a GRE key", s)
		}
		if n > 4294967295 {
			return 0, fmt.Errorf("GRE key %s is above the maximum of 4294967295", s)
		}
		return uint32(n), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("%q is not a GRE key in dotted form", s)
	}
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}
