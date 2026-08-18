package link

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/exec"
)

// IPCommand is the LinkManager implemented by running `ip` with `-j` and
// parsing its JSON (§8.1).
//
// It exists because netlink library coverage of the IPv6 GRE variants and of
// newer attributes is incomplete, and because having a second, independent path
// to the same state is the diagnostic escape hatch when the primary one is
// suspected. It is slower than netlink and spawns a process per call, so it is
// the fallback, not the default.
type IPCommand struct {
	Bin    string
	Runner exec.Runner
}

// NewIPCommand returns a manager driving the given `ip` binary.
func NewIPCommand(bin string, runner exec.Runner) *IPCommand {
	if runner == nil {
		runner = exec.NewRunner()
	}
	return &IPCommand{Bin: bin, Runner: runner}
}

// Name identifies the implementation.
func (c *IPCommand) Name() string { return ManagerIP }

// Capabilities reports availability, which here means the binary was found.
func (c *IPCommand) Capabilities() Capabilities {
	available := strings.TrimSpace(c.Bin) != ""
	detail := "iproute2 command line with JSON output"
	if !available {
		detail = "the ip binary was not found on this system"
	}
	types := map[string]TypeSupport{}
	for _, kind := range TunnelKinds() {
		note := ""
		if IsIPv6Kind(kind) {
			note = "served here because netlink library coverage of the IPv6 GRE variants is incomplete"
		}
		types[kind] = TypeSupport{Supported: available, Manager: ManagerIP, Note: note}
	}
	return Capabilities{
		Name:        ManagerIP,
		Available:   available,
		Detail:      detail,
		TunnelTypes: types,
		// `ip monitor` could stream events, but that means owning a long-lived
		// child process; the netlink subscription is the supported path.
		Events:     false,
		Statistics: available,
	}
}

func (c *IPCommand) ready() error {
	if strings.TrimSpace(c.Bin) == "" {
		return fmt.Errorf("%w: the ip binary was not found", ErrUnsupported)
	}
	return nil
}

func (c *IPCommand) run(ctx context.Context, args ...string) (exec.Result, error) {
	if err := c.ready(); err != nil {
		return exec.Result{}, err
	}
	return c.Runner.Run(ctx, args)
}

// List returns every interface with its addresses and statistics. Addresses
// come from `ip -j addr show`, which reports link attributes and addresses in
// one pass, and the detailed link attributes from `ip -j -d link show`.
func (c *IPCommand) List(ctx context.Context) ([]Link, error) {
	res, err := c.run(ctx, c.Bin, "-j", "-d", "-s", "link", "show")
	if err != nil {
		return nil, err
	}
	links, err := parseLinks([]byte(res.Stdout))
	if err != nil {
		return nil, err
	}

	addrRes, err := c.run(ctx, c.Bin, "-j", "addr", "show")
	if err != nil {
		return nil, err
	}
	byName, err := parseAddresses([]byte(addrRes.Stdout))
	if err != nil {
		return nil, err
	}
	for i := range links {
		links[i].Addresses = byName[links[i].Name]
	}
	return links, nil
}

// Get returns one interface.
func (c *IPCommand) Get(ctx context.Context, name string) (Link, error) {
	res, err := c.run(ctx, c.Bin, "-j", "-d", "-s", "link", "show", "dev", name)
	if err != nil {
		if isMissingDevice(res, err) {
			return Link{}, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return Link{}, err
	}
	links, err := parseLinks([]byte(res.Stdout))
	if err != nil {
		return Link{}, err
	}
	if len(links) == 0 {
		return Link{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}

	addrRes, err := c.run(ctx, c.Bin, "-j", "addr", "show", "dev", name)
	if err == nil {
		if byName, perr := parseAddresses([]byte(addrRes.Stdout)); perr == nil {
			links[0].Addresses = byName[name]
		}
	}
	return links[0], nil
}

// Routes returns the IPv4 and IPv6 routing tables.
func (c *IPCommand) Routes(ctx context.Context) ([]Route, error) {
	var out []Route
	for _, family := range []string{"-4", "-6"} {
		res, err := c.run(ctx, c.Bin, "-j", family, "route", "show")
		if err != nil {
			// A host with IPv6 disabled fails the -6 call; that is not a fault.
			if family == "-6" {
				continue
			}
			return nil, err
		}
		routes, err := parseRoutes([]byte(res.Stdout))
		if err != nil {
			return nil, err
		}
		out = append(out, routes...)
	}
	return out, nil
}

// Statistics returns the counters for one interface.
func (c *IPCommand) Statistics(ctx context.Context, name string) (Statistics, error) {
	l, err := c.Get(ctx, name)
	if err != nil {
		return Statistics{}, err
	}
	if l.Statistics == nil {
		return Statistics{}, nil
	}
	return *l.Statistics, nil
}

// Create adds a tunnel interface.
func (c *IPCommand) Create(ctx context.Context, spec TunnelSpec) error {
	_, err := c.run(ctx, CreateArgs(c.Bin, spec)...)
	return err
}

// Delete removes an interface. A device that is already gone is a success.
func (c *IPCommand) Delete(ctx context.Context, name string) error {
	res, err := c.run(ctx, DeleteArgs(c.Bin, name)...)
	if err != nil && isMissingDevice(res, err) {
		return nil
	}
	return err
}

func (c *IPCommand) SetMTU(ctx context.Context, name string, mtu int) error {
	_, err := c.run(ctx, SetMTUArgs(c.Bin, name, mtu)...)
	return err
}

func (c *IPCommand) SetTxQueueLength(ctx context.Context, name string, length int) error {
	_, err := c.run(ctx, SetTxQueueLenArgs(c.Bin, name, length)...)
	return err
}

func (c *IPCommand) SetUp(ctx context.Context, name string) error {
	_, err := c.run(ctx, SetUpArgs(c.Bin, name)...)
	return err
}

func (c *IPCommand) SetDown(ctx context.Context, name string) error {
	_, err := c.run(ctx, SetDownArgs(c.Bin, name)...)
	return err
}

func (c *IPCommand) AddAddress(ctx context.Context, name string, addr Address) error {
	_, err := c.run(ctx, AddAddressArgs(c.Bin, name, addr)...)
	return err
}

func (c *IPCommand) RemoveAddress(ctx context.Context, name string, addr Address) error {
	res, err := c.run(ctx, DelAddressArgs(c.Bin, name, addr)...)
	if err != nil && (isMissingDevice(res, err) || strings.Contains(res.Stderr, "Cannot assign requested address")) {
		return nil
	}
	return err
}

// Subscribe is not served here: streaming events means owning a long-lived
// child process, and the netlink subscription is the supported path (§8.1).
func (c *IPCommand) Subscribe(ctx context.Context) (<-chan Event, error) {
	return nil, fmt.Errorf("%w: the ip fallback does not stream link events", ErrUnsupported)
}

// isMissingDevice recognises the "device does not exist" failure, which several
// operations must treat as success rather than as an error.
func isMissingDevice(res exec.Result, err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(res.Stderr + " " + err.Error())
	return strings.Contains(text, "does not exist") ||
		strings.Contains(text, "cannot find device") ||
		strings.Contains(text, "no such device")
}

// ---------------------------------------------------------------- JSON shapes

// flexInt accepts a JSON number or a word such as "inherit", which is how
// iproute2 renders a zero TTL.
type flexInt struct {
	Value int
	Word  string
	Set   bool
}

func (f *flexInt) UnmarshalJSON(raw []byte) error {
	f.Set = true
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		f.Word = s
		if n, err := strconv.Atoi(s); err == nil {
			f.Value = n
		}
		return nil
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	f.Value = int(n)
	return nil
}

// flexKey accepts a GRE key as the dotted-quad string iproute2 prints or as a
// plain number (§2).
type flexKey struct {
	Value uint32
	Set   bool
}

func (f *flexKey) UnmarshalJSON(raw []byte) error {
	if string(raw) == "null" {
		return nil
	}
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		key, err := KeyFromDotted(s)
		if err != nil {
			return err
		}
		f.Value, f.Set = key, true
		return nil
	}
	var n float64
	if err := json.Unmarshal(raw, &n); err != nil {
		return err
	}
	f.Value, f.Set = uint32(n), true
	return nil
}

// ipTunnelData is the tunnel attribute block. iproute2 nests it under
// linkinfo.info_data, but the same field names also appear at the top level in
// some versions, so both shapes are decoded into this one struct.
type ipTunnelData struct {
	Local      string   `json:"local"`
	Remote     string   `json:"remote"`
	Ttl        *flexInt `json:"ttl"`
	HopLimit   *flexInt `json:"hoplimit"`
	Tos        *flexInt `json:"tos"`
	IKey       *flexKey `json:"ikey"`
	OKey       *flexKey `json:"okey"`
	ICsum      bool     `json:"icsum"`
	OCsum      bool     `json:"ocsum"`
	ISeq       bool     `json:"iseq"`
	OSeq       bool     `json:"oseq"`
	PMtuDisc   *bool    `json:"pmtudisc"`
	IgnoreDf   bool     `json:"ignore_df"`
	Link       string   `json:"link"`
	FwMark     *flexInt `json:"fwmark"`
	EncapLimit *flexInt `json:"encaplimit"`
	TClass     string   `json:"tclass"`
	FlowLabel  string   `json:"flowlabel"`
}

type ipLinkInfo struct {
	InfoKind string        `json:"info_kind"`
	InfoData *ipTunnelData `json:"info_data"`
}

type ipCounters struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Errors  uint64 `json:"errors"`
	Dropped uint64 `json:"dropped"`
}

type ipStats64 struct {
	Rx ipCounters `json:"rx"`
	Tx ipCounters `json:"tx"`
}

type ipLink struct {
	IfIndex   int         `json:"ifindex"`
	IfName    string      `json:"ifname"`
	Flags     []string    `json:"flags"`
	MTU       int         `json:"mtu"`
	OperState string      `json:"operstate"`
	LinkType  string      `json:"link_type"`
	Address   string      `json:"address"`
	TxQLen    int         `json:"txqlen"`
	Master    string      `json:"master"`
	LinkInfo  *ipLinkInfo `json:"linkinfo"`
	Stats64   *ipStats64  `json:"stats64"`

	// The flattened shape: the same tunnel fields at the top level.
	ipTunnelData
}

func parseLinks(raw []byte) ([]Link, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var decoded []ipLink
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, fmt.Errorf("parsing ip link output: %w", err)
	}

	out := make([]Link, 0, len(decoded))
	for _, d := range decoded {
		l := Link{
			Name:         d.IfName,
			Index:        d.IfIndex,
			MTU:          d.MTU,
			Kind:         normaliseKind(d),
			HardwareAddr: d.Address,
			TxQueueLen:   d.TxQLen,
			OperState:    strings.ToUpper(d.OperState),
			Flags:        d.Flags,
			IsUp:         hasFlag(d.Flags, "UP"),
			IsLowerUp:    hasFlag(d.Flags, "LOWER_UP"),
			IsRunning:    hasFlag(d.Flags, "RUNNING"),
		}
		if d.Stats64 != nil {
			l.Statistics = &Statistics{
				RxBytes: d.Stats64.Rx.Bytes, RxPackets: d.Stats64.Rx.Packets,
				RxErrors: d.Stats64.Rx.Errors, RxDropped: d.Stats64.Rx.Dropped,
				TxBytes: d.Stats64.Tx.Bytes, TxPackets: d.Stats64.Tx.Packets,
				TxErrors: d.Stats64.Tx.Errors, TxDropped: d.Stats64.Tx.Dropped,
			}
		}
		if IsTunnelKind(l.Kind) {
			data := d.ipTunnelData
			if d.LinkInfo != nil && d.LinkInfo.InfoData != nil {
				data = *d.LinkInfo.InfoData
			}
			l.Tunnel = tunnelAttrsFrom(data, IsIPv6Kind(l.Kind))
		}
		out = append(out, l)
	}
	return out, nil
}

// normaliseKind resolves the interface type. linkinfo.info_kind is the reliable
// source for virtual devices; link_type describes the layer-2 encapsulation and
// is what identifies a plain NIC and the loopback.
func normaliseKind(d ipLink) string {
	if d.LinkInfo != nil && d.LinkInfo.InfoKind != "" {
		return d.LinkInfo.InfoKind
	}
	switch d.LinkType {
	case "loopback":
		return "loopback"
	case "ether":
		return "device"
	case "":
		return "device"
	default:
		return d.LinkType
	}
}

func tunnelAttrsFrom(d ipTunnelData, ipv6 bool) *TunnelAttrs {
	attrs := &TunnelAttrs{
		Local:             d.Local,
		Remote:            d.Remote,
		HasInputChecksum:  d.ICsum,
		HasOutputChecksum: d.OCsum,
		HasInputSequence:  d.ISeq,
		HasOutputSequence: d.OSeq,
		IsIgnoreDf:        d.IgnoreDf,
		BindDevice:        d.Link,
		TrafficClass:      d.TClass,
		FlowLabel:         d.FlowLabel,
	}
	if d.PMtuDisc != nil {
		attrs.IsPathMtuDiscovery = *d.PMtuDisc
	}
	ttl := d.Ttl
	if ipv6 && d.HopLimit != nil {
		ttl = d.HopLimit
	}
	if ttl != nil {
		attrs.Ttl = ttl.Value
		if ttl.Word == "inherit" {
			attrs.Ttl = 0
		}
	}
	// The kernel encodes "copy the inner TOS" as the value 1, which iproute2
	// prints as 0x1 rather than as a word. Normalising it here keeps this
	// manager's readback identical to the netlink one's.
	attrs.Tos = "inherit"
	if d.Tos != nil {
		switch {
		case d.Tos.Word == "inherit" || d.Tos.Word == "0x1" || d.Tos.Value == 1 || d.Tos.Value == 0:
		case d.Tos.Word != "":
			attrs.Tos = d.Tos.Word
		default:
			attrs.Tos = "0x" + strconv.FormatInt(int64(d.Tos.Value), 16)
		}
	}
	if d.IKey != nil && d.IKey.Set {
		key := d.IKey.Value
		attrs.IKey = &key
	}
	if d.OKey != nil && d.OKey.Set {
		key := d.OKey.Value
		attrs.OKey = &key
	}
	if d.FwMark != nil && d.FwMark.Value != 0 {
		mark := uint32(d.FwMark.Value)
		attrs.FwMark = &mark
	}
	if ipv6 {
		if d.HopLimit != nil {
			hop := d.HopLimit.Value
			attrs.HopLimit = &hop
		}
		if d.EncapLimit != nil {
			limit := d.EncapLimit.Value
			attrs.EncapLimit = &limit
		}
	}
	return attrs
}

type ipAddrInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Address   string `json:"address"`
	PrefixLen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
	Label     string `json:"label"`
}

type ipAddrEntry struct {
	IfName   string       `json:"ifname"`
	AddrInfo []ipAddrInfo `json:"addr_info"`
}

func parseAddresses(raw []byte) (map[string][]Address, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return map[string][]Address{}, nil
	}
	var decoded []ipAddrEntry
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, fmt.Errorf("parsing ip addr output: %w", err)
	}
	out := make(map[string][]Address, len(decoded))
	for _, entry := range decoded {
		for _, info := range entry.AddrInfo {
			family := FamilyIPv4
			if info.Family == "inet6" {
				family = FamilyIPv6
			}
			addr := Address{
				Address: info.Local, PrefixLength: info.PrefixLen,
				Family: family, Scope: info.Scope, Label: info.Label,
			}
			// For a point-to-point assignment iproute2 reports the local address
			// in "local" and the peer in "address"; for an ordinary one both hold
			// the same value.
			if info.Address != "" && info.Address != info.Local {
				addr.Peer = info.Address
			}
			out[entry.IfName] = append(out[entry.IfName], addr)
		}
	}
	return out, nil
}

type ipRoute struct {
	Dst      string   `json:"dst"`
	Gateway  string   `json:"gateway"`
	Dev      string   `json:"dev"`
	PrefSrc  string   `json:"prefsrc"`
	Table    string   `json:"table"`
	Protocol string   `json:"protocol"`
	Metric   *flexInt `json:"metric"`
}

func parseRoutes(raw []byte) ([]Route, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, nil
	}
	var decoded []ipRoute
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, fmt.Errorf("parsing ip route output: %w", err)
	}
	out := make([]Route, 0, len(decoded))
	for _, d := range decoded {
		r := Route{
			Destination: d.Dst, Gateway: d.Gateway, Device: d.Dev,
			Source: d.PrefSrc, Table: d.Table, Protocol: d.Protocol,
			IsDefault: d.Dst == "default" || d.Dst == "0.0.0.0/0" || d.Dst == "::/0",
		}
		if d.Metric != nil {
			r.Metric = d.Metric.Value
		}
		out = append(out, r)
	}
	return out, nil
}

// Fallback runs one manager and retries through another when the first reports
// that it cannot serve the request. This is what §8.1 asks for: netlink first,
// `ip` when netlink reports an unsupported attribute.
type Fallback struct {
	Primary   LinkManager
	Secondary LinkManager
	// Forced routes every call to the secondary, which is the troubleshooting
	// switch of §8.1.
	Forced bool
}

// NewFallback pairs a primary manager with a secondary one.
func NewFallback(primary, secondary LinkManager) *Fallback {
	return &Fallback{Primary: primary, Secondary: secondary}
}

func (f *Fallback) active() LinkManager {
	if f.Forced && f.Secondary != nil {
		return f.Secondary
	}
	return f.Primary
}

// Name reports the manager that will actually serve calls.
func (f *Fallback) Name() string { return f.active().Name() }

// Capabilities merges both managers: a type is supported when either can serve
// it, attributed to whichever one would.
func (f *Fallback) Capabilities() Capabilities {
	primary := f.Primary.Capabilities()
	if f.Secondary == nil {
		return primary
	}
	secondary := f.Secondary.Capabilities()
	merged := primary
	merged.TunnelTypes = map[string]TypeSupport{}
	for _, kind := range TunnelKinds() {
		p := primary.TunnelTypes[kind]
		if p.Supported && !f.Forced {
			merged.TunnelTypes[kind] = p
			continue
		}
		s := secondary.TunnelTypes[kind]
		if s.Supported {
			merged.TunnelTypes[kind] = s
			continue
		}
		merged.TunnelTypes[kind] = p
	}
	merged.Available = primary.Available || secondary.Available
	return merged
}

// retry runs fn against the active manager and falls back to the other one when
// the failure was "this implementation cannot do that".
func (f *Fallback) retry(fn func(LinkManager) error) error {
	err := fn(f.active())
	if err == nil || !errors.Is(err, ErrUnsupported) || f.Secondary == nil || f.Forced {
		return err
	}
	return fn(f.Secondary)
}

func (f *Fallback) List(ctx context.Context) ([]Link, error) {
	var out []Link
	err := f.retry(func(m LinkManager) error {
		var err error
		out, err = m.List(ctx)
		return err
	})
	return out, err
}

func (f *Fallback) Get(ctx context.Context, name string) (Link, error) {
	var out Link
	err := f.retry(func(m LinkManager) error {
		var err error
		out, err = m.Get(ctx, name)
		return err
	})
	return out, err
}

func (f *Fallback) Routes(ctx context.Context) ([]Route, error) {
	var out []Route
	err := f.retry(func(m LinkManager) error {
		var err error
		out, err = m.Routes(ctx)
		return err
	})
	return out, err
}

func (f *Fallback) Statistics(ctx context.Context, name string) (Statistics, error) {
	var out Statistics
	err := f.retry(func(m LinkManager) error {
		var err error
		out, err = m.Statistics(ctx, name)
		return err
	})
	return out, err
}

func (f *Fallback) Create(ctx context.Context, spec TunnelSpec) error {
	return f.retry(func(m LinkManager) error { return m.Create(ctx, spec) })
}

func (f *Fallback) Delete(ctx context.Context, name string) error {
	return f.retry(func(m LinkManager) error { return m.Delete(ctx, name) })
}

func (f *Fallback) SetMTU(ctx context.Context, name string, mtu int) error {
	return f.retry(func(m LinkManager) error { return m.SetMTU(ctx, name, mtu) })
}

func (f *Fallback) SetTxQueueLength(ctx context.Context, name string, length int) error {
	return f.retry(func(m LinkManager) error { return m.SetTxQueueLength(ctx, name, length) })
}

func (f *Fallback) SetUp(ctx context.Context, name string) error {
	return f.retry(func(m LinkManager) error { return m.SetUp(ctx, name) })
}

func (f *Fallback) SetDown(ctx context.Context, name string) error {
	return f.retry(func(m LinkManager) error { return m.SetDown(ctx, name) })
}

func (f *Fallback) AddAddress(ctx context.Context, name string, addr Address) error {
	return f.retry(func(m LinkManager) error { return m.AddAddress(ctx, name, addr) })
}

func (f *Fallback) RemoveAddress(ctx context.Context, name string, addr Address) error {
	return f.retry(func(m LinkManager) error { return m.RemoveAddress(ctx, name, addr) })
}

// Subscribe uses the primary manager only: the event subscription is a netlink
// capability and there is nothing to fall back to.
func (f *Fallback) Subscribe(ctx context.Context) (<-chan Event, error) {
	return f.Primary.Subscribe(ctx)
}
