// Package rules is the system interaction layer for the panel's netfilter
// ruleset (§2.1 of the port forwarding specification).
//
// It defines Backend, the one interface through which the rest of the panel
// renders, installs and reads back forwarding rules, and three implementations
// of it:
//
//   - nftables, the primary path, which owns one table — `table inet gre_panel`
//     — and replaces its entire content in a single `nft -f` transaction, so
//     there is never a window with half a ruleset live and nothing else on the
//     host is touched;
//   - iptables, the fallback for hosts without nft, which owns a set of
//     dedicated chains, rebuilds only those, and adds exactly one jump rule per
//     built-in chain;
//   - a fake, which renders exactly what the real backends render but changes
//     nothing, and which powers the preview endpoint and every hermetic test.
//
// Nothing above this package builds a netfilter rule or parses one.
//
// Two decisions shape everything here, and both come from the defects of the
// hand-written script this subsystem replaces. Rules the panel generates live
// in a namespace it owns entirely, so a rebuild replaces the panel's rules and
// touches nobody else's — the script appended into shared built-in chains,
// which made ordering accidental and made a second run silently duplicate every
// rule. And every generated rule carries the identity comment
// grep:<RouteRuleID>, so a live kernel rule maps back to its database row
// exactly rather than by guesswork.
package rules

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Backend implementation names, reported through /system/capabilities. The
// first three are the RuleBackendType lookup titles in lower snake case; the
// fake is not a backend an installation can be running, only one a test or a
// preview can be using.
const (
	BackendNftables       = "nftables"
	BackendIptablesNft    = "iptables_nft"
	BackendIptablesLegacy = "iptables_legacy"
	BackendFake           = "fake"
)

// The nftables namespace: one table, owned entirely by the panel. Because
// nftables lets several tables hook the same point, this coexists with
// iptables-nft rules from Docker or firewalld instead of competing with them.
const (
	TableFamily = "inet"
	TableName   = "gre_panel"
)

// The iptables namespace: dedicated chains, rebuilt in place. The four the
// specification names carry the forwarding rules themselves; the other three
// exist because the same specification also requires locally-originated
// traffic, MSS clamping and fwmark, none of which can live in a nat chain.
// Each has exactly one jump rule in exactly one built-in chain.
const (
	ChainPre  = "GRE_PANEL_PRE"  // nat prerouting
	ChainOut  = "GRE_PANEL_OUT"  // nat output, for locally-originated traffic
	ChainPost = "GRE_PANEL_POST" // nat postrouting
	ChainFwd  = "GRE_PANEL_FWD"  // filter forward
	ChainAcct = "GRE_PANEL_ACCT" // filter forward, accounting only
	ChainMss  = "GRE_PANEL_MSS"  // mangle forward, MSS clamping
	ChainMark = "GRE_PANEL_MARK" // mangle prerouting, fwmark
)

// OwnedChains lists every chain the panel creates on the iptables backend, in a
// stable order. Nothing outside this list is ever flushed, reordered or deleted
// (§6.3.2), and the safety guard is built from it.
func OwnedChains() []string {
	return []string{ChainPre, ChainOut, ChainPost, ChainFwd, ChainAcct, ChainMss, ChainMark}
}

// IsPanelChain reports whether a chain name is one the panel created.
func IsPanelChain(name string) bool {
	for _, c := range OwnedChains() {
		if strings.EqualFold(strings.TrimSpace(name), c) {
			return true
		}
	}
	return false
}

// IdentityPrefix begins the comment every generated rule carries. Both
// netfilter interfaces support rule comments, so a rule's identity does not
// have to live only in the panel's database: the comment carries the row
// identifier, which is what makes reconciliation exact rather than heuristic
// (§2.5).
const IdentityPrefix = "grep:"

// Identity renders the identity comment for a rule.
func Identity(routeRuleID int64) string {
	return IdentityPrefix + strconv.FormatInt(routeRuleID, 10)
}

// StructuralComment marks a generated rule that belongs to the ruleset itself
// rather than to any one forwarding rule — the conntrack accept that heads the
// forward chain is the only one today.
//
// It exists so that every line inside the panel's namespace is accounted for:
// without it, reconciliation would find a rule with no identity in a chain the
// panel owns and would have to report the panel's own scaffolding as unmanaged.
const StructuralComment = "gre-panel:structural"

// identityRe matches an identity comment anywhere in a line of rule text,
// which is how a rule read back from the kernel is attributed to its row.
var identityRe = regexp.MustCompile(regexp.QuoteMeta(IdentityPrefix) + `([0-9]+)`)

// IsStructural reports whether a line of rule text is the ruleset's own
// scaffolding rather than a rule generated from a database row.
func IsStructural(s string) bool { return strings.Contains(s, StructuralComment) }

// ParseIdentity extracts the rule identifier from an identity comment. It
// accepts the bare comment and any text containing it, so a whole rule line as
// the kernel prints it can be passed straight in.
func ParseIdentity(s string) (int64, bool) {
	m := identityRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	id, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}

// IdentitiesIn returns every rule identifier mentioned in a block of rule text,
// in order of appearance and without duplicates.
func IdentitiesIn(text string) []int64 {
	var out []int64
	seen := map[int64]bool{}
	for _, m := range identityRe.FindAllStringSubmatch(text, -1) {
		id, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil || id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// Sentinel errors. Callers switch on these rather than on message text.
var (
	// ErrUnavailable means this backend cannot run here: its binary was not
	// found, or it is the unavailable stand-in returned when nothing was.
	ErrUnavailable = errors.New("rules: no netfilter backend is available on this host")
	// ErrUnsupported means the backend cannot express an option the rule asks
	// for. It names the option, because the answer an operator needs is which
	// setting to change, not that something went wrong.
	ErrUnsupported = errors.New("rules: unsupported by this backend")
	// ErrNoDestination means an enabled rule has nowhere to send traffic.
	ErrNoDestination = errors.New("rules: the rule has no enabled destination")
	// ErrRangeWidth means the bind and destination port ranges are different
	// widths, so there is no one-to-one mapping between them.
	ErrRangeWidth = errors.New("rules: the bind and destination port ranges are different widths")
	// ErrNotPanelOwned means a payload file on disk was not written by the
	// panel, so the panel will not overwrite it (§6.3.2).
	ErrNotPanelOwned = errors.New("rules: this file was not written by the panel")
)

// ---------------------------------------------------------------- vocabulary

// Protocol is the transport protocol a rule matches. Both is not a third
// protocol: it generates the parallel rule set for each of the other two.
type Protocol string

const (
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolBoth Protocol = "both"
)

// Expand returns the concrete protocols a rule generates rules for.
func (p Protocol) Expand() []Protocol {
	switch p {
	case ProtocolBoth:
		return []Protocol{ProtocolTCP, ProtocolUDP}
	case ProtocolTCP, ProtocolUDP:
		return []Protocol{p}
	}
	return nil
}

// Valid reports whether this is a protocol the panel understands.
func (p Protocol) Valid() bool { return len(p.Expand()) > 0 }

// NatMode decides what happens to the source address of relayed traffic. It is
// the most consequential option on a rule, which is why it is an explicit
// choice rather than a hardcoded masquerade (§2.4).
type NatMode string

const (
	// NatMasquerade rewrites the source to the outgoing interface's address,
	// resolved per packet. It always works, and the destination sees this
	// server instead of the client.
	NatMasquerade NatMode = "masquerade"
	// NatSnat rewrites the source to a fixed address: the same effect as
	// masquerade, deterministic and cheaper on a stable address.
	NatSnat NatMode = "snat"
	// NatNone preserves the client address, and therefore only works when the
	// destination's return path comes back through this server — typically the
	// far end of a tunnel this panel manages.
	NatNone NatMode = "none"
)

// Valid reports whether this is a NAT mode the panel understands.
func (m NatMode) Valid() bool {
	switch m {
	case NatMasquerade, NatSnat, NatNone:
		return true
	}
	return false
}

// LoadBalanceMode distributes traffic across several destinations.
type LoadBalanceMode string

const (
	LoadBalanceNone LoadBalanceMode = "none"
	// LoadBalanceRoundRobin sends each new connection to the next destination,
	// so one client's connections are spread across all of them.
	LoadBalanceRoundRobin LoadBalanceMode = "round_robin"
	// LoadBalanceSourceHash keeps a given client on a given destination, which
	// is what a service with per-connection state needs.
	LoadBalanceSourceHash LoadBalanceMode = "source_hash"
	// LoadBalanceWeighted is round-robin in proportion to per-destination
	// weights.
	LoadBalanceWeighted LoadBalanceMode = "weighted"
)

// Valid reports whether this is a load balancing mode the panel understands.
func (m LoadBalanceMode) Valid() bool {
	switch m {
	case LoadBalanceNone, LoadBalanceRoundRobin, LoadBalanceSourceHash, LoadBalanceWeighted:
		return true
	}
	return false
}

// Address families, spelled the way internal/link spells them so the two never
// have to be translated between.
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

// ---------------------------------------------------------------- the spec

// PortRange is a port or a contiguous range of them. End is zero for a single
// port rather than equal to Port, so "one port" and "a range of one" are the
// same value and cannot render differently.
type PortRange struct {
	Port int `json:"port"`
	End  int `json:"end,omitempty"`
}

// IsRange reports whether this covers more than one port.
func (r PortRange) IsRange() bool { return r.End > r.Port }

// Width is how many ports the range covers.
func (r PortRange) Width() int {
	if r.IsRange() {
		return r.End - r.Port + 1
	}
	return 1
}

// String renders the range for a human, e.g. "2044" or "20000-20100".
func (r PortRange) String() string {
	if r.IsRange() {
		return fmt.Sprintf("%d-%d", r.Port, r.End)
	}
	return strconv.Itoa(r.Port)
}

// Destination is one place a rule sends traffic to.
type Destination struct {
	Address string    `json:"address"`
	Ports   PortRange `json:"ports"`
	// Weight is the share of new connections this destination takes under
	// weighted load balancing. It is ignored by the other modes.
	Weight int `json:"weight,omitempty"`
}

// RouteSpec is everything needed to generate one rule's netfilter rules. It is
// the plan's view of a forwarding rule, deliberately independent of the
// database row so that the fake, the preview and the real backends all take
// exactly the same input.
type RouteSpec struct {
	// RouteRuleID is carried in the identity comment of every rule generated
	// from this spec.
	RouteRuleID int64  `json:"route_rule_id"`
	Title       string `json:"title"`

	Protocol Protocol `json:"protocol"`
	// Family is FamilyIPv4 or FamilyIPv6. The nftables backend serves both from
	// one inet table; the iptables backend renders a separate payload for each.
	Family string `json:"family"`

	// BindAddress is the local address traffic arrives on. Empty, 0.0.0.0 or ::
	// mean any local address, and generate no destination-address match at all
	// rather than a match on the literal unspecified address.
	BindAddress   string    `json:"bind_address"`
	BindPorts     PortRange `json:"bind_ports"`
	BindInterface string    `json:"bind_interface,omitempty"`

	// Destinations always has at least one entry. A rule with one destination
	// is not a special case: it is load balancing across a set of size one.
	Destinations []Destination `json:"destinations"`

	NatMode     NatMode `json:"nat_mode"`
	SnatAddress string  `json:"snat_address,omitempty"`

	LoadBalance LoadBalanceMode `json:"load_balance"`

	// AllowedSources restricts which sources may use the relay. Empty means any
	// source that can reach the bind address.
	AllowedSources []string `json:"allowed_sources,omitempty"`
	// SourceSet names the declared address set this rule matches against,
	// when it allows one of the operator's shared lists.
	//
	// It is one set and not several because netfilter has no way to say "in
	// this set or that one" within a rule: two matches on the same field are
	// an and, and the operator meant an or. So the lists a rule allows -- and
	// the addresses it names itself -- are folded into one set per rule at
	// build time, and AllowedSources is then empty. The cost is that two
	// rules allowing the same list hold the ranges twice in the kernel; the
	// thing that matters, which is that an operator edits those ranges in one
	// place, is a property of the panel and not of the ruleset.
	SourceSet string `json:"source_set,omitempty"`

	// ClampMssToPmtu rewrites the MSS of forwarded SYN packets to fit the path.
	// Its absence is the single most common cause of "the tunnel is up but my
	// service hangs on large transfers".
	ClampMssToPmtu bool `json:"clamp_mss_to_pmtu"`
	// IncludeLocalOriginated also relays traffic that processes on this server
	// generate, which the prerouting hook never sees.
	IncludeLocalOriginated bool `json:"include_local_originated"`
	// Logging logs new connections, rate limited.
	Logging bool `json:"logging"`

	FwMark *uint32 `json:"fwmark,omitempty"`

	// MaxConnectionsPerSource caps concurrent connections from one source
	// address; ConnectionRateLimit caps new connections per minute from one.
	// Zero disables each.
	MaxConnectionsPerSource int `json:"max_connections_per_source,omitempty"`
	ConnectionRateLimit     int `json:"connection_rate_limit,omitempty"`

	// SortOrder controls emission order, which is user-visible behaviour:
	// overlapping matches resolve first-match-wins.
	SortOrder int `json:"sort_order"`
}

// IsIPv6 reports whether this rule works in the IPv6 address family.
func (s RouteSpec) IsIPv6() bool { return s.Family == FamilyIPv6 }

// BindsAnyAddress reports whether the rule matches every local address.
func (s RouteSpec) BindsAnyAddress() bool { return isUnspecified(s.BindAddress) }

// Identity is the comment every rule generated from this spec carries.
func (s RouteSpec) Identity() string { return Identity(s.RouteRuleID) }

// Check reports whether the spec can be rendered at all, independently of the
// backend. It is the structural half of validation — the half that would
// otherwise produce a syntactically valid ruleset which forwards to nowhere.
func (s RouteSpec) Check() error {
	if s.RouteRuleID <= 0 {
		return fmt.Errorf("rules: a rule needs an identifier to be rendered")
	}
	if !s.Protocol.Valid() {
		return fmt.Errorf("rules: %q is not a protocol", s.Protocol)
	}
	if !s.NatMode.Valid() {
		return fmt.Errorf("rules: %q is not a NAT mode", s.NatMode)
	}
	if s.LoadBalance != "" && !s.LoadBalance.Valid() {
		return fmt.Errorf("rules: %q is not a load balancing mode", s.LoadBalance)
	}
	if len(s.Destinations) == 0 {
		return fmt.Errorf("%w: rule %d", ErrNoDestination, s.RouteRuleID)
	}
	if s.NatMode == NatSnat && strings.TrimSpace(s.SnatAddress) == "" {
		return fmt.Errorf("rules: rule %d uses SNAT but names no source address", s.RouteRuleID)
	}
	for _, d := range s.Destinations {
		if d.Ports.Width() != s.BindPorts.Width() {
			return fmt.Errorf("%w: rule %d binds %s (%d ports) and sends to %s (%d ports)",
				ErrRangeWidth, s.RouteRuleID, s.BindPorts, s.BindPorts.Width(),
				d.Ports, d.Ports.Width())
		}
	}
	return nil
}

// Ruleset is the complete desired state: every enabled rule, in the order they
// are to be emitted.
//
// Rendering takes the whole set rather than a delta, because an apply is a
// transactional replacement of the panel's namespace rather than a patch.
// SourceSet is a named collection of address ranges, declared once and matched
// by name from every rule that allows it.
type SourceSet struct {
	// Name is the identifier in the generated ruleset. It is stable across a
	// rename of the list it came from, because installed rules refer to it.
	Name string `json:"name"`
	// Title is what an operator calls the list, carried only so the rendered
	// ruleset can say which set is which in a comment.
	Title string `json:"title"`
	// Family is FamilyIPv4 or FamilyIPv6. A set holds one family: nftables
	// types them, and a rule works in one family anyway.
	Family string `json:"family"`
	// Prefixes are the ranges, already masked and deduplicated.
	Prefixes []string `json:"prefixes"`
}

type Ruleset struct {
	Routes []RouteSpec `json:"routes"`
	// SourceSets are the shared address sets the rules refer to, declared
	// once in the payload and matched by name. A set nothing refers to is
	// not declared: the ruleset is the desired state, and an unused set in
	// the kernel is state nothing asked for.
	SourceSets []SourceSet `json:"source_sets,omitempty"`
	// Retired names rules that no longer exist and whose named counter objects
	// are therefore to be removed.
	//
	// A counter deliberately outlives rule replacement (§5.1): flushing a table
	// empties its chains but leaves its stateful objects alone, which is what
	// lets a rule be edited without losing the kernel's own figures. A rule that
	// has been deleted has nothing left to preserve, so without this its
	// counters would sit in the kernel until the next reboot, describing a rule
	// the panel does not have.
	Retired []int64 `json:"retired,omitempty"`

	// LiveChains names the chains the kernel currently holds in the panel's own
	// namespace, so a render can converge the kernel's chain inventory to the
	// one it declares.
	//
	// It is here for the same reason Retired is: flushing a table empties its
	// chains but does not remove them, so a chain an earlier build created — or
	// one this ruleset no longer has any rule for — survives every subsequent
	// apply. Without this the kernel's shape is a function of a host's install
	// history rather than of what the panel declares, and two hosts running the
	// same binary end up holding different tables. That is exactly what happened
	// to the chain the renderer used to call `mss`.
	//
	// Nil means "not read", not "there are none": nothing is ever removed on the
	// strength of an inventory the panel failed to obtain.
	LiveChains []string `json:"live_chains,omitempty"`
}

// StaleChains returns the panel's own chains the kernel holds that a render
// declaring `declared` no longer has a use for, in a deterministic order.
//
// Only names the panel itself creates are ever considered, so a chain someone
// else put in the panel's namespace is reported by reconcile and left alone
// rather than quietly deleted.
func (r Ruleset) StaleChains(owned map[string]bool, declared map[string]bool) []string {
	if len(r.LiveChains) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, name := range r.LiveChains {
		if declared[name] || seen[name] || !owned[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Sorted returns the routes in emission order: the operator's sort order first,
// then the identifier, so the output is deterministic and the same request
// against the same state renders byte for byte the same payload.
func (r Ruleset) Sorted() []RouteSpec {
	out := make([]RouteSpec, len(r.Routes))
	copy(out, r.Routes)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SortOrder != out[j].SortOrder {
			return out[i].SortOrder < out[j].SortOrder
		}
		return out[i].RouteRuleID < out[j].RouteRuleID
	})
	return out
}

// RetiredSorted returns the retired rule identifiers in ascending order, with
// duplicates removed, so a payload does not depend on the order the caller
// happened to discover them in and never asks to delete the same object twice.
func (r Ruleset) RetiredSorted() []int64 {
	if len(r.Retired) == 0 {
		return nil
	}
	seen := make(map[int64]bool, len(r.Retired))
	out := make([]int64, 0, len(r.Retired))
	for _, id := range r.Retired {
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HasIPv6 reports whether any rule works in the IPv6 address family, which is
// what decides whether IPv6 forwarding has to be enabled.
func (r Ruleset) HasIPv6() bool {
	for _, route := range r.Routes {
		if route.IsIPv6() {
			return true
		}
	}
	return false
}

// Check validates every rule structurally, collecting the first failure.
func (r Ruleset) Check() error {
	for _, route := range r.Sorted() {
		if err := route.Check(); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- payloads

// Payload kinds, naming which tool consumes each part.
const (
	PartNftables  = "nftables"
	PartIptables  = "iptables"
	PartIp6tables = "ip6tables"
)

// Part is one rendered file and the command that installs it. The text is the
// exact bytes the tool is given, which is what the preview endpoint shows the
// operator before anything is carried out (§7).
type Part struct {
	Kind string   `json:"kind"`
	Path string   `json:"path"`
	Text string   `json:"text"`
	Argv []string `json:"argv"`
}

// Assertion is a rule the panel guarantees exists in a chain it does not own.
// Check reports whether it is already there and Install puts it in.
//
// The jump rules of the iptables backend are the only thing the panel ever adds
// to a built-in chain, and they are added this way — checked first, inserted
// only when missing — because appending unconditionally is exactly the defect
// that made running the legacy script twice duplicate every rule.
type Assertion struct {
	Description string   `json:"description"`
	Check       []string `json:"check"`
	Install     []string `json:"install"`
}

// Payload is everything one apply does. It is a complete replacement of the
// panel's namespace, never a delta.
type Payload struct {
	Backend    string      `json:"backend"`
	Parts      []Part      `json:"parts"`
	Assertions []Assertion `json:"assertions,omitempty"`
	// RemovesChains names the panel's own chains this payload takes out of the
	// kernel because the ruleset no longer declares them. It is stated here as
	// well as written into the text so a caller can tell that a payload does
	// something without reading it, which is what lets the startup pass decide
	// whether an otherwise empty ruleset is worth applying at all.
	RemovesChains []string `json:"removes_chains,omitempty"`
}

// Text renders the payload the way an operator reads it: every part, in order,
// with a header naming the file it is written to. This is what the preview
// panel displays.
func (p Payload) Text() string {
	var b strings.Builder
	for i, part := range p.Parts {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "# ---- %s: %s ----\n", part.Kind, part.Path)
		b.WriteString(part.Text)
		if !strings.HasSuffix(part.Text, "\n") {
			b.WriteString("\n")
		}
	}
	return b.String()
}

// LiveRule is one rule read back from the kernel, attributed to the database
// row that generated it by its identity comment.
// Chain roles. A live rule is attributed to the role its chain serves rather
// than to the chain's name, because the two backends name their chains
// differently and everything above this package cares about the role.
const (
	RolePrerouting  = "prerouting"
	RoleOutput      = "output"
	RolePostrouting = "postrouting"
	RoleForward     = "forward"
	RoleAccounting  = "accounting"
	RoleMss         = "mss"
	RoleMark        = "mark"

	// RoleLocalAccounting covers the chains that count traffic this server
	// originates itself. There are two of them — one on output, one on input —
	// because that is where such traffic goes; they share a role because they
	// are one measurement taken at the two hooks it passes through.
	RoleLocalAccounting = "local_accounting"
)

type LiveRule struct {
	// RouteRuleID is zero for a rule in the panel's namespace that carries no
	// identity comment, which reconciliation reports as unmanaged rather than
	// silently adopting or deleting — unless it is Structural, which is the
	// ruleset's own scaffolding.
	RouteRuleID int64 `json:"route_rule_id"`
	// Chain is the backend's own name for it; Role is what that chain serves.
	Chain      string `json:"chain"`
	Role       string `json:"role,omitempty"`
	Text       string `json:"text"`
	Structural bool   `json:"structural,omitempty"`
}

// Live is the panel's ruleset as the kernel actually holds it. Verification
// compares this against what was intended; a zero exit code from the apply is
// never taken as proof of anything (§7).
type Live struct {
	Backend string     `json:"backend"`
	Text    string     `json:"text"`
	Rules   []LiveRule `json:"rules"`
	// Chains names every chain the kernel holds in the panel's namespace, in the
	// order it reported them. An empty chain contributes no Rules entry at all,
	// so without this the inventory is invisible to everything above — which is
	// how a table could hold chains no build had rendered for months.
	Chains []string `json:"chains,omitempty"`
	// MissingJumps names the built-in chains whose jump into the panel's own
	// chains is absent. On the iptables backend this is the classic failure
	// after another tool flushes a built-in chain.
	MissingJumps []string `json:"missing_jumps,omitempty"`
}

// IDs returns the rule identifiers present in the live ruleset.
func (l Live) IDs() map[int64]bool {
	out := map[int64]bool{}
	for _, r := range l.Rules {
		if r.RouteRuleID != 0 {
			out[r.RouteRuleID] = true
		}
	}
	return out
}

// Counter is one rule's traffic as the kernel counts it. The direction is from
// the relay's point of view: Tx is what went to the destination and Rx is what
// came back from it.
type Counter struct {
	RouteRuleID int64  `json:"route_rule_id"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	RxPackets   uint64 `json:"rx_packets"`
	TxPackets   uint64 `json:"tx_packets"`
}

// Capabilities describes what one backend can do here and now, so the frontend
// can explain what is in use and disable what this host cannot serve.
type Capabilities struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`
	Version   string `json:"version,omitempty"`
	// Namespace names what the backend owns, e.g. "table inet gre_panel".
	Namespace string `json:"namespace"`
	// Binaries are the resolved tool paths this backend would run.
	Binaries map[string]string `json:"binaries,omitempty"`
	// Features reports per-option support, keyed by the option names below.
	Features map[string]bool `json:"features"`
}

// Feature keys reported in Capabilities.
const (
	FeatureIPv6                  = "ipv6"
	FeaturePortRanges            = "port_ranges"
	FeatureLoadBalanceRoundRobin = "load_balance_round_robin"
	FeatureLoadBalanceSourceHash = "load_balance_source_hash"
	FeatureLoadBalanceWeighted   = "load_balance_weighted"
	FeatureConnectionLimits      = "connection_limits"
	FeatureRateLimits            = "connection_rate_limits"
	FeatureLogging               = "logging"
	FeatureFwMark                = "fwmark"
	FeatureMssClamp              = "mss_clamp"
	FeatureNamedCounters         = "named_counters"
	// FeatureNamedSets is the backend's ability to declare a shared address
	// set once and match rules against it by name. Without it every rule that
	// allows a list carries the list's ranges itself.
	FeatureNamedSets = "named_sets"
)

// Backend is the whole contract between the panel and the host's netfilter
// configuration.
//
// Implementations must be safe for concurrent use: read paths are called from
// request handlers and from the traffic sampler while an apply is running.
// Serialising mutations is the caller's job, through the global mutation lock.
type Backend interface {
	// Name identifies the implementation, e.g. "nftables".
	Name() string
	// Capabilities reports what this implementation can do here and now.
	Capabilities() Capabilities

	// Render turns the desired ruleset into the exact payload that would be
	// applied. It is pure, deterministic, and touches nothing.
	Render(rs Ruleset) (Payload, error)
	// Apply writes the payload and submits it as one transaction per part.
	Apply(ctx context.Context, payload Payload) error
	// ReadBack returns the panel's ruleset as the kernel holds it.
	ReadBack(ctx context.Context) (Live, error)
	// Counters returns the per-rule byte and packet counters, read from the
	// forward-hook accounting rules and never from a nat chain (§5.1).
	Counters(ctx context.Context) (map[int64]Counter, error)
	// Foreign lists the redirecting rules on this host that the panel does not
	// own, so one shadowing the panel's own is reported rather than left to be
	// discovered as a rule that is installed and does nothing (§6.2, §9).
	// Nothing here ever modifies them.
	Foreign(ctx context.Context) (ForeignView, error)
	// Flush removes the panel's namespace, and only the panel's namespace.
	Flush(ctx context.Context) error
}

// ---------------------------------------------------------------- helpers

// isUnspecified reports whether an address means "any local address": empty,
// 0.0.0.0 or ::. Rendering a match on the literal unspecified address would
// match nothing, so these generate no address match at all.
func isUnspecified(address string) bool {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return true
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return false
	}
	return addr.IsUnspecified()
}

// FamilyOf reports the address family of a parsed address, in this package's
// spelling.
func FamilyOf(addr netip.Addr) string {
	if addr.Is4() || addr.Is4In6() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// FamilyOfAddress reports the family of an address in text form.
func FamilyOfAddress(address string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return "", false
	}
	return FamilyOf(addr.Unmap()), true
}

// hostPrefix renders an address as a single-host CIDR, which is the form
// iptables prints and therefore the form the panel writes so that a rule read
// back compares equal to the rule that was written.
func hostPrefix(address string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return strings.TrimSpace(address)
	}
	return fmt.Sprintf("%s/%d", addr.Unmap(), addr.Unmap().BitLen())
}

// weightsOf returns the weights of a set of destinations, defaulting a missing
// or nonsensical weight to 1 so a rule can never render a zero-width share.
func weightsOf(destinations []Destination) []int {
	out := make([]int, len(destinations))
	for i, d := range destinations {
		if d.Weight <= 0 {
			out[i] = 1
			continue
		}
		out[i] = d.Weight
	}
	return out
}

func sumOf(values []int) int {
	total := 0
	for _, v := range values {
		total += v
	}
	return total
}
