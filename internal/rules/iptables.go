package rules

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/exec"
)

// Default binary paths, used only when nothing better was resolved at startup.
const (
	DefaultIptablesBin        = "/usr/sbin/iptables"
	DefaultIptablesRestoreBin = "/usr/sbin/iptables-restore"
	DefaultIp6tablesBin       = "/usr/sbin/ip6tables"
	DefaultIp6tablesRestore   = "/usr/sbin/ip6tables-restore"
	DefaultIptablesSaveBin    = "/usr/sbin/iptables-save"
	DefaultIp6tablesSaveBin   = "/usr/sbin/ip6tables-save"
)

// Iptables is the fallback backend, for hosts without nft (§2.1).
//
// It owns a set of dedicated chains and rebuilds only those. The only thing it
// ever adds to a built-in chain is one jump rule per chain, checked before it is
// installed so a second apply cannot duplicate it — the defect that made running
// the script this subsystem replaces twice produce two matching rules.
//
// Persistence is the panel's own file, restored with --noflush against a
// payload containing only the panel's chains. The distribution's firewall
// persistence package is never installed and never used: it snapshots the whole
// system's ruleset, including other software's rules, and restores that
// snapshot later, which is a well-known way to corrupt the state of a machine
// running Docker.
type Iptables struct {
	// Bin and RestoreBin drive IPv4; Bin6 and RestoreBin6 drive IPv6.
	Bin         string
	RestoreBin  string
	Bin6        string
	RestoreBin6 string
	// Legacy reports that these binaries speak to the legacy netfilter backend
	// rather than to nf_tables, which only changes what is reported.
	Legacy  bool
	Version string
	Dir     string
	Runner  exec.Runner
}

// NewIptables returns the iptables backend.
func NewIptables(bin, restoreBin, bin6, restoreBin6, dir string, runner exec.Runner) *Iptables {
	if runner == nil {
		runner = exec.NewRunner()
	}
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir
	}
	return &Iptables{
		Bin: bin, RestoreBin: restoreBin, Bin6: bin6, RestoreBin6: restoreBin6,
		Dir: dir, Runner: runner,
	}
}

// Name identifies the implementation, distinguishing the two netfilter backends
// iptables can be speaking to.
func (t *Iptables) Name() string {
	if t.Legacy {
		return BackendIptablesLegacy
	}
	return BackendIptablesNft
}

// Path and Path6 are where this backend's rendered rulesets live.
func (t *Iptables) Path() string  { return filepath.Join(t.Dir, IptablesFileName) }
func (t *Iptables) Path6() string { return filepath.Join(t.Dir, Ip6tablesFileName) }

// Capabilities reports what this backend can do here.
func (t *Iptables) Capabilities() Capabilities {
	available := strings.TrimSpace(t.Bin) != "" && strings.TrimSpace(t.RestoreBin) != ""
	detail := "iptables with dedicated panel-owned chains, restored with --noflush so only " +
		"the panel's own chains are rebuilt"
	switch {
	case !available:
		detail = "the iptables and iptables-restore binaries were not both found on this system"
	case t.Legacy:
		detail += "; these binaries speak to the legacy netfilter backend, which does not share " +
			"tables with nftables rules on this host"
	}
	return Capabilities{
		Name:      t.Name(),
		Available: available,
		Detail:    detail,
		Version:   t.Version,
		Namespace: strings.Join(OwnedChains(), ", "),
		Binaries: map[string]string{
			"iptables": t.Bin, "iptables-restore": t.RestoreBin,
			"ip6tables": t.Bin6, "ip6tables-restore": t.RestoreBin6,
		},
		Features: map[string]bool{
			FeatureIPv6:                  strings.TrimSpace(t.Bin6) != "" && strings.TrimSpace(t.RestoreBin6) != "",
			FeaturePortRanges:            true,
			FeatureLoadBalanceRoundRobin: true,
			FeatureLoadBalanceWeighted:   true,
			// Source hashing has no direct equivalent here. DNAT to a contiguous
			// address range with --persistent keeps a client on one destination,
			// so it is served when the destinations happen to form one, and
			// refused with an explanation when they do not.
			FeatureLoadBalanceSourceHash: true,
			FeatureConnectionLimits:      true,
			FeatureRateLimits:            true,
			FeatureLogging:               true,
			FeatureFwMark:                true,
			FeatureMssClamp:              true,
			FeatureNamedCounters:         false,
		},
	}
}

func (t *Iptables) ready() error {
	if strings.TrimSpace(t.Bin) == "" || strings.TrimSpace(t.RestoreBin) == "" {
		return fmt.Errorf("%w: iptables and iptables-restore were not both found", ErrUnavailable)
	}
	return nil
}

// ---------------------------------------------------------------- rendering

// iptSections collects the rules of one render per chain, so the payload can be
// assembled table by table in a fixed order.
type iptSections struct {
	mark []string
	mss  []string
	pre  []string
	out  []string
	post []string
	fwd  []string
	acct []string
}

// Render produces both payloads: one for iptables and one for ip6tables.
//
// Both are always rendered, even when no rule uses that family. The payload is
// the complete desired state, so a family whose last rule was just deleted has
// to be given an empty ruleset rather than be left alone with stale rules in it.
func (t *Iptables) Render(rs Ruleset) (Payload, error) {
	if err := rs.Check(); err != nil {
		return Payload{}, err
	}

	var v4, v6 iptSections
	for _, route := range rs.Sorted() {
		target := &v4
		if route.IsIPv6() {
			target = &v6
		}
		if err := t.renderRoute(route, target); err != nil {
			return Payload{}, err
		}
	}

	restore := t.RestoreBin
	if restore == "" {
		restore = DefaultIptablesRestoreBin
	}
	restore6 := t.RestoreBin6
	if restore6 == "" {
		restore6 = DefaultIp6tablesRestore
	}

	payload := Payload{
		Backend: t.Name(),
		Parts: []Part{
			{
				Kind: PartIptables, Path: t.Path(), Text: renderIptablesFile(&v4, false),
				Argv: []string{restore, "--noflush", t.Path()},
			},
			{
				Kind: PartIp6tables, Path: t.Path6(), Text: renderIptablesFile(&v6, true),
				Argv: []string{restore6, "--noflush", t.Path6()},
			},
		},
		Assertions: t.jumpAssertions(),
	}
	return payload, nil
}

// builtIn describes where one panel chain is jumped to from.
type builtIn struct {
	table    string
	chain    string
	target   string
	position string
}

// jumpTargets is the complete list of what the panel adds to a built-in chain:
// one jump each, and nothing else, ever.
//
// The accounting chain is jumped to before the forward chain so that counting
// happens whatever the forward chain then decides, which is the same reason the
// nftables backend gives its accounting chain an earlier hook priority.
func jumpTargets() []builtIn {
	return []builtIn{
		{"mangle", "PREROUTING", ChainMark, "1"},
		{"mangle", "FORWARD", ChainMss, "1"},
		{"nat", "PREROUTING", ChainPre, "1"},
		{"nat", "OUTPUT", ChainOut, "1"},
		{"nat", "POSTROUTING", ChainPost, "1"},
		{"filter", "FORWARD", ChainAcct, "1"},
		{"filter", "FORWARD", ChainFwd, "2"},
	}
}

// jumpAssertions renders the check-then-install pair for every jump rule, for
// both address families.
func (t *Iptables) jumpAssertions() []Assertion {
	bins := []struct {
		bin    string
		family string
	}{
		{orFallback(t.Bin, DefaultIptablesBin), "IPv4"},
		{orFallback(t.Bin6, DefaultIp6tablesBin), "IPv6"},
	}

	var out []Assertion
	for _, b := range bins {
		for _, j := range jumpTargets() {
			out = append(out, Assertion{
				Description: fmt.Sprintf("%s jump from the %s table's %s chain into %s",
					b.family, j.table, j.chain, j.target),
				Check:   []string{b.bin, "-t", j.table, "-C", j.chain, "-j", j.target},
				Install: []string{b.bin, "-t", j.table, "-I", j.chain, j.position, "-j", j.target},
			})
		}
	}
	return out
}

// renderIptablesFile assembles one iptables-restore payload.
func renderIptablesFile(s *iptSections, ipv6 bool) string {
	family := "IPv4"
	if ipv6 {
		family = "IPv6"
	}
	var b strings.Builder
	b.WriteString(header(
		"The panel's port forwarding rules for "+family+", rendered from the database.",
		"Restored with --noflush against the panel's own chains only: no other chain on",
		"this host is read, flushed or reordered, and no whole-system snapshot is ever",
		"taken, and the distribution's firewall persistence package is deliberately unused.",
		"",
		"Each chain is declared so it exists, then flushed explicitly, because --noflush",
		"leaves an existing chain's rules in place. The jump rules that reach these",
		"chains are installed separately, checked before they are added, so a second",
		"apply cannot duplicate them.",
		"",
		"Every rule carries the comment "+IdentityPrefix+"<RouteRuleID>, which is what lets a rule read",
		"back from the kernel be matched to the database row that generated it.",
	))
	b.WriteString("\n")

	writeIptTable(&b, "mangle",
		[]tableChain{{ChainMark, s.mark}, {ChainMss, s.mss}})
	writeIptTable(&b, "nat",
		[]tableChain{{ChainPre, s.pre}, {ChainOut, s.out}, {ChainPost, s.post}})

	// The established/related accept heads the forward chain rather than
	// belonging to any one rule.
	forward := s.fwd
	if len(forward) > 0 {
		forward = append([]string{
			"-A " + ChainFwd + " -m conntrack --ctstate ESTABLISHED,RELATED" +
				" -m comment --comment " + quote(StructuralComment) + " -j ACCEPT",
		}, forward...)
	}
	writeIptTable(&b, "filter",
		[]tableChain{{ChainAcct, s.acct}, {ChainFwd, forward}})

	return b.String()
}

type tableChain struct {
	name  string
	rules []string
}

func writeIptTable(b *strings.Builder, table string, chains []tableChain) {
	fmt.Fprintf(b, "*%s\n", table)
	for _, c := range chains {
		fmt.Fprintf(b, ":%s - [0:0]\n", c.name)
	}
	for _, c := range chains {
		fmt.Fprintf(b, "-F %s\n", c.name)
	}
	for _, c := range chains {
		for _, rule := range c.rules {
			b.WriteString(rule)
			b.WriteString("\n")
		}
	}
	b.WriteString("COMMIT\n")
}

// renderRoute appends one rule's iptables rules to the sections.
func (t *Iptables) renderRoute(s RouteSpec, out *iptSections) error {
	comment := []string{"-m", "comment", "--comment", quote(s.Identity())}
	head := "# " + describe(s)

	out.pre = append(out.pre, head)
	out.fwd = append(out.fwd, head)
	out.acct = append(out.acct, head)
	if s.IncludeLocalOriginated {
		out.out = append(out.out, head)
	}
	if s.NatMode != NatNone {
		out.post = append(out.post, head)
	}
	if s.ClampMssToPmtu {
		out.mss = append(out.mss, head)
	}
	if s.FwMark != nil {
		out.mark = append(out.mark, head)
	}

	for _, proto := range s.Protocol.Expand() {
		dnat, err := iptDnatRules(s, proto)
		if err != nil {
			return err
		}
		// iptables matches one source per rule, so an allowlist becomes one rule
		// per entry rather than one rule holding a set. Expanding it here rather
		// than relying on the comma form iptables expands for itself keeps the
		// rendered payload identical to what the kernel ends up holding, which is
		// what verification compares against.
		for _, source := range allowedSourcesOrAny(s) {
			bind := iptBindMatch(s, proto, source)
			for _, d := range dnat {
				out.pre = append(out.pre, iptRule(ChainPre, bind, d.match, comment, d.target))
				if s.IncludeLocalOriginated {
					out.out = append(out.out, iptRule(ChainOut, bind, d.match, comment, d.target))
				}
			}
			if s.FwMark != nil {
				out.mark = append(out.mark, iptRule(ChainMark, bind, nil, comment,
					[]string{"-j", "MARK", "--set-mark", fmt.Sprintf("0x%x", *s.FwMark)}))
			}
		}

		for _, d := range s.Destinations {
			dest := iptDestMatch(d, proto)

			if s.MaxConnectionsPerSource > 0 {
				out.fwd = append(out.fwd, iptRule(ChainFwd, dest, []string{
					"-m", "connlimit",
					"--connlimit-above", itoa(s.MaxConnectionsPerSource),
					"--connlimit-mask", iptHostMask(s),
				}, comment, []string{"-j", "DROP"}))
			}
			if s.ConnectionRateLimit > 0 {
				out.fwd = append(out.fwd, iptRule(ChainFwd, dest, []string{
					"-m", "conntrack", "--ctstate", "NEW",
					"-m", "hashlimit",
					"--hashlimit-above", fmt.Sprintf("%d/minute", s.ConnectionRateLimit),
					"--hashlimit-mode", "srcip",
					"--hashlimit-name", fmt.Sprintf("grep_%d", s.RouteRuleID),
				}, comment, []string{"-j", "DROP"}))
			}
			if s.Logging {
				out.fwd = append(out.fwd, iptRule(ChainFwd, dest, []string{
					"-m", "conntrack", "--ctstate", "NEW",
					"-m", "limit", "--limit", LogRateLimit,
				}, comment, []string{"-j", "LOG", "--log-prefix", quote(iptLogPrefix(s))}))
			}
			for _, source := range allowedSourcesOrAny(s) {
				out.fwd = append(out.fwd, iptRule(ChainFwd, dest, sourceMatch(source), comment,
					[]string{"-j", "ACCEPT"}))
			}

			switch s.NatMode {
			case NatMasquerade:
				out.post = append(out.post, iptRule(ChainPost, dest, nil, comment,
					[]string{"-j", "MASQUERADE"}))
			case NatSnat:
				out.post = append(out.post, iptRule(ChainPost, dest, nil, comment,
					[]string{"-j", "SNAT", "--to-source", s.SnatAddress}))
			}

			// Accounting rules carry no target at all: they count and fall
			// through. They live in the filter table, never in nat, because a nat
			// hook only sees the first packet of each connection.
			out.acct = append(out.acct,
				iptRule(ChainAcct, dest, nil, comment, nil),
				iptRule(ChainAcct, iptReverseMatch(d, proto), nil, comment, nil))

			if s.ClampMssToPmtu && proto == ProtocolTCP {
				out.mss = append(out.mss, iptRule(ChainMss, dest,
					[]string{"--tcp-flags", "SYN,RST", "SYN"}, comment,
					[]string{"-j", "TCPMSS", "--clamp-mss-to-pmtu"}))
			}
		}
	}
	return nil
}

// iptRule assembles one -A line. The target comes last, because iptables parses
// everything after -j as options to that target.
func iptRule(chain string, groups ...[]string) string {
	parts := []string{"-A", chain}
	for _, g := range groups {
		parts = append(parts, g...)
	}
	return strings.Join(parts, " ")
}

// iptBindMatch renders the match for traffic arriving for this rule from one
// allowed source, or from anywhere when source is empty.
func iptBindMatch(s RouteSpec, proto Protocol, source string) []string {
	var parts []string
	if !s.BindsAnyAddress() {
		parts = append(parts, "-d", hostPrefix(s.BindAddress))
	}
	parts = append(parts, "-p", string(proto), "--dport", iptPorts(s.BindPorts))
	if iface := strings.TrimSpace(s.BindInterface); iface != "" {
		parts = append(parts, "-i", iface)
	}
	return append(parts, sourceMatch(source)...)
}

// iptDestMatch renders the match for traffic on its way to one destination.
func iptDestMatch(d Destination, proto Protocol) []string {
	return []string{"-d", hostPrefix(d.Address), "-p", string(proto), "--dport", iptPorts(d.Ports)}
}

// iptReverseMatch renders the return direction, used only for accounting.
func iptReverseMatch(d Destination, proto Protocol) []string {
	return []string{"-s", hostPrefix(d.Address), "-p", string(proto), "--sport", iptPorts(d.Ports)}
}

// allowedSourcesOrAny returns the rule's allowlist, or a single empty entry
// meaning "any source", so callers loop the same way whether or not the relay
// is restricted.
func allowedSourcesOrAny(s RouteSpec) []string {
	if len(s.AllowedSources) == 0 {
		return []string{""}
	}
	return s.AllowedSources
}

// sourceMatch renders one source match, or nothing for "any source".
func sourceMatch(source string) []string {
	if strings.TrimSpace(source) == "" {
		return nil
	}
	return []string{"-s", source}
}

// iptPorts renders a port or range in the colon form iptables uses.
func iptPorts(r PortRange) string {
	if r.IsRange() {
		return fmt.Sprintf("%d:%d", r.Port, r.End)
	}
	return itoa(r.Port)
}

// iptHostMask is the prefix length of a single host, which is what the
// connlimit mask has to be for "per source address" to mean one address.
func iptHostMask(s RouteSpec) string {
	if s.IsIPv6() {
		return "128"
	}
	return "32"
}

// iptDnat is one DNAT rule: an optional extra match that selects which share of
// traffic it takes, and the target itself.
type iptDnat struct {
	match  []string
	target []string
}

// iptDnatRules renders the DNAT rules for a route, expanding load balancing
// into the statistic-match ladder iptables expresses it with.
//
// The ladder is written so each rule takes 1/n of what reaches it: with three
// destinations the first takes every third packet, the second takes every
// second of the rest, and the last takes what is left. Written any other way
// the shares come out wrong.
func iptDnatRules(s RouteSpec, proto Protocol) ([]iptDnat, error) {
	live := s.Destinations
	if len(live) == 1 {
		return []iptDnat{{target: []string{"-j", "DNAT", "--to-destination", iptAddressPort(live[0])}}}, nil
	}

	mode := s.LoadBalance
	if mode == "" || mode == LoadBalanceNone {
		mode = LoadBalanceRoundRobin
	}
	for _, d := range live {
		if d.Ports.IsRange() {
			return nil, fmt.Errorf("%w: load balancing across a port range (%s on %s)",
				ErrUnsupported, d.Ports, d.Address)
		}
	}

	switch mode {
	case LoadBalanceSourceHash:
		// iptables has no source-hash distribution. DNAT to a contiguous address
		// range with --persistent keeps a given client on a given destination,
		// which is the same guarantee, so it is used when the destinations form
		// one and refused with an explanation when they do not.
		first, last, ok := contiguousRange(live)
		if !ok {
			return nil, fmt.Errorf("%w: source-hash load balancing on the iptables backend needs the "+
				"destinations to be a contiguous address range sharing one port; use round robin, or "+
				"run the nftables backend, which hashes across any set of destinations", ErrUnsupported)
		}
		return []iptDnat{{target: []string{"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s-%s:%d", first, last, live[0].Ports.Port),
			"--persistent"}}}, nil

	case LoadBalanceRoundRobin, LoadBalanceWeighted:
		weights := weightsOf(live)
		if mode == LoadBalanceRoundRobin {
			for i := range weights {
				weights[i] = 1
			}
		}
		remaining := sumOf(weights)
		out := make([]iptDnat, 0, len(live))
		for i, d := range live {
			target := []string{"-j", "DNAT", "--to-destination", iptAddressPort(d)}
			if i == len(live)-1 {
				out = append(out, iptDnat{target: target})
				break
			}
			// --every N --packet 0 takes one in N of what still reaches this rule,
			// so the divisor shrinks as earlier rules take their share.
			every := remaining / weights[i]
			out = append(out, iptDnat{
				match: []string{"-m", "statistic", "--mode", "nth",
					"--every", itoa(every), "--packet", "0"},
				target: target,
			})
			remaining -= weights[i]
		}
		return out, nil
	}
	return nil, fmt.Errorf("%w: load balancing mode %q", ErrUnsupported, s.LoadBalance)
}

// contiguousRange reports whether the destinations are consecutive addresses on
// one port, which is the only shape iptables can distribute by source.
func contiguousRange(destinations []Destination) (string, string, bool) {
	if len(destinations) < 2 {
		return "", "", false
	}
	port := destinations[0].Ports.Port
	previous, err := netip.ParseAddr(destinations[0].Address)
	if err != nil {
		return "", "", false
	}
	first := previous
	for _, d := range destinations[1:] {
		if d.Ports.Port != port || d.Ports.IsRange() {
			return "", "", false
		}
		addr, err := netip.ParseAddr(d.Address)
		if err != nil || addr != previous.Next() {
			return "", "", false
		}
		previous = addr
	}
	return first.String(), previous.String(), true
}

// iptAddressPort renders a destination for --to-destination, bracketing an IPv6
// address and rendering a range with a dash the way iptables expects.
func iptAddressPort(d Destination) string {
	address := d.Address
	if strings.Contains(address, ":") {
		address = "[" + address + "]"
	}
	if d.Ports.IsRange() {
		return fmt.Sprintf("%s:%d-%d", address, d.Ports.Port, d.Ports.End)
	}
	return fmt.Sprintf("%s:%d", address, d.Ports.Port)
}

// iptLogPrefixMax is iptables' hard limit on the length of a log prefix. A
// longer one is rejected outright, so it is trimmed here rather than allowed to
// fail an apply over a long identifier.
const iptLogPrefixMax = 29

func iptLogPrefix(s RouteSpec) string {
	prefix := logPrefix(s)
	if len(prefix) > iptLogPrefixMax {
		return prefix[:iptLogPrefixMax]
	}
	return prefix
}

func quote(s string) string { return `"` + s + `"` }

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func orFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// ---------------------------------------------------------------- applying

// Apply restores both payloads and then asserts the jump rules.
//
// The order matters: the chains have to exist before anything jumps into them,
// or the jump is refused and the panel would report a ruleset it does not have.
func (t *Iptables) Apply(ctx context.Context, payload Payload) error {
	if err := t.ready(); err != nil {
		return err
	}
	for _, part := range payload.Parts {
		if part.Kind == PartIp6tables && !t.ipv6Available() {
			// A host without ip6tables can still relay IPv4. Refusing the whole
			// apply because the v6 payload cannot be installed would take the
			// working half down with the missing one.
			continue
		}
		if err := writeOwned(ctx, part.Path, part.Text); err != nil {
			return err
		}
		if _, err := t.Runner.Run(ctx, part.Argv); err != nil {
			return fmt.Errorf("restoring the panel's %s rules: %w", part.Kind, err)
		}
	}

	for _, assertion := range payload.Assertions {
		if len(assertion.Check) == 0 || len(assertion.Install) == 0 {
			continue
		}
		if !t.ipv6Available() && strings.Contains(assertion.Check[0], "ip6tables") {
			continue
		}
		if _, err := t.Runner.Run(ctx, assertion.Check); err == nil {
			continue // already there; adding it again is what duplicates rules
		}
		if _, err := t.Runner.Run(ctx, assertion.Install); err != nil {
			return fmt.Errorf("installing the %s: %w", assertion.Description, err)
		}
	}
	return nil
}

func (t *Iptables) ipv6Available() bool {
	return strings.TrimSpace(t.Bin6) != "" && strings.TrimSpace(t.RestoreBin6) != ""
}

// ReadBack lists the panel's own chains, and reports any jump rule missing from
// a built-in chain — the classic failure after another tool flushes one.
func (t *Iptables) ReadBack(ctx context.Context) (Live, error) {
	if err := t.ready(); err != nil {
		return Live{}, err
	}
	live := Live{Backend: t.Name()}
	var text strings.Builder

	for _, chain := range OwnedChains() {
		for _, table := range tablesOf(chain) {
			res, err := t.Runner.Run(ctx, []string{t.Bin, "-t", table, "-S", chain})
			if err != nil {
				// A chain that does not exist yet is an empty chain, not a failure.
				continue
			}
			text.WriteString(res.Stdout)
			live.Rules = append(live.Rules, ParseIptablesRules(res.Stdout)...)
		}
	}

	for _, j := range jumpTargets() {
		if _, err := t.Runner.Run(ctx,
			[]string{t.Bin, "-t", j.table, "-C", j.chain, "-j", j.target}); err != nil {
			live.MissingJumps = append(live.MissingJumps,
				fmt.Sprintf("%s/%s -> %s", j.table, j.chain, j.target))
		}
	}

	live.Text = text.String()
	return live, nil
}

// iptChainRoles maps the panel's own chain names to the role each serves.
var iptChainRoles = map[string]string{
	ChainPre:  RolePrerouting,
	ChainOut:  RoleOutput,
	ChainPost: RolePostrouting,
	ChainFwd:  RoleForward,
	ChainAcct: RoleAccounting,
	ChainMss:  RoleMss,
	ChainMark: RoleMark,
}

// ParseIptablesRules reads the -A lines of an iptables ruleset — the form both
// `iptables -S` and a restore payload use — into live rules.
func ParseIptablesRules(text string) []LiveRule {
	var out []LiveRule
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chain := fields[1]
		if !IsPanelChain(chain) {
			continue
		}
		id, _ := ParseIdentity(line)
		out = append(out, LiveRule{
			RouteRuleID: id, Chain: chain, Role: iptChainRoles[chain],
			Text: line, Structural: IsStructural(line),
		})
	}
	return out
}

// tablesOf returns the table a panel chain lives in.
func tablesOf(chain string) []string {
	switch chain {
	case ChainPre, ChainOut, ChainPost:
		return []string{"nat"}
	case ChainFwd, ChainAcct:
		return []string{"filter"}
	case ChainMss, ChainMark:
		return []string{"mangle"}
	}
	return nil
}

// Counters reads the accounting chain's own counters.
//
// iptables-save -c prints each rule with its packet and byte counts in exactly
// the syntax the rule was written in, comment included, which makes attributing
// a count to a rule a matter of reading the identity comment rather than
// correlating two different listings.
func (t *Iptables) Counters(ctx context.Context) (map[int64]Counter, error) {
	if err := t.ready(); err != nil {
		return nil, err
	}
	saveBin := t.saveBin()
	res, err := t.Runner.Run(ctx, []string{saveBin, "-c", "-t", "filter"})
	if err != nil {
		return nil, fmt.Errorf("reading the panel's counters: %w", err)
	}
	return ParseIptablesCounters(res.Stdout), nil
}

// saveBin is iptables-save, derived from the restore binary beside it.
func (t *Iptables) saveBin() string {
	if strings.HasSuffix(t.RestoreBin, "-restore") {
		return strings.TrimSuffix(t.RestoreBin, "-restore") + "-save"
	}
	return DefaultIptablesSaveBin
}

// ParseIptablesCounters reads `iptables-save -c` output into per-rule figures.
//
// The direction comes from the match itself: the accounting rule watching
// traffic towards the destination matches on its destination port, and the one
// watching the return direction matches on its source port.
func ParseIptablesCounters(text string) map[int64]Counter {
	counters := map[int64]Counter{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		figures, rule, ok := strings.Cut(strings.TrimPrefix(line, "["), "] ")
		if !ok {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(rule), "-A "+ChainAcct+" ") {
			continue
		}
		id, ok := ParseIdentity(rule)
		if !ok {
			continue
		}
		packetsText, bytesText, ok := strings.Cut(figures, ":")
		if !ok {
			continue
		}
		packets, err1 := strconv.ParseUint(strings.TrimSpace(packetsText), 10, 64)
		bytes, err2 := strconv.ParseUint(strings.TrimSpace(bytesText), 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}

		counter := counters[id]
		counter.RouteRuleID = id
		if strings.Contains(rule, "--sport") {
			counter.RxPackets += packets
			counter.RxBytes += bytes
		} else {
			counter.TxPackets += packets
			counter.TxBytes += bytes
		}
		counters[id] = counter
	}
	return counters
}

// Foreign lists every redirecting rule in the host's nat table outside the
// panel's own chains (§9).
//
// The nat table is the only one that matters here: a DNAT anywhere else cannot
// exist, and a filter rule cannot take a packet the panel's prerouting rule
// would otherwise have redirected. Nothing found is ever modified.
func (t *Iptables) Foreign(ctx context.Context) (ForeignView, error) {
	if err := t.ready(); err != nil {
		return ForeignView{Detail: err.Error()}, err
	}
	view := ForeignView{}
	saveBin := t.saveBin()

	res, err := t.Runner.Run(ctx, []string{saveBin, "-t", "nat"})
	if err != nil {
		return ForeignView{
			Detail: "the host's nat table could not be listed: " + strings.TrimSpace(res.Stderr),
		}, fmt.Errorf("listing the host nat table: %w", err)
	}
	view.Readable = true
	view.Rules = append(view.Rules, ParseIptablesForeign(res.Stdout, "nat")...)

	// The IPv6 table is read when the host has one. A missing ip6tables is not
	// a failure: it means this host relays IPv4 only.
	if t.ipv6Available() {
		if res6, err := t.Runner.Run(ctx, []string{t.save6Bin(), "-t", "nat"}); err == nil {
			view.Rules = append(view.Rules, ParseIptablesForeign(res6.Stdout, "nat6")...)
		}
	}

	view.Managers = managerNames(view.Rules)
	return view, nil
}

// save6Bin is ip6tables-save, derived from the restore binary beside it.
func (t *Iptables) save6Bin() string {
	if strings.HasSuffix(t.RestoreBin6, "-restore") {
		return strings.TrimSuffix(t.RestoreBin6, "-restore") + "-save"
	}
	return DefaultIp6tablesSaveBin
}

// Flush empties and removes the panel's own chains, and only those, after
// taking out the jump rules that point at them. Anything already gone is
// skipped rather than treated as a failure.
func (t *Iptables) Flush(ctx context.Context) error {
	if err := t.ready(); err != nil {
		return err
	}
	bins := []string{t.Bin}
	if t.ipv6Available() {
		bins = append(bins, t.Bin6)
	}
	for _, bin := range bins {
		for _, j := range jumpTargets() {
			if _, err := t.Runner.Run(ctx,
				[]string{bin, "-t", j.table, "-C", j.chain, "-j", j.target}); err != nil {
				continue
			}
			if _, err := t.Runner.Run(ctx,
				[]string{bin, "-t", j.table, "-D", j.chain, "-j", j.target}); err != nil {
				return fmt.Errorf("removing the jump from %s/%s: %w", j.table, j.chain, err)
			}
		}
		for _, chain := range OwnedChains() {
			for _, table := range tablesOf(chain) {
				if _, err := t.Runner.Run(ctx, []string{bin, "-t", table, "-F", chain}); err != nil {
					continue // the chain is not there, so there is nothing to flush
				}
				if _, err := t.Runner.Run(ctx, []string{bin, "-t", table, "-X", chain}); err != nil {
					return fmt.Errorf("removing the chain %s: %w", chain, err)
				}
			}
		}
	}
	return nil
}
