package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/exec"
)

// DefaultNftBin is used only when nothing better was resolved at startup.
const DefaultNftBin = "/usr/sbin/nft"

// LogRateLimit bounds how often a rule may log a new connection. Logging every
// new connection on a busy relay fills the journal and hides everything else,
// so it is rate limited rather than optional.
const LogRateLimit = "5/minute"

// OldestSupportedNft is the oldest nft the rendered ruleset has to remain
// parseable by. It is the one Ubuntu 22.04 LTS ships, which is the oldest
// release this panel installs on.
//
// It is not a formality. nft's parser gained syntax over these releases, and a
// construct the newest version accepts can be a hard rejection on this one —
// which takes the whole transaction with it, since the payload is applied as
// one. TestGoldenPayloadsParseOnEveryNft is what holds the line: it refuses to
// certify the goldens against a newer parser alone.
const OldestSupportedNft = "1.0.2"

// Chain names inside the panel's table. They are the hook they serve, except
// for the two that exist because a nat chain cannot mangle a packet.
//
// The clamping chain is called mss_clamp rather than mss because `mss` is a
// keyword in the nft parser and cannot be a bare chain name before v1.0.3 —
// on Ubuntu 22.04's v1.0.2 the whole ruleset is rejected with "unexpected mss,
// expecting string". Quoting it is not a way out: both v1.0.2 and v1.0.9
// refuse a quoted chain name outright. Every other name here is checked
// against the oldest supported nft by TestGoldenPayloadsParseOnEveryNft.
const (
	nftChainPrerouting  = "prerouting"
	nftChainOutput      = "output"
	nftChainPostrouting = "postrouting"
	nftChainForward     = "forward"
	nftChainAccounting  = "accounting"
	nftChainMss         = "mss_clamp"
	nftChainMarking     = "marking"

	// The accounting chain hooks forward, and traffic this server originates
	// never goes near it: it leaves through output and its replies arrive at
	// input. A rule that relays local traffic therefore needs a counter on each
	// of those two hooks, or it reports live connections and no bytes at once.
	nftChainLocalOut = "local_out_accounting"
	nftChainLocalIn  = "local_in_accounting"

	// nftChainMssLegacy is what the clamping chain was called before the rename
	// above. It is not rendered any more, but hosts installed before the rename
	// still hold a chain by that name — flushing a table does not remove its
	// chains — so it stays here to be recognised as the panel's own and cleaned
	// up. A name the panel has ever created has to remain owned, or the cleanup
	// would refuse to touch it and the kernel would never converge.
	nftChainMssLegacy = "mss"
)

// nftChainNameFloor names the oldest nft release that parses a chain name the
// panel may have to spell. A name absent from the map parses everywhere.
//
// It exists because removing a stale chain means writing its name, and a name
// the running parser rejects does not fail on its own: it fails the whole
// transaction, taking every rule in it down. So a name is only ever spelled on
// a parser known to accept it. `mss` is unreachable in practice on a parser
// that rejects it — such a host could never have created the chain — but the
// panel does not get to assume that about a kernel it did not put there.
var nftChainNameFloor = map[string]string{
	nftChainMssLegacy: "1.0.3",
}

// nftOwnedChains is every chain name the panel has ever created in its own
// table. Only these are ever deleted: a chain someone else put in the panel's
// namespace is reported by reconcile and left exactly where it is.
var nftOwnedChains = map[string]bool{
	nftChainPrerouting:  true,
	nftChainOutput:      true,
	nftChainPostrouting: true,
	nftChainForward:     true,
	nftChainAccounting:  true,
	nftChainMss:         true,
	nftChainMarking:     true,
	nftChainMssLegacy:   true,
	nftChainLocalOut:    true,
	nftChainLocalIn:     true,
}

// nftChainRoles maps the panel's own chain names to the role each serves, so
// everything above this package compares roles rather than names.
var nftChainRoles = map[string]string{
	nftChainPrerouting:  RolePrerouting,
	nftChainOutput:      RoleOutput,
	nftChainPostrouting: RolePostrouting,
	nftChainForward:     RoleForward,
	nftChainAccounting:  RoleAccounting,
	nftChainMss:         RoleMss,
	nftChainMssLegacy:   RoleMss,
	nftChainMarking:     RoleMark,
	nftChainLocalOut:    RoleLocalAccounting,
	nftChainLocalIn:     RoleLocalAccounting,
}

// Nftables is the primary backend: one table, owned entirely by the panel,
// replaced atomically (§2.1).
type Nftables struct {
	// Bin is the resolved nft path, or "" when it was not found.
	Bin string
	// Dir is where the rendered ruleset is written.
	Dir string
	// Version is what `nft --version` reported at startup, for capabilities.
	Version string
	Runner  exec.Runner
}

// NewNftables returns the nftables backend.
func NewNftables(bin, dir string, runner exec.Runner) *Nftables {
	if runner == nil {
		runner = exec.NewRunner()
	}
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir
	}
	return &Nftables{Bin: bin, Dir: dir, Runner: runner}
}

// Name identifies the implementation.
func (n *Nftables) Name() string { return BackendNftables }

// Path is where this backend's rendered ruleset lives.
func (n *Nftables) Path() string { return filepath.Join(n.Dir, NftFileName) }

// Capabilities reports what this backend can do here.
func (n *Nftables) Capabilities() Capabilities {
	available := strings.TrimSpace(n.Bin) != ""
	detail := "native nftables in a table owned entirely by the panel; changes are one atomic " +
		"transaction and coexist with other tables on this host"
	if !available {
		detail = "the nft binary was not found on this system"
	}
	return Capabilities{
		Name:      BackendNftables,
		Available: available,
		Detail:    detail,
		Version:   n.Version,
		Namespace: fmt.Sprintf("table %s %s", TableFamily, TableName),
		Binaries:  map[string]string{"nft": n.Bin},
		Features: map[string]bool{
			FeatureIPv6:                  true,
			FeaturePortRanges:            true,
			FeatureNamedSets:             true,
			FeatureLoadBalanceRoundRobin: true,
			FeatureLoadBalanceSourceHash: true,
			FeatureLoadBalanceWeighted:   true,
			FeatureConnectionLimits:      true,
			FeatureRateLimits:            true,
			FeatureLogging:               true,
			FeatureFwMark:                true,
			FeatureMssClamp:              true,
			FeatureNamedCounters:         true,
		},
	}
}

// nftBannerVersion pulls the version out of the banner `nft --version` prints,
// e.g. "nftables v1.0.9 (Old Doc Yak #3)".
var nftBannerVersion = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// parseNftVersion returns the three version components, or ok=false when the
// banner did not carry one.
func parseNftVersion(banner string) ([3]int, bool) {
	match := nftBannerVersion.FindStringSubmatch(banner)
	if match == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// canSpellChain reports whether this host's nft will parse a chain name.
//
// An unknown version is treated as the oldest release the panel supports, so
// the cautious answer is the default: a chain that cannot be named is left in
// the kernel and reported, which is strictly better than rendering a payload
// the host refuses in full.
func (n *Nftables) canSpellChain(name string) bool {
	floor, restricted := nftChainNameFloor[name]
	if !restricted {
		return true
	}
	required, ok := parseNftVersion(floor)
	if !ok {
		return false
	}
	have, ok := parseNftVersion(n.Version)
	if !ok {
		have, _ = parseNftVersion(OldestSupportedNft)
	}
	for i := 0; i < 3; i++ {
		if have[i] != required[i] {
			return have[i] > required[i]
		}
	}
	return true
}

func (n *Nftables) ready() error {
	if strings.TrimSpace(n.Bin) == "" {
		return fmt.Errorf("%w: the nft binary was not found", ErrUnavailable)
	}
	return nil
}

// ---------------------------------------------------------------- rendering

// nftSections collects the rules of one render, grouped by the chain they go
// into, so the file can be assembled in a fixed order regardless of the order
// the rules were generated in.
type nftSections struct {
	counters    []string
	sets        []string
	prerouting  []string
	output      []string
	postrouting []string
	forward     []string
	accounting  []string
	localOut    []string
	localIn     []string
	mss         []string
	marking     []string
}

// Render produces the complete `nft -f` payload for the desired ruleset.
//
// The payload is the whole desired state, never a delta: it declares the
// table, flushes it, and fills it again, all in one file that nft applies as a
// single transaction. Declaring the table before flushing it is what makes the
// file work on a host that has never had it, where `flush table` alone is an
// error.
func (n *Nftables) Render(rs Ruleset) (Payload, error) {
	if err := rs.Check(); err != nil {
		return Payload{}, err
	}

	var s nftSections
	routes := rs.Sorted()
	if len(routes) > 0 {
		// The established/related accept belongs to the chain rather than to any
		// one rule, so it is emitted once and first.
		s.forward = append(s.forward,
			fmt.Sprintf("ct state established,related accept comment %q", StructuralComment))
	}
	for _, route := range routes {
		if err := n.renderRoute(route, &s); err != nil {
			return Payload{}, err
		}
	}

	var b strings.Builder
	b.WriteString(header(
		"The panel's port forwarding ruleset, rendered from the database. Every change",
		"rewrites this file in full and applies it with a single nft transaction, so the",
		"kernel never holds a partial ruleset.",
		"",
		"Everything the panel installs lives in the one table below. Replacing that table",
		"replaces the panel's rules and touches nothing else on this host: rules belonging",
		"to Docker, firewalld or anything else live in their own tables and are never read,",
		"flushed or reordered from here.",
		"",
		"Every rule carries the comment "+IdentityPrefix+"<RouteRuleID>, which is what lets a rule read",
		"back from the kernel be matched to the database row that generated it.",
	))
	b.WriteString("\n")
	b.WriteString("# Declaring the table before flushing it makes this file work on a host that has\n")
	b.WriteString("# never seen it; flushing a table that does not exist is an error.\n")
	fmt.Fprintf(&b, "table %s %s\n", TableFamily, TableName)
	fmt.Fprintf(&b, "flush table %s %s\n", TableFamily, TableName)
	b.WriteString("\n")

	if retired := rs.RetiredSorted(); len(retired) > 0 {
		b.WriteString("# Flushing a table empties its chains but leaves its stateful objects alone,\n")
		b.WriteString("# which is exactly what keeps a counter alive across an edit to the rule it\n")
		b.WriteString("# belongs to. A deleted rule has no such claim, so its counters go with it\n")
		b.WriteString("# instead of sitting in the kernel describing a rule that no longer exists.\n")
		b.WriteString("# This is part of the same transaction, so it cannot half happen.\n")
		b.WriteString("#\n")
		b.WriteString("# `add` before `delete`, for the same reason the chain removal below does it:\n")
		b.WriteString("# this file is what the boot-time restore replays, and at boot the table has\n")
		b.WriteString("# just been created and holds no counters, so deleting one outright is an\n")
		b.WriteString("# error that takes the whole transaction — every forwarding rule in it —\n")
		b.WriteString("# down with it. Declaring the table is not enough on its own: the table then\n")
		b.WriteString("# exists while the counter still does not. Adding a counter that is already\n")
		b.WriteString("# there does not reset it, so this costs no accounting.\n")
		for _, id := range retired {
			for _, direction := range []string{"rx", "tx"} {
				name := counterName(id, direction)
				fmt.Fprintf(&b, "add counter %s %s %s\n", TableFamily, TableName, name)
				fmt.Fprintf(&b, "delete counter %s %s %s\n", TableFamily, TableName, name)
			}
		}
		b.WriteString("\n")
	}

	writeSourceSets(&b, rs.SourceSets)

	// The chains this payload declares, which is what the kernel's inventory is
	// converged to below. writeChain omits a chain with no rules, so this is the
	// set that will actually exist after the transaction.
	chains := []struct {
		name  string
		hook  string
		doc   []string
		rules []string
	}{
		{nftChainPrerouting, "type nat hook prerouting priority dstnat; policy accept;",
			[]string{"Destination NAT: traffic arriving for a rule is redirected to its destination."},
			s.prerouting},
		// The output hook's dstnat priority is spelled numerically. The symbolic
		// name is only defined for prerouting before nft v1.0.3, and v1.0.2
		// answers `type nat hook output priority dstnat` with "invalid priority
		// expression value in this context". -100 is the value dstnat stands for,
		// and both versions accept it.
		{nftChainOutput, "type nat hook output priority -100; policy accept;",
			[]string{
				"The prerouting hook never sees traffic this host generates itself, so a rule",
				"that should also serve local processes is repeated here.",
			}, s.output},
		{nftChainPostrouting, "type nat hook postrouting priority srcnat; policy accept;",
			[]string{
				"Source NAT. Absent for a rule whose NAT mode is None, which preserves the",
				"client address and needs the return path to come back through this server.",
			}, s.postrouting},
		{nftChainForward, "type filter hook forward priority filter; policy accept;",
			[]string{
				"Forward permission. The established/related rule covers the return direction,",
				"so no reverse rule matching on source port is emitted: conntrack expresses the",
				"intent exactly, and matching on the far end's source port would accept traffic",
				"that belongs to no flow this server ever started.",
			}, s.forward},
		{nftChainAccounting, "type filter hook forward priority filter - 10; policy accept;",
			[]string{
				"Accounting. These rules carry no verdict, so they count and fall through",
				"without influencing policy, and they sit at their own priority so they see",
				"traffic whatever the forward chain decides.",
			}, s.accounting},
		{nftChainLocalOut, "type filter hook output priority filter - 10; policy accept;",
			[]string{
				"Accounting for traffic this server originates itself, which the forward hook",
				"never sees. It references the same counters as the chain above, so a rule's",
				"total is its whole total rather than the forwarded half of it.",
			}, s.localOut},
		{nftChainLocalIn, "type filter hook input priority filter - 10; policy accept;",
			[]string{
				"The return direction of the same traffic. Replies to a locally-originated",
				"connection are delivered to a socket on this host, so they arrive at input",
				"rather than being forwarded.",
			}, s.localIn},
		{nftChainMss, "type filter hook forward priority mangle; policy accept;",
			[]string{
				"MSS clamping. A relay whose destination is reached across a tunnel hands the",
				"client an MSS the path cannot carry; connections then establish and stall on",
				"the first large transfer. The mask form matches a SYN without RST, so a",
				"reset is not rewritten.",
			}, s.mss},
		{nftChainMarking, "type filter hook prerouting priority mangle; policy accept;",
			[]string{"Firewall marks, for integration with policy routing."}, s.marking},
	}
	declared := map[string]bool{}
	for _, c := range chains {
		if len(c.rules) > 0 {
			declared[c.name] = true
		}
	}

	stale := rs.StaleChains(nftOwnedChains, declared)
	var unspellable []string
	kept := stale[:0:0]
	for _, name := range stale {
		if n.canSpellChain(name) {
			kept = append(kept, name)
		} else {
			unspellable = append(unspellable, name)
		}
	}
	stale = kept

	if len(unspellable) > 0 {
		b.WriteString("# Left in place deliberately: this host's nft does not parse the name(s) " +
			strings.Join(unspellable, ", ") + "\n")
		b.WriteString("# as a bare chain name, and naming them here would not remove them — it would\n")
		b.WriteString("# fail the whole transaction and take every rule below with it.\n")
		b.WriteString("\n")
	}

	if len(stale) > 0 {
		b.WriteString("# Flushing a table empties its chains but does not remove them, so a chain this\n")
		b.WriteString("# ruleset no longer declares would otherwise sit in the kernel indefinitely,\n")
		b.WriteString("# hooked and owned by nobody, and the table's shape would be a function of the\n")
		b.WriteString("# host's install history rather than of what the panel declares. These are the\n")
		b.WriteString("# panel's own chains this host still holds and this ruleset has no use for.\n")
		b.WriteString("#\n")
		b.WriteString("# `add` before `delete` is what makes the statement idempotent, and it has to\n")
		b.WriteString("# be: this same file is what the boot-time restore replays, against a table\n")
		b.WriteString("# that does not exist yet, where deleting a chain outright is an error that\n")
		b.WriteString("# would take the whole transaction — and every rule in it — down with it.\n")
		b.WriteString("# Adding a chain that is already there changes nothing, including its hook.\n")
		b.WriteString("#\n")
		b.WriteString("# The counters are untouched: they are objects of the table, not of a chain.\n")
		for _, name := range stale {
			fmt.Fprintf(&b, "add chain %s %s %s\n", TableFamily, TableName, name)
			fmt.Fprintf(&b, "delete chain %s %s %s\n", TableFamily, TableName, name)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "table %s %s {\n", TableFamily, TableName)

	if len(s.counters) > 0 {
		b.WriteString("\t# Named counter objects, one pair per rule. Byte accounting reads these,\n")
		b.WriteString("\t# never the nat chains: a nat hook only ever sees the first packet of a\n")
		b.WriteString("\t# connection, so counting there would report connections as if they were\n")
		b.WriteString("\t# bytes and under-report traffic by orders of magnitude.\n")
		b.WriteString(strings.Join(s.counters, ""))
		b.WriteString("\n")
	}
	if len(s.sets) > 0 {
		b.WriteString("\t# Dynamic sets backing the per-source connection and rate limits.\n")
		b.WriteString(strings.Join(s.sets, ""))
		b.WriteString("\n")
	}

	for _, c := range chains {
		writeChain(&b, c.name, c.hook, c.doc, c.rules)
	}

	b.WriteString("}\n")

	bin := n.Bin
	if bin == "" {
		bin = DefaultNftBin
	}
	return Payload{
		Backend:       BackendNftables,
		RemovesChains: stale,
		Parts: []Part{{
			Kind: PartNftables,
			Path: n.Path(),
			Text: b.String(),
			Argv: []string{bin, "-f", n.Path()},
		}},
	}, nil
}

// writeChain emits one chain with its hook declaration and its rules, and
// nothing at all when the chain would be empty.
//
// An empty base chain with an accept policy changes no packet's fate, so the
// only thing it ever bought was the reassurance of seeing the whole shape of
// the ruleset in the kernel. That is not worth what it cost: a plain
// masquerade rule needs neither MSS clamping nor marking, and emitting those
// chains anyway put a construct in every payload that the oldest supported nft
// cannot parse — so the feature was unusable on that release for want of two
// chains that did nothing. What distinguishes "applied with no rules" from
// "never applied" is the table, which is always declared.
func writeChain(b *strings.Builder, name, hook string, doc []string, rules []string) {
	if len(rules) == 0 {
		return
	}
	fmt.Fprintf(b, "\tchain %s {\n", name)
	fmt.Fprintf(b, "\t\t%s\n", hook)
	for _, line := range doc {
		fmt.Fprintf(b, "\t\t# %s\n", line)
	}
	for _, rule := range rules {
		fmt.Fprintf(b, "\t\t%s\n", rule)
	}
	b.WriteString("\t}\n")
}

// renderRoute appends one rule's netfilter rules to the sections.
func (n *Nftables) renderRoute(s RouteSpec, out *nftSections) error {
	fam := nftFamily(s)
	id := s.RouteRuleID
	comment := fmt.Sprintf(`comment %q`, s.Identity())

	out.counters = append(out.counters,
		fmt.Sprintf("\tcounter %s {\n\t}\n", counterName(id, "rx")),
		fmt.Sprintf("\tcounter %s {\n\t}\n", counterName(id, "tx")))

	if s.MaxConnectionsPerSource > 0 {
		out.sets = append(out.sets, fmt.Sprintf(
			"\tset %s {\n\t\ttype %s\n\t\tsize 65535\n\t\tflags dynamic\n\t}\n",
			setName(id, "conn"), nftAddrType(s)))
	}
	if s.ConnectionRateLimit > 0 {
		out.sets = append(out.sets, fmt.Sprintf(
			"\tset %s {\n\t\ttype %s\n\t\tsize 65535\n\t\tflags dynamic, timeout\n\t\ttimeout 1m\n\t}\n",
			setName(id, "rate"), nftAddrType(s)))
	}

	head := "# " + describe(s)
	out.prerouting = append(out.prerouting, head)
	out.forward = append(out.forward, head)
	out.accounting = append(out.accounting, head)
	if s.IncludeLocalOriginated {
		out.output = append(out.output, head)
		out.localOut = append(out.localOut, head)
		out.localIn = append(out.localIn, head)
	}
	if s.NatMode != NatNone {
		out.postrouting = append(out.postrouting, head)
	}
	if s.ClampMssToPmtu {
		out.mss = append(out.mss, head)
	}
	if s.FwMark != nil {
		out.marking = append(out.marking, head)
	}

	for _, proto := range s.Protocol.Expand() {
		bind := nftBindMatch(s, proto, fam)

		target, err := nftDnatTarget(s)
		if err != nil {
			return err
		}
		out.prerouting = append(out.prerouting, join(bind, target, comment))
		if s.IncludeLocalOriginated {
			out.output = append(out.output, join(bind, target, comment))
		}
		if s.FwMark != nil {
			out.marking = append(out.marking,
				join(bind, fmt.Sprintf("meta mark set 0x%x", *s.FwMark), comment))
		}

		for _, d := range s.Destinations {
			dest := nftDestMatch(d, proto, fam)

			if s.MaxConnectionsPerSource > 0 {
				out.forward = append(out.forward, join(dest, fmt.Sprintf(
					"ct state new add @%s { %s saddr ct count over %d } drop",
					setName(id, "conn"), fam, s.MaxConnectionsPerSource), comment))
			}
			if s.ConnectionRateLimit > 0 {
				out.forward = append(out.forward, join(dest, fmt.Sprintf(
					"ct state new add @%s { %s saddr limit rate over %d/minute } drop",
					setName(id, "rate"), fam, s.ConnectionRateLimit), comment))
			}
			if s.Logging {
				out.forward = append(out.forward, join(dest, fmt.Sprintf(
					"ct state new limit rate %s log prefix %q", LogRateLimit, logPrefix(s)), comment))
			}
			out.forward = append(out.forward, join(dest, allowedSourceMatch(s, fam), "accept", comment))

			switch s.NatMode {
			case NatMasquerade:
				out.postrouting = append(out.postrouting, join(dest, "masquerade", comment))
			case NatSnat:
				out.postrouting = append(out.postrouting,
					join(dest, fmt.Sprintf("snat %s to %s", fam, s.SnatAddress), comment))
			}

			out.accounting = append(out.accounting,
				join(dest, fmt.Sprintf("counter name %q", counterName(id, "tx")), comment),
				join(nftReverseMatch(d, proto, fam),
					fmt.Sprintf("counter name %q", counterName(id, "rx")), comment))

			// The same two counter objects, on the two hooks locally-originated
			// traffic actually takes, so a rule's total covers both paths
			// instead of silently omitting one of them.
			if s.IncludeLocalOriginated {
				out.localOut = append(out.localOut,
					join(dest, fmt.Sprintf("counter name %q", counterName(id, "tx")), comment))
				out.localIn = append(out.localIn,
					join(nftReverseMatch(d, proto, fam),
						fmt.Sprintf("counter name %q", counterName(id, "rx")), comment))
			}

			// MSS clamping is a TCP option; there is nothing to clamp on UDP.
			if s.ClampMssToPmtu && proto == ProtocolTCP {
				out.mss = append(out.mss, join(dest,
					"tcp flags syn / syn,rst tcp option maxseg size set rt mtu", comment))
			}
		}
	}
	return nil
}

// nftBindMatch renders the match for traffic arriving for this rule, in the
// order §3 of the specification writes it.
func nftBindMatch(s RouteSpec, proto Protocol, fam string) string {
	var parts []string
	if !s.BindsAnyAddress() {
		parts = append(parts, fam, "daddr", s.BindAddress)
	}
	parts = append(parts, string(proto), "dport", s.BindPorts.String())
	if iface := strings.TrimSpace(s.BindInterface); iface != "" {
		parts = append(parts, "iifname", strconv.Quote(iface))
	}
	if match := allowedSourceMatch(s, fam); match != "" {
		parts = append(parts, match)
	}
	return strings.Join(parts, " ")
}

// nftDestMatch renders the match for traffic on its way to one destination,
// which is what the forward, postrouting, accounting and MSS rules key on.
func nftDestMatch(d Destination, proto Protocol, fam string) string {
	return fmt.Sprintf("%s daddr %s %s dport %s", fam, d.Address, proto, d.Ports)
}

// nftReverseMatch renders the return direction, used only for accounting.
func nftReverseMatch(d Destination, proto Protocol, fam string) string {
	return fmt.Sprintf("%s saddr %s %s sport %s", fam, d.Address, proto, d.Ports)
}

// allowedSourceMatch renders the source allowlist, or "" when the relay is open.
//
// A rule that allows one of the operator's shared lists matches a declared set
// by name; one that only names addresses of its own carries them in an
// anonymous set, which is what a handful of addresses should be.
func allowedSourceMatch(s RouteSpec, fam string) string {
	if set := strings.TrimSpace(s.SourceSet); set != "" {
		return fmt.Sprintf("%s saddr @%s", fam, set)
	}
	if len(s.AllowedSources) == 0 {
		return ""
	}
	return fmt.Sprintf("%s saddr { %s }", fam, strings.Join(s.AllowedSources, ", "))
}

// nftDnatTarget renders the dnat statement, including the load balancing
// expression when there is more than one destination.
//
// Round robin distributes each new connection to the next destination in turn;
// source hash keeps a given client on a given destination, which is what a
// service holding per-client state needs. Weighted is round robin over an
// interval map sized by the weights.
func nftDnatTarget(s RouteSpec) (string, error) {
	// In an inet table the family of a nat statement cannot always be inferred
	// from the match — a rule binding every local address has no address match
	// at all — so it is always stated. nft rejects the ambiguous form outright,
	// which is how this was found.
	fam := nftFamily(s)

	live := s.Destinations
	if len(live) == 1 {
		return fmt.Sprintf("dnat %s to %s", fam, nftAddressPort(live[0])), nil
	}

	mode := s.LoadBalance
	if mode == "" || mode == LoadBalanceNone {
		// Several destinations with no mode chosen is round robin: sending every
		// connection to the first would silently ignore the rest.
		mode = LoadBalanceRoundRobin
	}
	// A load balancing map carries one address and one port per entry, so a
	// range cannot be spread across destinations. Saying so is better than
	// silently mapping every connection to the first port of the range.
	for _, d := range live {
		if d.Ports.IsRange() {
			return "", fmt.Errorf("%w: load balancing across a port range (%s on %s)",
				ErrUnsupported, d.Ports, d.Address)
		}
	}

	switch mode {
	case LoadBalanceRoundRobin:
		entries := make([]string, 0, len(live))
		for i, d := range live {
			entries = append(entries, fmt.Sprintf("%d : %s . %d", i, d.Address, d.Ports.Port))
		}
		return fmt.Sprintf("dnat %s to numgen inc mod %d map { %s }",
			fam, len(live), strings.Join(entries, ", ")), nil

	case LoadBalanceSourceHash:
		entries := make([]string, 0, len(live))
		for i, d := range live {
			entries = append(entries, fmt.Sprintf("%d : %s . %d", i, d.Address, d.Ports.Port))
		}
		return fmt.Sprintf("dnat %s to jhash %s saddr mod %d map { %s }",
			fam, fam, len(live), strings.Join(entries, ", ")), nil

	case LoadBalanceWeighted:
		weights := weightsOf(live)
		total := sumOf(weights)
		entries := make([]string, 0, len(live))
		at := 0
		for i, d := range live {
			end := at + weights[i] - 1
			key := strconv.Itoa(at)
			if end > at {
				key = fmt.Sprintf("%d-%d", at, end)
			}
			entries = append(entries, fmt.Sprintf("%s : %s . %d", key, d.Address, d.Ports.Port))
			at = end + 1
		}
		return fmt.Sprintf("dnat %s to numgen inc mod %d map { %s }",
			fam, total, strings.Join(entries, ", ")), nil
	}
	return "", fmt.Errorf("%w: load balancing mode %q", ErrUnsupported, s.LoadBalance)
}

// nftAddressPort renders one destination as an address and port, bracketing an
// IPv6 address the way nft requires.
func nftAddressPort(d Destination) string {
	if strings.Contains(d.Address, ":") {
		return fmt.Sprintf("[%s]:%s", d.Address, d.Ports)
	}
	return fmt.Sprintf("%s:%s", d.Address, d.Ports)
}

func nftFamily(s RouteSpec) string {
	if s.IsIPv6() {
		return "ip6"
	}
	return "ip"
}

func nftAddrType(s RouteSpec) string {
	if s.IsIPv6() {
		return "ipv6_addr"
	}
	return "ipv4_addr"
}

func counterName(id int64, direction string) string {
	return fmt.Sprintf("route_%d_%s", id, direction)
}

func setName(id int64, kind string) string {
	return fmt.Sprintf("route_%d_%s", id, kind)
}

func logPrefix(s RouteSpec) string {
	return fmt.Sprintf("gre-panel route %d: ", s.RouteRuleID)
}

// describe renders the one-line summary that heads a rule's block in every
// chain, so an operator reading the payload can see what each group of rules is
// for without cross-referencing identifiers.
func describe(s RouteSpec) string {
	destinations := make([]string, 0, len(s.Destinations))
	for _, d := range s.Destinations {
		destinations = append(destinations, fmt.Sprintf("%s:%s", d.Address, d.Ports))
	}
	bind := s.BindAddress
	if s.BindsAnyAddress() {
		bind = "any"
	}
	title := s.Title
	if strings.TrimSpace(title) == "" {
		title = "untitled"
	}
	return fmt.Sprintf("route %d %q: %s %s:%s -> %s [nat %s]",
		s.RouteRuleID, title, s.Protocol, bind, s.BindPorts,
		strings.Join(destinations, ", "), s.NatMode)
}

// join assembles a rule from its parts, dropping the empty ones so an absent
// option leaves no double space behind.
func join(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, " ")
}

// ---------------------------------------------------------------- applying

// Apply writes the rendered ruleset and hands it to nft as one transaction.
//
// A zero exit code is not treated as proof of anything: the caller verifies by
// reading the ruleset back from the kernel.
func (n *Nftables) Apply(ctx context.Context, payload Payload) error {
	if err := n.ready(); err != nil {
		return err
	}
	for _, part := range payload.Parts {
		if err := writeOwned(ctx, part.Path, part.Text); err != nil {
			return err
		}
		if _, err := n.Runner.Run(ctx, part.Argv); err != nil {
			return fmt.Errorf("applying the nftables ruleset: %w", err)
		}
	}
	return nil
}

// ReadBack returns the panel's table as the kernel holds it.
func (n *Nftables) ReadBack(ctx context.Context) (Live, error) {
	if err := n.ready(); err != nil {
		return Live{}, err
	}
	res, err := n.Runner.Run(ctx, []string{n.Bin, "list", "table", TableFamily, TableName})
	if err != nil {
		// A table that does not exist is not a failure to read: it is an empty
		// ruleset, which is exactly what a host with no rules applied yet has.
		if isMissingTable(res.Stderr) {
			return Live{Backend: BackendNftables}, nil
		}
		return Live{Backend: BackendNftables}, fmt.Errorf("reading the panel's nftables table: %w", err)
	}
	return parseNftLive(res.Stdout), nil
}

// isMissingTable recognises nft's answer for a table that is not there.
func isMissingTable(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "does not exist")
}

// parseNftLive turns `nft list table` output into the live view. Only rules
// inside a chain are reported, and each is attributed by its identity comment;
// a rule in the panel's own table with no identity is reported with a zero
// identifier so reconciliation can call it unmanaged rather than guess.
func parseNftLive(out string) Live {
	live := Live{Backend: BackendNftables, Text: out}
	chain := ""
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "chain "):
			chain = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "chain ")), " {")
			// Recorded whether or not it holds a rule. An empty chain produces no
			// LiveRule at all, so this is the only thing that can ever see one.
			live.Chains = append(live.Chains, chain)
			continue
		case line == "}":
			chain = ""
			continue
		case chain == "":
			continue
		case strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "policy "):
			continue
		}
		id, _ := ParseIdentity(line)
		live.Rules = append(live.Rules, LiveRule{
			RouteRuleID: id, Chain: chain, Role: nftChainRoles[chain],
			Text: line, Structural: IsStructural(line),
		})
	}
	return live
}

// Counters reads the named counter objects, which is where byte accounting
// lives: the nat chains only ever see the first packet of a connection, so a
// counter there would measure connections while claiming to measure bytes
// (§5.1).
func (n *Nftables) Counters(ctx context.Context) (map[int64]Counter, error) {
	if err := n.ready(); err != nil {
		return nil, err
	}
	res, err := n.Runner.Run(ctx, []string{n.Bin, "-j", "list", "counters", "table", TableFamily, TableName})
	if err != nil {
		if isMissingTable(res.Stderr) {
			return map[int64]Counter{}, nil
		}
		return nil, fmt.Errorf("reading the panel's counters: %w", err)
	}
	return parseNftCounters(res.Stdout)
}

// nftCounterList is the shape `nft -j list counters` returns: one object per
// entry, of which the counters are the ones carrying a "counter" key.
type nftCounterList struct {
	Nftables []struct {
		Counter *struct {
			Name    string `json:"name"`
			Table   string `json:"table"`
			Packets uint64 `json:"packets"`
			Bytes   uint64 `json:"bytes"`
		} `json:"counter"`
	} `json:"nftables"`
}

// parseNftCounters turns the JSON into per-rule figures, keyed by the rule
// identifier the counter's name carries.
func parseNftCounters(out string) (map[int64]Counter, error) {
	var parsed nftCounterList
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return nil, fmt.Errorf("reading the counter list: %w", err)
	}
	counters := map[int64]Counter{}
	for _, entry := range parsed.Nftables {
		if entry.Counter == nil || entry.Counter.Table != TableName {
			continue
		}
		id, direction, ok := parseCounterName(entry.Counter.Name)
		if !ok {
			continue
		}
		counter := counters[id]
		counter.RouteRuleID = id
		if direction == "rx" {
			counter.RxBytes = entry.Counter.Bytes
			counter.RxPackets = entry.Counter.Packets
		} else {
			counter.TxBytes = entry.Counter.Bytes
			counter.TxPackets = entry.Counter.Packets
		}
		counters[id] = counter
	}
	return counters, nil
}

// parseCounterName reads "route_7_rx" back into its rule and its direction.
func parseCounterName(name string) (int64, string, bool) {
	rest, ok := strings.CutPrefix(name, "route_")
	if !ok {
		return 0, "", false
	}
	idText, direction, ok := strings.Cut(rest, "_")
	if !ok || (direction != "rx" && direction != "tx") {
		return 0, "", false
	}
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		return 0, "", false
	}
	return id, direction, true
}

// Foreign lists every redirecting rule on this host outside the panel's own
// table (§9).
//
// It reads the whole ruleset, which is the only way to see what else hooks
// prerouting, and modifies nothing: the panel never deletes a rule it does not
// own, whatever it finds.
func (n *Nftables) Foreign(ctx context.Context) (ForeignView, error) {
	if err := n.ready(); err != nil {
		return ForeignView{Detail: err.Error()}, err
	}
	res, err := n.Runner.Run(ctx, []string{n.Bin, "list", "ruleset"})
	if err != nil {
		return ForeignView{
			Detail: "the host's nftables ruleset could not be listed: " + strings.TrimSpace(res.Stderr),
		}, fmt.Errorf("listing the host ruleset: %w", err)
	}
	found := ParseNftForeign(res.Stdout)
	return ForeignView{Readable: true, Rules: found, Managers: managerNames(found)}, nil
}

// Flush removes the panel's table, and only the panel's table. Deleting a table
// that is already gone is a success, not an error.
func (n *Nftables) Flush(ctx context.Context) error {
	if err := n.ready(); err != nil {
		return err
	}
	res, err := n.Runner.Run(ctx, []string{n.Bin, "delete", "table", TableFamily, TableName})
	if err != nil && !isMissingTable(res.Stderr) {
		return fmt.Errorf("removing the panel's nftables table: %w", err)
	}
	return nil
}

// writeSourceSets declares the address sets the rules match against.
//
// They are declared inside the same transaction that flushes the table, so the
// sets a rule refers to always exist by the time the rule referring to them is
// added -- nft parses the file in order and a rule naming a set that is not
// there yet is an error that takes the whole apply down.
//
// `flags interval` is what makes a set hold ranges rather than single
// addresses, and `auto-merge` is what makes two ranges that overlap collapse
// instead of being refused: an operator's list, pasted from several sources,
// routinely contains 5.22.0.0/20 and 5.22.16.0/24 both.
func writeSourceSets(b *strings.Builder, sets []SourceSet) {
	if len(sets) == 0 {
		return
	}
	b.WriteString("# The address sets the rules below match their source against. Each one is a\n")
	b.WriteString("# list an operator maintains in the panel, written out here in full:\n")
	b.WriteString("# netfilter has no way to say \"in this set or that one\" inside a rule, so the\n")
	b.WriteString("# lists a rule allows are folded into one set per rule.\n")
	for _, set := range sets {
		if len(set.Prefixes) == 0 {
			continue
		}
		kind := "ipv4_addr"
		if set.Family == FamilyIPv6 {
			kind = "ipv6_addr"
		}
		fmt.Fprintf(b, "add set %s %s %s { type %s; flags interval; auto-merge; comment %s; }\n",
			TableFamily, TableName, set.Name, kind, strconv.Quote(set.Title))
		// The elements go in their own statement rather than in the declaration,
		// because a set with thousands of ranges produces a line no editor and no
		// error message can work with, and nft accepts the addition either way.
		fmt.Fprintf(b, "add element %s %s %s { %s }\n",
			TableFamily, TableName, set.Name, strings.Join(set.Prefixes, ", "))
	}
	b.WriteString("\n")
}
