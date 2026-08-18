package rules

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -update rewrites the golden files. Run `go test ./internal/rules -update`
// after a deliberate change to the rendered output, and read the diff: these
// files are the exact bytes that reach netfilter on a real host.
var update = flag.Bool("update", false, "rewrite the golden files")

// The backends under test are pinned to fixed binary paths and a fixed output
// directory, so a golden file records the rendering and not the machine it was
// rendered on.
func nftBackend() *Nftables {
	return NewNftables("/usr/sbin/nft", "/var/lib/gre-panel/rules", nil)
}

func iptBackend() *Iptables {
	return NewIptables("/usr/sbin/iptables", "/usr/sbin/iptables-restore",
		"/usr/sbin/ip6tables", "/usr/sbin/ip6tables-restore", "/var/lib/gre-panel/rules", nil)
}

func mark(v uint32) *uint32 { return &v }

// baseSpec is the plainest useful rule: one TCP port relayed to one
// destination, source rewritten so it works without the operator reasoning
// about return paths. Every case below is this with one thing changed, so a
// golden diff shows exactly what that option does to the ruleset.
func baseSpec() RouteSpec {
	return RouteSpec{
		RouteRuleID: 1,
		Title:       "Web relay",
		Protocol:    ProtocolTCP,
		Family:      FamilyIPv4,
		BindAddress: "203.0.113.10",
		BindPorts:   PortRange{Port: 2044},
		Destinations: []Destination{
			{Address: "198.51.100.20", Ports: PortRange{Port: 2044}},
		},
		NatMode:     NatMasquerade,
		LoadBalance: LoadBalanceNone,
	}
}

// cases are the option combinations both backends are asserted against.
func cases() []struct {
	name string
	rs   Ruleset
} {
	single := func(mutate func(*RouteSpec)) Ruleset {
		s := baseSpec()
		mutate(&s)
		return Ruleset{Routes: []RouteSpec{s}}
	}

	return []struct {
		name string
		rs   Ruleset
	}{
		{"empty", Ruleset{}},
		{"tcp_masquerade", single(func(s *RouteSpec) {})},
		{"udp", single(func(s *RouteSpec) {
			s.Protocol = ProtocolUDP
			s.BindPorts = PortRange{Port: 51820}
			s.Destinations = []Destination{{Address: "198.51.100.20", Ports: PortRange{Port: 51820}}}
		})},
		{"both_protocols", single(func(s *RouteSpec) { s.Protocol = ProtocolBoth })},
		{"port_range", single(func(s *RouteSpec) {
			s.BindPorts = PortRange{Port: 20000, End: 20100}
			s.Destinations = []Destination{{Address: "198.51.100.20", Ports: PortRange{Port: 30000, End: 30100}}}
		})},
		{"ipv6", single(func(s *RouteSpec) {
			s.Family = FamilyIPv6
			s.BindAddress = "2001:db8::10"
			s.Destinations = []Destination{{Address: "2001:db8:1::20", Ports: PortRange{Port: 2044}}}
			s.AllowedSources = []string{"2001:db8:2::/64"}
		})},
		{"bind_any_address", single(func(s *RouteSpec) { s.BindAddress = "0.0.0.0" })},
		{"allowlist_and_interface", single(func(s *RouteSpec) {
			s.AllowedSources = []string{"10.0.0.0/8", "192.168.0.0/16"}
			s.BindInterface = "eth0"
		})},
		{"nat_none_local_originated", single(func(s *RouteSpec) {
			s.NatMode = NatNone
			s.IncludeLocalOriginated = true
		})},
		{"snat", single(func(s *RouteSpec) {
			s.NatMode = NatSnat
			s.SnatAddress = "203.0.113.10"
		})},
		{"load_balance_round_robin", single(func(s *RouteSpec) {
			s.LoadBalance = LoadBalanceRoundRobin
			s.Destinations = []Destination{
				{Address: "198.51.100.20", Ports: PortRange{Port: 2044}},
				{Address: "198.51.100.21", Ports: PortRange{Port: 2044}},
				{Address: "198.51.100.22", Ports: PortRange{Port: 2044}},
			}
		})},
		{"load_balance_source_hash", single(func(s *RouteSpec) {
			s.LoadBalance = LoadBalanceSourceHash
			s.Destinations = []Destination{
				{Address: "198.51.100.20", Ports: PortRange{Port: 2044}},
				{Address: "198.51.100.21", Ports: PortRange{Port: 2044}},
			}
		})},
		{"load_balance_weighted", single(func(s *RouteSpec) {
			s.LoadBalance = LoadBalanceWeighted
			s.Destinations = []Destination{
				{Address: "198.51.100.20", Ports: PortRange{Port: 2044}, Weight: 7},
				{Address: "198.51.100.21", Ports: PortRange{Port: 2044}, Weight: 2},
				{Address: "198.51.100.22", Ports: PortRange{Port: 2044}, Weight: 1},
			}
		})},
		{"limits_logging_fwmark", single(func(s *RouteSpec) {
			s.MaxConnectionsPerSource = 10
			s.ConnectionRateLimit = 60
			s.Logging = true
			s.FwMark = mark(100)
		})},
		{"mss_clamp", single(func(s *RouteSpec) {
			s.Protocol = ProtocolBoth
			s.ClampMssToPmtu = true
			s.Destinations = []Destination{{Address: "172.31.7.2", Ports: PortRange{Port: 2044}}}
		})},
		{"every_option", single(func(s *RouteSpec) {
			s.Title = "Everything at once"
			s.Protocol = ProtocolBoth
			s.BindInterface = "eth0"
			s.AllowedSources = []string{"10.0.0.0/8"}
			s.NatMode = NatSnat
			s.SnatAddress = "203.0.113.10"
			s.LoadBalance = LoadBalanceWeighted
			s.Destinations = []Destination{
				{Address: "172.31.7.2", Ports: PortRange{Port: 2044}, Weight: 3},
				{Address: "172.31.7.6", Ports: PortRange{Port: 2044}, Weight: 1},
			}
			s.ClampMssToPmtu = true
			s.IncludeLocalOriginated = true
			s.Logging = true
			s.FwMark = mark(0x1f)
			s.MaxConnectionsPerSource = 25
			s.ConnectionRateLimit = 120
		})},
		// The kernel's chain inventory is converged to the rendered one. Flushing
		// a table empties its chains but does not remove them, so without this a
		// chain an earlier build created survives every apply for the life of the
		// host. The names here are the ones two real servers were found holding.
		{"stale_chains_removed", func() Ruleset {
			rs := single(func(s *RouteSpec) {})
			rs.LiveChains = []string{
				"prerouting", "output", "postrouting", "forward", "accounting", "marking",
			}
			return rs
		}()},
		// The same, with nothing left to declare: every rule has been deleted and
		// the chains have to go with them. This is the state a host reaches by
		// removing its last forwarding rule.
		{"stale_chains_empty_ruleset", Ruleset{LiveChains: []string{
			"prerouting", "output", "postrouting", "forward", "accounting", "marking",
		}}},
		// A chain in the panel's table that the panel never created is not the
		// panel's to remove, however tempting: §6.3 says the panel never deletes
		// what it did not create.
		{"foreign_chain_left_alone", Ruleset{LiveChains: []string{
			"prerouting", "somebody_elses_chain",
		}}},
		{"several_rules", Ruleset{Routes: []RouteSpec{
			// Deliberately out of order: emission order is the operator's sort
			// order, because overlapping matches resolve first-match-wins.
			{
				RouteRuleID: 7, Title: "Second", SortOrder: 20,
				Protocol: ProtocolTCP, Family: FamilyIPv4,
				BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 8443},
				Destinations: []Destination{{Address: "172.31.7.2", Ports: PortRange{Port: 443}}},
				NatMode:      NatNone, ClampMssToPmtu: true,
			},
			{
				RouteRuleID: 3, Title: "First", SortOrder: 10,
				Protocol: ProtocolUDP, Family: FamilyIPv4,
				BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 51820},
				Destinations: []Destination{{Address: "172.31.7.2", Ports: PortRange{Port: 51820}}},
				NatMode:      NatMasquerade,
			},
			{
				RouteRuleID: 9, Title: "IPv6 as well", SortOrder: 30,
				Protocol: ProtocolTCP, Family: FamilyIPv6,
				BindAddress: "2001:db8::10", BindPorts: PortRange{Port: 993},
				Destinations: []Destination{{Address: "2001:db8:1::20", Ports: PortRange{Port: 993}}},
				NatMode:      NatMasquerade,
			},
		}}},
	}
}

// assertGolden compares rendered output against a checked-in file.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\nRun the test with -update to create it.", path, err)
	}
	if got != string(want) {
		t.Fatalf("%s does not match the golden file.\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

func TestNftablesGolden(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := nftBackend().Render(tc.rs)
			if err != nil {
				t.Fatalf("rendering returned an unexpected error: %v", err)
			}
			if len(payload.Parts) != 1 {
				t.Fatalf("the nftables payload has %d parts, want exactly 1", len(payload.Parts))
			}
			assertGolden(t, filepath.Join("nftables", tc.name+".nft"), payload.Parts[0].Text)
		})
	}
}

func TestIptablesGolden(t *testing.T) {
	for _, tc := range cases() {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := iptBackend().Render(tc.rs)
			if err != nil {
				t.Fatalf("rendering returned an unexpected error: %v", err)
			}
			if len(payload.Parts) != 2 {
				t.Fatalf("the iptables payload has %d parts, want one per address family", len(payload.Parts))
			}
			assertGolden(t, filepath.Join("iptables", tc.name+".rules"), payload.Parts[0].Text)
			assertGolden(t, filepath.Join("iptables", tc.name+".6rules"), payload.Parts[1].Text)
		})
	}
}

// ------------------------------------------- converging the chain inventory

// TestStaleChainsAreRemovedFromTheKernel is the regression for a table whose
// shape was a function of the host's install history rather than of what the
// panel declared.
//
// `flush table` empties a table's chains and leaves the chains themselves
// exactly where they are, and nothing in the payload ever removed one. Two
// servers running the identical binary were found holding different tables —
// one with seven chains including one named `mss` from before that name was
// discovered to be unparseable on the oldest supported nft, the other with four
// — and every apply since had left both untouched.
func TestStaleChainsAreRemovedFromTheKernel(t *testing.T) {
	rs := Ruleset{
		Routes: []RouteSpec{baseSpec()},
		// What server A was actually holding, read off the kernel.
		LiveChains: []string{
			"prerouting", "output", "postrouting", "forward", "accounting", "mss", "marking",
		},
	}
	backend := nftBackend()
	backend.Version = "nftables v1.0.9 (Old Doc Yak #3)"

	payload, err := backend.Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	text := payload.Parts[0].Text

	// A plain masquerade rule needs none of these three, so all three have to go.
	for _, name := range []string{"output", "mss", "marking"} {
		if !strings.Contains(text, "delete chain inet gre_panel "+name+"\n") {
			t.Errorf("the payload does not remove the stale chain %q:\n%s", name, text)
		}
		// Idempotent, because this same file is what the boot-time restore
		// replays against a table that does not exist yet.
		if !strings.Contains(text, "add chain inet gre_panel "+name+"\n") {
			t.Errorf("the removal of %q is not idempotent, so the boot-time restore would fail "+
				"on a host where the chain is already gone:\n%s", name, text)
		}
	}
	for _, name := range []string{"prerouting", "postrouting", "forward", "accounting"} {
		if strings.Contains(text, "delete chain inet gre_panel "+name+"\n") {
			t.Errorf("the payload removes %q, which it declares", name)
		}
	}

	if got := fmt.Sprint(payload.RemovesChains); got != "[marking mss output]" {
		t.Errorf("RemovesChains = %s, want the three stale chains in a deterministic order", got)
	}

	// The counters are objects of the table, not of a chain, so converging the
	// inventory must not take a surviving rule's accounting with it.
	if strings.Contains(text, "delete counter") {
		t.Errorf("converging the chain inventory deleted a counter belonging to a live rule:\n%s", text)
	}
	if !strings.Contains(text, "counter route_1_rx") || !strings.Contains(text, "counter route_1_tx") {
		t.Errorf("the surviving rule's counters are not in the payload:\n%s", text)
	}
}

// TestAKeywordChainNameIsOnlySpelledWhereItParses covers the trap in fixing the
// above: removing a chain means writing its name, and `mss` is a keyword before
// nft v1.0.3. Naming it on such a host would not remove the chain — it would
// fail the whole transaction and take every rule in it down, which is precisely
// the failure that made the forwarding feature dead on Ubuntu 22.04 once
// before.
func TestAKeywordChainNameIsOnlySpelledWhereItParses(t *testing.T) {
	rs := Ruleset{LiveChains: []string{"mss", "marking"}}

	for _, tc := range []struct {
		version   string
		wantSpelt bool
	}{
		{"nftables v1.0.9 (Old Doc Yak #3)", true},
		{"nftables v1.0.3 (Topsy)", true},
		{"nftables v1.0.2 (Lester Gooch)", false},
		{"nftables v0.9.8 (Scrumptious Cabbage)", false},
		// An unreadable banner is treated as the oldest supported release: the
		// cautious answer has to be the default one.
		{"", false},
	} {
		backend := nftBackend()
		backend.Version = tc.version
		payload, err := backend.Render(rs)
		if err != nil {
			t.Fatalf("%q: rendering failed: %v", tc.version, err)
		}
		text := payload.Parts[0].Text
		spelt := strings.Contains(text, "delete chain inet gre_panel mss\n")
		if spelt != tc.wantSpelt {
			t.Errorf("nft %q: the payload spells the chain name `mss` = %v, want %v:\n%s",
				tc.version, spelt, tc.wantSpelt, text)
		}
		// `marking` parses on every release, so it goes either way.
		if !strings.Contains(text, "delete chain inet gre_panel marking\n") {
			t.Errorf("nft %q: `marking` parses everywhere and should always be removed:\n%s",
				tc.version, text)
		}
		if !tc.wantSpelt && !strings.Contains(text, "does not parse the name(s) mss") {
			t.Errorf("nft %q: the payload leaves `mss` behind without saying why:\n%s",
				tc.version, text)
		}
	}
}

// TestOnlyThePanelsOwnChainsAreRemoved holds §6.3: the panel never deletes
// something it did not create, whatever namespace it turns up in.
func TestOnlyThePanelsOwnChainsAreRemoved(t *testing.T) {
	rs := Ruleset{LiveChains: []string{"output", "docker_something", "custom"}}
	payload, err := nftBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if got := fmt.Sprint(payload.RemovesChains); got != "[output]" {
		t.Errorf("RemovesChains = %s, want only the panel's own chain", got)
	}
	for _, foreign := range []string{"docker_something", "custom"} {
		if strings.Contains(payload.Parts[0].Text, foreign) {
			t.Errorf("the payload names the foreign chain %q at all", foreign)
		}
	}
}

// TestAnUnreadInventoryRemovesNothing covers the difference between "the kernel
// holds no chains" and "the inventory could not be read". Acting on the second
// as if it were the first would delete a host's whole table shape on a
// transient read failure.
func TestAnUnreadInventoryRemovesNothing(t *testing.T) {
	payload, err := nftBackend().Render(Ruleset{Routes: []RouteSpec{baseSpec()}})
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if len(payload.RemovesChains) != 0 {
		t.Errorf("a render with no inventory removes %v", payload.RemovesChains)
	}
	if strings.Contains(payload.Parts[0].Text, "delete chain") {
		t.Errorf("a render with no inventory emits a chain deletion:\n%s", payload.Parts[0].Text)
	}
}

// TestConvergingAnAlreadyConvergedKernelEmitsNothing is the steady state, and
// the case that keeps a re-apply from being a transaction that can fail.
//
// `delete chain` on a chain that is not there is refused by both nft 1.0.2 and
// 1.0.9 — "Could not process rule: No such file or directory" — so a payload
// that names a chain it does not need to remove is a payload that can be
// rejected in full. A host whose kernel already matches must therefore emit no
// removal at all, and so must a host being installed for the first time.
func TestConvergingAnAlreadyConvergedKernelEmitsNothing(t *testing.T) {
	backend := nftBackend()
	backend.Version = "nftables v1.0.9 (Old Doc Yak #3)"

	for _, tc := range []struct {
		name string
		rs   Ruleset
	}{
		{
			// A first-ever install: the table does not exist, so nothing is live.
			name: "first install",
			rs:   Ruleset{Routes: []RouteSpec{baseSpec()}},
		},
		{
			// The same host a moment later: the kernel holds exactly the chains
			// this ruleset declares, and re-applying must change nothing.
			name: "already converged",
			rs: Ruleset{
				Routes:     []RouteSpec{baseSpec()},
				LiveChains: []string{"prerouting", "postrouting", "forward", "accounting"},
			},
		},
		{
			// No rules and no table: removing the last rule from a host that
			// never had one must not invent a removal either.
			name: "nothing at all",
			rs:   Ruleset{},
		},
	} {
		payload, err := backend.Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: rendering failed: %v", tc.name, err)
		}
		if len(payload.RemovesChains) != 0 {
			t.Errorf("%s: removes %v", tc.name, payload.RemovesChains)
		}
		for _, statement := range []string{"delete chain", "add chain"} {
			if strings.Contains(payload.Parts[0].Text, statement) {
				t.Errorf("%s: the payload contains %q, which both nft versions refuse when the "+
					"chain is absent:\n%s", tc.name, statement, payload.Parts[0].Text)
			}
		}
	}
}

// TestTheChainInventoryIsReadBackFromTheKernel covers the other half: an empty
// chain contributes no rule at all, so unless the inventory itself is parsed
// nothing above this package can ever see one.
func TestTheChainInventoryIsReadBackFromTheKernel(t *testing.T) {
	// Exactly what `nft list table inet gre_panel` printed on server A.
	live := parseNftLive(`table inet gre_panel {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
	}

	chain output {
		type nat hook output priority dstnat; policy accept;
	}

	chain mss {
		type filter hook forward priority mangle; policy accept;
	}
}`)
	if got := fmt.Sprint(live.Chains); got != "[prerouting output mss]" {
		t.Errorf("the chain inventory read back = %s", got)
	}
	if len(live.Rules) != 0 {
		t.Errorf("empty chains produced %d rules", len(live.Rules))
	}
}

// TestRenderingIsDeterministic is what makes the preview endpoint trustworthy:
// the payload an operator reads before committing is byte for byte the payload
// that is applied.
func TestRenderingIsDeterministic(t *testing.T) {
	for _, tc := range cases() {
		first, err := nftBackend().Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: rendering failed: %v", tc.name, err)
		}
		second, err := nftBackend().Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: rendering failed: %v", tc.name, err)
		}
		if first.Parts[0].Text != second.Parts[0].Text {
			t.Errorf("%s renders differently on a second pass", tc.name)
		}
	}
}

// TestEmissionOrderFollowsSortOrder covers the rule that makes ordering a
// user-visible setting rather than an accident of insertion.
func TestEmissionOrderFollowsSortOrder(t *testing.T) {
	rs := Ruleset{Routes: []RouteSpec{
		{RouteRuleID: 7, SortOrder: 30}, {RouteRuleID: 3, SortOrder: 10}, {RouteRuleID: 9, SortOrder: 20},
		// Two rules sharing a sort order fall back to the identifier, so the
		// order is total and the output stays deterministic.
		{RouteRuleID: 2, SortOrder: 10},
	}}
	var got []int64
	for _, r := range rs.Sorted() {
		got = append(got, r.RouteRuleID)
	}
	want := []int64{2, 3, 9, 7}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("emission order = %v, want %v", got, want)
	}
}

// TestNoCounterInANatChain is the accounting invariant of §5.1: a nat hook only
// processes the first packet of a connection, so a counter there measures
// connections while claiming to measure bytes. It is checked over every option
// combination rather than over one, because the mistake would be a single
// misplaced line.
func TestNoCounterInANatChain(t *testing.T) {
	for _, tc := range cases() {
		nft, err := nftBackend().Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: rendering failed: %v", tc.name, err)
		}
		for _, chain := range []string{nftChainPrerouting, nftChainOutput, nftChainPostrouting} {
			// A chain the rule did not need is not emitted at all, and one that
			// is absent cannot hold a counter in the wrong place.
			body, present := nftChainBodyIfPresent(nft.Parts[0].Text, chain)
			if present && strings.Contains(body, "counter") {
				t.Errorf("%s: the nftables %s chain contains a counter:\n%s", tc.name, chain, body)
			}
		}

		ipt, err := iptBackend().Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: rendering failed: %v", tc.name, err)
		}
		for _, part := range ipt.Parts {
			for _, rule := range iptTableRules(part.Text, "nat") {
				// A verdict-free rule is exactly what an iptables counting rule
				// looks like, so any rule in the nat table without a target
				// would be an accounting rule in the wrong place.
				if !strings.Contains(rule, " -j ") {
					t.Errorf("%s: the iptables nat table contains a rule with no target, which is "+
						"how accounting is expressed: %s", tc.name, rule)
				}
			}
		}
	}
}

// TestAccountingLivesInTheFilterForwardHook is the other half of the same
// invariant: the counters have to be somewhere, and that somewhere is the
// forward hook.
func TestAccountingLivesInTheFilterForwardHook(t *testing.T) {
	rs := Ruleset{Routes: []RouteSpec{baseSpec()}}

	nft, err := nftBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	body := nftChainBody(t, nft.Parts[0].Text, nftChainAccounting)
	if !strings.Contains(body, `counter name "route_1_tx"`) ||
		!strings.Contains(body, `counter name "route_1_rx"`) {
		t.Errorf("the accounting chain is missing a direction:\n%s", body)
	}
	if !strings.Contains(nft.Parts[0].Text, "hook forward priority filter - 10") {
		t.Error("the accounting chain must hook forward at its own priority")
	}
	// Counting rules carry no verdict, so they observe without deciding.
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "type ") {
			continue
		}
		for _, verdict := range []string{" accept", " drop", " reject", " dnat", " snat", " masquerade"} {
			if strings.Contains(line, verdict) {
				t.Errorf("an accounting rule carries a verdict: %s", line)
			}
		}
	}

	ipt, err := iptBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	for _, rule := range iptTableRules(ipt.Parts[0].Text, "filter") {
		if !strings.HasPrefix(rule, "-A "+ChainAcct+" ") {
			continue
		}
		if strings.Contains(rule, " -j ") {
			t.Errorf("an iptables accounting rule carries a target: %s", rule)
		}
	}
}

// TestForwardPermissionRestsOnConntrack covers the correction of §1.4: the
// legacy script accepted anything from the far end's source port, which accepts
// traffic belonging to no flow this server started.
func TestForwardPermissionRestsOnConntrack(t *testing.T) {
	rs := Ruleset{Routes: []RouteSpec{baseSpec()}}

	nft, err := nftBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	forward := nftChainBody(t, nft.Parts[0].Text, nftChainForward)
	if !strings.Contains(forward, "ct state established,related accept") {
		t.Error("the forward chain must let conntrack cover the return direction")
	}
	if strings.Contains(forward, "sport") {
		t.Errorf("the forward chain matches on a source port, which is the over-permissive "+
			"reverse rule this subsystem exists to correct:\n%s", forward)
	}

	ipt, err := iptBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	var forwardRules []string
	for _, rule := range iptTableRules(ipt.Parts[0].Text, "filter") {
		if strings.HasPrefix(rule, "-A "+ChainFwd+" ") {
			forwardRules = append(forwardRules, rule)
		}
	}
	if len(forwardRules) == 0 || !strings.Contains(forwardRules[0], "ESTABLISHED,RELATED") {
		t.Errorf("the first forward rule must be the conntrack accept, got %v", forwardRules)
	}
	for _, rule := range forwardRules {
		if strings.Contains(rule, "--sport") {
			t.Errorf("a forward rule matches on a source port: %s", rule)
		}
	}
}

// TestEveryRuleCarriesItsIdentity is what makes reconciliation exact.
func TestEveryRuleCarriesItsIdentity(t *testing.T) {
	rs := Ruleset{Routes: []RouteSpec{baseSpec()}}

	nft, err := nftBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	for _, line := range strings.Split(nft.Parts[0].Text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !isGeneratedNftRule(trimmed) {
			continue
		}
		if _, ok := ParseIdentity(trimmed); !ok {
			t.Errorf("a generated nftables rule carries no identity comment: %s", trimmed)
		}
	}

	ipt, err := iptBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	for _, part := range ipt.Parts {
		for _, line := range strings.Split(part.Text, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "-A ") {
				continue
			}
			// The conntrack accept belongs to the chain rather than to any one
			// rule, so it is the single line with no identity.
			if strings.Contains(trimmed, "ESTABLISHED,RELATED") {
				continue
			}
			if _, ok := ParseIdentity(trimmed); !ok {
				t.Errorf("a generated iptables rule carries no identity comment: %s", trimmed)
			}
		}
	}
}

// TestIdentityCommentRoundTrip covers the mapping in both directions, including
// the way it is actually used: pulled out of a whole rule line read back from
// the kernel.
func TestIdentityCommentRoundTrip(t *testing.T) {
	for _, id := range []int64{1, 7, 42, 1000000} {
		comment := Identity(id)
		got, ok := ParseIdentity(comment)
		if !ok || got != id {
			t.Errorf("ParseIdentity(%q) = %d, %v; want %d, true", comment, got, ok, id)
		}
	}

	line := `ip daddr 203.0.113.10 tcp dport 2044 dnat to 198.51.100.20:2044 comment "grep:12"`
	if got, ok := ParseIdentity(line); !ok || got != 12 {
		t.Errorf("ParseIdentity of a live nftables rule = %d, %v; want 12, true", got, ok)
	}
	iptLine := `-A GRE_PANEL_PRE -d 203.0.113.10/32 -p tcp --dport 2044 -m comment --comment "grep:12" -j DNAT`
	if got, ok := ParseIdentity(iptLine); !ok || got != 12 {
		t.Errorf("ParseIdentity of a live iptables rule = %d, %v; want 12, true", got, ok)
	}

	for _, notARule := range []string{"", "no comment here", "grep:", "grep:x", "grep:0"} {
		if got, ok := ParseIdentity(notARule); ok {
			t.Errorf("ParseIdentity(%q) = %d, true; want no identity", notARule, got)
		}
	}

	ids := IdentitiesIn(`comment "grep:3"` + "\n" + `comment "grep:1"` + "\n" + `comment "grep:3"`)
	if fmt.Sprint(ids) != fmt.Sprint([]int64{3, 1}) {
		t.Errorf("IdentitiesIn = %v, want [3 1] in order of appearance without duplicates", ids)
	}
}

// TestPortRangeWidthMismatchIsRejected covers the rule that a range only maps
// one-to-one when both ends are the same width.
func TestPortRangeWidthMismatchIsRejected(t *testing.T) {
	s := baseSpec()
	s.BindPorts = PortRange{Port: 20000, End: 20100}
	s.Destinations = []Destination{{Address: "198.51.100.20", Ports: PortRange{Port: 30000, End: 30050}}}

	err := Ruleset{Routes: []RouteSpec{s}}.Check()
	if !errors.Is(err, ErrRangeWidth) {
		t.Fatalf("Check returned %v, want an ErrRangeWidth", err)
	}
	if !strings.Contains(err.Error(), "101") || !strings.Contains(err.Error(), "51") {
		t.Errorf("the error should name both widths so the operator can see the mismatch: %v", err)
	}

	// Equal widths map one to one and are accepted.
	s.Destinations = []Destination{{Address: "198.51.100.20", Ports: PortRange{Port: 30000, End: 30100}}}
	if err := (Ruleset{Routes: []RouteSpec{s}}).Check(); err != nil {
		t.Errorf("equal-width ranges were rejected: %v", err)
	}
}

func TestRenderRejectsAnEmptyDestinationSet(t *testing.T) {
	s := baseSpec()
	s.Destinations = nil
	if _, err := nftBackend().Render(Ruleset{Routes: []RouteSpec{s}}); !errors.Is(err, ErrNoDestination) {
		t.Errorf("rendering a rule with no destination returned %v, want ErrNoDestination", err)
	}
	if _, err := iptBackend().Render(Ruleset{Routes: []RouteSpec{s}}); !errors.Is(err, ErrNoDestination) {
		t.Errorf("rendering a rule with no destination returned %v, want ErrNoDestination", err)
	}
}

// TestLoadBalancingAcrossAPortRangeIsRefused states the limitation rather than
// silently sending every connection to the first port of the range.
func TestLoadBalancingAcrossAPortRangeIsRefused(t *testing.T) {
	s := baseSpec()
	s.LoadBalance = LoadBalanceRoundRobin
	s.BindPorts = PortRange{Port: 20000, End: 20001}
	s.Destinations = []Destination{
		{Address: "198.51.100.20", Ports: PortRange{Port: 30000, End: 30001}},
		{Address: "198.51.100.21", Ports: PortRange{Port: 30000, End: 30001}},
	}
	for name, backend := range map[string]Backend{"nftables": nftBackend(), "iptables": iptBackend()} {
		if _, err := backend.Render(Ruleset{Routes: []RouteSpec{s}}); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s rendered load balancing across a port range (%v), want ErrUnsupported", name, err)
		}
	}
}

// TestIptablesRefusesSourceHashItCannotExpress covers the one option the
// fallback backend genuinely cannot serve. Refusing with an explanation is the
// requirement; quietly distributing by something else is not.
func TestIptablesRefusesSourceHashItCannotExpress(t *testing.T) {
	s := baseSpec()
	s.LoadBalance = LoadBalanceSourceHash
	s.Destinations = []Destination{
		{Address: "198.51.100.20", Ports: PortRange{Port: 2044}},
		{Address: "203.0.113.99", Ports: PortRange{Port: 2044}},
	}
	_, err := iptBackend().Render(Ruleset{Routes: []RouteSpec{s}})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("rendering returned %v, want ErrUnsupported", err)
	}
	if !strings.Contains(err.Error(), "nftables") {
		t.Errorf("the refusal should say what would serve it: %v", err)
	}

	// nftables hashes across any set of destinations, so the same rule renders.
	if _, err := nftBackend().Render(Ruleset{Routes: []RouteSpec{s}}); err != nil {
		t.Errorf("nftables refused source hashing: %v", err)
	}
}

// TestWeightedSharesAddUp checks the arithmetic of both backends' weighted
// distribution, which is easy to get subtly wrong in different ways.
func TestWeightedSharesAddUp(t *testing.T) {
	s := baseSpec()
	s.LoadBalance = LoadBalanceWeighted
	s.Destinations = []Destination{
		{Address: "198.51.100.20", Ports: PortRange{Port: 2044}, Weight: 7},
		{Address: "198.51.100.21", Ports: PortRange{Port: 2044}, Weight: 2},
		{Address: "198.51.100.22", Ports: PortRange{Port: 2044}, Weight: 1},
	}

	nft, err := nftBackend().Render(Ruleset{Routes: []RouteSpec{s}})
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	// Ten slots, split 7/2/1 as consecutive intervals.
	want := "dnat ip to numgen inc mod 10 map { 0-6 : 198.51.100.20 . 2044, 7-8 : 198.51.100.21 . 2044, " +
		"9 : 198.51.100.22 . 2044 }"
	if !strings.Contains(nft.Parts[0].Text, want) {
		t.Errorf("the nftables weighted map is wrong; want it to contain:\n%s", want)
	}

	ipt, err := iptBackend().Render(Ruleset{Routes: []RouteSpec{s}})
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	// Seven in ten, then two of the remaining three, then the rest.
	rules := iptTableRules(ipt.Parts[0].Text, "nat")
	var dnats []string
	for _, r := range rules {
		if strings.Contains(r, "DNAT") {
			dnats = append(dnats, r)
		}
	}
	if len(dnats) != 3 {
		t.Fatalf("want three DNAT rules for three destinations, got %d: %v", len(dnats), dnats)
	}
	if !strings.Contains(dnats[0], "--every 1 ") {
		t.Errorf("the first share of 7 in 10 should take one in one of what reaches it: %s", dnats[0])
	}
	if !strings.Contains(dnats[1], "--every 1 ") {
		t.Errorf("the second share of 2 in the remaining 3 should take one in one: %s", dnats[1])
	}
	if strings.Contains(dnats[2], "--every") {
		t.Errorf("the last destination takes whatever is left and needs no statistic match: %s", dnats[2])
	}
}

// TestIptablesInstallsExactlyOneJumpPerBuiltInChain covers §2.1: the jump rules
// are the only thing the panel ever adds to a chain it does not own, and they
// are checked before they are installed so a second apply cannot duplicate them.
func TestIptablesInstallsExactlyOneJumpPerBuiltInChain(t *testing.T) {
	payload, err := iptBackend().Render(Ruleset{Routes: []RouteSpec{baseSpec()}})
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if len(payload.Assertions) != len(jumpTargets())*2 {
		t.Fatalf("got %d jump assertions, want one per built-in chain per address family (%d)",
			len(payload.Assertions), len(jumpTargets())*2)
	}
	seen := map[string]int{}
	for _, a := range payload.Assertions {
		if len(a.Check) == 0 || len(a.Install) == 0 {
			t.Fatalf("the assertion %q has no check or no install command", a.Description)
		}
		if !contains(a.Check, "-C") {
			t.Errorf("the assertion %q does not check before installing: %v", a.Description, a.Check)
		}
		if !contains(a.Install, "-I") {
			t.Errorf("the assertion %q appends rather than inserting: %v", a.Description, a.Install)
		}
		seen[strings.Join(a.Install, " ")]++
	}
	for command, n := range seen {
		if n != 1 {
			t.Errorf("the jump rule %q is installed %d times, want exactly once", command, n)
		}
	}

	// Accounting has to be reached before the forward chain decides anything.
	acct, fwd := -1, -1
	for i, j := range jumpTargets() {
		switch j.target {
		case ChainAcct:
			acct = i
		case ChainFwd:
			fwd = i
		}
	}
	if acct == -1 || fwd == -1 || acct > fwd {
		t.Error("the accounting chain must be jumped to before the forward chain")
	}
}

// TestPayloadsRewriteOnlyThePanelsNamespace is the safety property of §6.3.2
// expressed against the rendered payload: nothing here flushes, reorders or
// deletes anything the panel did not create.
func TestPayloadsRewriteOnlyThePanelsNamespace(t *testing.T) {
	for _, tc := range cases() {
		nft, err := nftBackend().Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, line := range strings.Split(nft.Parts[0].Text, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "flush") && !strings.HasPrefix(trimmed, "delete") {
				continue
			}
			// The three destructive forms the panel is allowed to emit: flushing
			// its own table, removing a counter object inside it, and removing a
			// chain inside it that the panel itself created.
			flush := fmt.Sprintf("flush table %s %s", TableFamily, TableName)
			counterPrefix := fmt.Sprintf("delete counter %s %s ", TableFamily, TableName)
			chainPrefix := fmt.Sprintf("delete chain %s %s ", TableFamily, TableName)
			switch {
			case trimmed == flush:
			case strings.HasPrefix(trimmed, counterPrefix):
			case strings.HasPrefix(trimmed, chainPrefix):
				// Being in the panel's table is not enough. A chain someone else
				// put there is still not the panel's to delete, so the name has to
				// be one the panel has itself created.
				name := strings.TrimSpace(strings.TrimPrefix(trimmed, chainPrefix))
				if !nftOwnedChains[name] {
					t.Errorf("%s: the payload deletes the chain %q, which the panel did not create: %s",
						tc.name, name, trimmed)
				}
			default:
				t.Errorf("%s: the payload destroys something outside the panel's namespace: %s",
					tc.name, trimmed)
			}
		}

		ipt, err := iptBackend().Render(tc.rs)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, part := range ipt.Parts {
			for _, line := range strings.Split(part.Text, "\n") {
				trimmed := strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(trimmed, "-F "), strings.HasPrefix(trimmed, "-X "),
					strings.HasPrefix(trimmed, ":"), strings.HasPrefix(trimmed, "-A "):
					name := chainOfIptablesLine(trimmed)
					if !IsPanelChain(name) {
						t.Errorf("%s: the payload touches the chain %q, which the panel does not own: %s",
							tc.name, name, trimmed)
					}
				}
			}
		}
	}
}

// TestRenderedPayloadsAreOwned checks that every rendered file carries the
// ownership marker, which is what stops the panel overwriting a file somebody
// else put at the same path.
func TestRenderedPayloadsAreOwned(t *testing.T) {
	for name, backend := range map[string]Backend{"nftables": nftBackend(), "iptables": iptBackend()} {
		payload, err := backend.Render(Ruleset{Routes: []RouteSpec{baseSpec()}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, part := range payload.Parts {
			if !strings.Contains(part.Text, OwnershipMarker) {
				t.Errorf("%s: the %s payload carries no ownership marker", name, part.Kind)
			}
		}
	}
}

// TestRetiredCountersAreRemovedWithTheirRule covers the one thing a table flush
// does not do. Named counter objects survive it deliberately, so that editing a
// rule does not lose the kernel's figures for it (§5.1) — but that same
// property leaves the counters of a deleted rule in the kernel until the next
// reboot unless the payload says otherwise.
func TestRetiredCountersAreRemovedWithTheirRule(t *testing.T) {
	rs := Ruleset{Routes: []RouteSpec{baseSpec()}, Retired: []int64{7, 3, 7}}
	payload, err := nftBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	text := payload.Parts[0].Text

	for _, want := range []string{
		"delete counter inet gre_panel route_3_rx",
		"delete counter inet gre_panel route_3_tx",
		"delete counter inet gre_panel route_7_rx",
		"delete counter inet gre_panel route_7_tx",
	} {
		if strings.Count(text, want+"\n") != 1 {
			t.Errorf("the payload does not remove the retired counter exactly once: %s", want)
		}
	}

	// The rule that still exists keeps its counters, which is the whole point of
	// naming them.
	if strings.Contains(text, "delete counter inet gre_panel route_1_") {
		t.Error("the payload removes the counters of a rule that still exists")
	}
	if !strings.Contains(text, "counter route_1_rx {") {
		t.Error("the payload no longer declares the live rule's counters")
	}

	// Order matters: the objects exist until the table is flushed, and they have
	// to be gone before the table body is read, or nft would refuse a delete of
	// something it has just been told to keep.
	flushAt := strings.Index(text, "flush table inet gre_panel")
	deleteAt := strings.Index(text, "delete counter inet gre_panel route_3_rx")
	bodyAt := strings.Index(text, "table inet gre_panel {")
	if !(flushAt < deleteAt && deleteAt < bodyAt) {
		t.Errorf("the deletes are in the wrong place: flush at %d, delete at %d, body at %d",
			flushAt, deleteAt, bodyAt)
	}

	// Retired identifiers are emitted in a fixed order, so the same state
	// renders the same bytes.
	first := strings.Index(text, "route_3_rx")
	second := strings.Index(text, "route_7_rx")
	if first > second {
		t.Error("the retired counters are not emitted in identifier order")
	}
}

// TestARulesetWithNothingRetiredDeletesNoCounters keeps the common payload free
// of noise, and keeps the deletes from appearing on a host that has none.
func TestARulesetWithNothingRetiredDeletesNoCounters(t *testing.T) {
	for _, rs := range []Ruleset{{}, {Routes: []RouteSpec{baseSpec()}}} {
		payload, err := nftBackend().Render(rs)
		if err != nil {
			t.Fatalf("rendering failed: %v", err)
		}
		if strings.Contains(payload.Parts[0].Text, "delete counter") {
			t.Error("a ruleset with nothing retired still deletes counters")
		}
	}
}

// ---------------------------------------------------------------- helpers

// nftChainBody returns the lines of one chain of a rendered nftables ruleset.
func nftChainBody(t *testing.T, text, chain string) string {
	t.Helper()
	body, present := nftChainBodyIfPresent(text, chain)
	if !present {
		t.Fatalf("the rendered ruleset has no chain %q", chain)
	}
	return body
}

// nftChainBodyIfPresent is the same, for callers to which an absent chain is an
// answer rather than a failure: a chain with no rules is not emitted.
func nftChainBodyIfPresent(text, chain string) (string, bool) {
	var body strings.Builder
	inside := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "chain "+chain+" {":
			inside = true
		case inside && trimmed == "}":
			return body.String(), true
		case inside:
			body.WriteString(trimmed)
			body.WriteString("\n")
		}
	}
	return "", false
}

// iptTableRules returns the -A lines of one table of an iptables-restore
// payload.
func iptTableRules(text, table string) []string {
	var out []string
	inside := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "*"+table:
			inside = true
		case strings.HasPrefix(trimmed, "*"):
			inside = false
		case trimmed == "COMMIT":
			inside = false
		case inside && strings.HasPrefix(trimmed, "-A "):
			out = append(out, trimmed)
		}
	}
	return out
}

// chainOfIptablesLine returns the chain a payload line operates on.
func chainOfIptablesLine(line string) string {
	fields := strings.Fields(line)
	switch {
	case len(fields) >= 2 && (fields[0] == "-A" || fields[0] == "-F" || fields[0] == "-X"):
		return fields[1]
	case strings.HasPrefix(line, ":"):
		return strings.TrimPrefix(fields[0], ":")
	}
	return ""
}

// isGeneratedNftRule reports whether a line of a rendered nftables ruleset is a
// rule generated from a route, as opposed to structure or documentation.
func isGeneratedNftRule(line string) bool {
	switch {
	case line == "" || strings.HasPrefix(line, "#"):
		return false
	case strings.HasPrefix(line, "table "), strings.HasPrefix(line, "flush "),
		strings.HasPrefix(line, "chain "), strings.HasPrefix(line, "counter "),
		strings.HasPrefix(line, "set "), strings.HasPrefix(line, "type "),
		strings.HasPrefix(line, "size "), strings.HasPrefix(line, "flags "),
		strings.HasPrefix(line, "timeout "), line == "}", line == "{":
		return false
	case strings.HasPrefix(line, "ct state established,related"):
		// Belongs to the chain, not to any one rule.
		return false
	}
	return true
}

func contains(argv []string, want string) bool {
	for _, a := range argv {
		if a == want {
			return true
		}
	}
	return false
}

// A retired rule's counters are deleted in the same transaction that drops its
// rules. That deletion has to be idempotent for the same reason the chain
// removal does: this file is what gre-panel-rules.service replays at boot,
// against a table that has just been created and holds no counters at all.
//
// Observed after a real reboot of server A:
//
//	/var/lib/gre-panel/rules/gre-panel.nft:25:31-41: Error: Could not process
//	rule: No such file or directory
//	delete counter inet gre_panel route_28_rx
//	gre-panel-rules.service: Failed with result 'exit-code'
//
// The whole transaction is rejected, so a host that had forwarding rules would
// come back from a reboot with none of them, and the unit left failed. Measured
// on the host: declaring the table is not enough on its own, because the table
// then exists while the counter still does not; and `add counter` on a counter
// that already exists does not reset it, so the idiom costs no accounting.
func TestRetiredCountersAreRemovedIdempotently(t *testing.T) {
	rs := Ruleset{
		Routes:  []RouteSpec{baseSpec()},
		Retired: []int64{28},
	}
	payload, err := nftBackend().Render(rs)
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	text := payload.Parts[0].Text

	for _, suffix := range []string{"rx", "tx"} {
		name := "route_28_" + suffix
		del := "delete counter inet gre_panel " + name + "\n"
		add := "add counter inet gre_panel " + name + "\n"

		if !strings.Contains(text, del) {
			t.Errorf("the payload does not retire the counter %q:\n%s", name, text)
			continue
		}
		if !strings.Contains(text, add) {
			t.Errorf("the removal of counter %q is not idempotent, so the boot-time restore "+
				"fails on a host where it does not exist yet — which is every boot:\n%s", name, text)
			continue
		}
		if strings.Index(text, add) > strings.Index(text, del) {
			t.Errorf("counter %q is added after it is deleted, which is the wrong order", name)
		}
	}
}
