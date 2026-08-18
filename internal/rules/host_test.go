package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/exec"
)

// hostTestEnv gates the tests that really install rules.
//
// TestGoldenPayloadsParseOnThisHost is safe to run anywhere because it only
// asks the tools to check a ruleset. These do not: they submit a transaction,
// read it back, and flush. Running that on a host where the panel is installed
// would replace the panel's own live table, so it happens only when asked for,
// and the message says what to ask for.
const hostTestEnv = "GRE_PANEL_HOST_TESTS"

// requireIsolatedHost skips unless this is root, nft is present, and the caller
// has opted in.
//
// It also refuses to run in a network namespace that already holds the panel's
// table, because that is the shared namespace of a real installation and these
// tests would take its rules away.
func requireIsolatedHost(t *testing.T) (*Nftables, exec.Runner, string) {
	t.Helper()
	if os.Getenv(hostTestEnv) != "1" {
		t.Skipf("set %s=1 and run inside a private network namespace "+
			"(unshare -n) to exercise the real kernel", hostTestEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("nft needs root to open a netlink socket")
	}
	if _, err := os.Stat(DefaultNftBin); err != nil {
		t.Skipf("%s is not installed here", DefaultNftBin)
	}

	runner := exec.NewRunner()
	res, err := runner.Run(context.Background(), []string{DefaultNftBin, "list", "ruleset"})
	if err == nil && strings.Contains(res.Stdout, "table "+TableFamily+" "+TableName) {
		t.Fatalf("this network namespace already holds %s %s, which means it is a real "+
			"installation's. Run these tests under `unshare -n`.", TableFamily, TableName)
	}

	dir := t.TempDir()
	return NewNftables(DefaultNftBin, dir, runner), runner, dir
}

// hostRuleset covers the option combinations that have to survive a round trip
// through the real kernel: both protocols, port ranges, an allowlist, interface
// binding, load balancing, connection limits, logging, a mark, MSS clamping,
// all three NAT modes, and IPv6.
//
// Load balancing and a port range are deliberately on different rules. nftables
// cannot express a one-to-one port mapping across a set of destinations, and the
// backend refuses that combination rather than rendering something that would
// map the ports wrongly — so a fixture pairing them would be testing a rule the
// panel does not accept.
func hostRuleset() Ruleset {
	mark := uint32(0x64)
	return Ruleset{Routes: []RouteSpec{
		{
			RouteRuleID: 1, Title: "tcp masquerade", Protocol: ProtocolTCP, Family: FamilyIPv4,
			BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 2044},
			Destinations:   []Destination{{Address: "198.51.100.20", Ports: PortRange{Port: 2044}}},
			NatMode:        NatMasquerade,
			ClampMssToPmtu: true,
		},
		{
			RouteRuleID: 2, Title: "range, allowlist, limits, logging, mark",
			Protocol: ProtocolBoth, Family: FamilyIPv4,
			BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 20000, End: 20100},
			BindInterface: "eth0",
			Destinations: []Destination{
				{Address: "198.51.100.20", Ports: PortRange{Port: 30000, End: 30100}},
			},
			NatMode: NatSnat, SnatAddress: "203.0.113.10",
			AllowedSources: []string{"192.0.2.0/24"}, IncludeLocalOriginated: true,
			Logging: true, FwMark: &mark,
			MaxConnectionsPerSource: 25, ConnectionRateLimit: 120, SortOrder: 10,
		},
		{
			RouteRuleID: 3, Title: "weighted across two destinations",
			Protocol: ProtocolTCP, Family: FamilyIPv4,
			BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 8443},
			Destinations: []Destination{
				{Address: "198.51.100.20", Ports: PortRange{Port: 8443}, Weight: 3},
				{Address: "198.51.100.21", Ports: PortRange{Port: 8443}, Weight: 1},
			},
			NatMode: NatMasquerade, LoadBalance: LoadBalanceWeighted, SortOrder: 20,
		},
		{
			RouteRuleID: 4, Title: "ipv6, source preserved", Protocol: ProtocolUDP, Family: FamilyIPv6,
			BindAddress: "2001:db8::1", BindPorts: PortRange{Port: 5353},
			Destinations: []Destination{{Address: "2001:db8::2", Ports: PortRange{Port: 5353}}},
			NatMode:      NatNone, SortOrder: 30,
		},
	}}
}

// TestTheKernelHoldsWhatWasRenderedOnThisHost applies the panel's own ruleset
// to a real kernel and reads it back.
//
// The fixtures elsewhere prove the parsers handle output that was written by
// hand to look like nft's. This proves they handle nft's, which is a different
// claim and the one that matters: the kernel renders a rule in its own
// canonical form, and every read path above this package depends on that form
// being understood.
func TestTheKernelHoldsWhatWasRenderedOnThisHost(t *testing.T) {
	backend, _, _ := requireIsolatedHost(t)
	ctx := context.Background()

	payload, err := backend.Render(hostRuleset())
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := backend.Apply(ctx, payload); err != nil {
		t.Fatalf("the real nft refused the ruleset: %v", err)
	}
	t.Cleanup(func() { _ = backend.Flush(context.Background()) })

	live, err := backend.ReadBack(ctx)
	if err != nil {
		t.Fatalf("reading the ruleset back failed: %v", err)
	}
	if len(live.Rules) == 0 {
		t.Fatal("nft accepted the ruleset and the kernel holds nothing")
	}

	// Every rule is attributed to the row that generated it, which is what
	// makes reconciliation exact rather than heuristic.
	byRole := map[string]int{}
	for _, rule := range live.Rules {
		if rule.Structural {
			continue
		}
		if rule.RouteRuleID == 0 {
			t.Errorf("a rule in the panel's own table carries no identity comment: %s", rule.Text)
			continue
		}
		if rule.Role == "" {
			t.Errorf("a rule was read from chain %q with no role: %s", rule.Chain, rule.Text)
		}
		byRole[rule.Role]++
	}
	for _, role := range []string{RolePrerouting, RoleOutput, RolePostrouting,
		RoleForward, RoleAccounting, RoleMss, RoleMark} {
		if byRole[role] == 0 {
			t.Errorf("no rule was attributed to the %s role; the kernel's chain names were not "+
				"recognised", role)
		}
	}
	t.Logf("the kernel holds %d rules: %v", len(live.Rules), byRole)
}

// TestTheNamedCountersAreReadableOnThisHost proves the accounting reads the
// counter objects nft actually creates, in the JSON nft actually prints.
func TestTheNamedCountersAreReadableOnThisHost(t *testing.T) {
	backend, runner, _ := requireIsolatedHost(t)
	ctx := context.Background()

	payload, err := backend.Render(hostRuleset())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, payload); err != nil {
		t.Fatalf("the real nft refused the ruleset: %v", err)
	}
	t.Cleanup(func() { _ = backend.Flush(context.Background()) })

	counters, err := backend.Counters(ctx)
	if err != nil {
		t.Fatalf("reading the named counters failed: %v", err)
	}
	for _, id := range []int64{1, 2, 3, 4} {
		if _, ok := counters[id]; !ok {
			t.Errorf("rule %d has no counter in the kernel; the counter names were not parsed", id)
		}
	}

	// And the counters are in the forward hook, not a nat one (§5.1): a
	// counter in a nat chain would count connections while appearing to count
	// bytes.
	res, err := runner.Run(ctx, []string{DefaultNftBin, "list", "table", TableFamily, TableName})
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range natChainsOf(res.Stdout) {
		if strings.Contains(chain.body, "counter") {
			t.Errorf("the %s chain is a nat hook and holds a counter:\n%s", chain.name, chain.body)
		}
	}
}

// TestForeignRulesAreSeenAndThePanelsAreNotOnThisHost installs a rule in a
// table the panel does not own and confirms the panel sees it, does not
// mistake its own for foreign, and does not remove it.
func TestForeignRulesAreSeenAndThePanelsAreNotOnThisHost(t *testing.T) {
	backend, runner, dir := requireIsolatedHost(t)
	ctx := context.Background()

	payload, err := backend.Render(hostRuleset())
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, payload); err != nil {
		t.Fatalf("the real nft refused the ruleset: %v", err)
	}
	t.Cleanup(func() { _ = backend.Flush(context.Background()) })

	// Something else on the host claims the same listener.
	foreign := filepath.Join(dir, "foreign.nft")
	const body = `table ip other_software {
	chain DOCKER {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 203.0.113.10 tcp dport 2044 dnat to 172.17.0.2:80
	}
}
`
	if err := os.WriteFile(foreign, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(ctx, []string{DefaultNftBin, "-f", foreign}); err != nil {
		t.Fatalf("installing the foreign rule failed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(context.Background(),
			[]string{DefaultNftBin, "delete", "table", "ip", "other_software"})
	})

	view, err := backend.Foreign(ctx)
	if err != nil {
		t.Fatalf("reading the host's other rules failed: %v", err)
	}
	if !view.Readable {
		t.Fatal("the host's ruleset was reported as unreadable")
	}
	if len(view.Rules) != 1 {
		t.Fatalf("found %d foreign rules, want the one that was installed: %+v", len(view.Rules), view.Rules)
	}
	found := view.Rules[0]
	if found.Manager != "Docker" {
		t.Errorf("the rule was not attributed to the chain's owner: %+v", found)
	}
	if found.Protocol != "tcp" || found.Address != "203.0.113.10" || found.Port != 2044 {
		t.Errorf("the match was not read out of nft's own rendering: %+v", found)
	}
	if !found.Shadows(hostRuleset().Routes[0]) {
		t.Error("the rule claims the same protocol, address and port and was not reported as shadowing")
	}

	// Flushing takes the panel's table and nothing else.
	if err := backend.Flush(ctx); err != nil {
		t.Fatalf("flushing failed: %v", err)
	}
	after, err := backend.ReadBack(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Rules) != 0 {
		t.Errorf("the panel's table survived the flush: %d rules", len(after.Rules))
	}
	res, err := runner.Run(ctx, []string{DefaultNftBin, "list", "ruleset"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "other_software") {
		t.Error("flushing the panel's table removed a table it does not own")
	}
}

// natChain is one chain of a listed table, with the hook it is on.
type natChain struct {
	name string
	body string
}

// natChainsOf pulls the nat-hook chains out of `nft list table` output.
func natChainsOf(listing string) []natChain {
	var out []natChain
	var current *natChain
	for _, raw := range strings.Split(listing, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "chain "):
			name := strings.TrimSuffix(strings.TrimPrefix(line, "chain "), " {")
			current = &natChain{name: strings.TrimSpace(name)}
		case line == "}" && current != nil:
			if strings.Contains(current.body, "type nat hook") {
				out = append(out, *current)
			}
			current = nil
		case current != nil:
			current.body += line + "\n"
		}
	}
	return out
}
