package rules

import (
	"strings"
	"testing"
)

// nftRulesetWithDocker is the shape `nft list ruleset` prints on a host running
// Docker beside the panel: Docker's own nat table, and the panel's table, both
// hooking prerouting.
const nftRulesetWithDocker = `table ip nat {
	chain PREROUTING {
		type nat hook prerouting priority dstnat; policy accept;
		fib daddr type local counter packets 12 bytes 720 jump DOCKER
	}

	chain DOCKER {
		iifname "docker0" return
		ip daddr 203.0.113.10 tcp dport 2044 counter packets 3 bytes 180 dnat to 172.17.0.2:80
		meta l4proto tcp udp dport 5353 dnat to 172.17.0.9:5353
	}
}
table inet gre_panel {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 203.0.113.10 tcp dport 2044 dnat ip to 198.51.100.20:2044 comment "grep:7"
	}
}
`

// nftRulesetWithPanelCounters is what the real `nft list ruleset` prints for
// the panel's own table: the named counter objects come first, each with a
// block of its own, and the chains follow.
//
// It exists because treating one of those inner closing braces as the table's
// own made the parser forget which table it was in, and every rule after the
// first counter — all of the panel's own — was then reported as somebody
// else's. A hand-written fixture without the counter blocks never showed it.
const nftRulesetWithPanelCounters = `table inet gre_panel {
	counter route_1_rx {
		packets 0 bytes 0
	}

	counter route_1_tx {
		packets 0 bytes 0
	}

	set route_1_conn {
		type ipv4_addr
		size 65535
		flags dynamic
	}

	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 203.0.113.10 tcp dport 2044 dnat ip to 198.51.100.20:2044 comment "grep:1"
		ip daddr 203.0.113.10 tcp dport 8443 dnat ip to numgen inc mod 4 map { 0-2 : 198.51.100.20 . 8443, 3 : 198.51.100.21 . 8443 } comment "grep:3"
	}

	chain output {
		type nat hook output priority dstnat; policy accept;
		ip daddr 203.0.113.10 udp dport 20000-20100 dnat ip to 198.51.100.20:30000-30100 comment "grep:2"
	}
}
table ip nat {
	chain DOCKER {
		ip daddr 203.0.113.10 tcp dport 2044 dnat to 172.17.0.2:80
	}
}
`

// TestParseNftForeignTracksTheTableThroughItsCounterBlocks is the regression
// test for the defect a real kernel found and the fixtures did not.
func TestParseNftForeignTracksTheTableThroughItsCounterBlocks(t *testing.T) {
	found := ParseNftForeign(nftRulesetWithPanelCounters)

	for _, rule := range found {
		if strings.Contains(rule.Text, IdentityPrefix) {
			t.Errorf("a rule carrying the panel's own identity comment was reported as foreign: %+v",
				rule)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d foreign rules, want only Docker's: %+v", len(found), found)
	}
	if found[0].Table != "ip nat" || found[0].Chain != "DOCKER" {
		t.Errorf("the foreign rule's table was not tracked: %+v", found[0])
	}
}

func TestParseNftForeignSkipsThePanelsOwnTable(t *testing.T) {
	found := ParseNftForeign(nftRulesetWithDocker)

	for _, rule := range found {
		if rule.Table == TableName || rule.Table == TableFamily+" "+TableName {
			t.Errorf("the panel's own rule was reported as foreign: %+v", rule)
		}
	}
	if len(found) != 2 {
		t.Fatalf("found %d foreign rules, want the two of Docker's: %+v", len(found), found)
	}

	first := found[0]
	if first.Chain != "DOCKER" || first.Manager != "Docker" {
		t.Errorf("the rule was not attributed to Docker: %+v", first)
	}
	if first.Protocol != "tcp" || first.Address != "203.0.113.10" || first.Port != 2044 {
		t.Errorf("the match was not read out of the rule: %+v", first)
	}
	if second := found[1]; second.Protocol != "udp" || second.Port != 5353 {
		t.Errorf("the UDP rule was not read: %+v", second)
	}
}

// TestForeignRuleShadowsThePanelsRule is what the report rests on: a rule that
// claims the same protocol, address and port takes the packet first.
func TestForeignRuleShadowsThePanelsRule(t *testing.T) {
	spec := RouteSpec{
		RouteRuleID: 7, Protocol: ProtocolTCP,
		BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 2044},
	}
	found := ParseNftForeign(nftRulesetWithDocker)
	view := ForeignView{Readable: true, Rules: found, Managers: managerNames(found)}

	shadows := view.ShadowsOf(spec)
	if len(shadows) != 1 {
		t.Fatalf("got %d shadowing rules, want the one on the same port: %+v", len(shadows), shadows)
	}
	if shadows[0].Manager != "Docker" {
		t.Errorf("the shadowing rule was not named: %+v", shadows[0])
	}
	if len(view.Managers) != 1 || view.Managers[0] != "Docker" {
		t.Errorf("the foreign managers were not reported: %v", view.Managers)
	}
}

func TestForeignRuleShadowCases(t *testing.T) {
	tests := []struct {
		name    string
		foreign ForeignRule
		spec    RouteSpec
		want    bool
	}{
		{
			name:    "a different port does not shadow",
			foreign: ForeignRule{Protocol: "tcp", Address: "203.0.113.10", Port: 8080},
			spec: RouteSpec{Protocol: ProtocolTCP, BindAddress: "203.0.113.10",
				BindPorts: PortRange{Port: 2044}},
			want: false,
		},
		{
			name:    "a different protocol does not shadow",
			foreign: ForeignRule{Protocol: "udp", Address: "203.0.113.10", Port: 2044},
			spec: RouteSpec{Protocol: ProtocolTCP, BindAddress: "203.0.113.10",
				BindPorts: PortRange{Port: 2044}},
			want: false,
		},
		{
			name:    "a foreign rule on every address shadows a specific one",
			foreign: ForeignRule{Protocol: "tcp", Address: "", Port: 2044},
			spec: RouteSpec{Protocol: ProtocolTCP, BindAddress: "203.0.113.10",
				BindPorts: PortRange{Port: 2044}},
			want: true,
		},
		{
			name:    "an overlapping range shadows",
			foreign: ForeignRule{Protocol: "tcp", Address: "203.0.113.10", Port: 20050, PortEnd: 20150},
			spec: RouteSpec{Protocol: ProtocolTCP, BindAddress: "203.0.113.10",
				BindPorts: PortRange{Port: 20000, End: 20100}},
			want: true,
		},
		{
			name:    "a rule whose port could not be read is not guessed at",
			foreign: ForeignRule{Protocol: "tcp", Address: "203.0.113.10"},
			spec: RouteSpec{Protocol: ProtocolTCP, BindAddress: "203.0.113.10",
				BindPorts: PortRange{Port: 2044}},
			want: false,
		},
		{
			name:    "a both-protocol rule is shadowed by either",
			foreign: ForeignRule{Protocol: "udp", Address: "203.0.113.10", Port: 2044},
			spec: RouteSpec{Protocol: ProtocolBoth, BindAddress: "203.0.113.10",
				BindPorts: PortRange{Port: 2044}},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.foreign.Shadows(tc.spec); got != tc.want {
				t.Errorf("Shadows = %v, want %v", got, tc.want)
			}
		})
	}
}

// iptablesNatSave is what `iptables-save -t nat` prints on a host with the
// panel's chains and Docker's beside them.
const iptablesNatSave = `# Generated by iptables-save
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
:GRE_PANEL_PRE - [0:0]
-A PREROUTING -j GRE_PANEL_PRE
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A DOCKER -d 203.0.113.10/32 -p tcp -m tcp --dport 2044 -j DNAT --to-destination 172.17.0.2:80
-A DOCKER -p tcp -m tcp --dport 8080 -j REDIRECT --to-ports 3128
-A GRE_PANEL_PRE -d 203.0.113.10/32 -p tcp -m tcp --dport 2044 -m comment --comment "grep:7" -j DNAT --to-destination 198.51.100.20:2044
-A PREROUTING -p tcp -m tcp --dport 20000:20100 -j DNAT --to-destination 10.0.0.5
COMMIT
`

func TestParseIptablesForeignSkipsThePanelsChainsAndJumps(t *testing.T) {
	found := ParseIptablesForeign(iptablesNatSave, "nat")

	for _, rule := range found {
		if IsPanelChain(rule.Chain) {
			t.Errorf("a rule in the panel's own chain was reported as foreign: %+v", rule)
		}
		if rule.Text == "-A PREROUTING -j GRE_PANEL_PRE" {
			t.Error("the panel's own jump rule was reported as foreign")
		}
	}
	if len(found) != 3 {
		t.Fatalf("found %d foreign rules, want 3: %+v", len(found), found)
	}

	if found[0].Manager != "Docker" || found[0].Address != "203.0.113.10" ||
		found[0].Port != 2044 || found[0].Protocol != "tcp" {
		t.Errorf("the Docker DNAT was not read: %+v", found[0])
	}
	if found[1].Port != 8080 {
		t.Errorf("the REDIRECT was not read: %+v", found[1])
	}
	// A range spelled with a colon, in a built-in chain, with nothing to
	// attribute it to. That is exactly the rule an operator has to look at
	// themselves, so it is reported with no manager rather than dropped.
	last := found[2]
	if last.Port != 20000 || last.PortEnd != 20100 {
		t.Errorf("the port range was not read: %+v", last)
	}
	if last.Manager != "" {
		t.Errorf("a rule in a built-in chain was attributed to %q", last.Manager)
	}
}

// TestParseIptablesForeignIgnoresASubnetDestination: a rule covering a whole
// subnet claims no single address, so it is reported without one rather than
// with a prefix that would never compare equal to a bind address.
func TestParseIptablesForeignIgnoresASubnetDestination(t *testing.T) {
	const save = `*nat
-A PREROUTING -d 10.0.0.0/8 -p tcp -m tcp --dport 2044 -j DNAT --to-destination 172.17.0.2:80
COMMIT
`
	found := ParseIptablesForeign(save, "nat")
	if len(found) != 1 {
		t.Fatalf("found %d rules, want 1", len(found))
	}
	if found[0].Address != "" {
		t.Errorf("the subnet was reported as a single address: %q", found[0].Address)
	}
	if found[0].Port != 2044 {
		t.Errorf("the port was not read: %+v", found[0])
	}
}
