package rules

import (
	"strings"
	"testing"
)

// sharedDestination is two rules relaying to the same far service from two
// ports on this server: one rewrites the source, the other keeps it, and one
// binds every address so both spellings of the origin match are exercised.
func sharedDestination() []RouteSpec {
	far := []Destination{{Address: "198.51.100.20", Ports: PortRange{Port: 443}}}
	return []RouteSpec{
		{
			RouteRuleID: 1, Title: "Masqueraded", SortOrder: 10,
			Protocol: ProtocolTCP, Family: FamilyIPv4,
			BindAddress: "203.0.113.10", BindPorts: PortRange{Port: 8443},
			Destinations: far, NatMode: NatMasquerade, ClampMssToPmtu: true,
		},
		{
			RouteRuleID: 2, Title: "Client kept", SortOrder: 20,
			Protocol: ProtocolTCP, Family: FamilyIPv4,
			BindAddress: "0.0.0.0", BindPorts: PortRange{Port: 9443},
			Destinations: far, NatMode: NatNone,
		},
	}
}

// TestRulesSharingADestinationOnlyTouchTheirOwnConnections is the regression
// for a rule that keeps the client address having it rewritten anyway, and
// for a rule's traffic counter counting another rule's bytes.
//
// Both came from the same place: every rule after the DNAT was keyed on where
// the connection goes, and two rules may send connections to the same place.
// Every such line has to carry the original destination of its own rule --
// the one address and port no other rule may claim -- and no line may name
// another rule's.
func TestRulesSharingADestinationOnlyTouchTheirOwnConnections(t *testing.T) {
	rs := Ruleset{Routes: sharedDestination()}

	backends := []struct {
		name   string
		render func(Ruleset) (Payload, error)
		origin map[string]string // rule identity -> its origin match
	}{
		{"nftables", nftBackend().Render, map[string]string{
			"grep:1": "ct original ip daddr 203.0.113.10 ct original proto-dst 8443",
			"grep:2": "ct original proto-dst 9443",
		}},
		{"iptables", iptBackend().Render, map[string]string{
			"grep:1": "-m conntrack --ctorigdst 203.0.113.10/32 --ctorigdstport 8443",
			"grep:2": "-m conntrack --ctorigdstport 9443",
		}},
	}

	for _, b := range backends {
		payload, err := b.render(rs)
		if err != nil {
			t.Fatalf("%s: rendering failed: %v", b.name, err)
		}
		checked := 0
		for _, part := range payload.Parts {
			for _, line := range strings.Split(part.Text, "\n") {
				// Only the lines that act on a connection after it has been
				// redirected: they all name the far address.
				if !strings.Contains(line, "198.51.100.20") || strings.Contains(strings.ToLower(line), "dnat") {
					continue
				}
				owner := ""
				for identity := range b.origin {
					if strings.Contains(line, `"`+identity+`"`) {
						owner = identity
					}
				}
				if owner == "" {
					continue
				}
				checked++
				if !strings.Contains(line, b.origin[owner]) {
					t.Errorf("%s: a line of %s is not tied to its own connections, so it also acts on "+
						"the other rule's:\n  %s", b.name, owner, line)
				}
			}
		}
		// Rule 1: forward, masquerade, two accounting lines and MSS; rule 2:
		// forward and two accounting lines, and no NAT at all.
		if checked < 8 {
			t.Errorf("%s: only %d post-DNAT line(s) were found; the test is not looking at the ruleset",
				b.name, checked)
		}
		for _, part := range payload.Parts {
			for _, line := range strings.Split(part.Text, "\n") {
				if strings.Contains(line, `"grep:2"`) && strings.Contains(strings.ToLower(line), "masquerade") {
					t.Errorf("%s: the rule set to keep the client address renders a masquerade:\n  %s",
						b.name, line)
				}
			}
		}
	}
}
