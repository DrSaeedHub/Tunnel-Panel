package safety

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// recordedSockets is a socket table taken from a host rather than invented, so
// that "the SSH port" means what the running daemon says it is.
type recordedSockets struct {
	listeners []rules.Listener
	err       error
}

func (r recordedSockets) Listeners() ([]rules.Listener, error) { return r.listeners, r.err }

func (r recordedSockets) SshPorts() ([]int, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []int
	for _, l := range r.listeners {
		if l.Protocol == rules.ProtocolTCP && strings.HasPrefix(l.ProcessName, "sshd") {
			out = append(out, l.Port)
		}
	}
	return out, nil
}

// A host where the operator moved SSH off the conventional port and put
// something else on it — the case that makes assuming 22 both useless and
// dangerous.
func movedSshHost() recordedSockets {
	return recordedSockets{listeners: []rules.Listener{
		{Protocol: rules.ProtocolTCP, Address: "0.0.0.0", Port: 2222, ProcessName: "sshd", ProcessID: 812},
		{Protocol: rules.ProtocolTCP, Address: "0.0.0.0", Port: 22, ProcessName: "nginx", ProcessID: 900},
		{Protocol: rules.ProtocolTCP, Address: "0.0.0.0", Port: 8443, ProcessName: "gre-panel", ProcessID: 3300},
	}}
}

func routeSpec(port int) rules.RouteSpec {
	return rules.RouteSpec{
		RouteRuleID: 1, Title: "Relay", Protocol: rules.ProtocolTCP, Family: rules.FamilyIPv4,
		BindAddress: "203.0.113.10", BindPorts: rules.PortRange{Port: port},
		Destinations: []rules.Destination{
			{Address: "198.51.100.20", Ports: rules.PortRange{Port: port}},
		},
		NatMode: rules.NatMasquerade,
	}
}

// refusal asserts that an operation was refused with a given code and returns
// the violation, so a test can also check what the operator is told.
func refusal(t *testing.T, err error, code string) *Violation {
	t.Helper()
	if err == nil {
		t.Fatalf("the operation was allowed; expected a %s violation", code)
	}
	v, ok := AsViolation(err)
	if !ok {
		t.Fatalf("got %v, want a refusal", err)
	}
	if v.Code != code {
		t.Fatalf("got the violation %s, want %s (%s)", v.Code, code, v.Message)
	}
	return v
}

// TestThePanelPortCanNeverBeForwarded is the invariant that matters most: a
// rule redirecting the panel's own port makes the panel unreachable, and there
// is no way back except console access.
func TestThePanelPortCanNeverBeForwarded(t *testing.T) {
	ctx := context.Background()
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	v := refusal(t, guard.CheckRoute(ctx, routeSpec(8443)), CodeProtectedPort)
	if !strings.Contains(v.Message, "8443") {
		t.Errorf("the refusal does not name the port: %s", v.Message)
	}
	if !strings.Contains(v.Message, "console") {
		t.Errorf("the refusal does not say why it cannot be overridden: %s", v.Message)
	}

	// A range that happens to contain it is the same mistake with more ports.
	ranged := routeSpec(8000)
	ranged.BindPorts = rules.PortRange{Port: 8000, End: 9000}
	ranged.Destinations[0].Ports = rules.PortRange{Port: 8000, End: 9000}
	refusal(t, guard.CheckRoute(ctx, ranged), CodeProtectedPort)

	// And a neighbouring port is fine, so the rule is not simply refusing
	// everything.
	if err := guard.CheckRoute(ctx, routeSpec(8444)); err != nil {
		t.Errorf("an unrelated port was refused: %v", err)
	}
}

// TestTheLiveSshPortIsProtectedAndTheAssumedOneIsNot is the reason the port is
// read from the running daemon: on this host, forwarding 22 is harmless and
// forwarding 2222 would lock the operator out.
func TestTheLiveSshPortIsProtectedAndTheAssumedOneIsNot(t *testing.T) {
	ctx := context.Background()
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	v := refusal(t, guard.CheckRoute(ctx, routeSpec(2222)), CodeProtectedPort)
	if !strings.Contains(v.Message, "SSH") {
		t.Errorf("the refusal does not say what is on the port: %s", v.Message)
	}
	if err := guard.CheckRoute(ctx, routeSpec(22)); err != nil {
		t.Errorf("port 22 is not the SSH port on this host, so forwarding it should be allowed: %v", err)
	}

	// On a host where SSH is where it usually is, that is the port protected.
	usual := recordedSockets{listeners: []rules.Listener{
		{Protocol: rules.ProtocolTCP, Address: "0.0.0.0", Port: 22, ProcessName: "sshd", ProcessID: 812},
	}}
	guard = NewRouteGuard(8443, usual, "/var/lib/gre-panel/rules")
	refusal(t, guard.CheckRoute(ctx, routeSpec(22)), CodeProtectedPort)
	if err := guard.CheckRoute(ctx, routeSpec(2222)); err != nil {
		t.Errorf("port 2222 has nothing on it here, so forwarding it should be allowed: %v", err)
	}

	// OpenSSH 9.8 splits the daemon into sshd and sshd-session; both count.
	split := recordedSockets{listeners: []rules.Listener{
		{Protocol: rules.ProtocolTCP, Address: "::", Port: 2200, ProcessName: "sshd-session", ProcessID: 5},
	}}
	guard = NewRouteGuard(8443, split, "/var/lib/gre-panel/rules")
	refusal(t, guard.CheckRoute(ctx, routeSpec(2200)), CodeProtectedPort)
}

// TestAnUnreadableSocketTableProtectsTheConventionalPort covers the fallback:
// being wrong in this direction costs a forwarding rule, and being wrong in the
// other costs access to the machine.
func TestAnUnreadableSocketTableProtectsTheConventionalPort(t *testing.T) {
	ctx := context.Background()
	for name, guard := range map[string]*RouteGuard{
		"no socket table": NewRouteGuard(8443, nil, "/var/lib/gre-panel/rules"),
		"unreadable socket table": NewRouteGuard(8443,
			recordedSockets{err: errors.New("permission denied")}, "/var/lib/gre-panel/rules"),
	} {
		t.Run(name, func(t *testing.T) {
			v := refusal(t, guard.CheckRoute(ctx, routeSpec(DefaultSshPort)), CodeProtectedPort)
			if !strings.Contains(v.Message, "precaution") {
				t.Errorf("the refusal does not say it is a fallback: %s", v.Message)
			}
			// The panel's own port is known without reading anything.
			refusal(t, guard.CheckRoute(ctx, routeSpec(8443)), CodeProtectedPort)
		})
	}
}

// TestForceCannotReachTheProtectedPortRule is the explicit requirement: the
// invariant is not a warning and no flag relaxes it. The request carries force
// and every other override the API accepts, and the answer is the same.
func TestForceCannotReachTheProtectedPortRule(t *testing.T) {
	ctx := context.Background()
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	forced := validate.RouteInput{
		RouteRuleID: 1, RouteRuleTitle: "Take the panel down",
		RouteProtocolID: model.RouteProtocolTCP, AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress: "203.0.113.10", BindPort: 8443,
		DestinationAddress: "198.51.100.20", DestinationPort: 8443,
		NatModeID: model.NatModeMasquerade,
		IsEnabled: true,
		Force:     true,
	}
	// The request is well-formed: validation has nothing to say about it, which
	// is exactly why the invariant has to live below validation.
	if errs := validate.ValidateRouteStatic(forced); !errs.Empty() {
		t.Fatalf("the request itself is malformed, so this would not prove anything: %v", errs)
	}
	refusal(t, guard.CheckRoute(ctx, forced.Spec()), CodeProtectedPort)

	// The same through the whole-ruleset check the service calls before an
	// apply, with a legitimate rule alongside it so the refusal is not an
	// artefact of there being only one.
	rs := rules.Ruleset{Routes: []rules.RouteSpec{routeSpec(2044), forced.Spec()}}
	refusal(t, guard.CheckRuleset(ctx, rs), CodeProtectedPort)

	// And forcing the SSH port is refused the same way.
	forced.BindPort, forced.DestinationPort = 2222, 2222
	refusal(t, guard.CheckRoute(ctx, forced.Spec()), CodeProtectedPort)
}

// TestAUdpRuleCannotTakeTheSshOrPanelPort states the one exception precisely:
// SSH and the panel are TCP, so a UDP relay on the same number cannot take
// either, and refusing it would be refusing something harmless.
func TestAUdpRuleOnTheSamePortNumberIsAllowed(t *testing.T) {
	ctx := context.Background()
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	udp := routeSpec(2222)
	udp.Protocol = rules.ProtocolUDP
	if err := guard.CheckRoute(ctx, udp); err != nil {
		t.Errorf("a UDP rule on the SSH port number was refused: %v", err)
	}

	// A rule covering both protocols does include TCP, so it is refused.
	both := routeSpec(2222)
	both.Protocol = rules.ProtocolBoth
	refusal(t, guard.CheckRoute(ctx, both), CodeProtectedPort)
}

// TestProtectedPortsAreReportable lets the frontend grey the ports out rather
// than letting an operator discover the refusal by submitting.
func TestProtectedPortsAreReportable(t *testing.T) {
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")
	ports := guard.ProtectedPorts(context.Background())
	if len(ports) != 2 {
		t.Fatalf("got %d protected ports, want the panel's and SSH's: %+v", len(ports), ports)
	}
	if ports[0].Port != 2222 || ports[1].Port != 8443 {
		t.Errorf("protected ports = %+v, want 2222 and 8443 in order", ports)
	}
	for _, p := range ports {
		if p.Reason == "" {
			t.Errorf("port %d is protected with no reason given", p.Port)
		}
	}
}

// TestOnlyThePanelsOwnNetfilterObjectsMayBeTouched is invariant 2.
func TestOnlyThePanelsOwnNetfilterObjectsMayBeTouched(t *testing.T) {
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	if err := guard.CheckNetfilterObject("table", rules.TableName); err != nil {
		t.Errorf("the panel's own table was refused: %v", err)
	}
	for _, chain := range rules.OwnedChains() {
		if err := guard.CheckNetfilterObject("chain", chain); err != nil {
			t.Errorf("the panel's own chain %s was refused: %v", chain, err)
		}
	}

	for _, tc := range []struct{ kind, name string }{
		{"table", "filter"},
		{"table", "nat"},
		{"table", "docker"},
		{"chain", "FORWARD"},
		{"chain", "PREROUTING"},
		{"chain", "DOCKER-USER"},
		{"chain", "f2b-sshd"},
		{"rule", "anything"},
	} {
		v := refusal(t, guard.CheckNetfilterObject(tc.kind, tc.name), CodeForeignNetfilter)
		if !strings.Contains(v.Message, tc.name) {
			t.Errorf("the refusal does not name what was asked for: %s", v.Message)
		}
	}
}

// TestOnlyForwardingSysctlsAreEverSet is invariants 3 and 4.
func TestOnlyForwardingSysctlsAreEverSet(t *testing.T) {
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	for _, key := range AllowedSysctls {
		if err := guard.CheckSysctl(key); err != nil {
			t.Errorf("%s is what a relay needs and was refused: %v", key, err)
		}
	}

	v := refusal(t, guard.CheckSysctl("net.ipv4.conf.eth0.route_localnet"), CodeProtectedSysctl)
	if !strings.Contains(v.Message, "localhost") {
		t.Errorf("the refusal does not explain what route_localnet exposes: %s", v.Message)
	}
	refusal(t, guard.CheckSysctl("net.ipv4.conf.all.route_localnet"), CodeProtectedSysctl)
	refusal(t, guard.CheckSysctl("net.ipv4.tcp_syncookies"), CodeProtectedSysctl)
	refusal(t, guard.CheckSysctl("kernel.panic"), CodeProtectedSysctl)
}

// TestOnlyThePanelsOwnFilesAreWritten is invariant 3 at the file level,
// including the directory belonging to the persistence package this subsystem
// deliberately does not use.
func TestOnlyThePanelsOwnFilesAreWritten(t *testing.T) {
	guard := NewRouteGuard(8443, movedSshHost(), "/var/lib/gre-panel/rules")

	for _, allowed := range []string{
		"/var/lib/gre-panel/rules/gre-panel.nft",
		"/var/lib/gre-panel/rules/gre-panel.rules",
		"/var/lib/gre-panel/rules/gre-panel.6rules",
		PanelSysctlFile,
	} {
		if err := guard.CheckPath(allowed); err != nil {
			t.Errorf("the panel's own file %s was refused: %v", allowed, err)
		}
	}

	for _, refused := range []string{
		"/etc/iptables/rules.v4",
		"/etc/iptables/rules.v6",
		"/etc/sysctl.conf",
		"/etc/sysctl.d/99-sysctl.conf",
		"/etc/nftables.conf",
		"/etc/network/interfaces",
		"/etc/netplan/00-installer.yaml",
		"/var/lib/gre-panel/panel.db",
		"relative/path",
	} {
		refusal(t, guard.CheckPath(refused), CodeProtectedPath)
	}
}

// Both of the panel's own sysctl files are writable, and nothing else under
// /etc/sysctl.d is.
//
// The regression: the tuning file was given a path of its own and the guard was
// never told about it, so every attempt to tune the host was refused with a
// message about protected paths — the panel forbidding itself from writing its
// own file. The guard's job is to keep the panel out of files belonging to the
// system and to other software; a file the panel wrote, named after the panel,
// is neither.
func TestThePanelMayWriteItsOwnSysctlFilesAndNoOthers(t *testing.T) {
	guard := NewRouteGuard(8443, nil, "/var/lib/gre-panel/rules")

	for _, own := range []string{PanelSysctlFile, PanelTuningSysctlFile} {
		if err := guard.CheckPath(own); err != nil {
			t.Errorf("the panel is refused its own file %s: %v", own, err)
		}
	}

	for _, foreign := range []string{
		"/etc/sysctl.conf",
		"/etc/sysctl.d/99-sysctl.conf",
		"/etc/sysctl.d/10-network-security.conf",
		"/etc/sysctl.d/98-conntrack.conf",
	} {
		if err := guard.CheckPath(foreign); err == nil {
			t.Errorf("the panel was allowed to write %s, which is not its file", foreign)
		}
	}
}
