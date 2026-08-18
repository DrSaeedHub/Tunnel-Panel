package validate

import (
	"context"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// ---------------------------------------------------------------- fixtures

// fakeRouteRepo is the stored half of the picture validation checks against.
type fakeRouteRepo struct {
	routes  []ExistingRoute
	tunnels map[int64]bool
}

func (f fakeRouteRepo) ExistingRoutes(ctx context.Context) ([]ExistingRoute, error) {
	return f.routes, nil
}

func (f fakeRouteRepo) TunnelExists(ctx context.Context, id int64) (bool, error) {
	return f.tunnels[id], nil
}

// fakeSockets is the kernel socket table, recorded rather than read.
type fakeSockets struct {
	listeners []rules.Listener
	err       error
}

func (f fakeSockets) Listeners() ([]rules.Listener, error) { return f.listeners, f.err }

// routeValidator builds a validator over a plausible host: one NIC on
// 203.0.113.10 carrying the default route, plus whatever rows and sockets the
// test supplies.
func routeValidator(routes []ExistingRoute, listeners []rules.Listener) *RouteValidator {
	return NewRouteValidator(link.NewFakeWithHost(),
		fakeRouteRepo{routes: routes, tunnels: map[int64]bool{3: true}},
		fakeSockets{listeners: listeners}, nil)
}

// validRoute is a rule that passes every check: this server's own address,
// a free port, a reachable destination, and the NAT mode that works without the
// operator reasoning about return paths.
func validRoute() RouteInput {
	return RouteInput{
		RouteRuleTitle:     "Web relay",
		RouteProtocolID:    model.RouteProtocolTCP,
		AddressFamilyID:    model.AddressFamilyIPv4,
		BindAddress:        "203.0.113.10",
		BindPort:           2044,
		DestinationAddress: "198.51.100.20",
		DestinationPort:    2044,
		NatModeID:          model.NatModeMasquerade,
		LoadBalanceModeID:  model.LoadBalanceModeNone,
		IsEnabled:          true,
	}
}

func hasCode(errs *Errors, code string) bool {
	if errs == nil {
		return false
	}
	for _, f := range errs.Fields {
		if f.Code == code {
			return true
		}
	}
	return false
}

func fieldWithCode(t *testing.T, errs *Errors, code string) FieldError {
	t.Helper()
	for _, f := range errs.Fields {
		if f.Code == code {
			return f
		}
	}
	t.Fatalf("no failure with code %s; got %v", code, errs.Codes())
	return FieldError{}
}

func warningWithCode(t *testing.T, result Result, code string) Warning {
	t.Helper()
	for _, w := range result.Warnings {
		if w.Code == code {
			return w
		}
	}
	t.Fatalf("no warning with code %s; got %+v", code, result.Warnings)
	return Warning{}
}

// ---------------------------------------------------------------- static

func TestValidRouteIsAccepted(t *testing.T) {
	if errs := ValidateRouteStatic(validRoute()); !errs.Empty() {
		t.Fatalf("a valid rule was rejected: %v", errs)
	}
	result, err := routeValidator(nil, nil).Validate(context.Background(), validRoute())
	if err != nil {
		t.Fatalf("a valid rule was rejected: %v", err)
	}
	// The NAT advisory is not optional: it is the one thing an operator has to
	// understand about a relay.
	if !hasWarning(result, WarnNatHidesClient) {
		t.Errorf("no warning explains that masquerade hides the client address: %+v", result.Warnings)
	}
}

func TestRouteStaticRulesRejectMalformedInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RouteInput)
		code   string
		field  string
	}{
		{"no title", func(in *RouteInput) { in.RouteRuleTitle = "  " }, CodeInvalidRouteTitle, "route_rule_title"},
		{"long title", func(in *RouteInput) { in.RouteRuleTitle = strings.Repeat("x", 101) },
			CodeInvalidRouteTitle, "route_rule_title"},
		{"unknown protocol", func(in *RouteInput) { in.RouteProtocolID = 99 },
			CodeInvalidRouteProtocol, "route_protocol_id"},
		{"unknown nat mode", func(in *RouteInput) { in.NatModeID = 99 }, CodeInvalidNatMode, "nat_mode_id"},
		{"unknown load balance mode", func(in *RouteInput) { in.LoadBalanceModeID = 99 },
			CodeInvalidLoadBalanceMode, "load_balance_mode_id"},
		{"bind address is not an address", func(in *RouteInput) { in.BindAddress = "not-an-ip" },
			CodeInvalidBindAddress, "bind_address"},
		{"destination is not an address", func(in *RouteInput) { in.DestinationAddress = "example.org" },
			CodeInvalidDestination, "destination_address"},
		{"destination is unspecified", func(in *RouteInput) { in.DestinationAddress = "0.0.0.0" },
			CodeInvalidDestination, "destination_address"},
		{"mixed families", func(in *RouteInput) { in.DestinationAddress = "2001:db8::20" },
			CodeAddressFamilyMismatch, "destination_address"},
		{"declared family disagrees", func(in *RouteInput) { in.AddressFamilyID = model.AddressFamilyIPv6 },
			CodeAddressFamilyMismatch, "address_family_id"},
		{"port zero", func(in *RouteInput) { in.BindPort = 0 }, CodeInvalidPort, "bind_port"},
		{"port too high", func(in *RouteInput) { in.BindPort = 70000 }, CodeInvalidPort, "bind_port"},
		{"destination port zero", func(in *RouteInput) { in.DestinationPort = 0 },
			CodeInvalidPort, "destination_port"},
		{"range end below start", func(in *RouteInput) { in.BindPort = 3000; in.BindPortRangeEnd = 2000 },
			CodeInvalidPortRange, "bind_port_range_end"},
		{"snat without an address", func(in *RouteInput) { in.NatModeID = model.NatModeSnat },
			CodeSnatAddressRequired, "snat_address"},
		{"snat address is not an address",
			func(in *RouteInput) { in.NatModeID = model.NatModeSnat; in.SnatAddress = "nope" },
			CodeInvalidSnatAddress, "snat_address"},
		{"snat address in the wrong family",
			func(in *RouteInput) { in.NatModeID = model.NatModeSnat; in.SnatAddress = "2001:db8::1" },
			CodeAddressFamilyMismatch, "snat_address"},
		{"source address without snat", func(in *RouteInput) { in.SnatAddress = "203.0.113.10" },
			CodeSnatAddressUnused, "snat_address"},
		{"malformed allowlist entry",
			func(in *RouteInput) { in.AllowedSources = []RouteAllowedSourceInput{{Cidr: "10.0.0.0/33"}} },
			CodeInvalidCidr, "allowed_sources.0.cidr"},
		{"allowlist in the wrong family",
			func(in *RouteInput) { in.AllowedSources = []RouteAllowedSourceInput{{Cidr: "2001:db8::/64"}} },
			CodeAddressFamilyMismatch, "allowed_sources.0.cidr"},
		{"weight out of range", func(in *RouteInput) {
			in.Destinations = []RouteDestinationInput{
				{Address: "198.51.100.21", Port: 2044, Weight: 5000, IsEnabled: true},
			}
		}, CodeInvalidWeight, "destinations.0.weight"},
		{"connection limit out of range", func(in *RouteInput) {
			zero := int64(0)
			in.MaxConnectionsPerSource = &zero
		}, CodeInvalidConnectionLimit, "max_connections_per_source"},
		{"firewall mark out of range", func(in *RouteInput) {
			huge := int64(1) << 40
			in.FwMark = &huge
		}, CodeInvalidFwMark, "fwmark"},
		{"interface name is not one", func(in *RouteInput) { in.BindInterface = "this name is far too long" },
			CodeInvalidName, "bind_interface"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validRoute()
			tc.mutate(&in)
			errs := ValidateRouteStatic(in)
			if errs.Empty() {
				t.Fatalf("the request was accepted; expected %s on %s", tc.code, tc.field)
			}
			if !hasCode(errs, tc.code) {
				t.Errorf("got codes %v, want %s", errs.Codes(), tc.code)
			}
			if !errs.Has(tc.field) {
				t.Errorf("the failure is not attributed to %s: %v", tc.field, errs.Fields)
			}
		})
	}
}

// TestPortRangeWidthsMustMatch covers the rule that ranges map one to one, and
// that the refusal explains the mismatch rather than just naming it.
func TestPortRangeWidthsMustMatch(t *testing.T) {
	in := validRoute()
	in.BindPort, in.BindPortRangeEnd = 20000, 20100
	in.DestinationPort, in.DestinationPortRangeEnd = 30000, 30050

	errs := ValidateRouteStatic(in)
	field := fieldWithCode(t, errs, CodePortRangeWidthMismatch)
	for _, want := range []string{"101", "51", "20000-20100", "30000-30050"} {
		if !strings.Contains(field.Message, want) {
			t.Errorf("the explanation does not mention %s: %s", want, field.Message)
		}
	}
	if field.Details["bind_width"] != 101 || field.Details["destination_width"] != 51 {
		t.Errorf("the details do not carry both widths: %+v", field.Details)
	}

	// Equal widths map one to one and are accepted.
	in.DestinationPortRangeEnd = 30100
	if errs := ValidateRouteStatic(in); !errs.Empty() {
		t.Errorf("equal-width ranges were rejected: %v", errs)
	}

	// A single destination port with a bind range is also a width mismatch:
	// there is no rule that collapses a hundred ports onto one.
	in.DestinationPortRangeEnd = 0
	if errs := ValidateRouteStatic(in); !hasCode(errs, CodePortRangeWidthMismatch) {
		t.Errorf("a range mapped onto a single port was accepted: %v", errs.Codes())
	}
}

// ---------------------------------------------------------------- conflicts

func TestRoutePortConflictsIncludeRangeOverlap(t *testing.T) {
	existing := []ExistingRoute{{
		RouteRuleID: 5, Title: "Existing relay", RouteProtocolID: model.RouteProtocolTCP,
		BindAddress: "203.0.113.10", BindPort: 20000, BindPortRangeEnd: 20100, IsEnabled: true,
	}}

	cases := []struct {
		name     string
		mutate   func(*RouteInput)
		conflict bool
	}{
		{"the same single port inside the range", func(in *RouteInput) { in.BindPort = 20050 }, true},
		{"a range overlapping at its start", func(in *RouteInput) {
			in.BindPort, in.BindPortRangeEnd = 20100, 20200
			in.DestinationPort, in.DestinationPortRangeEnd = 30100, 30200
		}, true},
		{"a range overlapping at its end", func(in *RouteInput) {
			in.BindPort, in.BindPortRangeEnd = 19000, 20000
			in.DestinationPort, in.DestinationPortRangeEnd = 39000, 40000
		}, true},
		{"a range enclosing it", func(in *RouteInput) {
			in.BindPort, in.BindPortRangeEnd = 1000, 30000
			in.DestinationPort, in.DestinationPortRangeEnd = 31000, 60000
		}, true},
		{"a port just below", func(in *RouteInput) { in.BindPort = 19999 }, false},
		{"a port just above", func(in *RouteInput) { in.BindPort = 20101 }, false},
		{"the same range on the other protocol", func(in *RouteInput) {
			in.RouteProtocolID = model.RouteProtocolUDP
			in.BindPort, in.BindPortRangeEnd = 20000, 20100
			in.DestinationPort, in.DestinationPortRangeEnd = 30000, 30100
		}, false},
		{"both protocols overlapping a TCP rule", func(in *RouteInput) {
			in.RouteProtocolID = model.RouteProtocolBoth
			in.BindPort = 20050
		}, true},
		{"the same port on another address", func(in *RouteInput) {
			in.BindAddress = "198.51.100.7"
			in.BindPort = 20050
		}, false},
		{"every local address overlapping one of them", func(in *RouteInput) {
			in.BindAddress = "0.0.0.0"
			in.BindPort = 20050
		}, true},
		{"a disabled rule claims nothing", func(in *RouteInput) {
			in.BindPort = 20050
			in.IsEnabled = false
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validRoute()
			tc.mutate(&in)
			_, err := routeValidator(existing, nil).Validate(context.Background(), in)
			errs, _ := AsErrors(err)
			got := hasCode(errs, CodeRoutePortConflict)
			if got != tc.conflict {
				t.Fatalf("conflict = %v, want %v (error: %v)", got, tc.conflict, err)
			}
			if got {
				field := fieldWithCode(t, errs, CodeRoutePortConflict)
				if !strings.Contains(field.Message, "Existing relay") {
					t.Errorf("the refusal does not name the rule it collides with: %s", field.Message)
				}
			}
		})
	}
}

// TestADisabledExistingRuleDoesNotHoldItsPort: the partial unique index is
// filtered on IsEnabled for the same reason, so that a replacement rule can be
// prepared before the old one is removed.
func TestADisabledExistingRuleDoesNotHoldItsPort(t *testing.T) {
	existing := []ExistingRoute{{
		RouteRuleID: 5, Title: "Old relay", RouteProtocolID: model.RouteProtocolTCP,
		BindAddress: "203.0.113.10", BindPort: 2044, IsEnabled: false,
	}}
	if _, err := routeValidator(existing, nil).Validate(context.Background(), validRoute()); err != nil {
		t.Errorf("a disabled rule blocked its port: %v", err)
	}
}

// TestARuleDoesNotConflictWithItself covers the update path.
func TestARuleDoesNotConflictWithItself(t *testing.T) {
	existing := []ExistingRoute{{
		RouteRuleID: 5, Title: "Web relay", RouteProtocolID: model.RouteProtocolTCP,
		BindAddress: "203.0.113.10", BindPort: 2044, IsEnabled: true,
	}}
	in := validRoute()
	in.RouteRuleID = 5
	if _, err := routeValidator(existing, nil).Validate(context.Background(), in); err != nil {
		t.Errorf("updating a rule conflicted with itself: %v", err)
	}
}

func TestRouteTitleMustBeUnique(t *testing.T) {
	existing := []ExistingRoute{{
		RouteRuleID: 5, Title: "web relay", RouteProtocolID: model.RouteProtocolTCP,
		BindAddress: "198.51.100.7", BindPort: 9999, IsEnabled: true,
	}}
	_, err := routeValidator(existing, nil).Validate(context.Background(), validRoute())
	errs, _ := AsErrors(err)
	if !hasCode(errs, CodeRouteTitleConflict) {
		t.Errorf("a duplicate name was accepted: %v", err)
	}
}

// TestALocalListenerBlocksTheRuleAndIsNamed is the check that keeps a working
// service from breaking silently, and the reason it names the process: "port
// 8080 is in use" sends an operator hunting.
func TestALocalListenerBlocksTheRuleAndIsNamed(t *testing.T) {
	listeners := []rules.Listener{
		{Protocol: rules.ProtocolTCP, Address: "0.0.0.0", Port: 2044, ProcessName: "nginx", ProcessID: 812},
	}
	in := validRoute()
	_, err := routeValidator(nil, listeners).Validate(context.Background(), in)
	errs, _ := AsErrors(err)
	field := fieldWithCode(t, errs, CodePortInUse)
	for _, want := range []string{"nginx", "812"} {
		if !strings.Contains(field.Message, want) {
			t.Errorf("the refusal does not name the process holding the socket: %s", field.Message)
		}
	}
	if field.Details["process_name"] != "nginx" || field.Details["process_id"] != 812 {
		t.Errorf("the details do not carry the owning process: %+v", field.Details)
	}

	// Forcing it is legitimate — the operator may be replacing that service —
	// but it must not become silent.
	in.Force = true
	result, err := routeValidator(nil, listeners).Validate(context.Background(), in)
	if err != nil {
		t.Fatalf("forcing the conflict still failed: %v", err)
	}
	warning := warningWithCode(t, result, WarnPortInUse)
	if !strings.Contains(warning.Message, "nginx") {
		t.Errorf("the warning does not name the process: %s", warning.Message)
	}
}

func TestListenerConflictDetectionCoversRangesAndProtocols(t *testing.T) {
	listeners := []rules.Listener{
		{Protocol: rules.ProtocolTCP, Address: "203.0.113.10", Port: 20050, ProcessName: "postgres", ProcessID: 99},
		{Protocol: rules.ProtocolUDP, Address: "0.0.0.0", Port: 51820, ProcessName: "wg-quick", ProcessID: 44},
	}
	cases := []struct {
		name     string
		mutate   func(*RouteInput)
		conflict bool
	}{
		{"a range containing the listening port", func(in *RouteInput) {
			in.BindPort, in.BindPortRangeEnd = 20000, 20100
			in.DestinationPort, in.DestinationPortRangeEnd = 30000, 30100
		}, true},
		{"a range beside it", func(in *RouteInput) {
			in.BindPort, in.BindPortRangeEnd = 20051, 20100
			in.DestinationPort, in.DestinationPortRangeEnd = 30051, 30100
		}, false},
		{"a TCP rule over a UDP listener", func(in *RouteInput) { in.BindPort = 51820 }, false},
		{"a UDP rule over a UDP listener", func(in *RouteInput) {
			in.RouteProtocolID = model.RouteProtocolUDP
			in.BindPort = 51820
		}, true},
		{"a both-protocols rule over a UDP listener", func(in *RouteInput) {
			in.RouteProtocolID = model.RouteProtocolBoth
			in.BindPort = 51820
		}, true},
		{"a listener on another address", func(in *RouteInput) {
			in.BindAddress = "198.51.100.7"
			in.BindPort = 20050
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validRoute()
			tc.mutate(&in)
			_, err := routeValidator(nil, listeners).Validate(context.Background(), in)
			errs, _ := AsErrors(err)
			if got := hasCode(errs, CodePortInUse); got != tc.conflict {
				t.Errorf("conflict = %v, want %v (error: %v)", got, tc.conflict, err)
			}
		})
	}
}

// TestAnUnreadableSocketTableDoesNotInventAConflict: a host whose socket table
// cannot be read is reported as unknown rather than as empty, and validation
// carries on rather than refusing everything.
func TestAnUnreadableSocketTableDoesNotInventAConflict(t *testing.T) {
	v := NewRouteValidator(link.NewFakeWithHost(), fakeRouteRepo{},
		fakeSockets{err: context.DeadlineExceeded}, nil)
	st, err := v.CollectRouteState(context.Background())
	if err != nil {
		t.Fatalf("collecting state failed: %v", err)
	}
	if st.ListenersRead {
		t.Error("an unreadable socket table was reported as read")
	}
	if _, err := v.Validate(context.Background(), validRoute()); err != nil {
		t.Errorf("validation failed because the socket table could not be read: %v", err)
	}
}

func TestSnatAddressMustBeOnThisHost(t *testing.T) {
	in := validRoute()
	in.NatModeID = model.NatModeSnat
	in.SnatAddress = "198.51.100.99"

	_, err := routeValidator(nil, nil).Validate(context.Background(), in)
	errs, _ := AsErrors(err)
	if !hasCode(errs, CodeSnatAddressNotOnHost) {
		t.Fatalf("a source address this host does not have was accepted: %v", err)
	}

	// The address the fake host actually carries is accepted.
	in.SnatAddress = "203.0.113.10"
	if _, err := routeValidator(nil, nil).Validate(context.Background(), in); err != nil {
		t.Errorf("a source address on this host was rejected: %v", err)
	}
}

func TestLoopbackDestinationNeedsForceAndExplainsRouteLocalnet(t *testing.T) {
	in := validRoute()
	in.DestinationAddress = "127.0.0.1"

	_, err := routeValidator(nil, nil).Validate(context.Background(), in)
	errs, _ := AsErrors(err)
	field := fieldWithCode(t, errs, CodeLoopbackDestination)
	if !strings.Contains(field.Message, "route_localnet") {
		t.Errorf("the refusal does not explain what forwarding to loopback needs: %s", field.Message)
	}

	in.Force = true
	result, err := routeValidator(nil, nil).Validate(context.Background(), in)
	if err != nil {
		t.Fatalf("forcing a loopback destination still failed: %v", err)
	}
	warning := warningWithCode(t, result, WarnLoopbackDestination)
	if !strings.Contains(warning.Message, "route_localnet") {
		t.Errorf("the warning does not explain what is still needed: %s", warning.Message)
	}
}

func TestBindingEveryAddressIsAcceptedWithAWarning(t *testing.T) {
	in := validRoute()
	in.BindAddress = "0.0.0.0"

	result, err := routeValidator(nil, nil).Validate(context.Background(), in)
	if err != nil {
		t.Fatalf("binding every local address was rejected: %v", err)
	}
	if !hasWarning(result, WarnBindAnyAddress) {
		t.Errorf("binding every address produced no warning: %+v", result.Warnings)
	}

	// And so is the IPv6 form.
	in.BindAddress = "::"
	in.AddressFamilyID = model.AddressFamilyIPv6
	in.DestinationAddress = "2001:db8::20"
	if _, err := routeValidator(nil, nil).Validate(context.Background(), in); err != nil {
		t.Errorf("binding every IPv6 address was rejected: %v", err)
	}
}

func TestAMissingBindInterfaceIsRejected(t *testing.T) {
	in := validRoute()
	in.BindInterface = "eth9"
	_, err := routeValidator(nil, nil).Validate(context.Background(), in)
	errs, _ := AsErrors(err)
	if !hasCode(errs, CodeInterfaceNotFound) {
		t.Errorf("a rule bound to an interface that does not exist was accepted: %v", err)
	}

	in.BindInterface = "eth0"
	if _, err := routeValidator(nil, nil).Validate(context.Background(), in); err != nil {
		t.Errorf("a rule bound to a real interface was rejected: %v", err)
	}
}

func TestTunnelBoundRulesAreAdvisedToClampMss(t *testing.T) {
	tunnelID := int64(3)
	in := validRoute()
	in.TunnelID = &tunnelID

	result, err := routeValidator(nil, nil).Validate(context.Background(), in)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	warning := warningWithCode(t, result, WarnMssClampRecommended)
	if !strings.Contains(warning.Message, "stall") {
		t.Errorf("the advisory does not describe the symptom an operator would see: %s", warning.Message)
	}

	in.IsClampMssToPmtu = true
	result, err = routeValidator(nil, nil).Validate(context.Background(), in)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if hasWarning(result, WarnMssClampRecommended) {
		t.Error("clamping is already on, so it should not be recommended again")
	}
}

// ---------------------------------------------------------------- defaults

func TestDefaultBindAddressIsTheServersPrimaryAddress(t *testing.T) {
	ctx := context.Background()
	links, err := link.NewFakeWithHost().List(ctx)
	if err != nil {
		t.Fatalf("listing links failed: %v", err)
	}
	routes, err := link.NewFakeWithHost().Routes(ctx)
	if err != nil {
		t.Fatalf("listing routes failed: %v", err)
	}

	address, ok := DefaultBindAddress(links, routes, rules.FamilyIPv4)
	if !ok || address != "203.0.113.10" {
		t.Errorf("DefaultBindAddress = %q, %v; want the address on the default-route interface", address, ok)
	}

	// The loopback address is never the primary address, even on a host with
	// nothing else and no default route.
	loopbackOnly := []link.Link{{
		Name: "lo", Kind: "loopback",
		Addresses: []link.Address{{Address: "127.0.0.1", PrefixLength: 8, Family: link.FamilyIPv4}},
	}}
	if address, ok := DefaultBindAddress(loopbackOnly, nil, rules.FamilyIPv4); ok {
		t.Errorf("DefaultBindAddress on a loopback-only host = %q, want nothing", address)
	}

	// With no default route, any global address is better than none.
	noDefault := []link.Link{{
		Name: "eth1", Kind: "device",
		Addresses: []link.Address{{Address: "10.1.2.3", PrefixLength: 24, Family: link.FamilyIPv4}},
	}}
	if address, ok := DefaultBindAddress(noDefault, nil, rules.FamilyIPv4); !ok || address != "10.1.2.3" {
		t.Errorf("DefaultBindAddress with no default route = %q, %v; want 10.1.2.3", address, ok)
	}
}

// TestApplyDefaultsFillsInTheBindAddressAndTheRest covers §6.1: an empty bind
// address means this server's own, and the panel resolves it rather than making
// the operator look it up.
func TestApplyDefaultsFillsInTheBindAddressAndTheRest(t *testing.T) {
	ctx := context.Background()
	v := routeValidator(nil, nil)

	in := RouteInput{
		RouteRuleTitle:     "Web relay",
		DestinationAddress: "198.51.100.20",
		DestinationPort:    2044,
		BindPort:           2044,
		IsEnabled:          true,
	}
	if err := v.ApplyDefaults(ctx, &in); err != nil {
		t.Fatalf("ApplyDefaults returned an unexpected error: %v", err)
	}
	if in.BindAddress != "203.0.113.10" {
		t.Errorf("bind address = %q, want this server's primary address", in.BindAddress)
	}
	if in.RouteProtocolID != model.RouteProtocolTCP || in.NatModeID != model.NatModeMasquerade {
		t.Errorf("the protocol and NAT defaults were not applied: %+v", in)
	}
	if in.LoadBalanceModeID != model.LoadBalanceModeNone {
		t.Errorf("load balance mode = %d, want None", in.LoadBalanceModeID)
	}
	if in.AddressFamilyID != model.AddressFamilyIPv4 {
		t.Errorf("address family = %d, want it derived from the addresses", in.AddressFamilyID)
	}
	if _, err := v.Validate(ctx, in); err != nil {
		t.Errorf("a rule with defaults applied does not validate: %v", err)
	}

	// An address the request did state is left alone, and so is a protocol.
	stated := RouteInput{
		RouteRuleTitle: "Stated", BindAddress: "0.0.0.0", BindPort: 2044,
		RouteProtocolID: model.RouteProtocolUDP, NatModeID: model.NatModeNone,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044, IsEnabled: true,
	}
	if err := v.ApplyDefaults(ctx, &stated); err != nil {
		t.Fatalf("ApplyDefaults returned an unexpected error: %v", err)
	}
	if stated.BindAddress != "0.0.0.0" || stated.RouteProtocolID != model.RouteProtocolUDP ||
		stated.NatModeID != model.NatModeNone {
		t.Errorf("a stated value was overwritten by a default: %+v", stated)
	}

	// A tunnel-bound rule gets MSS clamping, which is the whole reason the
	// default exists.
	tunnelID := int64(3)
	tunnelled := RouteInput{
		RouteRuleTitle: "Through the tunnel", BindPort: 2044, TunnelID: &tunnelID,
		DestinationAddress: "172.31.7.2", DestinationPort: 2044, IsEnabled: true,
	}
	if err := v.ApplyDefaults(ctx, &tunnelled); err != nil {
		t.Fatalf("ApplyDefaults returned an unexpected error: %v", err)
	}
	if !tunnelled.IsClampMssToPmtu {
		t.Error("a tunnel-bound rule did not get MSS clamping by default")
	}
}

// ---------------------------------------------------------------- rendering

// TestSpecCarriesEveryOptionToTheRuleLayer covers the single translation from
// a request to what reaches netfilter.
func TestSpecCarriesEveryOptionToTheRuleLayer(t *testing.T) {
	fwmark := int64(100)
	maxConns := int64(25)
	rate := int64(120)
	in := RouteInput{
		RouteRuleID: 7, RouteRuleTitle: "Relay",
		RouteProtocolID: model.RouteProtocolBoth,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 20000, BindPortRangeEnd: 20100,
		BindInterface:      "eth0",
		DestinationAddress: "198.51.100.20", DestinationPort: 30000, DestinationPortRangeEnd: 30100,
		NatModeID: model.NatModeSnat, SnatAddress: "203.0.113.10",
		LoadBalanceModeID: model.LoadBalanceModeWeighted,
		Destinations: []RouteDestinationInput{
			{Address: "198.51.100.20", Port: 30000, PortRangeEnd: 30100, Weight: 3, IsEnabled: true},
			{Address: "198.51.100.21", Port: 30000, PortRangeEnd: 30100, Weight: 1, IsEnabled: true},
			{Address: "198.51.100.22", Port: 30000, PortRangeEnd: 30100, Weight: 1, IsEnabled: false},
		},
		AllowedSources:           []RouteAllowedSourceInput{{Cidr: "10.0.0.0/8"}},
		IsClampMssToPmtu:         true,
		IsIncludeLocalOriginated: true,
		IsLoggingEnabled:         true,
		FwMark:                   &fwmark,
		MaxConnectionsPerSource:  &maxConns,
		ConnectionRateLimit:      &rate,
		SortOrder:                20,
	}

	spec := in.Spec()
	if spec.Protocol != rules.ProtocolBoth || spec.NatMode != rules.NatSnat ||
		spec.LoadBalance != rules.LoadBalanceWeighted || spec.Family != rules.FamilyIPv4 {
		t.Errorf("the vocabulary did not survive the translation: %+v", spec)
	}
	if spec.BindPorts.Port != 20000 || spec.BindPorts.End != 20100 {
		t.Errorf("the bind range did not survive: %+v", spec.BindPorts)
	}
	// The primary destination is not repeated, and a disabled one is not sent
	// traffic.
	if len(spec.Destinations) != 2 {
		t.Fatalf("got %d destinations, want the primary and the one enabled extra: %+v",
			len(spec.Destinations), spec.Destinations)
	}
	if spec.Destinations[0].Address != "198.51.100.20" || spec.Destinations[0].Weight != 3 {
		t.Errorf("the primary destination lost its weight: %+v", spec.Destinations[0])
	}
	if spec.FwMark == nil || *spec.FwMark != 100 {
		t.Errorf("the firewall mark did not survive: %+v", spec.FwMark)
	}
	if spec.MaxConnectionsPerSource != 25 || spec.ConnectionRateLimit != 120 {
		t.Errorf("the limits did not survive: %+v", spec)
	}
	if len(spec.AllowedSources) != 1 || spec.AllowedSources[0] != "10.0.0.0/8" {
		t.Errorf("the allowlist did not survive: %+v", spec.AllowedSources)
	}
	if !spec.ClampMssToPmtu || !spec.IncludeLocalOriginated || !spec.Logging {
		t.Errorf("the boolean options did not survive: %+v", spec)
	}
	if spec.SortOrder != 20 {
		t.Errorf("the sort order did not survive: %d", spec.SortOrder)
	}

	// And what survives has to be renderable, or validation has accepted
	// something the rule layer cannot express.
	if err := (rules.Ruleset{Routes: []rules.RouteSpec{spec}}).Check(); err != nil {
		t.Errorf("the translated rule cannot be rendered: %v", err)
	}
}

// TestValidationAndRenderingAgreeOnRangeWidths keeps the two layers' idea of a
// valid rule in step: anything validation accepts, rendering must be able to
// express.
func TestValidationAndRenderingAgreeOnRangeWidths(t *testing.T) {
	in := validRoute()
	in.RouteRuleID = 1
	in.BindPort, in.BindPortRangeEnd = 20000, 20100
	in.DestinationPort, in.DestinationPortRangeEnd = 30000, 30100

	if errs := ValidateRouteStatic(in); !errs.Empty() {
		t.Fatalf("a valid range was rejected: %v", errs)
	}
	if err := (rules.Ruleset{Routes: []rules.RouteSpec{in.Spec()}}).Check(); err != nil {
		t.Errorf("validation accepted a rule the renderer refuses: %v", err)
	}

	in.DestinationPortRangeEnd = 30050
	if errs := ValidateRouteStatic(in); errs.Empty() {
		t.Error("validation accepted a width mismatch the renderer refuses")
	}
}
