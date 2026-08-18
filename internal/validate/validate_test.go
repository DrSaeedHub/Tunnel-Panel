package validate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
)

// ---------------------------------------------------------------- test doubles

type fakeRepo struct {
	tunnels []ExistingTunnel
	pools   map[int64]Pool
}

func (r *fakeRepo) ExistingTunnels(ctx context.Context) ([]ExistingTunnel, error) {
	return r.tunnels, nil
}

func (r *fakeRepo) PoolByID(ctx context.Context, id int64) (Pool, error) {
	p, ok := r.pools[id]
	if !ok {
		return Pool{}, fmt.Errorf("no pool %d", id)
	}
	return p, nil
}

type fakeSettings map[string]any

func (s fakeSettings) Bool(key string) bool {
	v, ok := s[key]
	if !ok {
		// The declared defaults for the settings validation reads. A fake that
		// answers false for everything is not a neutral stand-in: it silently
		// turns off whichever behaviour the real schema has on by default.
		switch key {
		case "addressing.check_route_overlap", "tunnel.auto_mtu_from_underlay":
			return true
		}
		return false
	}
	b, _ := v.(bool)
	return b
}
func (s fakeSettings) Int(key string) int64 { n, _ := s[key].(int64); return n }
func (s fakeSettings) String(key string) string {
	str, _ := s[key].(string)
	return str
}

func i64(v int64) *int64 { return &v }

// validInput is a request that passes every rule against the default host, so a
// test can change exactly one field and see only that failure.
func validInput() TunnelInput {
	return TunnelInput{
		TunnelTypeID:      model.TunnelTypeGRE,
		TunnelSideID:      model.TunnelSideA,
		PersistenceTypeID: model.PersistenceTypeSystemd,
		InterfaceName:     "gre-a-1",
		LocalEndpoint:     "203.0.113.10",
		RemoteEndpoint:    "198.51.100.20",
		Ttl:               255,
		Tos:               "inherit",
		Mtu:               1472,
		IKey:              i64(2749365187),
		OKey:              i64(2749365187),
		Addresses: []AddressInput{
			{Address: "172.17.1.1", PrefixLength: 30, IsPrimary: true},
		},
		IsEnabled: true,
	}
}

func newValidator(t *testing.T, repo *fakeRepo, set fakeSettings) (*Validator, *link.Fake) {
	t.Helper()
	links := link.NewFakeWithHost()
	if repo == nil {
		repo = &fakeRepo{}
	}
	if set == nil {
		set = fakeSettings{}
	}
	return New(links, repo, set, "/api/v1/reconcile/adopt"), links
}

func mustValidate(t *testing.T, v *Validator, in TunnelInput) Result {
	t.Helper()
	res, err := v.Validate(context.Background(), in)
	if err != nil {
		t.Fatalf("validation rejected a valid request: %v", err)
	}
	return res
}

func expectCode(t *testing.T, err error, field, code string) {
	t.Helper()
	errs, ok := AsErrors(err)
	if !ok {
		t.Fatalf("error %v is not a field-level validation failure", err)
	}
	for _, f := range errs.Fields {
		if f.Field == field && f.Code == code {
			return
		}
	}
	t.Fatalf("no %s failure on %q; got %+v", code, field, errs.Fields)
}

// ------------------------------------------------------------------- §7.1 name

func TestInterfaceNameRules(t *testing.T) {
	valid := []string{"gre-a-1", "gre0x", "a", "tun.1", "A_b-c.9", "abcdefghijklmno"}
	for _, name := range valid {
		if err := InterfaceName(name); err != nil {
			t.Fatalf("%q should be a valid interface name: %v", name, err)
		}
	}

	invalid := map[string]string{
		"":                 "empty",
		".":                "single dot",
		"..":               "double dot",
		"a/b":              "slash",
		"a b":              "space",
		"a\tb":             "tab",
		"abcdefghijklmnop": "sixteen characters",
		"-lead":            "leading dash",
		".lead":            "leading dot",
		"_lead":            "leading underscore",
		"gre$1":            "dollar sign",
	}
	for name, why := range invalid {
		if err := InterfaceName(name); err == nil {
			t.Fatalf("%q (%s) should be rejected", name, why)
		}
	}
}

func TestReservedInterfaceNamesAreRefused(t *testing.T) {
	for _, name := range []string{"gre0", "gretap0", "erspan0", "ip6gre0", "lo"} {
		in := validInput()
		in.InterfaceName = name
		errs := ValidateStatic(in)
		if errs.Empty() {
			t.Fatalf("%q was accepted; it is a device the kernel owns", name)
		}
		found := false
		for _, f := range errs.Fields {
			if f.Code == CodeNameReserved || f.Code == CodeInvalidName {
				found = true
			}
		}
		if !found {
			t.Fatalf("%q was rejected for the wrong reason: %+v", name, errs.Fields)
		}
	}
}

func TestNameCollidingWithAPhysicalInterfaceIsRefused(t *testing.T) {
	v, _ := newValidator(t, nil, nil)
	in := validInput()
	in.InterfaceName = "eth0"
	_, err := v.Validate(context.Background(), in)
	expectCode(t, err, "interface_name", CodeNameConflict)
}

func TestNameCollidingWithAStoredTunnelIsRefused(t *testing.T) {
	repo := &fakeRepo{tunnels: []ExistingTunnel{{
		TunnelID: 9, InterfaceName: "gre-a-1",
		LocalEndpoint: "203.0.113.10", RemoteEndpoint: "192.0.2.99",
	}}}
	v, _ := newValidator(t, repo, nil)
	_, err := v.Validate(context.Background(), validInput())
	expectCode(t, err, "interface_name", CodeNameConflict)
}

// ------------------------------------------------------------- §7.2 endpoints

// This is the legacy script's worst defect, stated as a test: `not-an-ip` must
// fail validation before anything reads or touches the kernel.
func TestNotAnIpFailsBeforeAnyKernelCall(t *testing.T) {
	v, links := newValidator(t, nil, nil)

	in := validInput()
	in.LocalEndpoint = "not-an-ip"

	_, err := v.Validate(context.Background(), in)
	if err == nil {
		t.Fatal("a request with LocalEndpoint = \"not-an-ip\" was accepted")
	}
	expectCode(t, err, "local_endpoint", CodeInvalidEndpoint)

	if calls := links.Calls(); len(calls) != 0 {
		t.Fatalf("the kernel was changed during a failed validation: %v", calls)
	}
	if reads := links.ReadCalls(); reads != 0 {
		t.Fatalf("kernel state was read %d times before the input was rejected; "+
			"a malformed endpoint must fail before any kernel call", reads)
	}
}

func TestEndpointRejectionRules(t *testing.T) {
	cases := []struct {
		endpoint string
		why      string
	}{
		{"not-an-ip", "unparseable"},
		{"", "empty"},
		{"0.0.0.0", "unspecified"},
		{"127.0.0.1", "loopback"},
		{"224.0.0.1", "multicast"},
		{"255.255.255.255", "broadcast"},
		{"240.0.0.1", "reserved"},
		{"0.1.2.3", "this network"},
		{"169.254.1.1", "link-local without a bind device"},
		{"203.0.113.10/24", "carries a prefix length"},
		{" ", "whitespace"},
	}
	for _, tc := range cases {
		in := validInput()
		in.RemoteEndpoint = tc.endpoint
		errs := ValidateStatic(in)
		if errs.Empty() {
			t.Fatalf("%q (%s) was accepted as a remote endpoint", tc.endpoint, tc.why)
		}
		if !errs.Has("remote_endpoint") {
			t.Fatalf("%q was rejected but not against remote_endpoint: %+v", tc.endpoint, errs.Fields)
		}
	}
}

func TestLinkLocalEndpointIsAcceptedWithABindDevice(t *testing.T) {
	in := validInput()
	in.RemoteEndpoint = "169.254.1.1"
	in.BindDevice = "eth0"
	if errs := ValidateStatic(in); !errs.Empty() {
		t.Fatalf("a link-local endpoint with a bind device was refused: %+v", errs.Fields)
	}
}

func TestEndpointFamilyMustMatchTheTunnelType(t *testing.T) {
	in := validInput()
	in.TunnelTypeID = model.TunnelTypeIP6GRE
	errs := ValidateStatic(in)
	if errs.Empty() {
		t.Fatal("IPv4 endpoints on an IPv6 tunnel type were accepted")
	}
	for _, f := range errs.Fields {
		if f.Code == CodeEndpointFamily {
			return
		}
	}
	t.Fatalf("the family mismatch was not reported: %+v", errs.Fields)
}

func TestIPv6TunnelTypeAcceptsIPv6Endpoints(t *testing.T) {
	in := validInput()
	in.TunnelTypeID = model.TunnelTypeIP6GRE
	in.LocalEndpoint = "2001:db8::1"
	in.RemoteEndpoint = "2001:db8::2"
	in.Addresses = []AddressInput{{Address: "fd00::1", PrefixLength: 127}}
	if errs := ValidateStatic(in); !errs.Empty() {
		t.Fatalf("a valid IPv6 tunnel was refused: %+v", errs.Fields)
	}
}

func TestIdenticalEndpointsAreRefused(t *testing.T) {
	in := validInput()
	in.RemoteEndpoint = in.LocalEndpoint
	errs := ValidateStatic(in)
	for _, f := range errs.Fields {
		if f.Code == CodeEndpointsIdentical {
			return
		}
	}
	t.Fatalf("identical endpoints were accepted: %+v", errs.Fields)
}

func TestLocalEndpointNotOnThisHostNeedsForce(t *testing.T) {
	v, _ := newValidator(t, nil, nil)

	in := validInput()
	in.LocalEndpoint = "192.0.2.77" // syntactically fine, not on the host
	_, err := v.Validate(context.Background(), in)
	expectCode(t, err, "local_endpoint", CodeInvalidEndpoint)

	in.Force = true
	res := mustValidate(t, v, in)
	if !hasWarning(res, WarnLocalEndpointNotFound) {
		t.Fatalf("forcing must keep the warning: %+v", res.Warnings)
	}
}

// --------------------------------------------------------------- §7.3 numbers

func TestNumericBounds(t *testing.T) {
	cases := []struct {
		name  string
		field string
		mut   func(*TunnelInput)
	}{
		{"mtu below the minimum", "mtu", func(in *TunnelInput) { in.Mtu = 575 }},
		{"mtu above the maximum", "mtu", func(in *TunnelInput) { in.Mtu = 9217 }},
		{"negative ttl", "ttl", func(in *TunnelInput) { in.Ttl = -1 }},
		{"ttl above 255", "ttl", func(in *TunnelInput) { in.Ttl = 256 }},
		{"key above the 32-bit maximum", "ikey", func(in *TunnelInput) { in.IKey = i64(4294967296) }},
		{"negative key", "okey", func(in *TunnelInput) { in.OKey = i64(-1) }},
		{"firewall mark out of range", "fwmark", func(in *TunnelInput) { in.FwMark = i64(4294967296) }},
		{"tunnel number above 65535", "tunnel_number", func(in *TunnelInput) { in.TunnelNumber = i64(65536) }},
		{"hop limit out of range", "hop_limit", func(in *TunnelInput) { in.HopLimit = i64(256) }},
		{"type of service nonsense", "tos", func(in *TunnelInput) { in.Tos = "banana" }},
	}
	for _, tc := range cases {
		in := validInput()
		tc.mut(&in)
		errs := ValidateStatic(in)
		if !errs.Has(tc.field) {
			t.Fatalf("%s was accepted: %+v", tc.name, errs.Fields)
		}
	}
}

// The legacy script could not exceed 255 tunnels because it welded the number
// to the third octet. That is a property of an addressing scheme, not of
// tunnels, so the general rule accepts the full range.
func TestTunnelNumberIsNotCappedAt255(t *testing.T) {
	in := validInput()
	in.TunnelNumber = i64(4000)
	if errs := ValidateStatic(in); errs.Has("tunnel_number") {
		t.Fatalf("tunnel number 4000 was refused: %+v", errs.Fields)
	}
}

func TestBoundaryValuesAreAccepted(t *testing.T) {
	in := validInput()
	in.Mtu = MinMtu
	in.Ttl = 0
	in.IKey = i64(0)
	in.OKey = i64(MaxGreKey)
	in.FwMark = i64(0)
	in.TunnelNumber = i64(0)
	if errs := ValidateStatic(in); !errs.Empty() {
		t.Fatalf("boundary values were refused: %+v", errs.Fields)
	}
}

// ------------------------------------------------------------- §7.4 addresses

func TestAddressSyntaxRules(t *testing.T) {
	cases := []struct {
		address string
		prefix  int
		why     string
	}{
		{"not-an-ip", 30, "unparseable"},
		{"172.17.1.1", 33, "prefix length above 32"},
		{"172.17.1.1", -1, "negative prefix length"},
		{"fd00::1", 129, "prefix length above 128"},
		{"224.0.0.1", 30, "multicast"},
		{"172.17.1.1", 32, "/32 with no peer"},
	}
	for _, tc := range cases {
		in := validInput()
		in.Addresses = []AddressInput{{Address: tc.address, PrefixLength: tc.prefix}}
		errs := ValidateStatic(in)
		if errs.Empty() {
			t.Fatalf("%s/%d (%s) was accepted", tc.address, tc.prefix, tc.why)
		}
	}
}

// RFC 3021 /31 point-to-point addressing must be supported; a tunnel is exactly
// the case it was written for.
func TestSlash31IsSupported(t *testing.T) {
	in := validInput()
	in.Addresses = []AddressInput{{Address: "172.17.1.0", PrefixLength: 31}}
	if errs := ValidateStatic(in); !errs.Empty() {
		t.Fatalf("a /31 address was refused: %+v", errs.Fields)
	}

	v, _ := newValidator(t, nil, nil)
	if _, err := v.Validate(context.Background(), in); err != nil {
		t.Fatalf("a /31 address was refused against live state: %v", err)
	}
}

func TestSlash32WithAPeerIsAccepted(t *testing.T) {
	in := validInput()
	in.Addresses = []AddressInput{{Address: "172.17.1.1", PrefixLength: 32, PeerAddress: "172.17.1.2"}}
	if errs := ValidateStatic(in); !errs.Empty() {
		t.Fatalf("a /32 address with a peer was refused: %+v", errs.Fields)
	}
}

func TestDuplicateAddressOnTheSameRequestIsRefused(t *testing.T) {
	in := validInput()
	in.Addresses = append(in.Addresses, AddressInput{Address: "172.17.1.1", PrefixLength: 30})
	errs := ValidateStatic(in)
	for _, f := range errs.Fields {
		if f.Code == CodeAddressConflict {
			return
		}
	}
	t.Fatalf("a repeated address was accepted: %+v", errs.Fields)
}

func TestAddressAlreadyOnAnotherInterfaceIsRefused(t *testing.T) {
	v, links := newValidator(t, nil, nil)
	links.AddLink(link.Link{
		Name: "gre-b-9", Kind: link.KindGRE, Index: 7,
		Addresses: []link.Address{{Address: "172.17.1.1", PrefixLength: 30, Family: link.FamilyIPv4}},
	})
	_, err := v.Validate(context.Background(), validInput())
	expectCode(t, err, "addresses.0.address", CodeAddressConflict)
}

func TestPublicRangeIsRefusedUnlessAllowedOrForced(t *testing.T) {
	in := validInput()
	in.Addresses = []AddressInput{{Address: "109.194.7.1", PrefixLength: 30}}

	v, _ := newValidator(t, nil, nil)
	_, err := v.Validate(context.Background(), in)
	expectCode(t, err, "addresses.0.address", CodePublicRange)

	// Forcing keeps the warning rather than hiding the problem.
	forced := in
	forced.Force = true
	res := mustValidate(t, v, forced)
	if !hasWarning(res, WarnPublicRange) {
		t.Fatalf("forcing a public range must still warn: %+v", res.Warnings)
	}

	allowed, _ := newValidator(t, nil, fakeSettings{"addressing.allow_public_ranges": true})
	res = mustValidate(t, allowed, in)
	if !hasWarning(res, WarnPublicRange) {
		t.Fatalf("allowing public ranges must still warn: %+v", res.Warnings)
	}
}

func TestPrivateRangesAreNotFlaggedPublic(t *testing.T) {
	for _, address := range []string{"10.0.0.1", "172.17.1.1", "192.168.1.1", "100.64.0.1", "fd00::1"} {
		in := validInput()
		in.Addresses = []AddressInput{{Address: address, PrefixLength: 30}}
		if address == "fd00::1" {
			in.Addresses[0].PrefixLength = 127
		}
		v, _ := newValidator(t, nil, nil)
		res, err := v.Validate(context.Background(), in)
		if err != nil {
			t.Fatalf("%s was refused: %v", address, err)
		}
		if hasWarning(res, WarnPublicRange) {
			t.Fatalf("%s was flagged as a public range", address)
		}
	}
}

func TestRouteOverlapIsRefusedUnlessForced(t *testing.T) {
	v, links := newValidator(t, nil, nil)
	links.SetRoutes([]link.Route{
		{Destination: "default", Gateway: "203.0.113.1", Device: "eth0", IsDefault: true},
		{Destination: "172.17.0.0/16", Device: "eth0"},
	})

	_, err := v.Validate(context.Background(), validInput())
	expectCode(t, err, "addresses.0.address", CodeRouteOverlap)

	forced := validInput()
	forced.Force = true
	res := mustValidate(t, v, forced)
	if !hasWarning(res, WarnRouteOverlap) {
		t.Fatalf("forcing an overlap must still warn: %+v", res.Warnings)
	}

	// With the check disabled the overlap is neither an error nor a warning.
	off, offLinks := newValidator(t, nil, fakeSettings{"addressing.check_route_overlap": false})
	offLinks.SetRoutes([]link.Route{
		{Destination: "default", Gateway: "203.0.113.1", Device: "eth0", IsDefault: true},
		{Destination: "172.17.0.0/16", Device: "eth0"},
	})
	if _, err := off.Validate(context.Background(), validInput()); err != nil {
		t.Fatalf("with the overlap check off the request must pass: %v", err)
	}
}

// ------------------------------------------------------------- §7.5 conflicts

func TestDuplicateEndpointAndKeyTupleIsRefusedInEitherDirection(t *testing.T) {
	base := validInput()

	forward := &fakeRepo{tunnels: []ExistingTunnel{{
		TunnelID: 3, InterfaceName: "gre-a-9",
		LocalEndpoint: base.LocalEndpoint, RemoteEndpoint: base.RemoteEndpoint,
		IKey: i64(2749365187), OKey: i64(2749365187),
	}}}
	v, _ := newValidator(t, forward, nil)
	_, err := v.Validate(context.Background(), base)
	expectCode(t, err, "remote_endpoint", CodeEndpointConflict)

	// Swapped endpoints are the same kernel-level tuple.
	reversed := &fakeRepo{tunnels: []ExistingTunnel{{
		TunnelID: 4, InterfaceName: "gre-b-9",
		LocalEndpoint: base.RemoteEndpoint, RemoteEndpoint: base.LocalEndpoint,
		IKey: i64(2749365187), OKey: i64(2749365187),
	}}}
	v, _ = newValidator(t, reversed, nil)
	_, err = v.Validate(context.Background(), base)
	expectCode(t, err, "remote_endpoint", CodeEndpointConflict)

	// A different key makes it a different tunnel, which the kernel allows.
	other := &fakeRepo{tunnels: []ExistingTunnel{{
		TunnelID: 5, InterfaceName: "gre-a-8",
		LocalEndpoint: base.LocalEndpoint, RemoteEndpoint: base.RemoteEndpoint,
		IKey: i64(11), OKey: i64(11),
	}}}
	v, _ = newValidator(t, other, nil)
	if _, err := v.Validate(context.Background(), base); err != nil {
		t.Fatalf("a differing key must not collide: %v", err)
	}
}

func TestUpdateDoesNotConflictWithItself(t *testing.T) {
	repo := &fakeRepo{tunnels: []ExistingTunnel{{
		TunnelID: 7, InterfaceName: "gre-a-1",
		LocalEndpoint: "203.0.113.10", RemoteEndpoint: "198.51.100.20",
		IKey: i64(2749365187), OKey: i64(2749365187),
		Addresses: []AddressInput{{Address: "172.17.1.1", PrefixLength: 30}},
	}}}
	v, _ := newValidator(t, repo, nil)

	in := validInput()
	in.TunnelID = 7
	in.Mtu = 1400
	if _, err := v.Validate(context.Background(), in); err != nil {
		t.Fatalf("updating a tunnel conflicted with itself: %v", err)
	}
}

// An interface that already exists and is a tunnel is not a naming problem to
// be worked around; it is a candidate for adoption (§7.5, §12).
func TestExistingUnmanagedTunnelIsReportedAsAdoptable(t *testing.T) {
	v, links := newValidator(t, nil, nil)
	key := uint32(2749365187)
	links.AddLink(link.Link{
		Name: "gre-a-1", Kind: link.KindGRE, Index: 8, MTU: 1472,
		OperState: "UNKNOWN", IsUp: true, IsLowerUp: true,
		Tunnel: &link.TunnelAttrs{
			Local: "203.0.113.10", Remote: "198.51.100.20", Ttl: 255,
			IKey: &key, OKey: &key,
		},
		Addresses: []link.Address{{Address: "172.17.1.1", PrefixLength: 30, Family: link.FamilyIPv4}},
	})

	_, err := v.Validate(context.Background(), validInput())
	adoptable, ok := AsAdoptable(err)
	if !ok {
		t.Fatalf("error %v is not an adoption suggestion", err)
	}
	if adoptable.InterfaceName != "gre-a-1" {
		t.Fatalf("adoptable interface = %q", adoptable.InterfaceName)
	}
	if adoptable.AdoptPath == "" {
		t.Fatal("the adoption suggestion must point at the adoption endpoint")
	}
	if adoptable.Observed["local_endpoint"] != "203.0.113.10" {
		t.Fatalf("the observed parameters were not reported: %+v", adoptable.Observed)
	}
}

func TestUnmanagedTunnelWithTheSameTupleIsReported(t *testing.T) {
	v, links := newValidator(t, nil, nil)
	key := uint32(2749365187)
	links.AddLink(link.Link{
		Name: "gre-legacy", Kind: link.KindGRE, Index: 8,
		Tunnel: &link.TunnelAttrs{
			Local: "203.0.113.10", Remote: "198.51.100.20", IKey: &key, OKey: &key,
		},
	})
	_, err := v.Validate(context.Background(), validInput())
	expectCode(t, err, "remote_endpoint", CodeEndpointConflict)
}

func TestUnknownPoolIsRefused(t *testing.T) {
	repo := &fakeRepo{pools: map[int64]Pool{
		1: {AddressPoolID: 1, Title: "Disabled", Cidr: "10.10.0.0/16", PrefixLength: 30, IsEnabled: false},
	}}
	v, _ := newValidator(t, repo, nil)

	in := validInput()
	in.AddressPoolID = i64(99)
	_, err := v.Validate(context.Background(), in)
	expectCode(t, err, "address_pool_id", CodeUnknownPool)

	in.AddressPoolID = i64(1)
	_, err = v.Validate(context.Background(), in)
	expectCode(t, err, "address_pool_id", CodeUnknownPool)
}

// ------------------------------------------------------------------ §7.6 MTU

func TestOverheadAcrossEveryCombination(t *testing.T) {
	cases := []struct {
		kind     string
		key      bool
		csum     bool
		seq      bool
		expected int
	}{
		// IPv4: outer 20 + GRE base 4, plus 4 per optional field.
		{link.KindGRE, false, false, false, 24},
		{link.KindGRE, true, false, false, 28},
		{link.KindGRE, false, true, false, 28},
		{link.KindGRE, false, false, true, 28},
		{link.KindGRE, true, true, false, 32},
		{link.KindGRE, true, false, true, 32},
		{link.KindGRE, false, true, true, 32},
		{link.KindGRE, true, true, true, 36},
		{link.KindGRETAP, true, false, false, 28},
		// IPv6: outer 40 instead of 20.
		{link.KindIP6GRE, false, false, false, 44},
		{link.KindIP6GRE, true, false, false, 48},
		{link.KindIP6GRE, true, true, false, 52},
		{link.KindIP6GRE, true, true, true, 56},
		{link.KindIP6GRETAP, true, true, true, 56},
	}
	for _, tc := range cases {
		got := Overhead(OverheadInput{Kind: tc.kind, HasKey: tc.key, Checksum: tc.csum, Sequence: tc.seq})
		if got != tc.expected {
			t.Fatalf("overhead(%s key=%v csum=%v seq=%v) = %d, want %d",
				tc.kind, tc.key, tc.csum, tc.seq, got, tc.expected)
		}
	}
}

// The documented case: IPv4 GRE with a key over a 1500-byte underlay gives
// 1472, which is what the legacy script used and is correct.
func TestMtuRecommendationMatchesTheDocumentedCase(t *testing.T) {
	in := validInput()
	advice := AdviseMtu(in, "eth0", 1500)
	if advice.Overhead != 28 {
		t.Fatalf("overhead = %d, want 28", advice.Overhead)
	}
	if advice.Recommended != 1472 {
		t.Fatalf("recommended MTU = %d, want 1472", advice.Recommended)
	}
	if !advice.Matches {
		t.Fatal("the default MTU of 1472 must match the recommendation")
	}
	if _, ok := advice.Warning(); ok {
		t.Fatal("a matching MTU must not warn")
	}
}

func TestMtuMismatchWarnsButDoesNotOverride(t *testing.T) {
	v, _ := newValidator(t, nil, nil)
	in := validInput()
	in.Mtu = 1400

	res := mustValidate(t, v, in)
	if res.Mtu.Requested != 1400 {
		t.Fatalf("the operator's choice was changed to %d", res.Mtu.Requested)
	}
	if res.Mtu.Recommended != 1472 {
		t.Fatalf("recommended = %d, want 1472", res.Mtu.Recommended)
	}
	if !hasWarning(res, WarnMtuAdvisory) {
		t.Fatalf("a mismatched MTU must warn: %+v", res.Warnings)
	}
}

func TestMtuBreakdownExplainsEveryTerm(t *testing.T) {
	in := validInput()
	in.HasOutputChecksum = true
	in.HasOutputSequence = true
	advice := AdviseMtu(in, "eth0", 1500)
	if advice.Overhead != 36 || advice.Recommended != 1464 {
		t.Fatalf("advice = %+v", advice)
	}
	if len(advice.Breakdown) != 5 {
		t.Fatalf("breakdown = %+v", advice.Breakdown)
	}
	total := 0
	for _, term := range advice.Breakdown {
		total += term.Bytes
	}
	if total != advice.Overhead {
		t.Fatalf("the breakdown sums to %d but the overhead is %d", total, advice.Overhead)
	}
}

// ----------------------------------------------------------- key conversion

func TestGreKeyConversionThroughValidate(t *testing.T) {
	if got := GreKeyToDotted(2749365187); got != "163.223.251.195" {
		t.Fatalf("GreKeyToDotted(2749365187) = %q, want 163.223.251.195", got)
	}
	got, err := GreKeyFromDotted("163.223.251.195")
	if err != nil || got != 2749365187 {
		t.Fatalf("GreKeyFromDotted = %d, %v", got, err)
	}
	if FormatGreKey(i64(2749365187)) != "2749365187" {
		t.Fatal("a key must always be presented to the operator as an integer")
	}
	if FormatGreKey(nil) != "none" {
		t.Fatal("an absent key must be reported as none")
	}
}

// The kernel names in internal/model must stay in step with those in
// internal/link, which are declared separately to avoid an import cycle.
func TestTunnelTypeKindsMatchTheLinkLayer(t *testing.T) {
	pairs := map[int64]string{
		model.TunnelTypeGRE:       link.KindGRE,
		model.TunnelTypeGRETAP:    link.KindGRETAP,
		model.TunnelTypeIP6GRE:    link.KindIP6GRE,
		model.TunnelTypeIP6GRETAP: link.KindIP6GRETAP,
	}
	for id, kind := range pairs {
		if model.TunnelTypeKind(id) != kind {
			t.Fatalf("model.TunnelTypeKind(%d) = %q, want %q", id, model.TunnelTypeKind(id), kind)
		}
		back, ok := model.TunnelTypeForKind(kind)
		if !ok || back != id {
			t.Fatalf("model.TunnelTypeForKind(%q) = %d, %v", kind, back, ok)
		}
	}
	if model.IsIPv6TunnelType(model.TunnelTypeGRE) || !model.IsIPv6TunnelType(model.TunnelTypeIP6GRE) {
		t.Fatal("IPv6 tunnel types were classified wrongly")
	}
}

// --------------------------------------------------------------- error shape

func TestErrorsReportEveryFailureAtOnce(t *testing.T) {
	in := validInput()
	in.InterfaceName = "this-name-is-far-too-long"
	in.LocalEndpoint = "nope"
	in.Mtu = 10
	errs := ValidateStatic(in)

	if len(errs.Fields) < 3 {
		t.Fatalf("validation stopped early; got %+v", errs.Fields)
	}
	for _, field := range []string{"interface_name", "local_endpoint", "mtu"} {
		if !errs.Has(field) {
			t.Fatalf("%s was not reported: %+v", field, errs.Fields)
		}
	}
	if err := errs.OrNil(); err == nil {
		t.Fatal("OrNil must return an error when fields were rejected")
	}
	if err := (&Errors{}).OrNil(); err != nil {
		t.Fatalf("OrNil on an empty collection must be nil, got %v (%T)", err, err)
	}
	if !strings.Contains(errs.Error(), "3 fields are invalid") {
		t.Fatalf("error summary = %q", errs.Error())
	}
}

func TestValidRequestPasses(t *testing.T) {
	v, _ := newValidator(t, nil, nil)
	res := mustValidate(t, v, validInput())
	if res.Mtu.Recommended != 1472 {
		t.Fatalf("mtu advice = %+v", res.Mtu)
	}
	// The shipped default key is the one the legacy script gave every user, so
	// it always warns.
	if !hasWarning(res, WarnLegacyDefaultKey) {
		t.Fatalf("the legacy default key must warn: %+v", res.Warnings)
	}
}

func TestRuntimePersistenceWarnsThatItDoesNotSurviveAReboot(t *testing.T) {
	v, _ := newValidator(t, nil, nil)
	in := validInput()
	in.PersistenceTypeID = model.PersistenceTypeRuntime
	res := mustValidate(t, v, in)
	if !hasWarning(res, WarnRuntimeOnly) {
		t.Fatalf("runtime persistence must warn: %+v", res.Warnings)
	}
}

func TestAsErrorsRejectsOtherErrors(t *testing.T) {
	if _, ok := AsErrors(errors.New("boom")); ok {
		t.Fatal("an unrelated error was reported as a validation failure")
	}
	if _, ok := AsAdoptable(errors.New("boom")); ok {
		t.Fatal("an unrelated error was reported as an adoption suggestion")
	}
}

func hasWarning(res Result, code string) bool {
	for _, w := range res.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}
