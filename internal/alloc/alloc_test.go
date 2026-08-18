package alloc

import (
	"context"
	"net/netip"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

func defaultPool() Pool {
	return Pool{
		AddressPoolID: 10, Title: "Private 172.17.0.0/16",
		Cidr: "172.17.0.0/16", PrefixLength: 30, IsEnabled: true,
	}
}

// The legacy script put the tunnel number in the third octet, and tunnels it
// created still exist, so the default pool must keep producing the same
// subnets: tunnel 7 is 172.17.7.0/30 with .1 and .2 as the two ends.
func TestThirdOctetSchemeMatchesTheLegacyLayout(t *testing.T) {
	prefix := netip.MustParsePrefix("172.17.0.0/16")
	if got := SchemeFor(prefix, 30); got != SchemeOctet {
		t.Fatalf("scheme = %q, want %q", got, SchemeOctet)
	}

	subnet, err := SubnetForNumber(prefix, 30, 7)
	if err != nil {
		t.Fatalf("subnet for 7 failed: %v", err)
	}
	if subnet.String() != "172.17.7.0/30" {
		t.Fatalf("subnet = %s, want 172.17.7.0/30", subnet)
	}

	a, b, err := SlotAddresses(subnet)
	if err != nil {
		t.Fatalf("slot addresses failed: %v", err)
	}
	if a.String() != "172.17.7.1" || b.String() != "172.17.7.2" {
		t.Fatalf("slot addresses = %s, %s; want 172.17.7.1, 172.17.7.2", a, b)
	}

	number, ok := NumberForSubnet(prefix, subnet)
	if !ok || number != 7 {
		t.Fatalf("reverse mapping = %d, %v; want 7", number, ok)
	}
}

// The ceiling of 255 belongs to that addressing scheme, not to tunnels: it is
// derived from the pool rather than hardcoded.
func TestCapacityComesFromThePool(t *testing.T) {
	cases := []struct {
		cidr      string
		prefixLen int
		scheme    Scheme
		capacity  int64
	}{
		{"172.17.0.0/16", 30, SchemeOctet, 256},
		{"10.10.0.0/16", 30, SchemeOctet, 256},
		{"10.0.0.0/8", 30, SchemeOctet, 65536},
		{"192.168.10.0/24", 30, SchemeDense, 64},
		{"192.168.10.0/24", 31, SchemeDense, 128},
		{"172.17.0.0/16", 31, SchemeOctet, 256},
		{"fd00::/64", 127, SchemeDense, 1 << 24},
	}
	for _, tc := range cases {
		prefix := netip.MustParsePrefix(tc.cidr)
		if got := SchemeFor(prefix, tc.prefixLen); got != tc.scheme {
			t.Fatalf("%s /%d scheme = %q, want %q", tc.cidr, tc.prefixLen, got, tc.scheme)
		}
		got, err := Capacity(prefix, tc.prefixLen)
		if err != nil {
			t.Fatalf("%s /%d capacity failed: %v", tc.cidr, tc.prefixLen, err)
		}
		if got != tc.capacity {
			t.Fatalf("%s /%d capacity = %d, want %d", tc.cidr, tc.prefixLen, got, tc.capacity)
		}
	}
}

func TestDenseSchemePacksSubnetsConsecutively(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.10.0/24")
	expected := []string{"192.168.10.0/30", "192.168.10.4/30", "192.168.10.8/30"}
	for i, want := range expected {
		subnet, err := SubnetForNumber(prefix, 30, int64(i))
		if err != nil {
			t.Fatalf("subnet %d failed: %v", i, err)
		}
		if subnet.String() != want {
			t.Fatalf("subnet %d = %s, want %s", i, subnet, want)
		}
	}
}

func TestNumberOutsideThePoolIsRefused(t *testing.T) {
	prefix := netip.MustParsePrefix("172.17.0.0/16")
	if _, err := SubnetForNumber(prefix, 30, 256); err == nil {
		t.Fatal("tunnel number 256 does not fit a /16 with the third-octet scheme")
	}
	if _, err := SubnetForNumber(prefix, 30, -1); err == nil {
		t.Fatal("a negative tunnel number was accepted")
	}
	if max, err := MaxNumber(prefix, 30); err != nil || max != 255 {
		t.Fatalf("max number = %d, %v; want 255", max, err)
	}
}

// RFC 3021: on a /31 both addresses are usable, which is exactly the
// point-to-point case a tunnel is.
func TestSlash31UsesBothAddresses(t *testing.T) {
	subnet := netip.MustParsePrefix("172.17.7.0/31")
	a, b, err := SlotAddresses(subnet)
	if err != nil {
		t.Fatalf("slot addresses failed: %v", err)
	}
	if a.String() != "172.17.7.0" || b.String() != "172.17.7.1" {
		t.Fatalf("addresses = %s, %s; want 172.17.7.0, 172.17.7.1", a, b)
	}
}

func TestIPv6SlotAddresses(t *testing.T) {
	if a, b, err := SlotAddresses(netip.MustParsePrefix("fd00::/127")); err != nil ||
		a.String() != "fd00::" || b.String() != "fd00::1" {
		t.Fatalf("/127 addresses = %s, %s, %v", a, b, err)
	}
	if a, b, err := SlotAddresses(netip.MustParsePrefix("fd00::/126")); err != nil ||
		a.String() != "fd00::1" || b.String() != "fd00::2" {
		t.Fatalf("/126 addresses = %s, %s, %v", a, b, err)
	}
}

// The slot decides which of the two addresses this server takes, and nothing
// else about the tunnel.
func TestAddressForSideMirrors(t *testing.T) {
	subnet := netip.MustParsePrefix("172.17.7.0/30")

	own, peer, err := AddressForSide(subnet, model.TunnelSideA)
	if err != nil || own.String() != "172.17.7.1" || peer.String() != "172.17.7.2" {
		t.Fatalf("slot A = %s/%s, %v", own, peer, err)
	}
	own, peer, err = AddressForSide(subnet, model.TunnelSideB)
	if err != nil || own.String() != "172.17.7.2" || peer.String() != "172.17.7.1" {
		t.Fatalf("slot B = %s/%s, %v", own, peer, err)
	}
}

func TestBadShapesAreRefused(t *testing.T) {
	cases := []struct {
		cidr      string
		prefixLen int
		why       string
	}{
		{"172.17.0.0/16", 8, "subnet larger than the pool"},
		{"172.17.0.0/16", 32, "a /32 cannot hold two addresses"},
		{"172.17.0.0/16", 33, "out of range for IPv4"},
		{"fd00::/64", 128, "a /128 cannot hold two addresses"},
	}
	for _, tc := range cases {
		if _, err := Capacity(netip.MustParsePrefix(tc.cidr), tc.prefixLen); err == nil {
			t.Fatalf("%s /%d (%s) was accepted", tc.cidr, tc.prefixLen, tc.why)
		}
	}
}

func TestNextFreeSkipsUsedSubnets(t *testing.T) {
	pool := defaultPool()
	used := map[netip.Addr]bool{
		netip.MustParseAddr("172.17.1.1"): true,
		netip.MustParseAddr("172.17.2.2"): true,
	}
	allocation, err := NextFreeIn(pool, 30, used)
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	if allocation.TunnelNumber != 3 || allocation.Subnet != "172.17.3.0/30" {
		t.Fatalf("allocation = %+v; want tunnel 3 on 172.17.3.0/30", allocation)
	}
	if allocation.AddressA != "172.17.3.1" || allocation.AddressB != "172.17.3.2" {
		t.Fatalf("addresses = %s, %s", allocation.AddressA, allocation.AddressB)
	}
	if allocation.IsPublicRange {
		t.Fatal("an RFC 1918 pool must not be flagged as a public range")
	}
	if allocation.OwnAddress(model.TunnelSideB) != "172.17.3.2" {
		t.Fatal("slot B must take the second address")
	}
	if allocation.PeerAddress(model.TunnelSideB) != "172.17.3.1" {
		t.Fatal("slot B's peer must be the first address")
	}
}

// Numbering starts at 1 under the third-octet scheme so the first subnet does
// not look like the pool's own network, which is what the legacy script did.
func TestNextFreeStartsAtOneForTheOctetScheme(t *testing.T) {
	allocation, err := NextFreeIn(defaultPool(), 30, map[netip.Addr]bool{})
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	if allocation.TunnelNumber != 1 || allocation.Subnet != "172.17.1.0/30" {
		t.Fatalf("first allocation = %+v", allocation)
	}
}

func TestExhaustedPoolIsReported(t *testing.T) {
	pool := Pool{AddressPoolID: 1, Title: "Tiny", Cidr: "192.168.10.0/29", PrefixLength: 30, IsEnabled: true}
	used := map[netip.Addr]bool{
		netip.MustParseAddr("192.168.10.1"): true,
		netip.MustParseAddr("192.168.10.5"): true,
	}
	if _, err := NextFreeIn(pool, 30, used); err == nil {
		t.Fatal("an exhausted pool must be reported rather than wrapping around")
	}
}

func TestPublicPoolCarriesAWarning(t *testing.T) {
	pool := Pool{
		AddressPoolID: 30, Title: "Legacy 109.194.0.0/16", Cidr: "109.194.0.0/16",
		PrefixLength: 30, IsPublicRange: true, IsEnabled: true,
	}
	allocation, err := NextFreeIn(pool, 30, map[netip.Addr]bool{})
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	if !allocation.IsPublicRange {
		t.Fatal("a globally routable pool must be detected, not merely declared")
	}
	if len(allocation.Warnings) != 1 || allocation.Warnings[0].Code != validate.WarnPublicRange {
		t.Fatalf("warnings = %+v", allocation.Warnings)
	}
}

func TestAtPinsASpecificNumber(t *testing.T) {
	allocation, err := At(defaultPool(), 30, 42)
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	if allocation.Subnet != "172.17.42.0/30" || allocation.TunnelNumber != 42 {
		t.Fatalf("allocation = %+v", allocation)
	}
	if allocation.Scheme != SchemeOctet {
		t.Fatalf("scheme = %q", allocation.Scheme)
	}
}

// ------------------------------------------------------------- the allocator

type fakeRepo struct {
	pools []Pool
	used  []string
}

func (r *fakeRepo) Pools(ctx context.Context) ([]Pool, error) { return r.pools, nil }
func (r *fakeRepo) PoolByID(ctx context.Context, id int64) (Pool, error) {
	for _, p := range r.pools {
		if p.AddressPoolID == id {
			return p, nil
		}
	}
	return Pool{}, context.Canceled
}
func (r *fakeRepo) UsedAddresses(ctx context.Context) ([]string, error) { return r.used, nil }

type fakeSettings map[string]any

func (s fakeSettings) Bool(key string) bool { b, _ := s[key].(bool); return b }
func (s fakeSettings) Int(key string) int64 { n, _ := s[key].(int64); return n }
func (s fakeSettings) IntPtr(key string) *int64 {
	n, ok := s[key].(int64)
	if !ok {
		return nil
	}
	return &n
}

func TestDefaultPoolFallsBackToTheFirstEnabledOne(t *testing.T) {
	repo := &fakeRepo{pools: []Pool{
		{AddressPoolID: 30, Title: "Legacy", Cidr: "109.194.0.0/16", PrefixLength: 30, IsEnabled: false},
		{AddressPoolID: 10, Title: "Private", Cidr: "172.17.0.0/16", PrefixLength: 30, IsEnabled: true},
	}}
	a := New(repo, link.NewFake(), fakeSettings{})

	pool, err := a.DefaultPool(context.Background())
	if err != nil {
		t.Fatalf("default pool failed: %v", err)
	}
	if pool.AddressPoolID != 10 {
		t.Fatalf("default pool = %d, want the first enabled one", pool.AddressPoolID)
	}

	// A configured pool wins, and a disabled one is refused rather than used.
	a.Settings = fakeSettings{"addressing.default_pool_id": int64(30)}
	if _, err := a.DefaultPool(context.Background()); err == nil {
		t.Fatal("a disabled configured pool must be refused")
	}
}

func TestUsedAddressesCombineTheDatabaseAndTheKernel(t *testing.T) {
	repo := &fakeRepo{
		pools: []Pool{defaultPool()},
		used:  []string{"172.17.1.1"},
	}
	links := link.NewFake()
	links.AddLink(link.Link{
		Name: "gre-b-2", Kind: link.KindGRE, Index: 3,
		Addresses: []link.Address{{Address: "172.17.2.2", PrefixLength: 30, Family: link.FamilyIPv4}},
	})

	a := New(repo, links, fakeSettings{"addressing.default_prefix_len": int64(30)})
	allocation, err := a.NextFree(context.Background(), defaultPool(), a.DefaultPrefixLength())
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	// Tunnel 1 is taken according to the database and tunnel 2 according to the
	// kernel; either alone would have handed out an address already in use.
	if allocation.TunnelNumber != 3 {
		t.Fatalf("allocated tunnel %d, want 3", allocation.TunnelNumber)
	}
}

func TestDefaultPrefixLengthFallsBackToThirty(t *testing.T) {
	a := New(&fakeRepo{}, link.NewFake(), fakeSettings{})
	if got := a.DefaultPrefixLength(); got != 30 {
		t.Fatalf("default prefix length = %d, want 30", got)
	}
	a.Settings = fakeSettings{"addressing.default_prefix_len": int64(31)}
	if got := a.DefaultPrefixLength(); got != 31 {
		t.Fatalf("configured prefix length = %d, want 31", got)
	}
}

func TestDescribeReportsCapacityAndErrors(t *testing.T) {
	got := Describe(defaultPool(), 30)
	if got.Capacity != 256 || got.MaxNumber != 255 || got.Scheme != SchemeOctet {
		t.Fatalf("capacity = %+v", got)
	}
	bad := Describe(Pool{AddressPoolID: 1, Title: "Broken", Cidr: "not-a-cidr"}, 30)
	if bad.Error == "" {
		t.Fatal("an invalid pool range must be reported rather than panicking")
	}
}
