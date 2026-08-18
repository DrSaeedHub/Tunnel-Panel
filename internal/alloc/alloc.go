// Package alloc turns an address pool into the point-to-point subnet a tunnel
// uses, and finds the next free one.
//
// The script this panel replaces welded the tunnel number to the third octet of
// a hardcoded prefix, which capped it at 255 tunnels and made the addressing
// scheme impossible to change. The scheme is kept as the default so tunnels
// that script created still line up, but it is derived from the pool rather
// than assumed, and a pool whose shape does not suit it falls back to dense
// allocation instead.
package alloc

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

// Pool is an address range tunnel subnets are allocated from.
type Pool struct {
	AddressPoolID int64  `json:"address_pool_id"`
	Title         string `json:"address_pool_title"`
	Cidr          string `json:"cidr"`
	PrefixLength  int    `json:"prefix_length"`
	IsPublicRange bool   `json:"is_public_range"`
	IsEnabled     bool   `json:"is_enabled"`
	Description   string `json:"description"`
}

// Prefix parses the pool's range.
func (p Pool) Prefix() (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(p.Cidr))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("address pool %q has an invalid range %q: %w", p.Title, p.Cidr, err)
	}
	return prefix.Masked(), nil
}

// Scheme describes how a tunnel number maps onto a subnet inside a pool.
type Scheme string

const (
	// SchemeOctet places the tunnel number in the third octet, so tunnel 7 in
	// 172.17.0.0/16 is 172.17.7.0/30. This is the scheme the legacy script used
	// and the reason its tunnel numbers stopped at 255.
	SchemeOctet Scheme = "third_octet"
	// SchemeDense packs subnets consecutively, so tunnel 7 in a /24 pool of /30
	// subnets is the eighth /30. It is used wherever the octet scheme does not
	// fit the pool.
	SchemeDense Scheme = "dense"
)

// octetStride is the address step of the third-octet scheme.
const octetStride = 256

// SchemeFor reports which scheme a pool and subnet size imply.
//
// The octet scheme needs an IPv4 pool large enough for the third octet to vary
// and subnets small enough to sit inside one, which is exactly the legacy
// 172.17.0.0/16 with /30 subnets.
func SchemeFor(pool netip.Prefix, prefixLen int) Scheme {
	if pool.Addr().Is4() && pool.Bits() < 24 && prefixLen >= 24 {
		return SchemeOctet
	}
	return SchemeDense
}

// Capacity reports how many tunnel numbers a pool can hold at the given subnet
// size. This is what §7.3 means by validating the number against the pool
// rather than applying the legacy 1-255 limit everywhere.
func Capacity(pool netip.Prefix, prefixLen int) (int64, error) {
	if err := checkShape(pool, prefixLen); err != nil {
		return 0, err
	}
	if SchemeFor(pool, prefixLen) == SchemeOctet {
		// One subnet per third-octet step: a /16 pool holds 256 of them, which is
		// where the legacy script's ceiling of 255 tunnels came from.
		return int64(1) << (24 - pool.Bits()), nil
	}
	span := prefixLen - pool.Bits()
	// An IPv6 pool can span more subnets than any counter usefully expresses.
	// Capping the reported capacity keeps the number meaningful rather than
	// returning one nothing can enumerate.
	if span > 24 {
		span = 24
	}
	return int64(1) << span, nil
}

// MaxNumber is the largest tunnel number a pool can hold.
func MaxNumber(pool netip.Prefix, prefixLen int) (int64, error) {
	capacity, err := Capacity(pool, prefixLen)
	if err != nil {
		return 0, err
	}
	return capacity - 1, nil
}

func checkShape(pool netip.Prefix, prefixLen int) error {
	if !pool.IsValid() {
		return fmt.Errorf("the address pool range is not valid")
	}
	max := pool.Addr().BitLen()
	if prefixLen < pool.Bits() {
		return fmt.Errorf("a /%d subnet is larger than the pool /%d it would come from",
			prefixLen, pool.Bits())
	}
	if prefixLen > max {
		return fmt.Errorf("prefix length /%d is out of range for this address family", prefixLen)
	}
	if pool.Addr().Is4() && prefixLen > 31 {
		return fmt.Errorf("a tunnel subnet needs at least two addresses; use /31 or /30")
	}
	if !pool.Addr().Is4() && prefixLen > 127 {
		return fmt.Errorf("a tunnel subnet needs at least two addresses; use /127 or shorter")
	}
	return nil
}

// SubnetForNumber returns the subnet a tunnel number maps to inside a pool.
func SubnetForNumber(pool netip.Prefix, prefixLen int, number int64) (netip.Prefix, error) {
	if err := checkShape(pool, prefixLen); err != nil {
		return netip.Prefix{}, err
	}
	max, err := MaxNumber(pool, prefixLen)
	if err != nil {
		return netip.Prefix{}, err
	}
	if number < 0 || number > max {
		return netip.Prefix{}, fmt.Errorf("tunnel number %d does not fit the pool %s with /%d subnets, "+
			"which holds numbers 0 to %d", number, pool, prefixLen, max)
	}

	stride := int64(1) << (pool.Addr().BitLen() - prefixLen)
	if SchemeFor(pool, prefixLen) == SchemeOctet {
		stride = octetStride
	}
	base, err := addOffset(pool.Addr(), number*stride)
	if err != nil {
		return netip.Prefix{}, err
	}
	subnet := netip.PrefixFrom(base, prefixLen)
	if !pool.Contains(base) {
		return netip.Prefix{}, fmt.Errorf("subnet %s falls outside the pool %s", subnet, pool)
	}
	return subnet, nil
}

// NumberForSubnet is the reverse mapping, used when importing a tunnel that
// already exists and working out which number it occupies.
func NumberForSubnet(pool netip.Prefix, subnet netip.Prefix) (int64, bool) {
	if !pool.Contains(subnet.Addr()) {
		return 0, false
	}
	offset, ok := distance(pool.Addr(), subnet.Addr())
	if !ok {
		return 0, false
	}
	stride := int64(1) << (pool.Addr().BitLen() - subnet.Bits())
	if SchemeFor(pool, subnet.Bits()) == SchemeOctet {
		stride = octetStride
	}
	if stride == 0 || offset%stride != 0 {
		return 0, false
	}
	return offset / stride, true
}

// SlotAddresses returns the two usable addresses of a tunnel subnet: the first
// for slot A and the second for slot B (§5.4).
//
// For an IPv4 /31 both addresses of the subnet are usable, which is what RFC
// 3021 is for and exactly the point-to-point case a tunnel is. For anything
// wider the first address is the network address, so the two usable ones are
// the following pair.
func SlotAddresses(subnet netip.Prefix) (a, b netip.Addr, err error) {
	subnet = subnet.Masked()
	first := subnet.Addr()
	offset := int64(1)
	if (first.Is4() && subnet.Bits() == 31) || (!first.Is4() && subnet.Bits() == 127) {
		offset = 0
	}
	a, err = addOffset(first, offset)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	b, err = addOffset(first, offset+1)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if !subnet.Contains(a) || !subnet.Contains(b) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("the subnet %s is too small to carry two addresses", subnet)
	}
	return a, b, nil
}

// AddressForSide returns the address a tunnel takes for its slot: A takes the
// first usable address of the subnet and B the second. That, the mirrored
// endpoints, and the {side} substitution in the name are the only three things
// the slot decides (§5.4).
func AddressForSide(subnet netip.Prefix, tunnelSideID int64) (own, peer netip.Addr, err error) {
	a, b, err := SlotAddresses(subnet)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if tunnelSideID == model.TunnelSideB {
		return b, a, nil
	}
	return a, b, nil
}

// addOffset advances an address by n, refusing to wrap past the end of the
// address space. The arithmetic is done on the address bytes rather than by
// stepping, so a large pool costs the same as a small one.
func addOffset(addr netip.Addr, n int64) (netip.Addr, error) {
	if n < 0 {
		return netip.Addr{}, fmt.Errorf("cannot move %d addresses backwards from %s", n, addr)
	}
	if addr.Is4() {
		v := uint64(beUint32(addr.As4()))
		sum := v + uint64(n)
		if sum > 0xFFFFFFFF {
			return netip.Addr{}, fmt.Errorf("address %s plus %d runs past the end of the address space", addr, n)
		}
		var out [4]byte
		putBeUint32(&out, uint32(sum))
		return netip.AddrFrom4(out), nil
	}

	bytes := addr.As16()
	carry := uint64(n)
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(bytes[i]) + (carry & 0xFF)
		bytes[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
	if carry > 0 {
		return netip.Addr{}, fmt.Errorf("address %s plus %d runs past the end of the address space", addr, n)
	}
	return netip.AddrFrom16(bytes), nil
}

// distance returns how many addresses separate two addresses of the same
// family. It reports false when they differ by more than an int64 can hold,
// which no pool this panel handles ever does.
func distance(from, to netip.Addr) (int64, bool) {
	if from.Is4() != to.Is4() {
		return 0, false
	}
	if from.Is4() {
		a, b := beUint32(from.As4()), beUint32(to.As4())
		if b < a {
			return 0, false
		}
		return int64(b - a), true
	}

	fromBytes, toBytes := from.As16(), to.As16()
	// Anything differing above the low 63 bits is far beyond any usable pool.
	for i := 0; i < 8; i++ {
		if fromBytes[i] != toBytes[i] {
			return 0, false
		}
	}
	var a, b uint64
	for i := 8; i < 16; i++ {
		a = a<<8 | uint64(fromBytes[i])
		b = b<<8 | uint64(toBytes[i])
	}
	if b < a || b-a > 1<<62 {
		return 0, false
	}
	return int64(b - a), true
}

func beUint32(b [4]byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func putBeUint32(b *[4]byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

// Allocation is one chosen subnet with everything the caller needs to build the
// tunnel from it.
type Allocation struct {
	AddressPoolID int64  `json:"address_pool_id"`
	PoolTitle     string `json:"address_pool_title"`
	Subnet        string `json:"subnet"`
	PrefixLength  int    `json:"prefix_length"`
	TunnelNumber  int64  `json:"tunnel_number"`
	Scheme        Scheme `json:"scheme"`
	// AddressA and AddressB are the two ends' addresses. Which one this server
	// takes depends only on its slot.
	AddressA string `json:"address_a"`
	AddressB string `json:"address_b"`
	// IsPublicRange marks a globally routable subnet, which is address squatting
	// and blackholes those destinations from this server.
	IsPublicRange bool `json:"is_public_range"`
	// Warnings carries the public-range warning when there is one.
	Warnings []validate.Warning `json:"warnings,omitempty"`
}

// OwnAddress returns the address this server takes for the given slot.
func (a Allocation) OwnAddress(tunnelSideID int64) string {
	if tunnelSideID == model.TunnelSideB {
		return a.AddressB
	}
	return a.AddressA
}

// PeerAddress returns the other end's address for the given slot.
func (a Allocation) PeerAddress(tunnelSideID int64) string {
	if tunnelSideID == model.TunnelSideB {
		return a.AddressA
	}
	return a.AddressB
}

// Repository is the stored state the allocator reads.
type Repository interface {
	// Pools returns every pool, including disabled ones.
	Pools(ctx context.Context) ([]Pool, error)
	// PoolByID returns one pool.
	PoolByID(ctx context.Context, id int64) (Pool, error)
	// UsedAddresses returns every address currently assigned to a live tunnel
	// row, in plain form without a prefix length.
	UsedAddresses(ctx context.Context) ([]string, error)
}

// Settings is the slice of the settings store the allocator reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	IntPtr(key string) *int64
}

// Allocator picks subnets from pools.
type Allocator struct {
	Repo     Repository
	Links    link.LinkManager
	Settings Settings
}

// New returns an allocator.
func New(repo Repository, links link.LinkManager, set Settings) *Allocator {
	return &Allocator{Repo: repo, Links: links, Settings: set}
}

// DefaultPrefixLength reads the configured subnet size, falling back to the
// documented default of /30 (§5.3).
func (a *Allocator) DefaultPrefixLength() int {
	if a.Settings == nil {
		return 30
	}
	n := a.Settings.Int("addressing.default_prefix_len")
	if n <= 0 {
		return 30
	}
	return int(n)
}

// DefaultPool returns the pool to allocate from when the request names none:
// the configured one, or the first enabled pool (§5.3).
func (a *Allocator) DefaultPool(ctx context.Context) (Pool, error) {
	pools, err := a.Repo.Pools(ctx)
	if err != nil {
		return Pool{}, err
	}
	if a.Settings != nil {
		if id := a.Settings.IntPtr("addressing.default_pool_id"); id != nil {
			for _, p := range pools {
				if p.AddressPoolID == *id {
					if !p.IsEnabled {
						return Pool{}, fmt.Errorf("the configured default address pool %q is disabled", p.Title)
					}
					return p, nil
				}
			}
			return Pool{}, fmt.Errorf("the configured default address pool %d does not exist", *id)
		}
	}
	for _, p := range pools {
		if p.IsEnabled {
			return p, nil
		}
	}
	return Pool{}, fmt.Errorf("no address pool is enabled; enable one before allocating a tunnel subnet")
}

// UsedAddressSet collects every address already in use, from the database and
// from the live kernel both, because either alone would miss half of them.
func (a *Allocator) UsedAddressSet(ctx context.Context) (map[netip.Addr]bool, error) {
	used := map[netip.Addr]bool{}

	if a.Repo != nil {
		stored, err := a.Repo.UsedAddresses(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range stored {
			if addr, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
				used[addr.Unmap()] = true
			}
		}
	}
	if a.Links != nil {
		links, err := a.Links.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading assigned addresses: %w", err)
		}
		for _, l := range links {
			for _, addr := range l.Addresses {
				if parsed, err := netip.ParseAddr(addr.Address); err == nil {
					used[parsed.Unmap()] = true
				}
			}
		}
	}
	return used, nil
}

// NextFree returns the lowest-numbered subnet in the pool with both of its
// addresses unused.
//
// Numbering starts at 1 for the third-octet scheme: the legacy script numbered
// its tunnels from 1, and starting at 0 would hand out a subnet whose addresses
// look like the pool's own network.
func (a *Allocator) NextFree(ctx context.Context, pool Pool, prefixLen int) (Allocation, error) {
	used, err := a.UsedAddressSet(ctx)
	if err != nil {
		return Allocation{}, err
	}
	return NextFreeIn(pool, prefixLen, used)
}

// NextFreeIn is the pure form of NextFree, taking the set of used addresses
// directly.
func NextFreeIn(pool Pool, prefixLen int, used map[netip.Addr]bool) (Allocation, error) {
	prefix, err := pool.Prefix()
	if err != nil {
		return Allocation{}, err
	}
	if err := checkShape(prefix, prefixLen); err != nil {
		return Allocation{}, err
	}
	max, err := MaxNumber(prefix, prefixLen)
	if err != nil {
		return Allocation{}, err
	}

	start := int64(0)
	if SchemeFor(prefix, prefixLen) == SchemeOctet {
		start = 1
	}
	for number := start; number <= max; number++ {
		subnet, err := SubnetForNumber(prefix, prefixLen, number)
		if err != nil {
			continue
		}
		addrA, addrB, err := SlotAddresses(subnet)
		if err != nil {
			continue
		}
		if used[addrA] || used[addrB] {
			continue
		}
		return describe(pool, prefix, subnet, number, addrA, addrB), nil
	}
	return Allocation{}, fmt.Errorf("the address pool %q has no free /%d subnet left; it holds %d",
		pool.Title, prefixLen, max+1)
}

// At returns the allocation for a specific tunnel number, which is how an
// operator pins a tunnel to a number rather than taking the next free one.
func At(pool Pool, prefixLen int, number int64) (Allocation, error) {
	prefix, err := pool.Prefix()
	if err != nil {
		return Allocation{}, err
	}
	subnet, err := SubnetForNumber(prefix, prefixLen, number)
	if err != nil {
		return Allocation{}, err
	}
	addrA, addrB, err := SlotAddresses(subnet)
	if err != nil {
		return Allocation{}, err
	}
	return describe(pool, prefix, subnet, number, addrA, addrB), nil
}

func describe(pool Pool, prefix, subnet netip.Prefix, number int64, addrA, addrB netip.Addr) Allocation {
	allocation := Allocation{
		AddressPoolID: pool.AddressPoolID,
		PoolTitle:     pool.Title,
		Subnet:        subnet.String(),
		PrefixLength:  subnet.Bits(),
		TunnelNumber:  number,
		Scheme:        SchemeFor(prefix, subnet.Bits()),
		AddressA:      addrA.String(),
		AddressB:      addrB.String(),
		IsPublicRange: validate.IsPublicRange(subnet.Addr()),
	}
	if allocation.IsPublicRange {
		allocation.Warnings = append(allocation.Warnings, validate.Warning{
			Code:  validate.WarnPublicRange,
			Field: "address_pool_id",
			Message: fmt.Sprintf("The pool %q hands out %s, which is globally routable. Assigning it to "+
				"a tunnel squats on address space belonging to someone else and blackholes those "+
				"destinations from this server.", pool.Title, subnet),
			Details: map[string]any{"subnet": subnet.String(), "pool": pool.Title},
		})
	}
	return allocation
}

// Describe reports what a pool can hold, for the pool listing endpoint.
type PoolCapacity struct {
	AddressPoolID int64  `json:"address_pool_id"`
	Scheme        Scheme `json:"scheme"`
	PrefixLength  int    `json:"prefix_length"`
	Capacity      int64  `json:"capacity"`
	MaxNumber     int64  `json:"max_tunnel_number"`
	IsPublicRange bool   `json:"is_public_range"`
	Error         string `json:"error,omitempty"`
}

// Describe computes the capacity of a pool at a subnet size.
func Describe(pool Pool, prefixLen int) PoolCapacity {
	out := PoolCapacity{AddressPoolID: pool.AddressPoolID, PrefixLength: prefixLen}
	prefix, err := pool.Prefix()
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.IsPublicRange = validate.IsPublicRange(prefix.Addr())
	capacity, err := Capacity(prefix, prefixLen)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.Scheme = SchemeFor(prefix, prefixLen)
	out.Capacity = capacity
	out.MaxNumber = capacity - 1
	return out
}

// SortPools orders pools by identifier so listings are stable.
func SortPools(pools []Pool) {
	sort.Slice(pools, func(i, j int) bool { return pools[i].AddressPoolID < pools[j].AddressPoolID })
}
