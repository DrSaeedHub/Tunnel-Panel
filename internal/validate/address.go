package validate

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// InterfaceNamePattern is the rule of §7.1. Linux caps interface names at 15
// characters because IFNAMSIZ is 16 including the terminating NUL.
const InterfaceNamePattern = `^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`

// MaxInterfaceNameLength is that cap.
const MaxInterfaceNameLength = 15

var interfaceNameRe = regexp.MustCompile(InterfaceNamePattern)

// ReservedInterfaceNames are the kernel's own tunnel devices plus the loopback.
// Creating a tunnel over one of these would collide with a device the kernel
// created for itself (§7.1).
var ReservedInterfaceNames = []string{"gre0", "gretap0", "erspan0", "ip6gre0", "ip6gretap0", "ip6tnl0", "tunl0", "sit0", "lo"}

// IsReservedInterfaceName reports whether a name is one of the kernel's own.
func IsReservedInterfaceName(name string) bool {
	for _, reserved := range ReservedInterfaceNames {
		if name == reserved {
			return true
		}
	}
	return false
}

// InterfaceName applies the syntactic rules of §7.1. The collision rules need
// live state and are checked separately.
func InterfaceName(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return fmt.Errorf("must not be empty")
	case name == "." || name == "..":
		return fmt.Errorf("%q is not a usable interface name", name)
	case strings.ContainsAny(name, "/"):
		return fmt.Errorf("must not contain a slash")
	case strings.ContainsAny(name, " \t\n\r\v\f"):
		return fmt.Errorf("must not contain whitespace")
	case len(name) > MaxInterfaceNameLength:
		return fmt.Errorf("is %d characters; Linux allows at most %d", len(name), MaxInterfaceNameLength)
	case !interfaceNameRe.MatchString(name):
		return fmt.Errorf("must be at most %d characters from A-Z a-z 0-9 . _ - and start with a "+
			"letter or digit", MaxInterfaceNameLength)
	}
	return nil
}

// PrefixLengthFor reports whether a prefix length is valid for an address, and
// permits /31 on IPv4 point-to-point links per RFC 3021 (§7.4).
func PrefixLengthFor(addr netip.Addr, prefixLen int) error {
	max := addr.BitLen()
	if prefixLen < 0 || prefixLen > max {
		return fmt.Errorf("prefix length /%d is out of range; for this family it must be 0 to %d",
			prefixLen, max)
	}
	return nil
}

// privateIPv4 are the ranges the specification treats as not globally routable:
// RFC 1918, RFC 6598 carrier-grade NAT, and link-local.
var privateIPv4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
}

// privateIPv6 are the unique-local and link-local ranges.
var privateIPv6 = []netip.Prefix{
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// reservedIPv4 are addresses that cannot be a tunnel endpoint: "this network",
// the ranges reserved for future use, and the limited broadcast address (§7.2).
var reservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// IsPublicRange reports whether an address is globally routable, which is what
// makes a tunnel subnet address squatting: the panel would blackhole those
// destinations from this server (§1, §7.4).
func IsPublicRange(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return false
	}
	ranges := privateIPv6
	if addr.Is4() {
		ranges = privateIPv4
	}
	for _, r := range ranges {
		if r.Contains(addr) {
			return false
		}
	}
	return true
}

// IsReservedAddress reports whether an address may not be a tunnel endpoint.
func IsReservedAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Is4() {
		if addr.String() == "255.255.255.255" {
			return true
		}
		for _, r := range reservedIPv4 {
			if r.Contains(addr) {
				return true
			}
		}
		return false
	}
	// The IPv4-mapped and discard-only ranges are not usable endpoints either.
	return netip.MustParsePrefix("100::/64").Contains(addr)
}

// ParsePrefix parses an address and prefix length into a network prefix,
// keeping the host bits so the caller can report the address itself.
func ParsePrefix(address string, prefixLen int) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address", address)
	}
	addr = addr.Unmap()
	if err := PrefixLengthFor(addr, prefixLen); err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, prefixLen), nil
}

// PrefixesOverlap reports whether two networks intersect.
func PrefixesOverlap(a, b netip.Prefix) bool {
	return a.Overlaps(b)
}
