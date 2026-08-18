//go:build linux

package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/drs/gre-panel/internal/audit"
)

// GRE flag bits carried in IFLA_GRE_IFLAGS and IFLA_GRE_OFLAGS. They are
// restated here rather than imported from the netlink library's nl subpackage
// so this file depends only on the library's public surface.
const (
	greFlagChecksum uint16 = 0x8000
	greFlagKey      uint16 = 0x2000
	greFlagSequence uint16 = 0x1000
)

// tosInherit is the value the kernel uses for "copy the inner TOS", which
// iproute2 spells "inherit".
const tosInherit uint8 = 1

// Netlink is the primary LinkManager (§8.1). It talks to the kernel directly,
// so it spawns no process, returns typed errors, and cannot be confused by a
// change in the output format of a command.
//
// Where the library cannot express an attribute — a firewall mark, ignore-df,
// or the IPv6 GRE variants — it returns ErrUnsupported so the caller falls back
// to the `ip` implementation rather than silently creating a different tunnel
// from the one that was asked for.
type Netlink struct{}

// NewNetlink returns the netlink-backed manager.
func NewNetlink() *Netlink { return &Netlink{} }

// Name identifies the implementation.
func (n *Netlink) Name() string { return ManagerNetlink }

// Capabilities probes whether netlink is usable here and reports which tunnel
// types this path can serve.
func (n *Netlink) Capabilities() Capabilities {
	available := true
	detail := "direct netlink, no process is spawned"
	if err := probeNetlink(); err != nil {
		available = false
		detail = err.Error()
	}

	types := map[string]TypeSupport{}
	for _, kind := range TunnelKinds() {
		if IsIPv6Kind(kind) {
			types[kind] = TypeSupport{
				Supported: false, Manager: ManagerIP,
				Note: "served through the ip command, because netlink library coverage of the " +
					"IPv6 GRE variants and their encapsulation limit and flow label is incomplete",
			}
			continue
		}
		types[kind] = TypeSupport{Supported: available, Manager: ManagerNetlink}
	}
	return Capabilities{
		Name: ManagerNetlink, Available: available, Detail: detail,
		TunnelTypes: types, Events: available, Statistics: available,
	}
}

// unsupported reports the attributes of a specification this path cannot
// express, so the caller can fall back rather than create the wrong tunnel.
func unsupported(spec TunnelSpec) error {
	switch {
	case IsIPv6Kind(spec.Kind):
		return fmt.Errorf("%w: the netlink library does not carry the IPv6 GRE attributes", ErrUnsupported)
	case spec.FwMark != nil:
		return fmt.Errorf("%w: the netlink library does not carry the tunnel firewall mark", ErrUnsupported)
	case spec.IsIgnoreDf:
		return fmt.Errorf("%w: the netlink library does not carry the ignore-df attribute", ErrUnsupported)
	case spec.IKey != nil && *spec.IKey == 0, spec.OKey != nil && *spec.OKey == 0:
		// The library treats a zero key as "no key", so an explicit key of zero
		// cannot be distinguished from its absence on this path.
		return fmt.Errorf("%w: the netlink library cannot express an explicit GRE key of 0", ErrUnsupported)
	}
	return nil
}

func (n *Netlink) Create(ctx context.Context, spec TunnelSpec) error {
	if err := unsupported(spec); err != nil {
		return err
	}
	local, err := parseIP(spec.Local, "local endpoint")
	if err != nil {
		return err
	}
	remote, err := parseIP(spec.Remote, "remote endpoint")
	if err != nil {
		return err
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = spec.Name
	if spec.Mtu > 0 {
		attrs.MTU = spec.Mtu
	}
	if spec.TxQueueLength != nil {
		attrs.TxQLen = *spec.TxQueueLength
	} else {
		attrs.TxQLen = -1 // leave the kernel default alone
	}

	var bindIndex uint32
	if spec.BindDevice != "" {
		dev, err := netlink.LinkByName(spec.BindDevice)
		if err != nil {
			return fmt.Errorf("bind device %q: %w", spec.BindDevice, err)
		}
		bindIndex = uint32(dev.Attrs().Index)
	}

	iflags, oflags := greFlags(spec)
	tos, err := parseTos(spec.Tos)
	if err != nil {
		return err
	}
	var pmtudisc uint8
	if spec.IsPathMtuDiscovery {
		pmtudisc = 1
	}

	var link netlink.Link
	switch spec.Kind {
	case KindGRE:
		link = &netlink.Gretun{
			LinkAttrs: attrs, Local: local, Remote: remote,
			Ttl: uint8(spec.Ttl), Tos: tos, PMtuDisc: pmtudisc,
			IKey: keyValue(spec.IKey), OKey: keyValue(spec.OKey),
			IFlags: iflags, OFlags: oflags, Link: bindIndex,
		}
	case KindGRETAP:
		link = &netlink.Gretap{
			LinkAttrs: attrs, Local: local, Remote: remote,
			Ttl: uint8(spec.Ttl), Tos: tos, PMtuDisc: pmtudisc,
			IKey: keyValue(spec.IKey), OKey: keyValue(spec.OKey),
			IFlags: iflags, OFlags: oflags, Link: bindIndex,
		}
	default:
		return fmt.Errorf("%w: tunnel kind %q", ErrUnsupported, spec.Kind)
	}

	trace(ctx, fmt.Sprintf("LinkAdd %s type %s local %s remote %s",
		spec.Name, spec.Kind, spec.Local, spec.Remote), nil)
	if err := netlink.LinkAdd(link); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s", ErrExists, spec.Name)
		}
		return fmt.Errorf("creating %s: %w", spec.Name, err)
	}
	return nil
}

func greFlags(spec TunnelSpec) (iflags, oflags uint16) {
	if spec.IKey != nil {
		iflags |= greFlagKey
	}
	if spec.OKey != nil {
		oflags |= greFlagKey
	}
	if spec.HasInputChecksum {
		iflags |= greFlagChecksum
	}
	if spec.HasOutputChecksum {
		oflags |= greFlagChecksum
	}
	if spec.HasInputSequence {
		iflags |= greFlagSequence
	}
	if spec.HasOutputSequence {
		oflags |= greFlagSequence
	}
	return iflags, oflags
}

func keyValue(key *uint32) uint32 {
	if key == nil {
		return 0
	}
	return *key
}

func parseIP(s, what string) (net.IP, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return nil, fmt.Errorf("%s %q is not an IP address: %w", what, s, err)
	}
	return net.IP(addr.AsSlice()), nil
}

// parseTos converts the stored TOS value. "inherit" is the kernel's flag value
// 1; anything else is a decimal or 0x-prefixed byte.
func parseTos(tos string) (uint8, error) {
	tos = strings.TrimSpace(tos)
	if tos == "" || tos == "inherit" {
		return tosInherit, nil
	}
	base := 10
	if strings.HasPrefix(tos, "0x") || strings.HasPrefix(tos, "0X") {
		tos, base = tos[2:], 16
	}
	n, err := strconv.ParseUint(tos, base, 8)
	if err != nil {
		return 0, fmt.Errorf("type of service %q must be \"inherit\" or a byte value: %w", tos, err)
	}
	return uint8(n), nil
}

func (n *Netlink) Delete(ctx context.Context, name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return nil // already gone, which is the requested end state
		}
		return fmt.Errorf("looking up %s: %w", name, err)
	}
	trace(ctx, "LinkDel "+name, nil)
	if err := netlink.LinkDel(l); err != nil {
		return fmt.Errorf("deleting %s: %w", name, err)
	}
	return nil
}

func (n *Netlink) SetMTU(ctx context.Context, name string, mtu int) error {
	l, err := n.byName(name)
	if err != nil {
		return err
	}
	trace(ctx, fmt.Sprintf("LinkSetMTU %s %d", name, mtu), nil)
	if err := netlink.LinkSetMTU(l, mtu); err != nil {
		return fmt.Errorf("setting the MTU of %s to %d: %w", name, mtu, err)
	}
	return nil
}

func (n *Netlink) SetTxQueueLength(ctx context.Context, name string, length int) error {
	l, err := n.byName(name)
	if err != nil {
		return err
	}
	trace(ctx, fmt.Sprintf("LinkSetTxQLen %s %d", name, length), nil)
	if err := netlink.LinkSetTxQLen(l, length); err != nil {
		return fmt.Errorf("setting the transmit queue length of %s: %w", name, err)
	}
	return nil
}

func (n *Netlink) SetUp(ctx context.Context, name string) error {
	l, err := n.byName(name)
	if err != nil {
		return err
	}
	trace(ctx, "LinkSetUp "+name, nil)
	if err := netlink.LinkSetUp(l); err != nil {
		return fmt.Errorf("bringing %s up: %w", name, err)
	}
	return nil
}

func (n *Netlink) SetDown(ctx context.Context, name string) error {
	l, err := n.byName(name)
	if err != nil {
		return err
	}
	trace(ctx, "LinkSetDown "+name, nil)
	if err := netlink.LinkSetDown(l); err != nil {
		return fmt.Errorf("bringing %s down: %w", name, err)
	}
	return nil
}

func (n *Netlink) AddAddress(ctx context.Context, name string, addr Address) error {
	l, err := n.byName(name)
	if err != nil {
		return err
	}
	na, err := toNetlinkAddr(addr)
	if err != nil {
		return err
	}
	trace(ctx, fmt.Sprintf("AddrAdd %s %s", name, addr), nil)
	if err := netlink.AddrAdd(l, na); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s already has %s", ErrExists, name, addr)
		}
		return fmt.Errorf("adding %s to %s: %w", addr, name, err)
	}
	return nil
}

func (n *Netlink) RemoveAddress(ctx context.Context, name string, addr Address) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return nil
		}
		return fmt.Errorf("looking up %s: %w", name, err)
	}
	na, err := toNetlinkAddr(addr)
	if err != nil {
		return err
	}
	trace(ctx, fmt.Sprintf("AddrDel %s %s", name, addr), nil)
	if err := netlink.AddrDel(l, na); err != nil {
		if errors.Is(err, unix.EADDRNOTAVAIL) || errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("removing %s from %s: %w", addr, name, err)
	}
	return nil
}

func toNetlinkAddr(addr Address) (*netlink.Addr, error) {
	parsed, err := addr.Prefix()
	if err != nil {
		return nil, err
	}
	bits := 32
	if parsed.Addr().Is6() && !parsed.Addr().Is4In6() {
		bits = 128
	}
	na := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.IP(parsed.Addr().AsSlice()),
		Mask: net.CIDRMask(parsed.Bits(), bits),
	}}
	if addr.NeedsExplicitPeer() {
		peer, err := netip.ParseAddr(addr.Peer)
		if err != nil {
			return nil, fmt.Errorf("peer address %q is not an IP address: %w", addr.Peer, err)
		}
		na.Peer = &net.IPNet{IP: net.IP(peer.AsSlice()), Mask: net.CIDRMask(parsed.Bits(), bits)}
	}
	return na, nil
}

func (n *Netlink) byName(name string) (netlink.Link, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		if isLinkNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, fmt.Errorf("looking up %s: %w", name, err)
	}
	return l, nil
}

func isLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, unix.ENODEV)
}

func (n *Netlink) List(ctx context.Context) ([]Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("listing interfaces: %w", err)
	}
	out := make([]Link, 0, len(links))
	for _, l := range links {
		converted := convertLink(l)
		converted.Addresses = listAddresses(l)
		out = append(out, converted)
	}
	return out, nil
}

func (n *Netlink) Get(ctx context.Context, name string) (Link, error) {
	l, err := n.byName(name)
	if err != nil {
		return Link{}, err
	}
	converted := convertLink(l)
	converted.Addresses = listAddresses(l)
	return converted, nil
}

func listAddresses(l netlink.Link) []Address {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	out := make([]Address, 0, len(addrs))
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		parsed, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		parsed = parsed.Unmap()
		ones, _ := a.Mask.Size()
		converted := Address{
			Address: parsed.String(), PrefixLength: ones,
			Family: FamilyOf(parsed), Label: a.Label,
			Scope: scopeName(a.Scope),
		}
		if a.Peer != nil && !a.Peer.IP.Equal(a.IP) {
			if peer, ok := netip.AddrFromSlice(a.Peer.IP); ok {
				converted.Peer = peer.Unmap().String()
			}
		}
		out = append(out, converted)
	}
	return out
}

func scopeName(scope int) string {
	switch scope {
	case unix.RT_SCOPE_UNIVERSE:
		return "global"
	case unix.RT_SCOPE_SITE:
		return "site"
	case unix.RT_SCOPE_LINK:
		return "link"
	case unix.RT_SCOPE_HOST:
		return "host"
	case unix.RT_SCOPE_NOWHERE:
		return "nowhere"
	}
	return strconv.Itoa(scope)
}

// convertLink turns a netlink link into the panel's representation. The
// operational state is carried through verbatim: a healthy GRE tunnel reports
// UNKNOWN and nothing here may treat that as a fault (§2).
func convertLink(l netlink.Link) Link {
	a := l.Attrs()
	out := Link{
		Name:        a.Name,
		Index:       a.Index,
		MTU:         a.MTU,
		Kind:        normaliseNetlinkKind(l),
		TxQueueLen:  a.TxQLen,
		OperState:   strings.ToUpper(a.OperState.String()),
		Flags:       flagNames(a),
		IsUp:        a.RawFlags&unix.IFF_UP != 0,
		IsLowerUp:   a.RawFlags&unix.IFF_LOWER_UP != 0,
		IsRunning:   a.RawFlags&unix.IFF_RUNNING != 0,
		MasterIndex: a.MasterIndex,
	}
	if a.HardwareAddr != nil {
		out.HardwareAddr = a.HardwareAddr.String()
	}
	if a.Statistics != nil {
		out.Statistics = &Statistics{
			RxBytes: a.Statistics.RxBytes, TxBytes: a.Statistics.TxBytes,
			RxPackets: a.Statistics.RxPackets, TxPackets: a.Statistics.TxPackets,
			RxErrors: a.Statistics.RxErrors, TxErrors: a.Statistics.TxErrors,
			RxDropped: a.Statistics.RxDropped, TxDropped: a.Statistics.TxDropped,
		}
	}
	out.Tunnel = tunnelAttrsOf(l)
	return out
}

// normaliseNetlinkKind maps the library's type name onto the panel's, so a
// plain NIC is "device" and the loopback is "loopback" whichever manager
// reported it.
func normaliseNetlinkKind(l netlink.Link) string {
	kind := l.Type()
	if kind == "device" {
		if l.Attrs().RawFlags&unix.IFF_LOOPBACK != 0 {
			return "loopback"
		}
		return "device"
	}
	return kind
}

func flagNames(a *netlink.LinkAttrs) []string {
	type flag struct {
		bit  uint32
		name string
	}
	all := []flag{
		{unix.IFF_UP, "UP"},
		{unix.IFF_BROADCAST, "BROADCAST"},
		{unix.IFF_LOOPBACK, "LOOPBACK"},
		{unix.IFF_POINTOPOINT, "POINTOPOINT"},
		{unix.IFF_RUNNING, "RUNNING"},
		{unix.IFF_NOARP, "NOARP"},
		{unix.IFF_PROMISC, "PROMISC"},
		{unix.IFF_MULTICAST, "MULTICAST"},
		{unix.IFF_LOWER_UP, "LOWER_UP"},
	}
	out := make([]string, 0, len(all))
	for _, f := range all {
		if a.RawFlags&f.bit != 0 {
			out = append(out, f.name)
		}
	}
	return out
}

// tunnelAttrsOf extracts the tunnel attributes from a link, or nil when the
// link is not a GRE-family tunnel.
func tunnelAttrsOf(l netlink.Link) *TunnelAttrs {
	switch t := l.(type) {
	case *netlink.Gretun:
		return greAttrs(t.Local, t.Remote, int(t.Ttl), t.Tos, t.PMtuDisc,
			t.IKey, t.OKey, t.IFlags, t.OFlags, t.Link, IsIPv6Kind(l.Type()))
	case *netlink.Gretap:
		return greAttrs(t.Local, t.Remote, int(t.Ttl), t.Tos, t.PMtuDisc,
			t.IKey, t.OKey, t.IFlags, t.OFlags, t.Link, IsIPv6Kind(l.Type()))
	}
	return nil
}

func greAttrs(local, remote net.IP, ttl int, tos, pmtudisc uint8,
	ikey, okey uint32, iflags, oflags uint16, bindIndex uint32, ipv6 bool) *TunnelAttrs {

	attrs := &TunnelAttrs{
		Local:              ipString(local),
		Remote:             ipString(remote),
		Ttl:                ttl,
		Tos:                tosString(tos),
		HasInputChecksum:   iflags&greFlagChecksum != 0,
		HasOutputChecksum:  oflags&greFlagChecksum != 0,
		HasInputSequence:   iflags&greFlagSequence != 0,
		HasOutputSequence:  oflags&greFlagSequence != 0,
		IsPathMtuDiscovery: pmtudisc != 0,
	}
	if iflags&greFlagKey != 0 {
		key := ikey
		attrs.IKey = &key
	}
	if oflags&greFlagKey != 0 {
		key := okey
		attrs.OKey = &key
	}
	if bindIndex != 0 {
		if dev, err := netlink.LinkByIndex(int(bindIndex)); err == nil {
			attrs.BindDevice = dev.Attrs().Name
		}
	}
	if ipv6 {
		hop := ttl
		attrs.HopLimit = &hop
	}
	return attrs
}

func ipString(ip net.IP) string {
	if len(ip) == 0 || ip.IsUnspecified() {
		return ""
	}
	if parsed, ok := netip.AddrFromSlice(ip); ok {
		return parsed.Unmap().String()
	}
	return ip.String()
}

func tosString(tos uint8) string {
	if tos == tosInherit || tos == 0 {
		return "inherit"
	}
	return "0x" + strconv.FormatUint(uint64(tos), 16)
}

func (n *Netlink) Routes(ctx context.Context) ([]Route, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	names := map[int]string{}
	if links, err := netlink.LinkList(); err == nil {
		for _, l := range links {
			names[l.Attrs().Index] = l.Attrs().Name
		}
	}

	out := make([]Route, 0, len(routes))
	for _, r := range routes {
		converted := Route{
			Device:   names[r.LinkIndex],
			Metric:   r.Priority,
			Table:    strconv.Itoa(r.Table),
			Protocol: r.Protocol.String(),
		}
		if r.Dst == nil {
			converted.Destination = "default"
			converted.IsDefault = true
		} else {
			converted.Destination = r.Dst.String()
			ones, _ := r.Dst.Mask.Size()
			converted.IsDefault = ones == 0
		}
		if r.Gw != nil {
			converted.Gateway = ipString(r.Gw)
		}
		if r.Src != nil {
			converted.Source = ipString(r.Src)
		}
		out = append(out, converted)
	}
	return out, nil
}

func (n *Netlink) Statistics(ctx context.Context, name string) (Statistics, error) {
	l, err := n.byName(name)
	if err != nil {
		return Statistics{}, err
	}
	a := l.Attrs()
	if a.Statistics == nil {
		return Statistics{}, nil
	}
	return Statistics{
		RxBytes: a.Statistics.RxBytes, TxBytes: a.Statistics.TxBytes,
		RxPackets: a.Statistics.RxPackets, TxPackets: a.Statistics.TxPackets,
		RxErrors: a.Statistics.RxErrors, TxErrors: a.Statistics.TxErrors,
		RxDropped: a.Statistics.RxDropped, TxDropped: a.Statistics.TxDropped,
	}, nil
}

// Subscribe streams link notifications. Detecting an interface appearing or
// vanishing this way is what keeps the monitor supervisor event-driven rather
// than polling (§8.1, §10.3).
func (n *Netlink) Subscribe(ctx context.Context) (<-chan Event, error) {
	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})

	if err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		// A dropped notification would silently desynchronise the panel from the
		// kernel, so the error is surfaced rather than swallowed.
		ErrorCallback: func(err error) {
			trace(context.Background(), "LinkSubscribe", err)
		},
	}); err != nil {
		close(done)
		return nil, fmt.Errorf("subscribing to link events: %w", err)
	}

	out := make(chan Event, 64)
	go func() {
		defer close(out)
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case update, ok := <-updates:
				if !ok {
					return
				}
				ev := Event{Kind: EventChanged, Link: convertLink(update.Link)}
				switch update.Header.Type {
				case unix.RTM_NEWLINK:
					ev.Kind = EventAdded
				case unix.RTM_DELLINK:
					ev.Kind = EventRemoved
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// trace appends a netlink call to the operation trace on the context.
func trace(ctx context.Context, detail string, err error) {
	op := audit.Operation{Kind: audit.KindNetlink, Detail: detail}
	if err != nil {
		op.Error = err.Error()
	}
	audit.TraceFrom(ctx).Add(op)
}
