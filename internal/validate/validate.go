package validate

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/settings"
)

// Numeric bounds of §7.3.
const (
	MaxTtl          = 255
	MaxGreKey       = 4294967295
	MaxFwMark       = 4294967295
	MaxTunnelNumber = 65535
	MaxQueueLength  = 1000000
)

var tosRe = regexp.MustCompile(`^(inherit|0x[0-9a-fA-F]{1,2}|[0-9]{1,3})$`)

// Validator checks a tunnel request against the rules of §7.
//
// It owns no state of its own: kernel state comes from the link manager and
// stored state from the repository, both collected once per pass so that every
// rule sees the same snapshot.
type Validator struct {
	Links    link.LinkManager
	Repo     Repository
	Settings Settings
	// AdoptPath is the API path of the adoption endpoint, quoted in an
	// ADOPTABLE answer so the frontend can offer the action directly (§7.5).
	AdoptPath string
}

// New returns a validator.
func New(links link.LinkManager, repo Repository, set Settings, adoptPath string) *Validator {
	return &Validator{Links: links, Repo: repo, Settings: set, AdoptPath: adoptPath}
}

// ValidateStatic applies every rule that needs no live state: the syntax of the
// interface name, the endpoints, the numeric fields, and the addresses.
//
// This is the phase that fixes the legacy script's worst bug. Given
// LocalEndpoint = "not-an-ip" it fails here, before the kernel or the database
// has been consulted at all, so no code path exists along which a malformed
// endpoint could reach a systemd unit.
func ValidateStatic(in TunnelInput) *Errors { return validateStatic(in, false) }

// ValidateSupplied applies the same static rules to the fields a request
// actually carries, skipping the ones the panel is about to fill in from the
// settings. It exists so that a malformed endpoint is rejected before anything
// at all happens — including the kernel read that allocating a subnet needs.
// The full static pass runs again once the defaults are in place.
func ValidateSupplied(in TunnelInput) *Errors { return validateStatic(in, true) }

func validateStatic(in TunnelInput, partial bool) *Errors {
	errs := &Errors{}

	validateType(in, errs, partial)
	if !partial || strings.TrimSpace(in.InterfaceName) != "" {
		validateName(in, errs)
	}
	validateEndpoints(in, errs, partial)
	validateNumbers(in, errs, partial)
	validateAddressSyntax(in, errs)

	return errs
}

// validateType checks the three lookup references. When partial is set, a zero
// identifier means "the panel will fill this in" rather than "invalid".
func validateType(in TunnelInput, errs *Errors, partial bool) {
	unset := func(id int64) bool { return partial && id == 0 }

	if !unset(in.TunnelTypeID) && model.TunnelTypeKind(in.TunnelTypeID) == "" {
		errs.Addf("tunnel_type_id", CodeInvalidType, "%d is not a known tunnel type", in.TunnelTypeID)
	}
	if !unset(in.TunnelSideID) && model.SideSlot(in.TunnelSideID) == "" {
		errs.Addf("tunnel_side_id", CodeInvalidSide,
			"%d is not a known side; a tunnel has exactly two ends, A and B", in.TunnelSideID)
	}
	if !unset(in.PersistenceTypeID) {
		switch in.PersistenceTypeID {
		case model.PersistenceTypeSystemd, model.PersistenceTypeNetworkd, model.PersistenceTypeRuntime:
		default:
			errs.Addf("persistence_type_id", CodeInvalidPersistence,
				"%d is not a known persistence type", in.PersistenceTypeID)
		}
	}
}

func validateName(in TunnelInput, errs *Errors) {
	if err := InterfaceName(in.InterfaceName); err != nil {
		errs.Addf("interface_name", CodeInvalidName, "The interface name %s.", err.Error())
		return
	}
	if IsReservedInterfaceName(in.InterfaceName) {
		errs.Add("interface_name", CodeNameReserved,
			fmt.Sprintf("%q is a device the kernel creates for itself and cannot be used for a tunnel.",
				in.InterfaceName),
			map[string]any{"reserved": ReservedInterfaceNames})
	}
}

// validateEndpoints applies §7.2. Every address is parsed with net/netip and
// anything unparseable is rejected outright.
func validateEndpoints(in TunnelInput, errs *Errors, partial bool) {
	wantIPv6 := in.IsIPv6()
	// With no tunnel type chosen yet there is nothing to match the family
	// against; the full pass checks it once the default is in place.
	checkFamily := !partial || in.TunnelTypeID != 0

	local, localOK := parseEndpoint(in.LocalEndpoint, "local_endpoint", "local", wantIPv6, checkFamily, in.BindDevice, errs)
	remote, remoteOK := parseEndpoint(in.RemoteEndpoint, "remote_endpoint", "remote", wantIPv6, checkFamily, in.BindDevice, errs)

	if localOK && remoteOK && local == remote {
		errs.Add("remote_endpoint", CodeEndpointsIdentical,
			"The local and remote endpoints are the same address. A tunnel connects two different hosts.", nil)
	}
}

// parseEndpoint parses and rejects one endpoint per §7.2.
func parseEndpoint(value, field, label string, wantIPv6, checkFamily bool, bindDevice string, errs *Errors) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		errs.Addf(field, CodeInvalidEndpoint, "The %s endpoint is required.", label)
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		errs.Add(field, CodeInvalidEndpoint,
			fmt.Sprintf("%q is not an IP address.", value),
			map[string]any{"value": value})
		return netip.Addr{}, false
	}
	addr = addr.Unmap()

	switch {
	case addr.IsUnspecified():
		errs.Addf(field, CodeInvalidEndpoint,
			"The %s endpoint may not be the unspecified address %s.", label, addr)
		return addr, false
	case addr.IsLoopback():
		errs.Addf(field, CodeInvalidEndpoint,
			"The %s endpoint may not be a loopback address.", label)
		return addr, false
	case addr.IsMulticast():
		errs.Addf(field, CodeInvalidEndpoint,
			"The %s endpoint may not be a multicast address.", label)
		return addr, false
	case IsReservedAddress(addr):
		errs.Addf(field, CodeInvalidEndpoint,
			"The %s endpoint %s is in a reserved range and cannot carry a tunnel.", label, addr)
		return addr, false
	case addr.IsLinkLocalUnicast() && strings.TrimSpace(bindDevice) == "":
		// A link-local address is only meaningful together with the interface it
		// is scoped to, so it is accepted only when a bind device is given.
		errs.Addf(field, CodeInvalidEndpoint,
			"The %s endpoint %s is link-local, which is only usable when a bind device is set.", label, addr)
		return addr, false
	}

	if !checkFamily {
		return addr, true
	}
	if wantIPv6 && addr.Is4() {
		errs.Add(field, CodeEndpointFamily,
			fmt.Sprintf("The %s endpoint %s is IPv4, but this tunnel type carries its underlay over IPv6.",
				label, addr), nil)
		return addr, false
	}
	if !wantIPv6 && addr.Is6() {
		errs.Add(field, CodeEndpointFamily,
			fmt.Sprintf("The %s endpoint %s is IPv6, but this tunnel type carries its underlay over IPv4.",
				label, addr), nil)
		return addr, false
	}
	return addr, true
}

func validateNumbers(in TunnelInput, errs *Errors, partial bool) {
	// A zero MTU or TTL in a partial request means the request did not state one,
	// so the setting supplies it; the full pass checks the resulting value.
	if (!partial || in.Mtu != 0) && (in.Mtu < MinMtu || in.Mtu > MaxMtu) {
		errs.Addf("mtu", CodeInvalidMtu, "The MTU must be between %d and %d.", MinMtu, MaxMtu)
	}
	if in.Ttl < 0 || in.Ttl > MaxTtl {
		errs.Addf("ttl", CodeInvalidTtl, "The TTL must be between 0 and %d, where 0 means inherit.", MaxTtl)
	}
	if in.HopLimit != nil && (*in.HopLimit < 0 || *in.HopLimit > MaxTtl) {
		errs.Addf("hop_limit", CodeInvalidTtl,
			"The hop limit must be between 0 and %d, where 0 means inherit.", MaxTtl)
	}
	if in.Tos != "" && !tosRe.MatchString(in.Tos) {
		errs.Add("tos", CodeInvalidTos,
			`The type of service must be "inherit" or a value such as 0x10 or 16.`, nil)
	}
	if in.IKey != nil && (*in.IKey < 0 || *in.IKey > MaxGreKey) {
		errs.Addf("ikey", CodeInvalidKey, "A GRE key must be between 0 and %d.", int64(MaxGreKey))
	}
	if in.OKey != nil && (*in.OKey < 0 || *in.OKey > MaxGreKey) {
		errs.Addf("okey", CodeInvalidKey, "A GRE key must be between 0 and %d.", int64(MaxGreKey))
	}
	if in.FwMark != nil && (*in.FwMark < 0 || *in.FwMark > MaxFwMark) {
		errs.Addf("fwmark", CodeInvalidFwMark, "A firewall mark must be between 0 and %d.", int64(MaxFwMark))
	}
	if in.TxQueueLength != nil && (*in.TxQueueLength < 0 || *in.TxQueueLength > MaxQueueLength) {
		errs.Addf("tx_queue_length", CodeInvalidQueueLength,
			"The transmit queue length must be between 0 and %d.", MaxQueueLength)
	}
	// The legacy script welded the tunnel number to the third octet and so could
	// not exceed 255. That limit belongs to an addressing scheme, not to tunnels,
	// so the general rule is the full 16-bit range; a pool that cannot hold the
	// number rejects it separately, against the pool (§7.3).
	if in.TunnelNumber != nil && (*in.TunnelNumber < 0 || *in.TunnelNumber > MaxTunnelNumber) {
		errs.Addf("tunnel_number", CodeInvalidNumber,
			"The tunnel number must be between 0 and %d.", MaxTunnelNumber)
	}
	if in.EncapLimit != nil && (*in.EncapLimit < 0 || *in.EncapLimit > 255) {
		errs.Add("encap_limit", CodeInvalidNumber, "The encapsulation limit must be between 0 and 255.", nil)
	}
	validateMonitorOverrides(in, errs)
}

// validateMonitorOverrides holds a per-tunnel override to the same bounds as
// the global it overrides.
//
// The bounds are read from the settings schema rather than repeated here. That
// is the whole point: a tunnel must not accept a probe interval the settings
// page would refuse, and the two must not be able to drift apart when one of
// them is changed. A field the schema does not describe is left alone rather
// than guessed at.
func validateMonitorOverrides(in TunnelInput, errs *Errors) {
	for _, o := range in.MonitorOverrides() {
		if o.Value == nil {
			continue // null means inherit, which is always allowed
		}
		def, ok := settings.Lookup(o.SettingKey)
		if !ok {
			continue
		}
		value := *o.Value
		if o.Whole && value != math.Trunc(value) {
			errs.Addf(o.Field, CodeInvalidMonitorOverride, "%s must be a whole number.", capitalise(def.Description))
			continue
		}
		if min := def.Constraints.Min; min != nil && value < *min {
			errs.Addf(o.Field, CodeInvalidMonitorOverride,
				"This must be between %s and %s, the same range as the global setting it overrides, or empty to inherit it.",
				formatBound(*min), formatBound(orInf(def.Constraints.Max)))
			continue
		}
		if max := def.Constraints.Max; max != nil && value > *max {
			errs.Addf(o.Field, CodeInvalidMonitorOverride,
				"This must be between %s and %s, the same range as the global setting it overrides, or empty to inherit it.",
				formatBound(orNegInf(def.Constraints.Min)), formatBound(*max))
		}
	}
}

func orInf(v *float64) float64 {
	if v == nil {
		return math.Inf(1)
	}
	return *v
}

func orNegInf(v *float64) float64 {
	if v == nil {
		return math.Inf(-1)
	}
	return *v
}

// formatBound prints a bound the way the settings page does: as a whole number
// when it is one, so an operator is not told the minimum is "0.2000000".
func formatBound(v float64) string {
	if math.IsInf(v, 1) {
		return "no maximum"
	}
	if math.IsInf(v, -1) {
		return "no minimum"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// validateAddressSyntax applies the parsing half of §7.4.
func validateAddressSyntax(in TunnelInput, errs *Errors) {
	seen := map[string]bool{}
	for i, addr := range in.Addresses {
		field := fmt.Sprintf("addresses.%d.address", i)
		prefix, err := ParsePrefix(addr.Address, addr.PrefixLength)
		if err != nil {
			errs.Add(field, CodeInvalidAddress, capitalise(err.Error())+".", nil)
			continue
		}
		if prefix.Addr().IsMulticast() {
			errs.Add(field, CodeInvalidAddress, "A tunnel address may not be a multicast address.", nil)
			continue
		}
		// /31 is explicitly permitted for IPv4 point-to-point links (RFC 3021),
		// which is exactly what a tunnel is; /32 needs an explicit peer.
		if prefix.Addr().Is4() && prefix.Bits() == 32 && strings.TrimSpace(addr.PeerAddress) == "" {
			errs.Add(fmt.Sprintf("addresses.%d.prefix_length", i), CodeInvalidPrefixLen,
				"A /32 address needs an explicit peer address, or use /31 for a two-address "+
					"point-to-point link or /30 for the classic four-address form.", nil)
		}
		if addr.PeerAddress != "" {
			peer, err := netip.ParseAddr(strings.TrimSpace(addr.PeerAddress))
			if err != nil {
				errs.Add(fmt.Sprintf("addresses.%d.peer_address", i), CodeInvalidAddress,
					fmt.Sprintf("%q is not an IP address.", addr.PeerAddress), nil)
			} else if peer.Unmap().Is4() != prefix.Addr().Is4() {
				errs.Add(fmt.Sprintf("addresses.%d.peer_address", i), CodeInvalidAddress,
					"The peer address is not in the same address family as the address.", nil)
			}
		}

		key := prefix.String()
		if seen[key] {
			errs.Add(field, CodeAddressConflict,
				fmt.Sprintf("%s is listed more than once on this tunnel.", key), nil)
		}
		seen[key] = true
	}
}

// CollectState gathers the live picture every stateful rule checks against.
func (v *Validator) CollectState(ctx context.Context) (State, error) {
	var st State
	links, err := v.Links.List(ctx)
	if err != nil {
		return st, fmt.Errorf("reading interfaces: %w", err)
	}
	st.Links = links

	routes, err := v.Links.Routes(ctx)
	if err != nil {
		// A host with no routing table readable is unusual but not a reason to
		// refuse validation; the overlap rule simply has nothing to check.
		routes = nil
	}
	st.Routes = routes

	if v.Repo != nil {
		tunnels, err := v.Repo.ExistingTunnels(ctx)
		if err != nil {
			return st, fmt.Errorf("reading stored tunnels: %w", err)
		}
		st.Tunnels = tunnels
	}
	return st, nil
}

// Validate runs both phases. Static rules run first and short-circuit: nothing
// is read from the kernel or the database until the input itself is sound.
func (v *Validator) Validate(ctx context.Context, in TunnelInput) (Result, error) {
	if errs := ValidateStatic(in); !errs.Empty() {
		return Result{}, errs
	}
	st, err := v.CollectState(ctx)
	if err != nil {
		return Result{}, err
	}
	return v.ValidateAgainst(ctx, in, st)
}

// ValidateAgainst applies the rules that need live state: name and endpoint
// collisions, address conflicts, route overlap, public ranges, and the MTU
// advisory (§7.1, §7.4, §7.5, §7.6).
func (v *Validator) ValidateAgainst(ctx context.Context, in TunnelInput, st State) (Result, error) {
	var result Result
	errs := &Errors{}

	if err := v.checkNameCollision(in, st, errs); err != nil {
		return result, err
	}
	v.checkEndpointConflicts(in, st, errs, &result)
	v.checkAddressConflicts(in, st, errs, &result)
	v.checkLocalEndpointPresent(in, st, errs, &result)
	v.checkPool(ctx, in, errs)

	if !errs.Empty() {
		return result, errs
	}

	result.Mtu = v.adviseMtu(in, st)
	if w, ok := result.Mtu.Warning(); ok {
		result.AddWarning(w)
	}
	v.addKeyWarnings(in, &result)
	if in.PersistenceTypeID == model.PersistenceTypeRuntime {
		result.AddWarning(Warning{
			Code:  WarnRuntimeOnly,
			Field: "persistence_type_id",
			Message: "This tunnel is configured in the running kernel only. It will not exist after a " +
				"reboot. Choose systemd or networkd persistence if it should come back.",
		})
	}
	return result, nil
}

// checkNameCollision applies the live half of §7.1 and the adoption rule of
// §7.5. A tunnel that already exists and matches the request is not a conflict
// to be renamed around; it is a candidate for adoption.
func (v *Validator) checkNameCollision(in TunnelInput, st State, errs *Errors) error {
	for _, existing := range st.Tunnels {
		if existing.TunnelID == in.TunnelID {
			continue
		}
		if existing.InterfaceName == in.InterfaceName {
			errs.Add("interface_name", CodeNameConflict,
				fmt.Sprintf("A tunnel named %q already exists in the panel.", in.InterfaceName),
				map[string]any{"tunnel_id": existing.TunnelID})
			return nil
		}
	}

	observed, exists := st.LinkByName(in.InterfaceName)
	if !exists {
		return nil
	}
	// Updating a tunnel that already exists under its own name is normal.
	if in.TunnelID != 0 && v.tunnelOwnsName(in.TunnelID, in.InterfaceName, st) {
		return nil
	}

	if observed.IsTunnel() {
		return &AdoptableError{
			InterfaceName: in.InterfaceName,
			Reason: "An interface of this name already exists on this system and is a tunnel, but the " +
				"panel has no record of it. Adopt it to import its parameters instead of creating a " +
				"second one.",
			AdoptPath: v.AdoptPath,
			Observed:  observedSummary(observed),
		}
	}
	errs.Add("interface_name", CodeNameConflict,
		fmt.Sprintf("The interface %q already exists on this system and is not a tunnel.", in.InterfaceName),
		map[string]any{"kind": observed.Kind, "index": observed.Index})
	return nil
}

func (v *Validator) tunnelOwnsName(id int64, name string, st State) bool {
	for _, existing := range st.Tunnels {
		if existing.TunnelID == id {
			return existing.InterfaceName == name
		}
	}
	return false
}

func observedSummary(l link.Link) map[string]any {
	out := map[string]any{
		"interface_name": l.Name,
		"kind":           l.Kind,
		"mtu":            l.MTU,
		"oper_state":     l.OperState,
		"is_up":          l.IsUp,
	}
	if l.Tunnel != nil {
		out["local_endpoint"] = l.Tunnel.Local
		out["remote_endpoint"] = l.Tunnel.Remote
		out["ttl"] = l.Tunnel.Ttl
		if l.Tunnel.IKey != nil {
			out["ikey"] = *l.Tunnel.IKey
		}
		if l.Tunnel.OKey != nil {
			out["okey"] = *l.Tunnel.OKey
		}
	}
	addresses := make([]string, 0, len(l.Addresses))
	for _, a := range l.Addresses {
		addresses = append(addresses, a.String())
	}
	out["addresses"] = addresses
	return out
}

// checkEndpointConflicts applies §7.5: the tuple that actually collides at the
// kernel level is (local, remote, ikey, okey), and it collides in either
// direction.
func (v *Validator) checkEndpointConflicts(in TunnelInput, st State, errs *Errors, result *Result) {
	for _, existing := range st.Tunnels {
		if existing.TunnelID == in.TunnelID {
			continue
		}
		if !sameEndpointPair(in, existing) || !sameKeys(in.IKey, in.OKey, existing.IKey, existing.OKey) {
			continue
		}
		errs.Add("remote_endpoint", CodeEndpointConflict,
			fmt.Sprintf("The tunnel %q already uses this combination of endpoints and keys. "+
				"The kernel identifies a GRE tunnel by exactly that, so a second one would collide.",
				existing.InterfaceName),
			map[string]any{"tunnel_id": existing.TunnelID, "interface_name": existing.InterfaceName})
		return
	}

	// The same check against live state, which catches a tunnel created outside
	// the panel.
	for _, l := range st.Links {
		if !l.IsTunnel() || l.Tunnel == nil || l.Name == in.InterfaceName {
			continue
		}
		if !sameEndpointStrings(in.LocalEndpoint, in.RemoteEndpoint, l.Tunnel.Local, l.Tunnel.Remote) {
			continue
		}
		if !sameKeys(in.IKey, in.OKey, keyPtr(l.Tunnel.IKey), keyPtr(l.Tunnel.OKey)) {
			continue
		}
		errs.Add("remote_endpoint", CodeEndpointConflict,
			fmt.Sprintf("The interface %q on this system already uses this combination of endpoints "+
				"and keys, though the panel does not manage it. Adopt it or change the key.", l.Name),
			map[string]any{"interface_name": l.Name, "adopt_path": v.AdoptPath})
		return
	}
}

func keyPtr(v *uint32) *int64 {
	if v == nil {
		return nil
	}
	n := int64(*v)
	return &n
}

func sameEndpointPair(in TunnelInput, existing ExistingTunnel) bool {
	return sameEndpointStrings(in.LocalEndpoint, in.RemoteEndpoint, existing.LocalEndpoint, existing.RemoteEndpoint)
}

// sameEndpointStrings compares an endpoint pair in either direction, since a
// tunnel with the endpoints swapped is the same kernel-level tuple.
func sameEndpointStrings(localA, remoteA, localB, remoteB string) bool {
	a1, err1 := netip.ParseAddr(strings.TrimSpace(localA))
	a2, err2 := netip.ParseAddr(strings.TrimSpace(remoteA))
	b1, err3 := netip.ParseAddr(strings.TrimSpace(localB))
	b2, err4 := netip.ParseAddr(strings.TrimSpace(remoteB))
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return false
	}
	a1, a2, b1, b2 = a1.Unmap(), a2.Unmap(), b1.Unmap(), b2.Unmap()
	return (a1 == b1 && a2 == b2) || (a1 == b2 && a2 == b1)
}

func sameKeys(ia, oa, ib, ob *int64) bool {
	return sameKey(ia, ib) && sameKey(oa, ob)
}

func sameKey(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// checkAddressConflicts applies the live half of §7.4: an address already on
// another interface, a subnet overlapping an existing route, and a globally
// routable range.
func (v *Validator) checkAddressConflicts(in TunnelInput, st State, errs *Errors, result *Result) {
	allowPublic := v.settingBool("addressing.allow_public_ranges", false)
	checkOverlap := v.settingBool("addressing.check_route_overlap", true)

	for i, addr := range in.Addresses {
		field := fmt.Sprintf("addresses.%d.address", i)
		prefix, err := ParsePrefix(addr.Address, addr.PrefixLength)
		if err != nil {
			continue // already reported by the static phase
		}

		for _, l := range st.Links {
			if l.Name == in.InterfaceName {
				continue
			}
			for _, existing := range l.Addresses {
				if existing.Address == prefix.Addr().String() {
					errs.Add(field, CodeAddressConflict,
						fmt.Sprintf("%s is already assigned to the interface %q.", existing.Address, l.Name),
						map[string]any{"interface_name": l.Name})
				}
			}
		}

		for _, existing := range st.Tunnels {
			if existing.TunnelID == in.TunnelID {
				continue
			}
			for _, stored := range existing.Addresses {
				if strings.EqualFold(strings.TrimSpace(stored.Address), prefix.Addr().String()) {
					errs.Add(field, CodeAddressConflict,
						fmt.Sprintf("%s is already assigned to the tunnel %q.", stored.Address, existing.InterfaceName),
						map[string]any{"tunnel_id": existing.TunnelID})
				}
			}
		}

		network := prefix.Masked()
		if checkOverlap {
			if route, overlaps := overlappingRoute(network, st.Routes, in.InterfaceName); overlaps {
				if in.Force {
					result.AddWarning(Warning{
						Code: WarnRouteOverlap, Field: field,
						Message: fmt.Sprintf("The subnet %s overlaps the existing route %s via %s. "+
							"You chose to proceed anyway.", network, route.Destination, route.Device),
						Details: map[string]any{"route": route.Destination, "device": route.Device},
					})
				} else {
					errs.Add(field, CodeRouteOverlap,
						fmt.Sprintf("The subnet %s overlaps the existing route %s via %s. Choose another "+
							"subnet, or set force to proceed.", network, route.Destination, route.Device),
						map[string]any{"route": route.Destination, "device": route.Device})
				}
			}
		}

		if IsPublicRange(prefix.Addr()) {
			details := map[string]any{"subnet": network.String()}
			message := fmt.Sprintf("The subnet %s is globally routable. Assigning it to a tunnel squats "+
				"on address space belonging to someone else and blackholes those destinations from this "+
				"server.", network)
			if allowPublic || in.Force {
				result.AddWarning(Warning{Code: WarnPublicRange, Field: field, Message: message, Details: details})
			} else {
				errs.Add(field, CodePublicRange, message+" Enable addressing.allow_public_ranges or set "+
					"force to proceed.", details)
			}
		}
	}
}

// overlappingRoute finds a route whose destination intersects the subnet.
// Routes belonging to the interface being configured are skipped, since those
// are the tunnel's own.
func overlappingRoute(network netip.Prefix, routes []link.Route, ownDevice string) (link.Route, bool) {
	for _, r := range routes {
		if r.Device == ownDevice || r.IsDefault || r.Destination == "" || r.Destination == "default" {
			continue
		}
		dest, err := netip.ParsePrefix(r.Destination)
		if err != nil {
			continue
		}
		if PrefixesOverlap(network, dest) {
			return r, true
		}
	}
	return link.Route{}, false
}

// checkPool validates the tunnel number against the selected pool, which is
// where the legacy 1-255 limit actually belongs (§7.3).
func (v *Validator) checkPool(ctx context.Context, in TunnelInput, errs *Errors) {
	if in.AddressPoolID == nil || v.Repo == nil {
		return
	}
	pool, err := v.Repo.PoolByID(ctx, *in.AddressPoolID)
	if err != nil {
		errs.Addf("address_pool_id", CodeUnknownPool, "Address pool %d does not exist.", *in.AddressPoolID)
		return
	}
	if !pool.IsEnabled {
		errs.Addf("address_pool_id", CodeUnknownPool,
			"The address pool %q is disabled. Enable it before allocating from it.", pool.Title)
	}
}

// adviseMtu computes the §7.6 advisory against the interface the tunnel will
// actually egress through.
//
// tunnel.auto_mtu_from_underlay decides whether the underlay is consulted at
// all. With it off the overhead is still computed and reported — that is the
// arithmetic of the encapsulation and does not depend on any interface — but no
// recommendation is derived and no mismatch warning is raised, because both of
// those are statements about an underlay the operator has asked the panel not
// to read. The setting had no consumer at all, so turning it off changed
// nothing and the panel went on measuring an interface it had been told to
// ignore.
func (v *Validator) adviseMtu(in TunnelInput, st State) MtuAdvice {
	if !v.settingBool("tunnel.auto_mtu_from_underlay", true) {
		return AdviseMtu(in, "", 0)
	}
	device, mtu := underlayOf(in, st)
	return AdviseMtu(in, device, mtu)
}

// underlayOf finds the interface the local endpoint lives on, falling back to
// the default-route interface, which is where the traffic would leave from.
func underlayOf(in TunnelInput, st State) (string, int) {
	if in.BindDevice != "" {
		if l, ok := st.LinkByName(in.BindDevice); ok {
			return l.Name, l.MTU
		}
	}
	local, err := netip.ParseAddr(strings.TrimSpace(in.LocalEndpoint))
	if err == nil {
		local = local.Unmap()
		for _, l := range st.Links {
			for _, addr := range l.Addresses {
				if parsed, perr := netip.ParseAddr(addr.Address); perr == nil && parsed.Unmap() == local {
					return l.Name, l.MTU
				}
			}
		}
	}
	for device := range link.DefaultRouteDevices(st.Routes) {
		if l, ok := st.LinkByName(device); ok {
			return l.Name, l.MTU
		}
	}
	return "", 0
}

// checkLocalEndpointPresent applies the softer half of §7.2. A local endpoint
// that is not on this host is a warning rather than a hard error, because
// floating and failover addresses are legitimate — but proceeding takes force,
// since the far more common cause is a typo, and the resulting tunnel comes up
// and carries nothing.
func (v *Validator) checkLocalEndpointPresent(in TunnelInput, st State, errs *Errors, result *Result) {
	local, err := netip.ParseAddr(strings.TrimSpace(in.LocalEndpoint))
	if err != nil {
		return // already reported by the static phase
	}
	local = local.Unmap()
	for _, l := range st.Links {
		for _, addr := range l.Addresses {
			if parsed, perr := netip.ParseAddr(addr.Address); perr == nil && parsed.Unmap() == local {
				return
			}
		}
	}

	message := fmt.Sprintf("The local endpoint %s is not currently assigned to any interface on this "+
		"server. That is legitimate for a floating or failover address, but if it is a typo the "+
		"tunnel will come up and carry no traffic.", local)
	details := map[string]any{"local_endpoint": local.String()}

	if in.Force {
		result.AddWarning(Warning{
			Code: WarnLocalEndpointNotFound, Field: "local_endpoint",
			Message: message + " You chose to proceed anyway.", Details: details,
		})
		return
	}
	errs.Add("local_endpoint", CodeInvalidEndpoint, message+" Set force to proceed.", details)
}

// addKeyWarnings reports the two key mistakes that produce a tunnel which comes
// up locally and carries nothing.
func (v *Validator) addKeyWarnings(in TunnelInput, result *Result) {
	switch {
	case in.IKey == nil && in.OKey == nil:
		result.AddWarning(Warning{
			Code: WarnNoKey, Field: "ikey",
			Message: "This tunnel has no GRE key. That is valid, but both ends must agree, and a keyed " +
				"tunnel is easier to tell apart from another one between the same two addresses.",
		})
	case !sameKey(in.IKey, in.OKey):
		result.AddWarning(Warning{
			Code: WarnKeyMismatch, Field: "okey",
			Message: "The inbound and outbound GRE keys differ. That is supported, but the far end must " +
				"mirror them exactly: its inbound key must equal this outbound key and the reverse.",
		})
	}
	if in.IKey != nil && *in.IKey == LegacyDefaultKey && in.OKey != nil && *in.OKey == LegacyDefaultKey {
		result.AddWarning(Warning{
			Code: WarnLegacyDefaultKey, Field: "ikey",
			Message: fmt.Sprintf("The GRE key %d is the one the install script this panel replaces "+
				"shipped to every user. Change it unless you are matching an existing tunnel.",
				int64(LegacyDefaultKey)),
		})
	}
}

// LegacyDefaultKey is the GRE key the script this panel replaces used for every
// tunnel of every one of its users (§1).
const LegacyDefaultKey int64 = 2749365187

func (v *Validator) settingBool(key string, def bool) bool {
	if v.Settings == nil {
		return def
	}
	return v.Settings.Bool(key)
}

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// AsErrors extracts the field-level failures from an error, if it carries any.
func AsErrors(err error) (*Errors, bool) {
	var errs *Errors
	if errors.As(err, &errs) {
		return errs, true
	}
	return nil, false
}

// AsAdoptable extracts an adoption suggestion from an error, if it is one.
func AsAdoptable(err error) (*AdoptableError, bool) {
	var adoptable *AdoptableError
	if errors.As(err, &adoptable) {
		return adoptable, true
	}
	return nil, false
}

// GreKeyToDotted renders a GRE key in the dotted-quad form iproute2 prints
// (§2). The panel always shows the operator the integer; this exists for the
// fallback path, for adopting a tunnel created by the legacy script, and for
// explaining what `ip -d link show` is displaying.
func GreKeyToDotted(key uint32) string { return link.KeyToDotted(key) }

// GreKeyFromDotted parses a GRE key from either the dotted-quad form or a plain
// integer.
func GreKeyFromDotted(s string) (uint32, error) { return link.KeyFromDotted(s) }

// FormatGreKey renders a key for display: always the integer (§2).
func FormatGreKey(key *int64) string {
	if key == nil {
		return "none"
	}
	return strconv.FormatInt(*key, 10)
}
