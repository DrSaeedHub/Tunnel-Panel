package validate

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// RouteValidator checks a forwarding rule against §6.1 and §6.2 of the port
// forwarding specification.
//
// It owns no state of its own: kernel state comes from the link manager and the
// socket table, stored state from the repository, and all of it is collected
// once per pass so that every rule sees the same snapshot.
type RouteValidator struct {
	Links    link.LinkManager
	Repo     RouteRepository
	Sockets  SocketTable
	Settings Settings
}

// NewRouteValidator returns a validator for forwarding rules.
func NewRouteValidator(links link.LinkManager, repo RouteRepository, sockets SocketTable, set Settings) *RouteValidator {
	return &RouteValidator{Links: links, Repo: repo, Sockets: sockets, Settings: set}
}

// RouteState is the live picture route validation checks against. It is
// collected once per pass so that every rule sees the same snapshot.
type RouteState struct {
	Links     []link.Link
	Routes    []ExistingRoute
	Listeners []rules.Listener
	// ListenersRead reports whether the socket table could be read at all. A
	// host that refuses it is reported rather than silently treated as one with
	// nothing listening.
	ListenersRead bool
}

// LocalAddresses returns every address assigned to this host, parsed.
func (s RouteState) LocalAddresses() []netip.Addr {
	var out []netip.Addr
	for _, l := range s.Links {
		for _, a := range l.Addresses {
			if addr, err := netip.ParseAddr(a.Address); err == nil {
				out = append(out, addr.Unmap())
			}
		}
	}
	return out
}

// HasLocalAddress reports whether an address is assigned to this host.
func (s RouteState) HasLocalAddress(address string) bool {
	want, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	want = want.Unmap()
	for _, addr := range s.LocalAddresses() {
		if addr == want {
			return true
		}
	}
	return false
}

// HasInterface reports whether an interface of that name exists here.
func (s RouteState) HasInterface(name string) bool {
	for _, l := range s.Links {
		if l.Name == name {
			return true
		}
	}
	return false
}

// ApplyDefaults fills in what the request left out, before validation runs
// against it (§6.1).
//
// The one that matters is the bind address: leaving it empty means "this
// server's own address", and the panel resolves that rather than making the
// operator look it up — the frontend prefills the same value, so what they see
// is what is stored. The rest come from the routes.* settings, so a shop that
// always relays UDP or always preserves the client address configures that once
// instead of on every rule.
func (v *RouteValidator) ApplyDefaults(ctx context.Context, in *RouteInput) error {
	if in.RouteProtocolID == 0 {
		in.RouteProtocolID = v.settingInt("routes.default_protocol", model.RouteProtocolTCP)
	}
	if in.NatModeID == 0 {
		in.NatModeID = v.settingInt("routes.default_nat_mode", model.NatModeMasquerade)
	}
	if in.LoadBalanceModeID == 0 {
		in.LoadBalanceModeID = model.LoadBalanceModeNone
	}

	if strings.TrimSpace(in.BindAddress) == "" && v.Links != nil {
		links, err := v.Links.List(ctx)
		if err != nil {
			return fmt.Errorf("reading interfaces to resolve the bind address: %w", err)
		}
		routes, err := v.Links.Routes(ctx)
		if err != nil {
			// Without a routing table the primary address cannot be identified
			// with confidence, but any global address is still better than
			// none, and DefaultBindAddress falls back to one.
			routes = nil
		}
		if address, ok := DefaultBindAddress(links, routes, in.Family()); ok {
			in.BindAddress = address
		}
	}

	// The family is derived rather than asked for: the addresses already say
	// which one this is, and a field that can disagree with them is a field
	// that eventually does.
	if in.AddressFamilyID == 0 {
		switch in.Family() {
		case rules.FamilyIPv6:
			in.AddressFamilyID = model.AddressFamilyIPv6
		case rules.FamilyIPv4:
			in.AddressFamilyID = model.AddressFamilyIPv4
		}
	}

	// A rule that sends traffic through a tunnel gets MSS clamping by default,
	// because that is precisely the case where its absence produces connections
	// that establish and then stall.
	if in.TunnelID != nil && !in.IsClampMssToPmtu {
		in.IsClampMssToPmtu = v.settingBool("routes.default_clamp_mss", true)
	}
	return nil
}

func (v *RouteValidator) settingInt(key string, def int64) int64 {
	if v.Settings == nil {
		return def
	}
	if value := v.Settings.Int(key); value != 0 {
		return value
	}
	return def
}

func (v *RouteValidator) settingBool(key string, def bool) bool {
	if v.Settings == nil {
		return def
	}
	return v.Settings.Bool(key)
}

// ValidateRouteStatic applies every rule that needs no live state: the syntax
// of the addresses, the ports, the ranges and the numeric fields.
//
// This phase runs first and short-circuits, so nothing is read from the kernel
// or from the database until the request itself is sound.
func ValidateRouteStatic(in RouteInput) *Errors {
	errs := &Errors{}

	validateRouteTitle(in, errs)
	validateRouteLookups(in, errs)
	validateRouteAddresses(in, errs)
	validateRoutePorts(in, errs)
	validateRouteNumbers(in, errs)
	validateAllowedSources(in, errs)

	return errs
}

func validateRouteTitle(in RouteInput, errs *Errors) {
	title := strings.TrimSpace(in.RouteRuleTitle)
	switch {
	case title == "":
		errs.Add("route_rule_title", CodeInvalidRouteTitle,
			"A forwarding rule needs a name: it is how you will recognise it in the list, "+
				"in the audit log and in the generated rules.", nil)
	case len(title) > MaxRouteTitleLength:
		errs.Addf("route_rule_title", CodeInvalidRouteTitle,
			"The name is %d characters; the maximum is %d.", len(title), MaxRouteTitleLength)
	}
}

func validateRouteLookups(in RouteInput, errs *Errors) {
	if model.RouteProtocolName(in.RouteProtocolID) == "" {
		errs.Addf("route_protocol_id", CodeInvalidRouteProtocol,
			"%d is not a known protocol; a rule forwards TCP, UDP, or both.", in.RouteProtocolID)
	}
	if model.NatModeName(in.NatModeID) == "" {
		errs.Addf("nat_mode_id", CodeInvalidNatMode,
			"%d is not a known NAT mode.", in.NatModeID)
	}
	if in.LoadBalanceModeID != 0 && model.LoadBalanceModeName(in.LoadBalanceModeID) == "" {
		errs.Addf("load_balance_mode_id", CodeInvalidLoadBalanceMode,
			"%d is not a known load balancing mode.", in.LoadBalanceModeID)
	}
	if in.AddressFamilyID != 0 &&
		in.AddressFamilyID != model.AddressFamilyIPv4 && in.AddressFamilyID != model.AddressFamilyIPv6 {
		errs.Addf("address_family_id", CodeInvalidAddressFamily,
			"%d is not a known address family.", in.AddressFamilyID)
	}
}

// validateRouteAddresses applies the parsing half of §6.1, including the rule
// that every address on one rule must be in the same family: a rule that binds
// an IPv4 address and forwards to an IPv6 one describes a translation this
// subsystem does not do.
func validateRouteAddresses(in RouteInput, errs *Errors) {
	family := ""

	// The bind address is optional in the request: empty means the server's
	// primary address, which the panel fills in before this runs again.
	if bind := strings.TrimSpace(in.BindAddress); bind != "" {
		addr, err := netip.ParseAddr(bind)
		switch {
		case err != nil:
			errs.Add("bind_address", CodeInvalidBindAddress,
				fmt.Sprintf("%q is not an IP address. Leave it empty to use this server's primary "+
					"address, or use 0.0.0.0 to mean every local address.", in.BindAddress),
				map[string]any{"value": in.BindAddress})
		case addr.Unmap().IsMulticast():
			errs.Add("bind_address", CodeInvalidBindAddress,
				"A relay cannot bind a multicast address.", nil)
		default:
			family = rules.FamilyOf(addr.Unmap())
		}
	}

	for i, d := range in.EffectiveDestinations() {
		field := "destination_address"
		if i > 0 {
			field = fmt.Sprintf("destinations.%d.address", i-1)
		}
		address := strings.TrimSpace(d.Address)
		if address == "" {
			errs.Add(field, CodeInvalidDestination,
				"A forwarding rule needs a destination address.", nil)
			continue
		}
		addr, err := netip.ParseAddr(address)
		if err != nil {
			errs.Add(field, CodeInvalidDestination,
				fmt.Sprintf("%q is not an IP address.", d.Address),
				map[string]any{"value": d.Address})
			continue
		}
		addr = addr.Unmap()
		switch {
		case addr.IsUnspecified():
			errs.Add(field, CodeInvalidDestination,
				"The destination may not be the unspecified address: traffic has to go somewhere.", nil)
			continue
		case addr.IsMulticast():
			errs.Add(field, CodeInvalidDestination,
				"The destination may not be a multicast address.", nil)
			continue
		}
		if destFamily := rules.FamilyOf(addr); family != "" && destFamily != family {
			errs.Add(field, CodeAddressFamilyMismatch,
				fmt.Sprintf("The destination %s is %s but the rule binds an %s address. A rule works "+
					"in one address family.", addr, familyLabel(destFamily), familyLabel(family)),
				map[string]any{"bind_family": family, "destination_family": destFamily})
		} else if family == "" {
			family = rules.FamilyOf(addr)
		}
	}

	if in.NatModeID == model.NatModeSnat {
		validateSnatAddressSyntax(in, family, errs)
	} else if strings.TrimSpace(in.SnatAddress) != "" {
		errs.Add("snat_address", CodeSnatAddressUnused,
			"A source address is only used when the NAT mode is SNAT. Choose SNAT, or clear the address.",
			nil)
	}

	if in.AddressFamilyID != 0 && family != "" {
		declared := rules.FamilyIPv4
		if in.AddressFamilyID == model.AddressFamilyIPv6 {
			declared = rules.FamilyIPv6
		}
		if declared != family {
			errs.Add("address_family_id", CodeAddressFamilyMismatch,
				fmt.Sprintf("The rule is declared as %s but its addresses are %s.",
					familyLabel(declared), familyLabel(family)), nil)
		}
	}
}

func validateSnatAddressSyntax(in RouteInput, family string, errs *Errors) {
	address := strings.TrimSpace(in.SnatAddress)
	if address == "" {
		errs.Add("snat_address", CodeSnatAddressRequired,
			"SNAT rewrites the source address to one you choose, so it needs that address. "+
				"Use masquerade instead to have the outgoing interface's address used automatically.", nil)
		return
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		errs.Add("snat_address", CodeInvalidSnatAddress,
			fmt.Sprintf("%q is not an IP address.", in.SnatAddress), nil)
		return
	}
	addr = addr.Unmap()
	switch {
	case addr.IsUnspecified(), addr.IsMulticast(), addr.IsLoopback():
		errs.Add("snat_address", CodeInvalidSnatAddress,
			fmt.Sprintf("%s cannot be used as a source address for relayed traffic.", addr), nil)
	case family != "" && rules.FamilyOf(addr) != family:
		errs.Add("snat_address", CodeAddressFamilyMismatch,
			fmt.Sprintf("The source address %s is %s but the rule works in %s.",
				addr, familyLabel(rules.FamilyOf(addr)), familyLabel(family)), nil)
	}
}

// validateRoutePorts applies the port half of §6.1, including the range width
// rule: ranges map one to one, so widths that differ have no mapping at all.
func validateRoutePorts(in RouteInput, errs *Errors) {
	bind := in.BindPorts()
	validatePortRange("bind_port", "bind_port_range_end", bind, errs)

	for i, d := range in.EffectiveDestinations() {
		portField, endField := "destination_port", "destination_port_range_end"
		if i > 0 {
			portField = fmt.Sprintf("destinations.%d.port", i-1)
			endField = fmt.Sprintf("destinations.%d.port_range_end", i-1)
		}
		ports := rules.PortRange{Port: d.Port, End: d.PortRangeEnd}
		if !validatePortRange(portField, endField, ports, errs) {
			continue
		}
		if bind.Port < MinPort || bind.Width() == ports.Width() {
			continue
		}
		errs.Add(endField, CodePortRangeWidthMismatch,
			fmt.Sprintf("The bind range %s covers %d port(s) and the destination range %s covers %d. "+
				"A range is mapped one port to one port, so the two have to be the same width: either "+
				"make them match, or forward a single port.",
				bind, bind.Width(), ports, ports.Width()),
			map[string]any{
				"bind_ports": bind.String(), "bind_width": bind.Width(),
				"destination_ports": ports.String(), "destination_width": ports.Width(),
			})
	}
}

func validatePortRange(portField, endField string, r rules.PortRange, errs *Errors) bool {
	ok := true
	if r.Port < MinPort || r.Port > MaxPort {
		errs.Addf(portField, CodeInvalidPort, "A port must be between %d and %d.", MinPort, MaxPort)
		ok = false
	}
	if r.End == 0 {
		return ok
	}
	if r.End < MinPort || r.End > MaxPort {
		errs.Addf(endField, CodeInvalidPort, "A port must be between %d and %d.", MinPort, MaxPort)
		return false
	}
	if r.End <= r.Port {
		errs.Addf(endField, CodeInvalidPortRange,
			"The end of a port range must be above its start; %d is not above %d. Leave it empty to "+
				"forward a single port.", r.End, r.Port)
		return false
	}
	return ok
}

func validateRouteNumbers(in RouteInput, errs *Errors) {
	if in.FwMark != nil && (*in.FwMark < 0 || *in.FwMark > MaxFwMark) {
		errs.Addf("fwmark", CodeInvalidFwMark, "A firewall mark must be between 0 and %d.", int64(MaxFwMark))
	}
	if in.MaxConnectionsPerSource != nil &&
		(*in.MaxConnectionsPerSource < 1 || *in.MaxConnectionsPerSource > MaxConnectionsPerSource) {
		errs.Addf("max_connections_per_source", CodeInvalidConnectionLimit,
			"The concurrent connection limit must be between 1 and %d. Leave it empty for no limit.",
			MaxConnectionsPerSource)
	}
	if in.ConnectionRateLimit != nil &&
		(*in.ConnectionRateLimit < 1 || *in.ConnectionRateLimit > MaxConnectionRateLimit) {
		errs.Addf("connection_rate_limit", CodeInvalidConnectionLimit,
			"The connection rate limit is in new connections per minute and must be between 1 and %d. "+
				"Leave it empty for no limit.", MaxConnectionRateLimit)
	}

	if len(in.Destinations) > MaxDestinations {
		errs.Addf("destinations", CodeInvalidDestination,
			"A rule may have at most %d destinations.", MaxDestinations)
	}
	for i, d := range in.Destinations {
		if d.Weight < 0 || d.Weight > MaxDestinationWeight {
			errs.Addf(fmt.Sprintf("destinations.%d.weight", i), CodeInvalidWeight,
				"A weight must be between 1 and %d. Leave it empty for an equal share.",
				MaxDestinationWeight)
		}
	}

	if len(in.AllowedSources) > MaxAllowedSources {
		errs.Addf("allowed_sources", CodeInvalidCidr,
			"A rule may have at most %d allowlist entries.", MaxAllowedSources)
	}
	if in.BindInterface != "" {
		if err := InterfaceName(in.BindInterface); err != nil {
			errs.Addf("bind_interface", CodeInvalidName, "The interface name %s.", err.Error())
		}
	}
}

func validateAllowedSources(in RouteInput, errs *Errors) {
	family := in.Family()
	seen := map[string]bool{}
	for i, source := range in.AllowedSources {
		field := fmt.Sprintf("allowed_sources.%d.cidr", i)
		text := strings.TrimSpace(source.Cidr)
		if text == "" {
			errs.Add(field, CodeInvalidCidr, "An allowlist entry needs an address or a CIDR range.", nil)
			continue
		}
		prefix, err := parseCidrOrAddress(text)
		if err != nil {
			errs.Add(field, CodeInvalidCidr,
				fmt.Sprintf("%q is not an address or a CIDR range such as 10.0.0.0/8.", source.Cidr), nil)
			continue
		}
		if entryFamily := rules.FamilyOf(prefix.Addr()); family != "" && entryFamily != family {
			errs.Add(field, CodeAddressFamilyMismatch,
				fmt.Sprintf("%s is %s but this rule works in %s.",
					prefix, familyLabel(entryFamily), familyLabel(family)), nil)
			continue
		}
		if seen[prefix.String()] {
			errs.Add(field, CodeInvalidCidr,
				fmt.Sprintf("%s is listed more than once.", prefix), nil)
		}
		seen[prefix.String()] = true
	}
}

// parseCidrOrAddress accepts both forms an operator writes an allowlist entry
// in: a bare address, meaning that one host, and a CIDR range.
func parseCidrOrAddress(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func familyLabel(family string) string {
	if family == rules.FamilyIPv6 {
		return "IPv6"
	}
	return "IPv4"
}

// ---------------------------------------------------------------- live state

// CollectRouteState gathers the live picture every stateful rule checks
// against.
func (v *RouteValidator) CollectRouteState(ctx context.Context) (RouteState, error) {
	var st RouteState
	if v.Links != nil {
		links, err := v.Links.List(ctx)
		if err != nil {
			return st, fmt.Errorf("reading interfaces: %w", err)
		}
		st.Links = links
	}
	if v.Repo != nil {
		routes, err := v.Repo.ExistingRoutes(ctx)
		if err != nil {
			return st, fmt.Errorf("reading stored forwarding rules: %w", err)
		}
		st.Routes = routes
	}
	if v.Sockets != nil {
		listeners, err := v.Sockets.Listeners()
		if err == nil {
			st.Listeners = listeners
			st.ListenersRead = true
		}
	}
	return st, nil
}

// Validate runs both phases. Static rules run first and short-circuit.
func (v *RouteValidator) Validate(ctx context.Context, in RouteInput) (Result, error) {
	if errs := ValidateRouteStatic(in); !errs.Empty() {
		return Result{}, errs
	}
	st, err := v.CollectRouteState(ctx)
	if err != nil {
		return Result{}, err
	}
	return v.ValidateAgainst(ctx, in, st)
}

// ValidateAgainst applies the rules that need live state: the name collision,
// the port conflicts including range overlap, the locally listening socket, the
// SNAT address, the bind interface, and the advisories.
func (v *RouteValidator) ValidateAgainst(ctx context.Context, in RouteInput, st RouteState) (Result, error) {
	var result Result
	errs := &Errors{}

	v.checkTitleCollision(in, st, errs)
	v.checkTunnel(ctx, in, errs)
	v.checkListenerConflicts(in, st, errs)
	v.checkPortConflicts(in, st, errs, &result)
	v.checkSnatAddressPresent(in, st, errs)
	v.checkBindAddressPresent(in, st, errs, &result)
	v.checkBindInterface(in, st, errs)
	v.checkLoopbackDestination(in, errs, &result)

	if !errs.Empty() {
		return result, errs
	}

	v.addRouteWarnings(in, st, &result)
	return result, nil
}

// checkTitleCollision keeps rule names unique among live rows, which the
// partial unique index also enforces; catching it here means the operator gets
// a field-level message rather than a constraint violation.
func (v *RouteValidator) checkTitleCollision(in RouteInput, st RouteState, errs *Errors) {
	title := strings.TrimSpace(in.RouteRuleTitle)
	for _, existing := range st.Routes {
		if existing.RouteRuleID == in.RouteRuleID {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(existing.Title), title) {
			errs.Add("route_rule_title", CodeRouteTitleConflict,
				fmt.Sprintf("A forwarding rule named %q already exists.", existing.Title),
				map[string]any{"route_rule_id": existing.RouteRuleID})
			return
		}
	}
}

// checkTunnel keeps the tunnel binding of §10 honest: a rule may say its
// destination is reached through one of the panel's tunnels, and one that names
// a tunnel that is not there would otherwise fail at the database with a
// message about a constraint.
func (v *RouteValidator) checkTunnel(ctx context.Context, in RouteInput, errs *Errors) {
	if in.TunnelID == nil || v.Repo == nil {
		return
	}
	exists, err := v.Repo.TunnelExists(ctx, *in.TunnelID)
	if err != nil || exists {
		return
	}
	errs.Addf("tunnel_id", CodeUnknownTunnel,
		"There is no tunnel %d in this panel. Choose one of its tunnels, or enter the destination "+
			"address directly.", *in.TunnelID)
}

// checkPortConflicts applies §6.2: two enabled rules may not claim the same
// listener, and the check is range overlap rather than equality, because
// 20000-20100 and 20050 collide just as surely as two rules on port 2044.
func (v *RouteValidator) checkPortConflicts(in RouteInput, st RouteState, errs *Errors, result *Result) {
	if !in.IsEnabled {
		// A disabled rule generates nothing, so it holds no port. Refusing to
		// store one would make preparing a replacement impossible.
		return
	}
	want := in.BindPorts()
	for _, existing := range st.Routes {
		if existing.RouteRuleID == in.RouteRuleID || !existing.IsEnabled {
			continue
		}
		if !protocolsOverlap(in.RouteProtocolID, existing.RouteProtocolID) {
			continue
		}
		if !bindAddressesOverlap(in.BindAddress, existing.BindAddress) {
			continue
		}
		if !portRangesOverlap(want, existing.Ports()) {
			continue
		}
		errs.Add("bind_port", CodeRoutePortConflict,
			fmt.Sprintf("The rule %q already forwards %s on %s port %s, which overlaps this rule's %s. "+
				"Two enabled rules cannot claim the same listener.",
				existing.Title, describeBind(existing.BindAddress),
				model.RouteProtocolName(existing.RouteProtocolID), existing.Ports(), want),
			map[string]any{
				"route_rule_id": existing.RouteRuleID,
				"title":         existing.Title,
				"bind_address":  existing.BindAddress,
				"bind_ports":    existing.Ports().String(),
			})
		return
	}
}

// checkListenerConflicts is the other half of §6.2, and the one that quietly
// breaks a working service if it is skipped: DNAT in prerouting takes
// precedence over a local listener, so forwarding a port something on this
// server is already listening on sends that service's traffic elsewhere.
func (v *RouteValidator) checkListenerConflicts(in RouteInput, st RouteState, errs *Errors) {
	if !in.IsEnabled || !st.ListenersRead {
		return
	}
	protocol := in.Protocol()
	bind := in.BindPorts()

	for _, l := range st.Listeners {
		if protocol != rules.ProtocolBoth && l.Protocol != protocol {
			continue
		}
		if l.Port < bind.Port || (bind.End > 0 && l.Port > bind.End) ||
			(bind.End == 0 && l.Port != bind.Port) {
			continue
		}
		if !l.Covers(in.BindAddress, l.Port) {
			continue
		}
		if in.Force {
			// Forcing this is legitimate — the operator may be replacing that
			// service with the relay — so it becomes a warning rather than
			// being silently ignored.
			continue
		}
		errs.Add("bind_port", CodePortInUse,
			fmt.Sprintf("%s. Forwarding that port would send its traffic to the destination instead, "+
				"because destination NAT happens before a local socket is consulted, and that service "+
				"would stop working with no error anywhere. Stop or move it first, or set force if "+
				"that is what you intend.", l.Describe()),
			map[string]any{
				"process_name": l.ProcessName, "process_id": l.ProcessID,
				"address": l.Address, "port": l.Port, "protocol": string(l.Protocol),
			})
		return
	}
}

// checkSnatAddressPresent applies the rest of the SNAT rule: the address has to
// be on this host, or the rewritten traffic has a source nothing will answer.
func (v *RouteValidator) checkSnatAddressPresent(in RouteInput, st RouteState, errs *Errors) {
	if in.NatModeID != model.NatModeSnat {
		return
	}
	address := strings.TrimSpace(in.SnatAddress)
	if address == "" || len(st.Links) == 0 {
		return // already reported, or there is nothing to check against
	}
	if st.HasLocalAddress(address) {
		return
	}
	errs.Add("snat_address", CodeSnatAddressNotOnHost,
		fmt.Sprintf("%s is not assigned to any interface on this server. Relayed traffic would leave "+
			"with a source address that nothing here answers for, and the replies would never come "+
			"back.", address),
		map[string]any{"snat_address": address})
}

// checkBindAddressPresent warns when a rule binds an address this host does not
// have. It is not an error: a floating address may be assigned later, and the
// rule is harmless until it is.
func (v *RouteValidator) checkBindAddressPresent(in RouteInput, st RouteState, errs *Errors, result *Result) {
	address := strings.TrimSpace(in.BindAddress)
	if address == "" || isAnyAddress(address) || len(st.Links) == 0 || st.HasLocalAddress(address) {
		return
	}
	result.AddWarning(Warning{
		Code: WarnBindAddressNotFound, Field: "bind_address",
		Message: fmt.Sprintf("The bind address %s is not currently assigned to any interface on this "+
			"server, so nothing will arrive on it. That is legitimate for a floating address that is "+
			"assigned later.", address),
		Details: map[string]any{"bind_address": address},
	})
}

func (v *RouteValidator) checkBindInterface(in RouteInput, st RouteState, errs *Errors) {
	name := strings.TrimSpace(in.BindInterface)
	if name == "" || len(st.Links) == 0 || st.HasInterface(name) {
		return
	}
	errs.Add("bind_interface", CodeInterfaceNotFound,
		fmt.Sprintf("There is no interface named %q on this server, so the rule would match nothing. "+
			"Leave it empty to accept traffic arriving on any interface.", name),
		map[string]any{"interface_name": name})
}

// checkLoopbackDestination applies the loopback rule of §6.1. Forwarding to
// 127.0.0.0/8 additionally needs net.ipv4.conf.*.route_localnet, which the
// panel will not enable by itself (§6.3.4), so the operator is told what they
// would have to do rather than being handed a rule that silently drops traffic.
func (v *RouteValidator) checkLoopbackDestination(in RouteInput, errs *Errors, result *Result) {
	for i, d := range in.EffectiveDestinations() {
		addr, err := netip.ParseAddr(strings.TrimSpace(d.Address))
		if err != nil || !addr.Unmap().IsLoopback() {
			continue
		}
		field := "destination_address"
		if i > 0 {
			field = fmt.Sprintf("destinations.%d.address", i-1)
		}
		message := fmt.Sprintf("%s is a loopback address. Forwarding to it needs "+
			"net.ipv4.conf.<interface>.route_localnet turned on, which the panel will not do for you: "+
			"it makes the kernel treat 127.0.0.0/8 as routable on that interface and exposes every "+
			"service bound to localhost.", addr)
		details := map[string]any{
			"destination_address": addr.String(),
			"sysctl":              "net.ipv4.conf.<interface>.route_localnet",
		}
		if in.Force {
			result.AddWarning(Warning{
				Code: WarnLoopbackDestination, Field: field,
				Message: message + " You chose to proceed anyway; set that sysctl yourself for the " +
					"rule to carry traffic.",
				Details: details,
			})
			continue
		}
		errs.Add(field, CodeLoopbackDestination, message+" Set force to proceed anyway.", details)
	}
}

// addRouteWarnings collects the advisories a successful validation returns:
// what the chosen NAT mode does to the client address, what binding every
// address exposes, and when MSS clamping should be on.
func (v *RouteValidator) addRouteWarnings(in RouteInput, st RouteState, result *Result) {
	if isAnyAddress(in.BindAddress) {
		result.AddWarning(Warning{
			Code: WarnBindAnyAddress, Field: "bind_address",
			Message: "This rule binds every local address, so the relay is reachable on every interface " +
				"this server has, including any it gains later. Name one address to limit it.",
		})
	}

	switch in.NatModeID {
	case model.NatModeMasquerade, model.NatModeSnat:
		result.AddWarning(Warning{
			Code: WarnNatHidesClient, Field: "nat_mode_id",
			Message: "The source address of relayed traffic is rewritten, so the destination sees this " +
				"server rather than the client. Choose None to preserve the client address — but only " +
				"if the destination's return path comes back through this server, typically the far " +
				"end of a tunnel.",
		})
	case model.NatModeNone:
		result.AddWarning(Warning{
			Code: WarnNatPreservesClient, Field: "nat_mode_id",
			Message: "The client address is preserved, which only works when the destination routes its " +
				"replies back through this server. If it does not, connections will be established and " +
				"then hang.",
		})
	}

	if in.TunnelID != nil && !in.IsClampMssToPmtu {
		result.AddWarning(Warning{
			Code: WarnMssClampRecommended, Field: "is_clamp_mss_to_pmtu",
			Message: "This rule sends traffic through a tunnel, whose MTU is smaller than the " +
				"interface the client is on. Without MSS clamping, connections establish normally and " +
				"then stall on the first large transfer, which is the single most common way a working " +
				"tunnel looks broken.",
		})
	}

	if in.IsEnabled && st.ListenersRead && in.Force {
		if listener, found := listenerFor(in, st); found {
			result.AddWarning(Warning{
				Code: WarnPortInUse, Field: "bind_port",
				Message: listener.Describe() + ". You chose to proceed anyway: that service will stop " +
					"receiving traffic on this port as soon as the rule is applied.",
				Details: map[string]any{
					"process_name": listener.ProcessName, "process_id": listener.ProcessID,
					"port": listener.Port,
				},
			})
		}
	}
}

// listenerFor returns the local listener a rule would take the port from.
func listenerFor(in RouteInput, st RouteState) (rules.Listener, bool) {
	protocol := in.Protocol()
	bind := in.BindPorts()
	for _, l := range st.Listeners {
		if protocol != rules.ProtocolBoth && l.Protocol != protocol {
			continue
		}
		if bind.End == 0 && l.Port != bind.Port {
			continue
		}
		if bind.End > 0 && (l.Port < bind.Port || l.Port > bind.End) {
			continue
		}
		if l.Covers(in.BindAddress, l.Port) {
			return l, true
		}
	}
	return rules.Listener{}, false
}

// ---------------------------------------------------------------- overlap

// protocolsOverlap reports whether two rules could match the same packet. Both
// generates rules for TCP and UDP, so it overlaps either.
func protocolsOverlap(a, b int64) bool {
	if a == b {
		return true
	}
	return a == model.RouteProtocolBoth || b == model.RouteProtocolBoth
}

// bindAddressesOverlap reports whether two rules bind addresses that can both
// receive the same packet. A rule on every local address overlaps a rule on any
// single one of them.
func bindAddressesOverlap(a, b string) bool {
	if isAnyAddress(a) || isAnyAddress(b) {
		return true
	}
	first, err1 := netip.ParseAddr(strings.TrimSpace(a))
	second, err2 := netip.ParseAddr(strings.TrimSpace(b))
	if err1 != nil || err2 != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return first.Unmap() == second.Unmap()
}

// portRangesOverlap reports whether two port ranges intersect. This is the
// check a unique index cannot express, and the reason §4 says range overlap has
// to be caught in validation.
func portRangesOverlap(a, b rules.PortRange) bool {
	aEnd, bEnd := a.Port, b.Port
	if a.IsRange() {
		aEnd = a.End
	}
	if b.IsRange() {
		bEnd = b.End
	}
	return a.Port <= bEnd && b.Port <= aEnd
}

func isAnyAddress(address string) bool {
	trimmed := strings.TrimSpace(address)
	if trimmed == "" {
		return false
	}
	addr, err := netip.ParseAddr(trimmed)
	return err == nil && addr.IsUnspecified()
}

func describeBind(address string) string {
	if isAnyAddress(strings.TrimSpace(address)) || strings.TrimSpace(address) == "" {
		return "every local address"
	}
	return address
}

// DefaultBindAddress returns the address a rule binds when the request names
// none: this server's primary address (§6.1).
//
// The primary address is the one on the interface carrying the default route,
// which is the address traffic from elsewhere actually arrives on. Falling back
// to any global address on any non-loopback interface covers a host with no
// default route, where the alternative would be no default at all.
func DefaultBindAddress(links []link.Link, routes []link.Route, family string) (string, bool) {
	if family == "" {
		family = rules.FamilyIPv4
	}
	defaults := link.DefaultRouteDevices(routes)

	var fallback string
	for _, l := range links {
		if l.IsLoopback() {
			continue
		}
		for _, a := range l.Addresses {
			addr, err := netip.ParseAddr(a.Address)
			if err != nil {
				continue
			}
			addr = addr.Unmap()
			if rules.FamilyOf(addr) != family || addr.IsLinkLocalUnicast() || addr.IsLoopback() {
				continue
			}
			if defaults[l.Name] {
				return addr.String(), true
			}
			if fallback == "" {
				fallback = addr.String()
			}
		}
	}
	return fallback, fallback != ""
}
