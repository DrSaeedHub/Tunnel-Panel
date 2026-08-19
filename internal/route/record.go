// Package route owns the port forwarding lifecycle: validate → plan → apply →
// verify → commit or rollback, under the same global mutation lock and with the
// same audit trail as the tunnel subsystem (§7 of the port forwarding
// specification).
//
// The rule this package exists to enforce is the one the tunnel package
// enforces for interfaces: never report success without reading the result back
// from the kernel. An apply here is a transactional replacement of the panel's
// whole netfilter namespace, so the plan renders the complete desired ruleset
// rather than a delta, and verification lists the live ruleset and confirms
// every intended rule is in it.
//
// This package contains no HTTP concerns. Handlers translate; services act.
package route

import (
	"strings"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// Record is a forwarding rule together with its destinations and its source
// allowlist, which are always read and written as one unit: a rule without them
// is not a usable description of anything.
type Record struct {
	model.RouteRule
	Destinations   []model.RouteDestination   `json:"destinations"`
	AllowedSources []model.RouteAllowedSource `json:"allowed_sources"`
}

// normalise makes the two child lists empty rather than nil.
//
// A nil slice marshals to JSON null, and null is not a list: the edit dialog
// seeds itself with route.allowed_sources.map(...), which throws on null and
// takes the whole page down. Every rule created without an allowed-source list
// — which is most of them — could not be edited at all. The API promises two
// arrays here, so it has to send two arrays.
func (r Record) normalise() Record {
	if r.Destinations == nil {
		r.Destinations = []model.RouteDestination{}
	}
	if r.AllowedSources == nil {
		r.AllowedSources = []model.RouteAllowedSource{}
	}
	return r
}

// Spec builds the rendering input for a stored rule. It is the single
// translation from stored state to what reaches netfilter, so the preview, the
// apply and the fake can never be given different things.
func (r Record) Spec() rules.RouteSpec {
	spec := rules.RouteSpec{
		RouteRuleID:            r.RouteRuleID,
		Title:                  r.RouteRuleTitle,
		Protocol:               rules.Protocol(model.RouteProtocolName(r.RouteProtocolID)),
		Family:                 familyOf(r.AddressFamilyID),
		BindAddress:            strings.TrimSpace(r.BindAddress),
		BindPorts:              rules.PortRange{Port: int(r.BindPort), End: intOrZero(r.BindPortRangeEnd)},
		BindInterface:          strings.TrimSpace(stringOrEmpty(r.BindInterface)),
		NatMode:                rules.NatMode(model.NatModeName(r.NatModeID)),
		SnatAddress:            strings.TrimSpace(stringOrEmpty(r.SnatAddress)),
		LoadBalance:            rules.LoadBalanceMode(model.LoadBalanceModeName(r.LoadBalanceModeID)),
		ClampMssToPmtu:         r.IsClampMssToPmtu,
		IncludeLocalOriginated: r.IsIncludeLocalOriginated,
		Logging:                r.IsLoggingEnabled,
		SortOrder:              int(r.SortOrder),
	}
	for _, d := range r.Destinations {
		if !d.IsEnabled {
			// A destination taken out of rotation is not sent traffic. It stays
			// on the rule so putting it back is one click rather than retyping.
			continue
		}
		if d.IsSuppressed {
			// The same, decided by the monitor rather than by the operator. The
			// two are separate columns so that recovering one never re-enables
			// a destination somebody switched off by hand.
			continue
		}
		spec.Destinations = append(spec.Destinations, rules.Destination{
			Address: d.Address,
			Ports:   rules.PortRange{Port: int(d.Port), End: intOrZero(d.PortRangeEnd)},
			Weight:  int(d.Weight),
		})
	}
	if len(spec.Destinations) == 0 && strings.TrimSpace(r.DestinationAddress) != "" {
		// A rule stored before its destination rows, or one whose rows were all
		// disabled, still has the primary destination on the rule itself.
		spec.Destinations = append(spec.Destinations, rules.Destination{
			Address: r.DestinationAddress,
			Ports:   rules.PortRange{Port: int(r.DestinationPort), End: intOrZero(r.DestinationPortRangeEnd)},
			Weight:  1,
		})
	}
	for _, s := range r.AllowedSources {
		if cidr := strings.TrimSpace(s.Cidr); cidr != "" {
			spec.AllowedSources = append(spec.AllowedSources, cidr)
		}
	}
	if r.FwMark != nil {
		mark := uint32(*r.FwMark)
		spec.FwMark = &mark
	}
	if r.MaxConnectionsPerSource != nil {
		spec.MaxConnectionsPerSource = int(*r.MaxConnectionsPerSource)
	}
	if r.ConnectionRateLimit != nil {
		spec.ConnectionRateLimit = int(*r.ConnectionRateLimit)
	}
	return spec
}

// Input turns a stored rule back into the request shape, so an update that
// mentions one field starts from what the rule already is rather than from
// nothing.
func Input(r Record) validate.RouteInput {
	in := validate.RouteInput{
		RouteRuleID:              r.RouteRuleID,
		RouteRuleTitle:           r.RouteRuleTitle,
		Description:              r.Description,
		RouteProtocolID:          r.RouteProtocolID,
		AddressFamilyID:          r.AddressFamilyID,
		BindAddress:              r.BindAddress,
		BindPort:                 int(r.BindPort),
		BindPortRangeEnd:         intOrZero(r.BindPortRangeEnd),
		BindInterface:            stringOrEmpty(r.BindInterface),
		DestinationAddress:       r.DestinationAddress,
		DestinationPort:          int(r.DestinationPort),
		DestinationPortRangeEnd:  intOrZero(r.DestinationPortRangeEnd),
		NatModeID:                r.NatModeID,
		SnatAddress:              stringOrEmpty(r.SnatAddress),
		LoadBalanceModeID:        r.LoadBalanceModeID,
		TunnelID:                 r.TunnelID,
		IsClampMssToPmtu:         r.IsClampMssToPmtu,
		IsIncludeLocalOriginated: r.IsIncludeLocalOriginated,
		IsLoggingEnabled:         r.IsLoggingEnabled,
		FwMark:                   r.FwMark,
		MaxConnectionsPerSource:  r.MaxConnectionsPerSource,
		ConnectionRateLimit:      r.ConnectionRateLimit,
		IsEnabled:                r.IsEnabled,
		SortOrder:                r.SortOrder,
	}
	for _, d := range r.Destinations {
		in.Destinations = append(in.Destinations, validate.RouteDestinationInput{
			RouteDestinationID: d.RouteDestinationID,
			Address:            d.Address,
			Port:               int(d.Port),
			PortRangeEnd:       intOrZero(d.PortRangeEnd),
			Weight:             int(d.Weight),
			IsEnabled:          d.IsEnabled,
			SortOrder:          int(d.SortOrder),
		})
	}
	for _, s := range r.AllowedSources {
		in.AllowedSources = append(in.AllowedSources, validate.RouteAllowedSourceInput{
			RouteAllowedSourceID: s.RouteAllowedSourceID,
			Cidr:                 s.Cidr,
			Description:          s.Description,
		})
	}
	return in
}

// RecordFrom builds the record a request describes, without storing it. The
// preview endpoint renders from this, so what an operator reads before
// committing is rendered from exactly the same shape as what is applied after.
func RecordFrom(in validate.RouteInput) Record {
	// The two lookups the database requires but a request may leave out. These
	// are structural rather than policy: None is what "no load balancing" is,
	// and the family is already implied by the addresses. The policy defaults —
	// protocol, NAT mode, the bind address — come from the settings in
	// RouteValidator.ApplyDefaults.
	if in.LoadBalanceModeID == 0 {
		in.LoadBalanceModeID = model.LoadBalanceModeNone
	}
	if in.AddressFamilyID == 0 {
		in.AddressFamilyID = model.AddressFamilyIPv4
		if in.Family() == rules.FamilyIPv6 {
			in.AddressFamilyID = model.AddressFamilyIPv6
		}
	}

	rec := Record{RouteRule: model.RouteRule{
		RouteRuleID:              in.RouteRuleID,
		RouteRuleTitle:           strings.TrimSpace(in.RouteRuleTitle),
		Description:              in.Description,
		RouteProtocolID:          in.RouteProtocolID,
		AddressFamilyID:          in.AddressFamilyID,
		BindAddress:              strings.TrimSpace(in.BindAddress),
		BindPort:                 int64(in.BindPort),
		BindPortRangeEnd:         nullableInt(in.BindPortRangeEnd),
		BindInterface:            nullableString(in.BindInterface),
		DestinationAddress:       strings.TrimSpace(in.DestinationAddress),
		DestinationPort:          int64(in.DestinationPort),
		DestinationPortRangeEnd:  nullableInt(in.DestinationPortRangeEnd),
		NatModeID:                in.NatModeID,
		SnatAddress:              nullableString(in.SnatAddress),
		LoadBalanceModeID:        in.LoadBalanceModeID,
		TunnelID:                 in.TunnelID,
		IsClampMssToPmtu:         in.IsClampMssToPmtu,
		IsIncludeLocalOriginated: in.IsIncludeLocalOriginated,
		IsLoggingEnabled:         in.IsLoggingEnabled,
		FwMark:                   in.FwMark,
		MaxConnectionsPerSource:  in.MaxConnectionsPerSource,
		ConnectionRateLimit:      in.ConnectionRateLimit,
		IsEnabled:                in.IsEnabled,
		ApplyStatusID:            model.ApplyStatusPending,
		SortOrder:                in.SortOrder,
		IsMonitorEnabled:         in.IsMonitorEnabled,
		MonitorModeID:            in.MonitorModeID,
		MonitorIntervalSeconds:   in.MonitorIntervalSeconds,
		MonitorTimeoutSeconds:    in.MonitorTimeoutSeconds,
		MonitorFailureThreshold:  in.MonitorFailureThreshold,
		MonitorRecoveryThreshold: in.MonitorRecoveryThreshold,
	}}
	for i, d := range in.EffectiveDestinations() {
		rec.Destinations = append(rec.Destinations, model.RouteDestination{
			RouteDestinationID: d.RouteDestinationID,
			RouteRuleID:        in.RouteRuleID,
			Address:            strings.TrimSpace(d.Address),
			Port:               int64(d.Port),
			PortRangeEnd:       nullableInt(d.PortRangeEnd),
			Weight:             int64(weightOrOne(d.Weight)),
			IsEnabled:          d.IsEnabled,
			SortOrder:          int64(i),

			IsMonitorEnabled:         d.IsMonitorEnabled,
			MonitorPort:              d.MonitorPort,
			MonitorIntervalSeconds:   d.MonitorIntervalSeconds,
			MonitorTimeoutSeconds:    d.MonitorTimeoutSeconds,
			MonitorFailureThreshold:  d.MonitorFailureThreshold,
			MonitorRecoveryThreshold: d.MonitorRecoveryThreshold,
		})
	}
	for _, s := range in.AllowedSources {
		if strings.TrimSpace(s.Cidr) == "" {
			continue
		}
		rec.AllowedSources = append(rec.AllowedSources, model.RouteAllowedSource{
			RouteAllowedSourceID: s.RouteAllowedSourceID,
			RouteRuleID:          in.RouteRuleID,
			Cidr:                 strings.TrimSpace(s.Cidr),
			Description:          s.Description,
		})
	}
	return rec
}

// Describe renders the rule the way the audit log and the logs name it.
func (r Record) Describe() string {
	spec := r.Spec()
	bind := spec.BindAddress
	if spec.BindsAnyAddress() {
		bind = "any"
	}
	destinations := make([]string, 0, len(spec.Destinations))
	for _, d := range spec.Destinations {
		destinations = append(destinations, d.Address+":"+d.Ports.String())
	}
	return strings.Join([]string{
		r.RouteRuleTitle, string(spec.Protocol), bind + ":" + spec.BindPorts.String(),
		"->", strings.Join(destinations, ","),
	}, " ")
}

func familyOf(id int64) string {
	if id == model.AddressFamilyIPv6 {
		return rules.FamilyIPv6
	}
	return rules.FamilyIPv4
}

func weightOrOne(weight int) int {
	if weight <= 0 {
		return 1
	}
	return weight
}

func intOrZero(v *int64) int {
	if v == nil {
		return 0
	}
	return int(*v)
}

func stringOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func nullableInt(v int) *int64 {
	if v == 0 {
		return nil
	}
	n := int64(v)
	return &n
}

func nullableString(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	trimmed := strings.TrimSpace(v)
	return &trimmed
}
