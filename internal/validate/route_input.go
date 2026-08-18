package validate

import (
	"context"
	"strings"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// Port bounds. Zero is not a port an application can be reached on, and a
// forwarding rule that matched it would match nothing.
const (
	MinPort = 1
	MaxPort = 65535
)

// Bounds on the abuse-control options. They are generous: the point is to
// reject a value that cannot mean what the operator thinks it means, not to
// second-guess a busy relay.
const (
	MaxConnectionsPerSource = 1000000
	MaxConnectionRateLimit  = 1000000
	MaxDestinationWeight    = 1000
	MaxRouteTitleLength     = 100
	MaxAllowedSources       = 256
	MaxDestinations         = 64
)

// RouteDestinationInput is one destination of a forwarding rule.
type RouteDestinationInput struct {
	RouteDestinationID int64  `json:"route_destination_id,omitempty"`
	Address            string `json:"address"`
	Port               int    `json:"port"`
	PortRangeEnd       int    `json:"port_range_end,omitempty"`
	// Weight is the share of new connections this destination takes under
	// weighted load balancing. Zero means one.
	Weight    int  `json:"weight,omitempty"`
	IsEnabled bool `json:"is_enabled"`
	SortOrder int  `json:"sort_order,omitempty"`
}

// RouteAllowedSourceInput is one entry of a rule's source allowlist.
type RouteAllowedSourceInput struct {
	RouteAllowedSourceID int64  `json:"route_allowed_source_id,omitempty"`
	Cidr                 string `json:"cidr"`
	Description          string `json:"description,omitempty"`
}

// RouteInput is the complete desired state of one forwarding rule as a request
// states it. It is the type the API decodes into, the type validation checks,
// and the type the planner turns into a rendered ruleset, so the same fields
// carry all the way through with no re-mapping in between.
type RouteInput struct {
	// RouteRuleID is zero when creating. On update it names the row being
	// changed, so the rule does not conflict with itself.
	RouteRuleID int64 `json:"route_rule_id,omitempty"`

	RouteRuleTitle string `json:"route_rule_title"`
	Description    string `json:"description,omitempty"`

	RouteProtocolID int64 `json:"route_protocol_id"`
	AddressFamilyID int64 `json:"address_family_id"`

	// BindAddress is the local address traffic arrives on. Empty means the
	// server's primary address, which is what the panel fills in; 0.0.0.0 and ::
	// mean every local address and are accepted with a warning.
	BindAddress      string `json:"bind_address"`
	BindPort         int    `json:"bind_port"`
	BindPortRangeEnd int    `json:"bind_port_range_end,omitempty"`
	BindInterface    string `json:"bind_interface,omitempty"`

	// The primary destination. Extra destinations for load balancing live in
	// Destinations; the primary is repeated there when the rule is stored, so
	// nothing downstream has to special-case a rule with one destination.
	DestinationAddress      string `json:"destination_address"`
	DestinationPort         int    `json:"destination_port"`
	DestinationPortRangeEnd int    `json:"destination_port_range_end,omitempty"`

	NatModeID         int64  `json:"nat_mode_id"`
	SnatAddress       string `json:"snat_address,omitempty"`
	LoadBalanceModeID int64  `json:"load_balance_mode_id"`

	// TunnelID marks a rule whose destination is reached through a tunnel this
	// panel manages.
	TunnelID *int64 `json:"tunnel_id,omitempty"`

	IsClampMssToPmtu         bool   `json:"is_clamp_mss_to_pmtu"`
	IsIncludeLocalOriginated bool   `json:"is_include_local_originated"`
	IsLoggingEnabled         bool   `json:"is_logging_enabled"`
	FwMark                   *int64 `json:"fwmark,omitempty"`

	MaxConnectionsPerSource *int64 `json:"max_connections_per_source,omitempty"`
	ConnectionRateLimit     *int64 `json:"connection_rate_limit,omitempty"`

	IsEnabled bool  `json:"is_enabled"`
	SortOrder int64 `json:"sort_order,omitempty"`

	Destinations   []RouteDestinationInput   `json:"destinations,omitempty"`
	AllowedSources []RouteAllowedSourceInput `json:"allowed_sources,omitempty"`

	// Force overrides the warnings that are overridable. It never overrides a
	// safety invariant (§6.3).
	Force bool `json:"force,omitempty"`
}

// Protocol returns the rule layer's name for the requested protocol.
func (in RouteInput) Protocol() rules.Protocol {
	return rules.Protocol(model.RouteProtocolName(in.RouteProtocolID))
}

// NatMode returns the rule layer's name for the requested NAT mode.
func (in RouteInput) NatMode() rules.NatMode {
	return rules.NatMode(model.NatModeName(in.NatModeID))
}

// LoadBalance returns the rule layer's name for the requested distribution.
func (in RouteInput) LoadBalance() rules.LoadBalanceMode {
	return rules.LoadBalanceMode(model.LoadBalanceModeName(in.LoadBalanceModeID))
}

// Family returns the address family the rule works in, taken from the declared
// family when there is one and otherwise from the bind address itself.
func (in RouteInput) Family() string {
	switch in.AddressFamilyID {
	case model.AddressFamilyIPv4:
		return rules.FamilyIPv4
	case model.AddressFamilyIPv6:
		return rules.FamilyIPv6
	}
	if family, ok := rules.FamilyOfAddress(in.BindAddress); ok {
		return family
	}
	if family, ok := rules.FamilyOfAddress(in.DestinationAddress); ok {
		return family
	}
	return ""
}

// BindPorts returns the bind port range.
func (in RouteInput) BindPorts() rules.PortRange {
	return rules.PortRange{Port: in.BindPort, End: in.BindPortRangeEnd}
}

// EffectiveDestinations returns every destination the rule sends to, with the
// primary first. A rule that lists none is a rule with exactly one, which is
// what keeps single-destination rules from being a special case anywhere below
// this point.
func (in RouteInput) EffectiveDestinations() []RouteDestinationInput {
	primary := RouteDestinationInput{
		Address: strings.TrimSpace(in.DestinationAddress),
		Port:    in.DestinationPort, PortRangeEnd: in.DestinationPortRangeEnd,
		Weight: 1, IsEnabled: true,
	}
	out := []RouteDestinationInput{primary}
	for _, d := range in.Destinations {
		if strings.EqualFold(strings.TrimSpace(d.Address), primary.Address) &&
			d.Port == primary.Port && d.PortRangeEnd == primary.PortRangeEnd {
			// The stored set repeats the primary; listing it twice would double
			// its share of a load-balanced rule.
			out[0].Weight = weightOrOne(d.Weight)
			out[0].IsEnabled = d.IsEnabled
			out[0].RouteDestinationID = d.RouteDestinationID
			continue
		}
		out = append(out, d)
	}
	return out
}

func weightOrOne(weight int) int {
	if weight <= 0 {
		return 1
	}
	return weight
}

// Spec converts the request into the rendering input, which is the single
// translation from what an operator asked for to what reaches netfilter. The
// preview, the apply and the fake all take the result of this one function, so
// they cannot be given different things.
func (in RouteInput) Spec() rules.RouteSpec {
	spec := rules.RouteSpec{
		RouteRuleID:            in.RouteRuleID,
		Title:                  in.RouteRuleTitle,
		Protocol:               in.Protocol(),
		Family:                 in.Family(),
		BindAddress:            strings.TrimSpace(in.BindAddress),
		BindPorts:              in.BindPorts(),
		BindInterface:          strings.TrimSpace(in.BindInterface),
		NatMode:                in.NatMode(),
		SnatAddress:            strings.TrimSpace(in.SnatAddress),
		LoadBalance:            in.LoadBalance(),
		ClampMssToPmtu:         in.IsClampMssToPmtu,
		IncludeLocalOriginated: in.IsIncludeLocalOriginated,
		Logging:                in.IsLoggingEnabled,
		SortOrder:              int(in.SortOrder),
	}
	for _, d := range in.EffectiveDestinations() {
		if !d.IsEnabled {
			// A disabled destination is one the operator has taken out of
			// rotation; rendering it would keep sending traffic there.
			continue
		}
		spec.Destinations = append(spec.Destinations, rules.Destination{
			Address: strings.TrimSpace(d.Address),
			Ports:   rules.PortRange{Port: d.Port, End: d.PortRangeEnd},
			Weight:  weightOrOne(d.Weight),
		})
	}
	for _, s := range in.AllowedSources {
		if cidr := strings.TrimSpace(s.Cidr); cidr != "" {
			spec.AllowedSources = append(spec.AllowedSources, cidr)
		}
	}
	if in.FwMark != nil {
		fwmark := uint32(*in.FwMark)
		spec.FwMark = &fwmark
	}
	if in.MaxConnectionsPerSource != nil {
		spec.MaxConnectionsPerSource = int(*in.MaxConnectionsPerSource)
	}
	if in.ConnectionRateLimit != nil {
		spec.ConnectionRateLimit = int(*in.ConnectionRateLimit)
	}
	return spec
}

// ExistingRoute is the database's view of a forwarding rule, reduced to the
// fields conflict detection needs.
type ExistingRoute struct {
	RouteRuleID      int64
	Title            string
	RouteProtocolID  int64
	BindAddress      string
	BindPort         int
	BindPortRangeEnd int
	IsEnabled        bool
}

// Ports returns the listener range this rule claims.
func (r ExistingRoute) Ports() rules.PortRange {
	return rules.PortRange{Port: r.BindPort, End: r.BindPortRangeEnd}
}

// RouteRepository is the database view route validation needs. Keeping it an
// interface declared here means validation can be tested with a handful of rows
// and no database at all.
type RouteRepository interface {
	// ExistingRoutes returns every route rule that is not soft-deleted.
	ExistingRoutes(ctx context.Context) ([]ExistingRoute, error)
	// TunnelExists reports whether a live tunnel carries that identifier. A
	// rule may name one, and naming one that is not there has to be a
	// field-level answer rather than a foreign key violation from the database.
	TunnelExists(ctx context.Context, tunnelID int64) (bool, error)
}

// SocketTable is the kernel's socket table as validation reads it.
// *rules.SocketReader satisfies it.
type SocketTable interface {
	Listeners() ([]rules.Listener, error)
}
