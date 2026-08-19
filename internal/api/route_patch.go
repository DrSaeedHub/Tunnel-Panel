package api

import (
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/validate"
)

// routePatch is the request body for creating, previewing and updating a
// forwarding rule.
//
// Every field is optional, and the semantics match the tunnel patch exactly: on
// create, what is absent takes its default from the routes.* settings; on
// update, what is absent keeps the value the rule already has. That is what
// makes a PATCH saying only `{"is_clamp_mss_to_pmtu": true}` change the clamp
// and nothing else — in particular not clearing the destination list, which
// would leave the rule forwarding nowhere.
type routePatch struct {
	// RouteRuleID selects an existing rule for the preview endpoint. The update
	// endpoint takes the identifier from the path instead.
	RouteRuleID *int64 `json:"route_rule_id,omitempty"`

	RouteRuleTitle *string `json:"route_rule_title,omitempty"`
	Description    *string `json:"description,omitempty"`

	RouteProtocolID *int64 `json:"route_protocol_id,omitempty"`
	AddressFamilyID *int64 `json:"address_family_id,omitempty"`

	BindAddress      *string `json:"bind_address,omitempty"`
	BindPort         *int    `json:"bind_port,omitempty"`
	BindPortRangeEnd *int    `json:"bind_port_range_end,omitempty"`
	BindInterface    *string `json:"bind_interface,omitempty"`

	DestinationAddress      *string `json:"destination_address,omitempty"`
	DestinationPort         *int    `json:"destination_port,omitempty"`
	DestinationPortRangeEnd *int    `json:"destination_port_range_end,omitempty"`

	NatModeID         *int64  `json:"nat_mode_id,omitempty"`
	SnatAddress       *string `json:"snat_address,omitempty"`
	LoadBalanceModeID *int64  `json:"load_balance_mode_id,omitempty"`

	// TunnelID is nullable: sending null detaches a rule from its tunnel, which
	// is a different instruction from not mentioning the tunnel at all.
	TunnelID nullableInt `json:"tunnel_id,omitempty"`

	IsClampMssToPmtu         *bool       `json:"is_clamp_mss_to_pmtu,omitempty"`
	IsIncludeLocalOriginated *bool       `json:"is_include_local_originated,omitempty"`
	IsLoggingEnabled         *bool       `json:"is_logging_enabled,omitempty"`
	FwMark                   nullableInt `json:"fwmark,omitempty"`

	MaxConnectionsPerSource nullableInt `json:"max_connections_per_source,omitempty"`
	ConnectionRateLimit     nullableInt `json:"connection_rate_limit,omitempty"`

	IsEnabled *bool  `json:"is_enabled,omitempty"`
	SortOrder *int64 `json:"sort_order,omitempty"`

	// Monitoring. Every one is nullable rather than merely optional,
	// because clearing one is an instruction of its own: null means "go
	// back to inheriting this", which is not the same as not saying it.
	IsMonitorEnabled         nullableBool  `json:"is_monitor_enabled,omitempty"`
	MonitorModeID            nullableInt   `json:"monitor_mode_id,omitempty"`
	MonitorIntervalSeconds   nullableFloat `json:"monitor_interval_seconds,omitempty"`
	MonitorTimeoutSeconds    nullableFloat `json:"monitor_timeout_seconds,omitempty"`
	MonitorFailureThreshold  nullableInt   `json:"monitor_failure_threshold,omitempty"`
	MonitorRecoveryThreshold nullableInt   `json:"monitor_recovery_threshold,omitempty"`

	// SourceListIDs replaces the set of lists the rule allows. Sending an
	// empty array clears them, which is why it is a pointer: absent means
	// leave them alone.
	SourceListIDs *[]int64 `json:"source_list_ids,omitempty"`

	Destinations   *[]validate.RouteDestinationInput   `json:"destinations,omitempty"`
	AllowedSources *[]validate.RouteAllowedSourceInput `json:"allowed_sources,omitempty"`

	// Force overrides the warnings that are overridable. It never overrides a
	// safety invariant (§6.3).
	Force *bool `json:"force,omitempty"`
	// IUnderstandIMayLoseAccess acknowledges a change that could sever the path
	// the request itself arrived over (§6.3.5).
	IUnderstandIMayLoseAccess bool    `json:"i_understand_i_may_lose_access,omitempty"`
	IdempotencyKey            *string `json:"idempotency_key,omitempty"`
}

// applyTo overlays the supplied fields onto a rule description.
func (p routePatch) applyTo(in *validate.RouteInput) {
	setInt64 := func(dst *int64, src *int64) {
		if src != nil {
			*dst = *src
		}
	}
	setInt := func(dst *int, src *int) {
		if src != nil {
			*dst = *src
		}
	}
	setString := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	setBool := func(dst *bool, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	setNullable := func(dst **int64, src nullableInt) {
		if src.Set {
			*dst = src.Value
		}
	}

	setString(&in.RouteRuleTitle, p.RouteRuleTitle)
	setString(&in.Description, p.Description)
	setInt64(&in.RouteProtocolID, p.RouteProtocolID)
	setInt64(&in.AddressFamilyID, p.AddressFamilyID)

	setString(&in.BindAddress, p.BindAddress)
	setInt(&in.BindPort, p.BindPort)
	setInt(&in.BindPortRangeEnd, p.BindPortRangeEnd)
	setString(&in.BindInterface, p.BindInterface)

	setString(&in.DestinationAddress, p.DestinationAddress)
	setInt(&in.DestinationPort, p.DestinationPort)
	setInt(&in.DestinationPortRangeEnd, p.DestinationPortRangeEnd)

	setInt64(&in.NatModeID, p.NatModeID)
	setString(&in.SnatAddress, p.SnatAddress)
	setInt64(&in.LoadBalanceModeID, p.LoadBalanceModeID)
	setNullable(&in.TunnelID, p.TunnelID)

	setBool(&in.IsClampMssToPmtu, p.IsClampMssToPmtu)
	setBool(&in.IsIncludeLocalOriginated, p.IsIncludeLocalOriginated)
	setBool(&in.IsLoggingEnabled, p.IsLoggingEnabled)
	setNullable(&in.FwMark, p.FwMark)
	setNullable(&in.MaxConnectionsPerSource, p.MaxConnectionsPerSource)
	setNullable(&in.ConnectionRateLimit, p.ConnectionRateLimit)

	setBool(&in.IsEnabled, p.IsEnabled)
	setInt64(&in.SortOrder, p.SortOrder)
	setBool(&in.Force, p.Force)

	if p.IsMonitorEnabled.Set {
		in.IsMonitorEnabled = p.IsMonitorEnabled.Value
	}
	setNullable(&in.MonitorModeID, p.MonitorModeID)
	setNullable(&in.MonitorFailureThreshold, p.MonitorFailureThreshold)
	setNullable(&in.MonitorRecoveryThreshold, p.MonitorRecoveryThreshold)
	if p.MonitorIntervalSeconds.Set {
		in.MonitorIntervalSeconds = p.MonitorIntervalSeconds.Value
	}
	if p.MonitorTimeoutSeconds.Set {
		in.MonitorTimeoutSeconds = p.MonitorTimeoutSeconds.Value
	}

	if p.SourceListIDs != nil {
		in.SourceListIDs = *p.SourceListIDs
	}
	if p.Destinations != nil {
		in.Destinations = *p.Destinations
	}
	if p.AllowedSources != nil {
		in.AllowedSources = *p.AllowedSources
	}
}

// request builds the service request from a patch overlaid on a starting point.
func (p routePatch) request(base validate.RouteInput, clientIP string) route.Request {
	p.applyTo(&base)
	req := route.Request{RouteInput: base, ClientIP: clientIP}
	if p.IdempotencyKey != nil {
		req.IdempotencyKey = *p.IdempotencyKey
	}
	return req
}

// newRouteRequest is the starting point for a create: an empty description that
// IsEnabled defaults to true on, because a rule nobody asked to be off is meant
// to carry traffic.
func newRouteRequest() validate.RouteInput {
	return validate.RouteInput{IsEnabled: true}
}
