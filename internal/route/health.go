package route

import (
	"context"
	"net/netip"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// Health states. They are stable strings: the frontend renders a different
// status pill for each.
const (
	HealthDisabled     = "disabled"
	HealthPending      = "pending"
	HealthHealthy      = "healthy"
	HealthImpaired     = "impaired"
	HealthFailed       = "failed"
	HealthInconsistent = "inconsistent"
)

// Health is one forwarding rule's state as the panel reports it.
//
// Impaired is the state that matters here (§10): the rules are installed
// exactly as intended and the tunnel they relay over is down, so the rule is
// neither healthy nor broken. Reporting it as failed would send an operator to
// edit a rule that has nothing wrong with it.
type Health struct {
	RouteRuleID int64  `json:"route_rule_id"`
	State       string `json:"state"`
	Detail      string `json:"detail"`
	// Installed reports whether the rule's rules are in the kernel now.
	Installed bool `json:"installed"`
	// Tunnel is the state of the tunnel this rule relays over, when it has one.
	Tunnel *TunnelHealth `json:"tunnel,omitempty"`
}

// Health reports the state of every rule given, reading the live ruleset once
// for the whole set rather than once per rule.
func (s *Service) Health(ctx context.Context, records []Record) map[int64]Health {
	installed := map[int64]bool{}
	readable := false
	if live, err := s.backend.ReadBack(ctx); err == nil {
		readable = true
		installed = live.IDs()
	}

	host := s.hostPath(ctx)
	tunnels := s.tunnelSource()
	out := make(map[int64]Health, len(records))
	for _, rec := range records {
		health := Health{
			RouteRuleID: rec.RouteRuleID,
			Installed:   installed[rec.RouteRuleID],
		}
		if rec.TunnelID != nil && tunnels != nil {
			if state, ok := tunnels.TunnelHealth(ctx, *rec.TunnelID); ok {
				health.Tunnel = &state
			}
		}
		health.State, health.Detail = healthOf(ctx, rec, health, readable, host)
		out[rec.RouteRuleID] = health
	}
	return out
}

// hostPath is what the host itself contributes to whether an installed rule
// can carry anything: the kernel has to forward, and a rule that relays to a
// loopback address needs the kernel to route 127.0.0.0/8 off the wire.
//
// These used to be left out, so a rule on a host that had stopped forwarding
// read as healthy -- "the path they use is up" -- beside a banner saying the
// kernel was forwarding nothing. Both were shown on the same page.
type hostPath struct {
	known          bool
	ipv4Forwarding bool
	ipv6Forwarding bool
	routeLocalnet  bool
}

func (s *Service) hostPath(ctx context.Context) hostPath {
	if s.forwarding == nil {
		return hostPath{}
	}
	status := s.forwarding.Status(ctx, false, 0, 0)
	return hostPath{
		known:          true,
		ipv4Forwarding: status.IPv4Forwarding,
		ipv6Forwarding: status.IPv6Forwarding,
		routeLocalnet:  s.forwarding.RoutesLocalnet(),
	}
}

// blocked returns why the host keeps an installed rule from carrying traffic,
// or "" when nothing on the host stands in the way.
func (h hostPath) blocked(ctx context.Context, spec rules.RouteSpec) string {
	if !h.known {
		return ""
	}
	if spec.IsIPv6() && !h.ipv6Forwarding {
		return i18n.T(ctx, "the rules are installed correctly, but this kernel is not forwarding IPv6 "+
			"packets, so nothing crosses them")
	}
	if !spec.IsIPv6() && !h.ipv4Forwarding {
		return i18n.T(ctx, "the rules are installed correctly, but this kernel is not forwarding "+
			"packets, so nothing crosses them")
	}
	if !h.routeLocalnet {
		for _, d := range spec.Destinations {
			if addr, err := netip.ParseAddr(d.Address); err == nil && addr.Is4() && addr.IsLoopback() {
				return i18n.T(ctx, "the rules are installed correctly, but %s is a loopback address "+
					"and route_localnet is off on every interface, so the kernel drops what they send "+
					"there", d.Address)
			}
		}
	}
	return ""
}

// healthOf decides one rule's state, in the order the answers matter.
func healthOf(ctx context.Context, rec Record, health Health, readable bool, host hostPath) (string, string) {
	switch {
	case !rec.IsEnabled:
		return HealthDisabled, i18n.T(ctx, "the rule is switched off, so it installs nothing")

	case rec.ApplyStatusID == model.ApplyStatusInconsistent:
		if rec.LastApplyError != nil {
			return HealthInconsistent, i18n.T(ctx, "the last change could not be applied and could "+
				"not be undone either: %s", *rec.LastApplyError)
		}
		return HealthInconsistent, i18n.T(ctx, "the last change could not be applied and could not "+
			"be undone either")

	case rec.ApplyStatusID == model.ApplyStatusFailed:
		if rec.LastApplyError != nil {
			return HealthFailed, i18n.T(ctx, "the last apply failed: %s", *rec.LastApplyError)
		}
		return HealthFailed, i18n.T(ctx, "the last apply failed")

	case rec.ApplyStatusID == model.ApplyStatusPending:
		return HealthPending, i18n.T(ctx, "the rule has not been applied yet")

	case !readable:
		return HealthPending, i18n.T(ctx, "the panel's ruleset could not be read back, so this rule's "+
			"state is unknown")

	case !health.Installed:
		return HealthFailed, i18n.T(ctx, "the rule is enabled and none of its rules are in the kernel; "+
			"reapply it")

	// The rules are installed and correct. What can still be wrong is the path
	// they relay over.
	case health.Tunnel != nil && !health.Tunnel.Healthy():
		return HealthImpaired, i18n.T(ctx, "the rules are installed correctly, and %s — the tunnel "+
			"this rule relays over — is not up, so nothing crosses it", health.Tunnel.InterfaceName)
	}
	if reason := host.blocked(ctx, rec.Spec()); reason != "" {
		return HealthImpaired, reason
	}
	return HealthHealthy, i18n.T(ctx, "the rules are installed and the path they use is up")
}
