package route

import (
	"context"
	"fmt"

	"github.com/drs/gre-panel/internal/model"
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
		health.State, health.Detail = healthOf(rec, health, readable)
		out[rec.RouteRuleID] = health
	}
	return out
}

// healthOf decides one rule's state, in the order the answers matter.
func healthOf(rec Record, health Health, readable bool) (string, string) {
	switch {
	case !rec.IsEnabled:
		return HealthDisabled, "the rule is switched off, so it installs nothing"

	case rec.ApplyStatusID == model.ApplyStatusInconsistent:
		detail := "the last change could not be applied and could not be undone either"
		if rec.LastApplyError != nil {
			detail += ": " + *rec.LastApplyError
		}
		return HealthInconsistent, detail

	case rec.ApplyStatusID == model.ApplyStatusFailed:
		detail := "the last apply failed"
		if rec.LastApplyError != nil {
			detail += ": " + *rec.LastApplyError
		}
		return HealthFailed, detail

	case rec.ApplyStatusID == model.ApplyStatusPending:
		return HealthPending, "the rule has not been applied yet"

	case !readable:
		return HealthPending, "the panel's ruleset could not be read back, so this rule's state is unknown"

	case !health.Installed:
		return HealthFailed, "the rule is enabled and none of its rules are in the kernel; reapply it"

	// The rules are installed and correct. What can still be wrong is the path
	// they relay over.
	case health.Tunnel != nil && !health.Tunnel.Healthy():
		return HealthImpaired, fmt.Sprintf("the rules are installed correctly, and %s — the tunnel "+
			"this rule relays over — is not up, so nothing crosses it", health.Tunnel.InterfaceName)
	}
	return HealthHealthy, "the rules are installed and the path they use is up"
}
