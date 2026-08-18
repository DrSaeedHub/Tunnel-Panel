package tunnel

import (
	"context"
	"fmt"
	"strings"

	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/validate"
)

// RouteDependants is the slice of the forwarding subsystem this package needs:
// which forwarding rules send their traffic through a given tunnel (§10).
//
// It is an interface, and wired after construction, because the route service
// is built after this one — and because a panel built without forwarding rules
// should behave exactly as it did before them.
type RouteDependants interface {
	ByTunnel(ctx context.Context, tunnelID int64) ([]route.Record, error)
}

// SetRouteDependants wires the forwarding subsystem.
func (s *Service) SetRouteDependants(source RouteDependants) {
	s.mu.Lock()
	s.routes = source
	s.mu.Unlock()
}

func (s *Service) routeDependants() RouteDependants {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes
}

// PeerAddressOf returns the address at the far end of a tunnel: the peer of its
// primary address, falling back to the peer of any address it carries.
//
// It is what the frontend prefills a forwarding rule's destination with when
// the operator chooses "send to a tunnel" (§10), so a relay across a tunnel
// takes one choice rather than looking up an address.
func PeerAddressOf(rec Record) string {
	fallback := ""
	for _, a := range rec.Addresses {
		if a.PeerAddress == nil || strings.TrimSpace(*a.PeerAddress) == "" {
			continue
		}
		if a.IsPrimary {
			return *a.PeerAddress
		}
		if fallback == "" {
			fallback = *a.PeerAddress
		}
	}
	return fallback
}

// DependentRoute is one forwarding rule that depends on a tunnel, reduced to
// what a warning and a tunnel detail page need.
type DependentRoute struct {
	RouteRuleID int64  `json:"route_rule_id"`
	Title       string `json:"title"`
	Protocol    string `json:"protocol"`
	Bind        string `json:"bind"`
	Destination string `json:"destination"`
	IsEnabled   bool   `json:"is_enabled"`
}

// DependentRoutes lists the forwarding rules whose traffic crosses a tunnel, so
// the tunnel detail page can show them and so deleting or disabling one can say
// what it would break (§10).
func (s *Service) DependentRoutes(ctx context.Context, tunnelID int64) ([]DependentRoute, error) {
	source := s.routeDependants()
	if source == nil {
		return nil, nil
	}
	records, err := source.ByTunnel(ctx, tunnelID)
	if err != nil {
		return nil, err
	}

	out := make([]DependentRoute, 0, len(records))
	for _, rec := range records {
		spec := rec.Spec()
		bind := spec.BindAddress
		if spec.BindsAnyAddress() {
			bind = "any"
		}
		destinations := make([]string, 0, len(spec.Destinations))
		for _, d := range spec.Destinations {
			destinations = append(destinations, d.Address+":"+d.Ports.String())
		}
		out = append(out, DependentRoute{
			RouteRuleID: rec.RouteRuleID, Title: rec.RouteRuleTitle,
			Protocol: string(spec.Protocol), Bind: bind + ":" + spec.BindPorts.String(),
			Destination: strings.Join(destinations, ", "), IsEnabled: rec.IsEnabled,
		})
	}
	return out, nil
}

// WarnRouteDependants is the warning code the frontend renders as a list of
// affected forwarding rules.
const WarnRouteDependants = "TUNNEL_HAS_DEPENDENT_ROUTES"

// routeDependencyWarning describes what taking a tunnel away would do to the
// forwarding rules that cross it.
//
// It is a warning rather than a refusal. The operator may well be deleting the
// routes next, or replacing the tunnel; what they must not do is find out
// afterwards, from a relay that quietly stopped working.
func (s *Service) routeDependencyWarning(ctx context.Context, tunnelID int64,
	rec Record, action string) []validate.Warning {

	dependants, err := s.DependentRoutes(ctx, tunnelID)
	if err != nil {
		s.log.Error("listing the forwarding rules that depend on a tunnel failed",
			"tunnel_id", tunnelID, "error", err)
		return nil
	}
	enabled := make([]string, 0, len(dependants))
	for _, dependant := range dependants {
		if dependant.IsEnabled {
			enabled = append(enabled, fmt.Sprintf("%s (%s → %s)",
				dependant.Title, dependant.Bind, dependant.Destination))
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	return []validate.Warning{{
		Code:  WarnRouteDependants,
		Field: "tunnel_id",
		Message: fmt.Sprintf("%d forwarding rule(s) send their traffic through %s and stop working "+
			"when it goes %s: %s. Their rules stay installed and correct; the path they use is what "+
			"disappears.", len(enabled), rec.InterfaceName, action, strings.Join(enabled, "; ")),
	}}
}

// SetMonitorState wires the prober's verdict about a tunnel.
//
// It is a function rather than an interface so this package does not depend on
// the monitoring one, which already depends on the tunnel repository. Without
// it a tunnel's health is judged from the kernel's flags alone, which is
// correct but blind to a tunnel that is up and carrying nothing.
func (s *Service) SetMonitorState(fn func(tunnelID int64) (string, bool)) {
	s.mu.Lock()
	s.monitorState = fn
	s.mu.Unlock()
}

func (s *Service) monitorStateFor(tunnelID int64) string {
	s.mu.Lock()
	fn := s.monitorState
	s.mu.Unlock()
	if fn == nil {
		return ""
	}
	if state, ok := fn(tunnelID); ok {
		return state
	}
	return ""
}

// TunnelHealth reports what a forwarding rule needs to know about the tunnel it
// depends on, so a route whose tunnel is down is reported as impaired rather
// than as broken (§10). It satisfies route.TunnelSource.
//
// The administrative state comes from the kernel's flags and never from the
// operational state: a healthy GRE tunnel reports UNKNOWN, and reading that as
// a fault is exactly the mistake the tunnel subsystem exists not to make.
func (s *Service) TunnelHealth(ctx context.Context, tunnelID int64) (route.TunnelHealth, bool) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return route.TunnelHealth{}, false
	}

	health := route.TunnelHealth{
		TunnelID:      rec.TunnelID,
		InterfaceName: rec.InterfaceName,
		IsEnabled:     rec.IsEnabled,
		PeerAddress:   PeerAddressOf(rec),
		MonitorState:  s.monitorStateFor(tunnelID),
	}
	if rec.DisplayName != nil {
		health.DisplayName = *rec.DisplayName
	}
	if observed, exists := s.observe(ctx, rec.InterfaceName); exists {
		health.IsUp = observed.IsUp && observed.IsLowerUp
		for _, address := range observed.Addresses {
			health.Addresses = append(health.Addresses, address.String())
		}
	}
	return health, true
}
