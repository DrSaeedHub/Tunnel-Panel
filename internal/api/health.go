package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/metrics"
	"github.com/drs/gre-panel/internal/monitor"
)

// Component status values reported by GET /system/health (§20).
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
	StatusError    = "error"
	StatusUnknown  = "unknown"
)

// Component names. They are constants because the installer's readiness poll
// and external monitoring both key off them.
const (
	ComponentDatabase     = "database"
	ComponentMonitor      = "monitor_supervisor"
	ComponentNetlink      = "netlink"
	ComponentKernelModule = "kernel_module"
	ComponentMetrics      = "metrics_sampler"
	// ComponentListenAddress reports a panel that is not where it was
	// configured to be. It is degraded rather than an error: the panel is
	// serving and everything works, but it is answering somewhere the operator
	// did not choose, and nothing else on any screen would say so.
	ComponentListenAddress = "listen_address"
)

// ComponentHealth is the state of one subsystem.
type ComponentHealth struct {
	Name   string         `json:"name"`
	Status string         `json:"status"`
	Detail string         `json:"detail,omitempty"`
	Data   map[string]any `json:"data,omitempty"`
}

// HealthCheck reports the state of one component. It must return promptly; the
// registry gives every check a short deadline.
type HealthCheck func(ctx context.Context) ComponentHealth

// HealthRegistry holds the component checks. Subsystems that start after the
// HTTP server register themselves by name, replacing any placeholder.
type HealthRegistry struct {
	mu     sync.RWMutex
	checks map[string]HealthCheck
	order  []string
}

// NewHealthRegistry returns an empty registry.
func NewHealthRegistry() *HealthRegistry {
	return &HealthRegistry{checks: map[string]HealthCheck{}}
}

// Register adds or replaces a component check, preserving registration order.
func (h *HealthRegistry) Register(name string, check HealthCheck) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.checks[name]; !exists {
		h.order = append(h.order, name)
	}
	h.checks[name] = check
}

// Snapshot runs every check and returns the components plus the overall status,
// which is the worst individual status.
func (h *HealthRegistry) Snapshot(ctx context.Context) (string, []ComponentHealth) {
	h.mu.RLock()
	names := make([]string, len(h.order))
	copy(names, h.order)
	checks := make(map[string]HealthCheck, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	components := make([]ComponentHealth, 0, len(names))
	overall := StatusOK
	for _, name := range names {
		c := checks[name](ctx)
		c.Name = name
		components = append(components, c)
		overall = worseStatus(overall, c.Status)
	}
	return overall, components
}

// worseStatus orders the statuses so the overall result is the worst component.
// Unknown ranks below degraded: not knowing is a weaker signal than knowing
// something is wrong, but it is still not "ok".
func worseStatus(a, b string) string {
	rank := map[string]int{StatusOK: 0, StatusUnknown: 1, StatusDegraded: 2, StatusError: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// RegisterCoreComponents wires the checks the panel can answer on its own.
func (s *Server) RegisterCoreComponents() {
	s.health.Register(ComponentDatabase, func(ctx context.Context) ComponentHealth {
		if s.db == nil {
			return ComponentHealth{Status: StatusError, Detail: "no database is configured"}
		}
		if err := s.db.Healthy(ctx); err != nil {
			return ComponentHealth{Status: StatusError, Detail: err.Error()}
		}
		return ComponentHealth{Status: StatusOK, Data: map[string]any{"path": s.db.Path}}
	})

	s.health.Register(ComponentListenAddress, func(context.Context) ComponentHealth {
		data := map[string]any{
			"port": s.cfg.BindPort, "web_path": s.cfg.WebPath,
			"port_source": s.addressSources.Port, "web_path_source": s.addressSources.WebPath,
		}
		if s.addressFallback == nil {
			return ComponentHealth{Status: StatusOK, Data: data}
		}
		data["configured_port"] = s.addressFallback.Wanted
		data["bind_error"] = s.addressFallback.Reason
		return ComponentHealth{
			Status: StatusDegraded,
			Detail: fmt.Sprintf("port %d could not be bound, so the panel is serving on %d instead: %s",
				s.addressFallback.Wanted, s.addressFallback.Serving, s.addressFallback.Reason),
			Data: data,
		}
	})

	s.health.Register(ComponentNetlink, func(ctx context.Context) ComponentHealth {
		a := link.Probe()
		if !a.NetlinkAvailable {
			return ComponentHealth{
				Status: StatusError,
				Detail: "netlink is not usable, so tunnels cannot be configured: " + a.NetlinkError,
			}
		}
		return ComponentHealth{Status: StatusOK}
	})

	s.health.Register(ComponentKernelModule, func(ctx context.Context) ComponentHealth {
		a := link.Probe()
		loaded := a.LoadedModules[link.GreModule]
		// Not loaded is the normal state on a server with no tunnels yet: the
		// module autoloads the first time one is created. Reporting that as a
		// fault would make every fresh install look broken.
		detail := "loaded"
		if !loaded {
			detail = "not loaded; it autoloads when the first tunnel is created"
		}
		return ComponentHealth{
			Status: StatusOK,
			Detail: detail,
			Data: map[string]any{
				"module":         link.GreModule,
				"loaded":         loaded,
				"kernel_release": a.KernelRelease,
			},
		}
	})

	// A placeholder until the monitoring supervisor starts and replaces it, so
	// the component always appears in the response and an external check never
	// sees a field come and go.
	s.health.Register(ComponentMonitor, func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Status: StatusUnknown, Detail: "the monitor supervisor is not running"}
	})
}

// healthResponse is the body of GET /system/health.
type healthResponse struct {
	Status        string            `json:"status"`
	Version       string            `json:"version"`
	UptimeSeconds int64             `json:"uptime_seconds"`
	SetupRequired bool              `json:"setup_required"`
	Components    []ComponentHealth `json:"components"`
	CheckedAt     string            `json:"checked_at"`
}

// handleHealth reports component status for external checks and for the
// installer's readiness poll (§20). It is deliberately unauthenticated and
// reachable before setup, so it exposes nothing beyond liveness.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	overall, components := s.health.Snapshot(ctx)
	sort.SliceStable(components, func(i, j int) bool { return components[i].Name < components[j].Name })

	hasUser, err := s.auth.HasUser(ctx)
	if err != nil {
		overall = worseStatus(overall, StatusError)
	}

	// A seeded CSRF token here means the frontend can reach setup with a single
	// prior request, which is all it makes before the panel is configured.
	s.ensureCSRFCookie(w, r)

	status := http.StatusOK
	if overall == StatusError {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, healthResponse{
		Status:        overall,
		Version:       s.build.Version,
		UptimeSeconds: int64(time.Since(s.started).Seconds()),
		SetupRequired: !hasUser,
		Components:    components,
		CheckedAt:     time.Now().UTC().Format(time.RFC3339),
	})
}

// RegisterMonitorComponent replaces the monitoring placeholder with the real
// check once the supervisor is running (§20).
func (s *Server) RegisterMonitorComponent(supervisor *monitor.Supervisor) {
	s.health.Register(ComponentMonitor, func(ctx context.Context) ComponentHealth {
		if supervisor == nil {
			return ComponentHealth{Status: StatusUnknown, Detail: "the monitor supervisor is not running"}
		}
		counts := supervisor.Counts()
		return ComponentHealth{
			Status: StatusOK,
			Detail: fmt.Sprintf("%d prober(s) running", supervisor.Running()),
			Data: map[string]any{
				"probers":     supervisor.Running(),
				"subscribers": supervisor.Hub().Subscribers(),
				"states":      counts,
			},
		}
	})
}

// RegisterMetricsComponent adds the sampler's health once it is running.
//
// A sampler that has not produced a reading yet is Unknown rather than OK: the
// component exists, but nothing has been measured, and saying so is the point
// of a health endpoint.
func (s *Server) RegisterMetricsComponent(sampler *metrics.Sampler) {
	s.health.Register(ComponentMetrics, func(ctx context.Context) ComponentHealth {
		if sampler == nil {
			return ComponentHealth{Status: StatusUnknown, Detail: "the metrics sampler is not running"}
		}
		healthy, at := sampler.Healthy()
		if !healthy {
			return ComponentHealth{Status: StatusUnknown, Detail: "no reading has been taken yet"}
		}
		age := time.Since(at)
		status := StatusOK
		detail := fmt.Sprintf("the last reading was %s ago", age.Round(time.Second))
		// A sampler whose last reading is minutes old has stalled, which the
		// dashboard would otherwise show as merely stale numbers.
		if age > 2*time.Minute {
			status = StatusDegraded
			detail = fmt.Sprintf("the last reading was %s ago, so sampling has stalled", age.Round(time.Second))
		}
		return ComponentHealth{
			Status: status, Detail: detail,
			Data: map[string]any{
				"last_reading": at.UTC().Format(time.RFC3339),
				"subscribers":  sampler.Hub().Subscribers(),
			},
		}
	})
}
