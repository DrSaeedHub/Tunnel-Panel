package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
)

// requireMonitor answers clearly when the monitoring subsystem is not wired,
// rather than letting a nil dereference become a 500.
func (s *Server) requireMonitor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.monitor == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Monitoring is not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// statusResponse is one tunnel's live monitoring picture (§10.5).
type statusResponse struct {
	monitor.Snapshot
	// Events are the recent state changes, which explain how it got here.
	Events []monitor.Event `json:"events"`
}

func (s *Server) handleTunnelStatus(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	snapshot, known := s.monitor.Snapshot(rec.TunnelID)
	if !known {
		// A tunnel the supervisor has not yet seen is Unknown rather than
		// absent: the panel knows the tunnel, it just has no measurement.
		snapshot = monitor.Snapshot{
			TunnelID:       rec.TunnelID,
			InterfaceName:  rec.InterfaceName,
			MonitorStateID: model.MonitorStateUnknown,
			State:          monitor.StateName(model.MonitorStateUnknown),
			Reason:         "monitoring has not reported on this tunnel yet",
			UpdatedAt:      time.Now(),
		}
	}

	events, err := s.monitor.Store().Events(r.Context(), rec.TunnelID, 20)
	if err != nil {
		s.log.Error("reading monitoring events failed", "tunnel_id", rec.TunnelID, "error", err)
		events = []monitor.Event{}
	}
	writeJSON(w, http.StatusOK, statusResponse{Snapshot: snapshot, Events: events})
}

// handleTunnelHistory serves the stored history over a time range at a chosen
// resolution (§10.4).
func (s *Server) handleTunnelHistory(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	query := monitor.HistoryQuery{TunnelID: rec.TunnelID}
	if raw := r.URL.Query().Get("from"); raw != "" {
		parsed, err := parseTimeParam(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"The from parameter is not a time: "+err.Error(), "from", nil)
			return
		}
		query.From = parsed
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		parsed, err := parseTimeParam(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"The to parameter is not a time: "+err.Error(), "to", nil)
			return
		}
		query.To = parsed
	}
	if raw := r.URL.Query().Get("resolution_seconds"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			query.ResolutionSeconds = n
		}
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			query.Limit = n
		}
	}

	points, err := s.monitor.Store().History(r.Context(), query)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnel_id":          rec.TunnelID,
		"points":             points,
		"total":              len(points),
		"resolution_seconds": query.ResolutionSeconds,
	})
}

// parseTimeParam accepts RFC 3339 or the panel's own stored format.
func parseTimeParam(raw string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed, nil
	}
	return model.ParseTime(raw)
}

// handleMonitorToggle switches monitoring on or off for one tunnel and asks the
// supervisor to act on it at once (§10.3).
func (s *Server) handleMonitorToggle(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec, ok := s.tunnelFromPath(w, r)
		if !ok {
			return
		}

		if err := s.tunnels.Repo().SetMonitorEnabled(r.Context(), rec.TunnelID, &enabled); err != nil {
			s.writeDomainError(w, r, err)
			return
		}
		// The change takes effect immediately rather than at the next sweep.
		s.monitor.TunnelsChanged()

		action := model.AuditActionTunnelEnable
		if !enabled {
			action = model.AuditActionTunnelDisable
		}
		s.auditTunnel(r, action, rec.InterfaceName,
			map[string]any{"monitor_enabled": enabled}, nil, nil, start)

		updated, _ := s.tunnels.Repo().ByID(r.Context(), rec.TunnelID)
		writeJSON(w, http.StatusOK, map[string]any{
			"tunnel_id":       rec.TunnelID,
			"monitor_enabled": enabled,
			"tunnel":          updated,
		})
	}
}

// handleMonitorSummary reports every tunnel's state at once, which is what the
// dashboard header shows.
func (s *Server) handleMonitorSummary(w http.ResponseWriter, r *http.Request) {
	snapshots := s.monitor.Summary()
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnels": snapshots,
		"total":   len(snapshots),
		"counts":  s.monitor.Counts(),
		"running": s.monitor.Running(),
	})
}

// handleMonitorStream pushes per-tunnel state, loss and latency as they change
// (§10.5).
//
// Every subscriber gets its own channel, the heartbeat keeps intermediaries
// from closing an idle connection, and the deferred unsubscribe is what ends
// the goroutine feeding it when the client goes away.
func (s *Server) handleMonitorStream(w http.ResponseWriter, r *http.Request) {
	stream, ok := newSSE(w)
	if !ok {
		streamNotSupported(w)
		return
	}

	id, events := s.monitor.Hub().Subscribe()
	defer s.monitor.Hub().Unsubscribe(id)

	// The current picture first, so a client that connects between changes sees
	// the state rather than an empty pane until something moves.
	if err := stream.Send("summary", map[string]any{
		"tunnels": s.monitor.Summary(),
		"counts":  s.monitor.Counts(),
	}); err != nil {
		return
	}

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case snapshot, open := <-events:
			if !open {
				return
			}
			if err := stream.Send("tunnel", snapshot); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := stream.Comment("heartbeat"); err != nil {
				return
			}
		}
	}
}
