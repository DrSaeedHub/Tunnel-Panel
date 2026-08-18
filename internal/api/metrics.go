package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/drs/gre-panel/internal/metrics"
)

// requireMetrics answers clearly when the sampler is not wired.
func (s *Server) requireMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.metrics == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"System metrics are not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleMetrics returns the most recent reading (§11.4).
//
// Every figure is a raw byte count or a rate in bytes per second. Converting to
// bits, or to binary or decimal multiples, is presentation and belongs to the
// frontend, driven by the display settings (§11.2).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snapshot := s.metrics.Latest()

	// The disk list is filtered by the setting, but the full one stays
	// retrievable for an operator who wants to see everything.
	if r.URL.Query().Get("all_filesystems") == "true" {
		if disks, err := s.metrics.AllDisks(); err == nil {
			snapshot.Disks = disks
		}
	}
	writeJSON(w, http.StatusOK, snapshot)
}

// handleMetricsHistory returns the in-memory ring buffer for the sparklines.
func (s *Server) handleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	history := s.metrics.History(limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"points": history,
		"total":  len(history),
	})
}

// handleMetricsStream pushes each reading as it is taken (§11.4).
func (s *Server) handleMetricsStream(w http.ResponseWriter, r *http.Request) {
	stream, ok := newSSE(w)
	if !ok {
		streamNotSupported(w)
		return
	}

	id, readings := s.metrics.Hub().Subscribe()
	defer s.metrics.Hub().Unsubscribe(id)

	// The latest reading first, so a client sees the machine immediately rather
	// than waiting a sampling interval for the first event.
	if latest := s.metrics.Latest(); !latest.At.IsZero() {
		if err := stream.Send("metrics", latest); err != nil {
			return
		}
	}

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case snapshot, open := <-readings:
			if !open {
				return
			}
			if err := stream.Send("metrics", snapshot); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := stream.Comment("heartbeat"); err != nil {
				return
			}
		}
	}
}

// volumeResponse reports cumulative traffic with the two figures kept apart
// (§11.3).
type volumeResponse struct {
	Interfaces []metrics.Interface   `json:"interfaces"`
	Totals     metrics.NetworkTotals `json:"totals"`
	Note       string                `json:"note"`
}
