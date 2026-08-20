package api

import (
	"net/http"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/tuning"
)

// The kernel parameters a relay's throughput and stability depend on.
//
// The panel reads them, says what this host should be setting them to, and
// applies them on request. The one exception is the connection tracking pair,
// which it keeps sized by itself: a full table does not make the host slow, it
// takes it off the network, and the panel's own rules are what fill it.

func (s *Server) requireTuning(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.tuning == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Kernel tuning is not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleTuning(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.tuning.Report(s.liveConnections()))
}

// handleApplyTuning sets the throughput parameters and records them.
//
// The safety group is applied too, because an operator who asked for the host
// to be tuned did not mean "except for the part that keeps it reachable".
func (s *Server) handleApplyTuning(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	applied, err := s.tuning.Apply(r.Context(), tuning.GroupSafety, tuning.GroupThroughput)
	if err != nil {
		s.auditRoute(r, model.AuditActionSettingUpdate, "tuning", nil, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}
	s.auditRoute(r, model.AuditActionSettingUpdate, "tuning",
		map[string]any{"applied": applied}, nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"applied": applied,
		"tuning":  s.tuning.Report(s.liveConnections()),
	})
}

// handleRevertTuning puts the parameters back to what they were before the
// panel first changed them.
func (s *Server) handleRevertTuning(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if err := s.tuning.Revert(r.Context()); err != nil {
		s.auditRoute(r, model.AuditActionSettingUpdate, "tuning", nil, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}
	s.auditRoute(r, model.AuditActionSettingUpdate, "tuning",
		map[string]any{"reverted": true}, nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"reverted": true,
		"tuning":   s.tuning.Report(s.liveConnections()),
	})
}

// liveConnections is what the relays on this host are carrying, which is the
// only honest input to how large the tracking table has to be. Zero when the
// accounting is not running, and the recommendation then falls back to what
// the machine's memory can hold.
func (s *Server) liveConnections() int {
	if s.accounting == nil {
		return 0
	}
	return s.accounting.Summary().ActiveConnections
}
