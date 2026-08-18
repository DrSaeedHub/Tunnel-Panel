package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drs/gre-panel/internal/diag"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
)

// requireDiag answers clearly when diagnostics are not wired.
func (s *Server) requireDiag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.diag == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Diagnostics are not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleDiagPing streams a manual high-precision ping (§13.1).
//
// The run identifier is the first event, so a client can stop the run by
// deleting it. When the connection cannot stream, the whole run is carried out
// and returned in one response instead.
func (s *Server) handleDiagPing(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	var params diag.PingParams
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &params) {
			return
		}
	}

	stream, streaming := newSSE(w)
	if !streaming {
		run, err := s.diag.Ping(r.Context(), rec.TunnelID, params, nil, nil)
		if err != nil {
			s.writeDomainError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}

	heartbeat := time.NewTicker(heartbeatInterval)
	defer heartbeat.Stop()
	// A heartbeat goroutine would race the packet writes on one response
	// writer, so the stream is written from this goroutine only and the
	// heartbeat is checked between packets.
	sendHeartbeat := func() {
		select {
		case <-heartbeat.C:
			_ = stream.Comment("heartbeat")
		default:
		}
	}

	run, err := s.diag.Ping(r.Context(), rec.TunnelID, params,
		func(started diag.Run) { _ = stream.Send("run", started) },
		func(packet monitor.PingPacket) {
			_ = stream.Send("packet", packet)
			sendHeartbeat()
		})
	if err != nil && !errors.Is(err, context.Canceled) {
		_ = stream.Send("error", map[string]any{"message": err.Error()})
		return
	}
	_ = stream.Send("summary", run)
}

// handleDiagMtuProbe runs the path MTU binary search (§13.2).
func (s *Server) handleDiagMtuProbe(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	var params diag.MtuParams
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &params) {
			return
		}
	}

	run, result, err := s.diag.MtuProbe(r.Context(), rec.TunnelID, params)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run":    run,
		"result": result,
		// The one-click path: what to send back to apply the recommendation.
		"apply": map[string]any{
			"method": http.MethodPatch,
			"path":   s.cfg.APIBasePath() + "/tunnels/" + strconv.FormatInt(rec.TunnelID, 10),
			"body":   map[string]any{"mtu": result.RecommendedTunnelMtu},
		},
	})
}

// handleDiagTraceroute walks the path.
func (s *Server) handleDiagTraceroute(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	var params diag.TracerouteParams
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &params) {
			return
		}
	}

	run, result, err := s.diag.Traceroute(r.Context(), rec.TunnelID, params)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "result": result})
}

// handleDiagAnalyze runs the decision tree and returns a specific verdict with
// its evidence (§13.4).
func (s *Server) handleDiagAnalyze(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	var params diag.AnalyzeParams
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &params) {
			return
		}
	}

	run, result, err := s.diag.Analyze(r.Context(), rec.TunnelID, params)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "result": result})
}

// handleTunnelCounters reports the raw interface statistics and their movement
// (§13.3).
func (s *Server) handleTunnelCounters(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	sampleSeconds := 1.0
	if raw := r.URL.Query().Get("sample_seconds"); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil && v > 0 {
			sampleSeconds = v
		}
	}

	snapshot, err := s.diag.Counters(r.Context(), rec.TunnelID, sampleSeconds)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

// handleDiagRuns lists stored diagnostic runs.
func (s *Server) handleDiagRuns(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	filter := diag.RunFilter{Limit: limit, Offset: offset}

	if raw := r.URL.Query().Get("tunnel_id"); raw != "" {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
			filter.TunnelID = &id
		}
	}
	if raw := r.URL.Query().Get("type"); raw != "" {
		if id, ok := diagnosticTypeByName(raw); ok {
			filter.TypeID = &id
		}
	}

	runs, total, err := s.diag.Runs(r.Context(), filter)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"runs": runs, "total": total, "limit": limit, "offset": offset,
	})
}

func diagnosticTypeByName(name string) (int64, bool) {
	switch name {
	case "ping":
		return model.DiagnosticTypePing, true
	case "mtu-probe", "mtu_probe":
		return model.DiagnosticTypeMtuProbe, true
	case "traceroute":
		return model.DiagnosticTypeTraceroute, true
	case "analyze":
		return model.DiagnosticTypeAnalyze, true
	}
	return 0, false
}

func (s *Server) handleDiagRun(w http.ResponseWriter, r *http.Request) {
	id, ok := runIDFromPath(w, r)
	if !ok {
		return
	}
	run, err := s.diag.RunByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, diag.ErrNotFound) {
			writeError(w, http.StatusNotFound, CodeNotFound, err.Error(), "id", nil)
			return
		}
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// handleDeleteDiagRun cancels an in-flight run and drops the record. Deleting
// is how a long ping is stopped (§13.1).
func (s *Server) handleDeleteDiagRun(w http.ResponseWriter, r *http.Request) {
	id, ok := runIDFromPath(w, r)
	if !ok {
		return
	}
	cancelled, err := s.diag.DeleteRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, diag.ErrNotFound) {
			writeError(w, http.StatusNotFound, CodeNotFound, err.Error(), "id", nil)
			return
		}
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"deleted":   true,
		"cancelled": cancelled,
		"run_id":    id,
	})
}

func runIDFromPath(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"The run identifier in the path is not a number.", "id", nil)
		return 0, false
	}
	return id, true
}
