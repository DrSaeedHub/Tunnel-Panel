package api

import (
	"net/http"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/reconcile"
)

// handleReconcile compares what the panel believes against what the host
// actually holds (§12).
func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	report, err := s.reconcile.Report(r.Context())
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// handleAdopt imports an interface that already exists (§12).
func (s *Server) handleAdopt(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req reconcile.AdoptRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	result, err := s.reconcile.Adopt(r.Context(), req)
	if err != nil {
		s.auditTunnel(r, model.AuditActionTunnelAdopt, req.InterfaceName, req, nil, err, start)
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelAdopt, req.InterfaceName, req, nil, nil, start)
	writeJSON(w, http.StatusCreated, map[string]any{
		"tunnel":            result.Tunnel,
		"legacy":            result.Legacy,
		"imported":          result.Imported,
		"units_taken_over":  result.UnitsTakenOver,
		"backups":           result.Backups,
		"interface_bounced": result.InterfaceBounced,
		"warnings":          reconcileWarnings(result),
	})
}

// handleReconcileReapply rebuilds a tunnel from its stored desired state, which
// is the remedy for drift (§12).
func (s *Server) handleReconcileReapply(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	var patch tunnelPatch
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &patch) {
			return
		}
	}
	req := patch.request(tunnelInputOf(rec), ClientIP(r))

	result, err := s.tunnels.Reapply(r.Context(), rec.TunnelID, req)
	if err != nil {
		s.auditTunnel(r, model.AuditActionTunnelReapply, rec.InterfaceName, patch, nil, err, start)
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelReapply, rec.InterfaceName, patch, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"action":       "reapply",
		"tunnel":       result.Tunnel,
		"plan":         result.Plan,
		"verification": result.Verify,
		"warnings":     warningsOf(result.Warnings),
	})
}

// handleForget drops the panel's record of a tunnel without touching the
// kernel. It is the right action for a tunnel something else now owns (§12).
func (s *Server) handleForget(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	forgotten, err := s.reconcile.Forget(r.Context(), rec.TunnelID)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelDelete, rec.InterfaceName,
		map[string]any{"forgotten": true}, nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"forgotten": true,
		"tunnel":    forgotten,
		"note": "The record has been dropped. The interface " + forgotten.InterfaceName +
			" was not touched and is still on this host.",
	})
}

// ignoreRequest names an interface reconcile should stop reporting.
type ignoreRequest struct {
	InterfaceName string `json:"interface_name"`
	// Ignored defaults to true; send false to start reporting it again.
	Ignored *bool `json:"ignored,omitempty"`
}

func (s *Server) handleIgnore(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req ignoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ignored := true
	if req.Ignored != nil {
		ignored = *req.Ignored
	}

	var userID *int64
	if user := UserFromContext(r.Context()); user != nil {
		id := user.UserID
		userID = &id
	}

	list, err := reconcile.SetIgnored(r.Context(), s.settings, req.InterfaceName, ignored, userID)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			capitalise(err.Error())+".", "interface_name", nil)
		return
	}

	s.auditTunnel(r, model.AuditActionSettingUpdate, req.InterfaceName, req, nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"ignored_interfaces": list,
		"note": "Ignoring an interface only stops it being reported. The panel never changes or removes " +
			"an interface it does not manage either way.",
	})
}
