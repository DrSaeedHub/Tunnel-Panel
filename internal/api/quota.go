package api

import (
	"net/http"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/quota"
	"github.com/drs/gre-panel/internal/validate"
)

// Traffic limits.
//
// One endpoint reports every limit's standing, one sets or removes a limit,
// and one resets a count. The statuses ride in a single response keyed by
// subject rather than being embedded into every list the subjects appear in,
// so a page shows them by joining two things it already has.

func (s *Server) requireQuota(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.quota == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Traffic limits are not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleQuotaStatuses(w http.ResponseWriter, r *http.Request) {
	tunnels, rules, destinations := s.quota.All()
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnels":      tunnels,
		"rules":        rules,
		"destinations": destinations,
	})
}

// quotaRequest names one subject and, for setting, its limit.
type quotaRequest struct {
	Scope       string `json:"scope"`
	TunnelID    int64  `json:"tunnel_id,omitempty"`
	RouteRuleID int64  `json:"route_rule_id,omitempty"`
	Address     string `json:"address,omitempty"`
	Port        int64  `json:"port,omitempty"`

	// LimitBytes of zero or absent removes the limit.
	LimitBytes int64 `json:"limit_bytes"`
	ModeID     int64 `json:"mode_id"`
	PeriodID   int64 `json:"period_id"`
}

func (s *Server) quotaSubject(w http.ResponseWriter, req quotaRequest) (quota.Subject, bool) {
	scope, err := quota.ParseScope(req.Scope)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed, err.Error(), "scope", nil)
		return quota.Subject{}, false
	}
	subject := quota.Subject{ScopeID: scope, TunnelID: req.TunnelID,
		RouteRuleID: req.RouteRuleID, Address: req.Address, Port: req.Port}

	switch scope {
	case model.QuotaScopeTunnel:
		if req.TunnelID <= 0 {
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
				"A tunnel limit needs the tunnel's id.", "tunnel_id", nil)
			return subject, false
		}
	case model.QuotaScopeRule:
		if req.RouteRuleID <= 0 {
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
				"A rule limit needs the rule's id.", "route_rule_id", nil)
			return subject, false
		}
	case model.QuotaScopeDestination:
		if req.RouteRuleID <= 0 || req.Address == "" ||
			req.Port < validate.MinPort || req.Port > validate.MaxPort {
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
				"A destination limit needs the rule's id and the destination's address and port.",
				"address", nil)
			return subject, false
		}
	}
	return subject, true
}

// handleSetQuota creates, replaces or removes one limit.
func (s *Server) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req quotaRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	subject, ok := s.quotaSubject(w, req)
	if !ok {
		return
	}

	err := s.quota.Set(r.Context(), subject,
		quota.Limit{LimitBytes: req.LimitBytes, ModeID: req.ModeID, PeriodID: req.PeriodID})
	s.auditRoute(r, model.AuditActionSettingUpdate, "traffic-limit", req, nil, err, start)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	s.quota.Sweep(r.Context())
	s.handleQuotaStatuses(w, r)
}

// handleResetQuota starts one limit's count over, and starts the subject again
// if this limit had stopped it.
func (s *Server) handleResetQuota(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req quotaRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	subject, ok := s.quotaSubject(w, req)
	if !ok {
		return
	}

	err := s.quota.Reset(r.Context(), subject)
	s.auditRoute(r, model.AuditActionSettingUpdate, "traffic-limit-reset", req, nil, err, start)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	s.handleQuotaStatuses(w, r)
}
