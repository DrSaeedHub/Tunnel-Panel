package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// requireRoutes answers clearly when the forwarding subsystem is not wired,
// rather than letting a nil dereference become a 500. In practice this only
// happens in a test that builds the HTTP layer on its own.
func (s *Server) requireRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.routes == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Port forwarding is not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// routeResponse is one forwarding rule as the API reports it: the stored
// desired state, its health, and its live traffic — kept as separate fields
// because conflating what the panel intends with what the kernel holds is how a
// panel ends up reporting a rule as working when it is not.
type routeResponse struct {
	Route   route.Record   `json:"route"`
	Health  route.Health   `json:"health"`
	Traffic *route.Traffic `json:"traffic,omitempty"`
}

// routeListResponse is the paginated envelope, matching the tunnel list.
type routeListResponse struct {
	Routes []routeResponse `json:"routes"`
	Total  int             `json:"total"`
	Limit  int             `json:"limit"`
	Offset int             `json:"offset"`
	// Note explains the two sets of byte figures wherever they are returned.
	Note string `json:"note"`
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	records, err := s.routes.Repo().List(ctx)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	records = filterRoutes(records, r)

	// One read of the live ruleset for the whole list rather than one per rule.
	health := s.routes.Health(ctx, records)

	limit, offset := pagination(r)
	total := len(records)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	out := routeListResponse{
		Routes: []routeResponse{}, Total: total, Limit: limit, Offset: offset,
		Note: route.SinceBootMeaning,
	}
	for _, rec := range records[offset:end] {
		out.Routes = append(out.Routes, routeResponse{
			Route: rec, Health: health[rec.RouteRuleID], Traffic: s.trafficFor(rec.RouteRuleID),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// filterRoutes applies the query filters the list page uses. Filtering here
// rather than in SQL keeps the repository's one query simple, and the set is
// small: a host with thousands of forwarding rules is not the case this is for.
func filterRoutes(records []route.Record, r *http.Request) []route.Record {
	query := r.URL.Query()
	search := strings.ToLower(strings.TrimSpace(query.Get("search")))
	protocol := query.Get("route_protocol_id")
	natMode := query.Get("nat_mode_id")
	tunnel := query.Get("tunnel_id")
	enabled := query.Get("is_enabled")

	out := make([]route.Record, 0, len(records))
	for _, rec := range records {
		if search != "" && !strings.Contains(strings.ToLower(rec.Describe()), search) &&
			!strings.Contains(strings.ToLower(rec.Description), search) {
			continue
		}
		if protocol != "" && strconv.FormatInt(rec.RouteProtocolID, 10) != protocol {
			continue
		}
		if natMode != "" && strconv.FormatInt(rec.NatModeID, 10) != natMode {
			continue
		}
		if tunnel != "" {
			if rec.TunnelID == nil || strconv.FormatInt(*rec.TunnelID, 10) != tunnel {
				continue
			}
		}
		if enabled != "" {
			want := enabled == "true" || enabled == "1"
			if rec.IsEnabled != want {
				continue
			}
		}
		out = append(out, rec)
	}
	return out
}

func (s *Server) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	health := s.routes.Health(r.Context(), []route.Record{rec})
	writeJSON(w, http.StatusOK, routeResponse{
		Route: rec, Health: health[rec.RouteRuleID], Traffic: s.trafficFor(rec.RouteRuleID),
	})
}

// routeResultResponse carries the rule, the plan that was carried out, the
// verification report and the warnings, matching the tunnel create response.
type routeResultResponse struct {
	Route        route.Record       `json:"route"`
	Plan         route.Plan         `json:"plan"`
	Verification route.VerifyReport `json:"verification"`
	Warnings     []Warning          `json:"warnings"`
}

func routeResult(result route.Result) routeResultResponse {
	return routeResultResponse{
		Route: result.Route, Plan: result.Plan, Verification: result.Verify,
		Warnings: warningsOf(result.Warnings),
	}
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var patch routePatch
	if !decodeJSON(w, r, &patch) {
		return
	}
	req := patch.request(newRouteRequest(), ClientIP(r))

	result, err := s.routes.Create(r.Context(), req)
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteCreate, req.RouteRuleTitle, patch, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteCreate, result.Route.RouteRuleTitle, patch,
		result.Operations, nil, start)
	writeJSON(w, http.StatusCreated, routeResult(result))
}

func (s *Server) handleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}

	var patch routePatch
	if !decodeJSON(w, r, &patch) {
		return
	}
	// An update starts from what the rule already is, so a request mentioning
	// one field changes only that field.
	req := patch.request(route.Input(rec), ClientIP(r))

	result, err := s.routes.Update(r.Context(), rec.RouteRuleID, req)
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteUpdate, rec.RouteRuleTitle, patch, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteUpdate, rec.RouteRuleTitle, patch, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, routeResult(result))
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}

	var patch routePatch
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &patch) {
			return
		}
	}
	req := patch.request(route.Input(rec), ClientIP(r))

	report, err := s.routes.Delete(r.Context(), rec.RouteRuleID, req)
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteDelete, rec.RouteRuleTitle, patch,
			report.Operations, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteDelete, rec.RouteRuleTitle, patch,
		report.Operations, nil, start)
	body := map[string]any{
		"route_rule_id":              report.RouteRuleID,
		"title":                      report.Title,
		"plan":                       report.Plan,
		"verification":               report.Verify,
		"forwarding_can_be_reverted": report.ForwardingCanBeReverted,
	}
	if report.ForwardingCanBeReverted {
		body["note"] = "That was the last forwarding rule, and the panel was the one that turned IP " +
			"forwarding on. It has been left on: other software on this server may have come to " +
			"depend on it. Turn it off from the forwarding page if you want it reverted."
	}
	writeJSON(w, http.StatusOK, body)
}

// routeAction serves enable, disable and reapply, which differ only in the
// service method they call and the audit action they record.
func (s *Server) routeAction(action string, actionID int64,
	run func(context.Context, int64, route.Request) (route.Result, error)) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec, ok := s.routeFromPath(w, r)
		if !ok {
			return
		}

		var patch routePatch
		if r.ContentLength > 0 {
			if !decodeJSON(w, r, &patch) {
				return
			}
		}
		req := patch.request(route.Input(rec), ClientIP(r))

		result, err := run(r.Context(), rec.RouteRuleID, req)
		if err != nil {
			s.auditRoute(r, actionID, rec.RouteRuleTitle, patch, nil, err, start)
			s.writeRouteError(w, r, err)
			return
		}

		s.auditRoute(r, actionID, rec.RouteRuleTitle, patch, result.Operations, nil, start)
		writeJSON(w, http.StatusOK, map[string]any{
			"action":       action,
			"route":        result.Route,
			"plan":         result.Plan,
			"verification": result.Verify,
			"warnings":     warningsOf(result.Warnings),
		})
	}
}

// handlePreviewRoute runs validate and plan only, returning the exact ruleset
// that would be applied. Nothing is stored and nothing on the host is touched
// (§7).
func (s *Server) handlePreviewRoute(w http.ResponseWriter, r *http.Request) {
	var patch routePatch
	if !decodeJSON(w, r, &patch) {
		return
	}

	var (
		preview route.Preview
		err     error
	)
	if patch.RouteRuleID != nil {
		rec, lookupErr := s.routes.Repo().ByID(r.Context(), *patch.RouteRuleID)
		if lookupErr != nil {
			s.writeRouteError(w, r, lookupErr)
			return
		}
		preview, err = s.routes.PreviewUpdate(r.Context(), rec.RouteRuleID,
			patch.request(route.Input(rec), ClientIP(r)))
	} else {
		preview, err = s.routes.PreviewCreate(r.Context(), patch.request(newRouteRequest(), ClientIP(r)))
	}
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"plan":     preview.Plan,
		"route":    preview.Route,
		"payload":  preview.Payload,
		"warnings": warningsOf(preview.Warnings),
		"note": "Nothing has been applied. This is the exact ruleset that would be submitted to " +
			"netfilter, in one transaction.",
	})
}

func (s *Server) handleDuplicateRoute(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}

	var patch routePatch
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &patch) {
			return
		}
	}
	req := route.Request{ClientIP: ClientIP(r)}
	if patch.RouteRuleTitle != nil {
		req.RouteRuleTitle = *patch.RouteRuleTitle
	}

	result, err := s.routes.Duplicate(r.Context(), rec.RouteRuleID, req)
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteCreate, rec.RouteRuleTitle, patch, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteCreate, result.Route.RouteRuleTitle, patch,
		result.Operations, nil, start)
	writeJSON(w, http.StatusCreated, map[string]any{
		"route":        result.Route,
		"plan":         result.Plan,
		"verification": result.Verify,
		"warnings":     warningsOf(result.Warnings),
		"note": "The copy was created disabled and with a free name, because an exact copy of an " +
			"enabled rule would claim the same listener and be refused. Edit it and enable it.",
	})
}

// reorderRequest is the new emission order, most significant first.
type reorderRequest struct {
	RouteRuleIDs []int64 `json:"route_rule_ids"`
}

// handleReorderRoutes writes a new emission order and reinstalls the ruleset.
// The order is user-visible behaviour: two overlapping rules resolve
// first-match-wins, so which one is emitted first decides which one matches.
func (s *Server) handleReorderRoutes(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req reorderRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.RouteRuleIDs) == 0 {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			"Send the forwarding rule identifiers in the order they should be emitted.",
			"route_rule_ids", nil)
		return
	}

	result, err := s.routes.Reorder(r.Context(), req.RouteRuleIDs, route.Request{ClientIP: ClientIP(r)})
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteUpdate, "reorder", req, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteUpdate, "reorder", req, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"action":       "reorder",
		"plan":         result.Plan,
		"verification": result.Verify,
		"warnings":     warningsOf(result.Warnings),
		"note": "Rules are emitted in this order. Where two rules could match the same packet, the " +
			"first one wins.",
	})
}

// handleApplyAllRoutes installs every enabled rule as one transaction, which is
// what editing several rules produces: one apply, not one per rule (§7).
func (s *Server) handleApplyAllRoutes(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	result, err := s.routes.ApplyAll(r.Context(), route.Request{ClientIP: ClientIP(r)})
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteReapply, "apply-all", nil, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteReapply, "apply-all", nil, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"action":        "apply_all",
		"plan":          result.Plan,
		"verification":  result.Verify,
		"warnings":      warningsOf(result.Warnings),
		"rules_applied": len(result.Plan.AffectedRouteRuleIDs),
		"note":          "Every enabled rule was installed in one transaction.",
	})
}

// ---------------------------------------------------------- nested children

// handleListDestinations returns a rule's destinations.
func (s *Server) handleListDestinations(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"destinations":         rec.Destinations,
		"total":                len(rec.Destinations),
		"load_balance_mode_id": rec.LoadBalanceModeID,
	})
}

// changeDestinations rewrites a rule's destination list through the ordinary
// update path, so adding one is validated, planned, applied, verified and
// rolled back exactly like any other change.
func (s *Server) changeDestinations(w http.ResponseWriter, r *http.Request,
	mutate func([]validate.RouteDestinationInput, validate.RouteDestinationInput) []validate.RouteDestinationInput) {

	start := time.Now()
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	var body validate.RouteDestinationInput
	if !decodeJSON(w, r, &body) {
		return
	}

	in := route.Input(rec)
	in.Destinations = mutate(in.EffectiveDestinations(), body)
	req := route.Request{RouteInput: in, ClientIP: ClientIP(r)}

	result, err := s.routes.Update(r.Context(), rec.RouteRuleID, req)
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteUpdate, rec.RouteRuleTitle, body, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteUpdate, rec.RouteRuleTitle, body, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, routeResult(result))
}

func (s *Server) handleAddDestination(w http.ResponseWriter, r *http.Request) {
	s.changeDestinations(w, r, func(current []validate.RouteDestinationInput,
		add validate.RouteDestinationInput) []validate.RouteDestinationInput {
		return append(current, add)
	})
}

func (s *Server) handleRemoveDestination(w http.ResponseWriter, r *http.Request) {
	s.changeDestinations(w, r, func(current []validate.RouteDestinationInput,
		remove validate.RouteDestinationInput) []validate.RouteDestinationInput {

		kept := make([]validate.RouteDestinationInput, 0, len(current))
		for _, d := range current {
			matchesID := remove.RouteDestinationID != 0 && d.RouteDestinationID == remove.RouteDestinationID
			matchesAddress := remove.RouteDestinationID == 0 && d.Address == remove.Address &&
				(remove.Port == 0 || d.Port == remove.Port)
			if matchesID || matchesAddress {
				continue
			}
			kept = append(kept, d)
		}
		return kept
	})
}

func (s *Server) handleListAllowedSources(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	body := map[string]any{"allowed_sources": rec.AllowedSources, "total": len(rec.AllowedSources)}
	if len(rec.AllowedSources) == 0 {
		body["note"] = "This rule has no allowlist, so any source that can reach the bind address " +
			"may use the relay."
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) changeAllowedSources(w http.ResponseWriter, r *http.Request,
	mutate func([]validate.RouteAllowedSourceInput, validate.RouteAllowedSourceInput) []validate.RouteAllowedSourceInput) {

	start := time.Now()
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	var body validate.RouteAllowedSourceInput
	if !decodeJSON(w, r, &body) {
		return
	}

	in := route.Input(rec)
	in.AllowedSources = mutate(in.AllowedSources, body)
	req := route.Request{RouteInput: in, ClientIP: ClientIP(r)}

	result, err := s.routes.Update(r.Context(), rec.RouteRuleID, req)
	if err != nil {
		s.auditRoute(r, model.AuditActionRouteUpdate, rec.RouteRuleTitle, body, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionRouteUpdate, rec.RouteRuleTitle, body, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, routeResult(result))
}

func (s *Server) handleAddAllowedSource(w http.ResponseWriter, r *http.Request) {
	s.changeAllowedSources(w, r, func(current []validate.RouteAllowedSourceInput,
		add validate.RouteAllowedSourceInput) []validate.RouteAllowedSourceInput {
		return append(current, add)
	})
}

func (s *Server) handleRemoveAllowedSource(w http.ResponseWriter, r *http.Request) {
	s.changeAllowedSources(w, r, func(current []validate.RouteAllowedSourceInput,
		remove validate.RouteAllowedSourceInput) []validate.RouteAllowedSourceInput {

		kept := make([]validate.RouteAllowedSourceInput, 0, len(current))
		for _, source := range current {
			matchesID := remove.RouteAllowedSourceID != 0 &&
				source.RouteAllowedSourceID == remove.RouteAllowedSourceID
			matchesCidr := remove.RouteAllowedSourceID == 0 && source.Cidr == remove.Cidr
			if matchesID || matchesCidr {
				continue
			}
			kept = append(kept, source)
		}
		return kept
	})
}

// ---------------------------------------------------------------- traffic

// requireAccounting answers clearly when the traffic sampler is not wired.
func (s *Server) requireAccounting(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.accounting == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Forwarding traffic accounting is not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) trafficFor(routeRuleID int64) *route.Traffic {
	if s.accounting == nil {
		return nil
	}
	if traffic, ok := s.accounting.Traffic(routeRuleID); ok {
		return &traffic
	}
	return nil
}

// handleRouteTraffic returns one rule's current figures plus the in-memory ring
// buffer the sparkline is drawn from.
func (s *Server) handleRouteTraffic(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	limit := intQuery(r, "points", 0)
	traffic, known := s.accounting.Traffic(rec.RouteRuleID)

	writeJSON(w, http.StatusOK, map[string]any{
		"route_rule_id": rec.RouteRuleID,
		"title":         rec.RouteRuleTitle,
		"traffic":       traffic,
		"sampled":       known,
		"points":        s.accounting.History(rec.RouteRuleID, limit),
		"note":          route.SinceBootMeaning,
	})
}

// handleRouteTrafficHistory returns the stored aggregate buckets.
func (s *Server) handleRouteTrafficHistory(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	hours := intQuery(r, "hours", 24)
	if hours <= 0 || hours > 24*365 {
		hours = 24
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)

	samples, err := s.accounting.StoredHistory(r.Context(), rec.RouteRuleID, since, intQuery(r, "limit", 0))
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_rule_id": rec.RouteRuleID,
		"samples":       samples,
		"total":         len(samples),
		"since":         model.FormatTime(since.UTC()),
		"note": "Each row covers one aggregate interval and holds the bytes that moved in it, not a " +
			"running total.",
	})
}

// handleRouteTrafficSummary totals every rule, which the dashboard shows.
func (s *Server) handleRouteTrafficSummary(w http.ResponseWriter, r *http.Request) {
	all := s.accounting.All()
	sort.Slice(all, func(i, j int) bool {
		return all[i].RxBytesPerSecond+all[i].TxBytesPerSecond >
			all[j].RxBytesPerSecond+all[j].TxBytesPerSecond
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"summary": s.accounting.Summary(),
		"routes":  all,
		"note":    route.SinceBootMeaning,
	})
}

// ---------------------------------------------------------------- diagnostics

// requireRouteDiag answers clearly when the forwarding diagnostics are not
// wired.
func (s *Server) requireRouteDiag(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.routeDiag == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Forwarding diagnostics are not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleRouteTest probes a destination.
//
// It is routed both under a rule and on its own, because §8 requires it as a
// pre-flight before the rule exists — which is the moment it is most useful,
// since it turns "create it and see" into an answer. Like the tunnel probes it
// changes nothing and is not audited: it is a read of the network.
func (s *Server) handleRouteTest(w http.ResponseWriter, r *http.Request) {
	var params route.ReachabilityParams
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &params) {
			return
		}
	}

	routeRuleID := int64(0)
	if chi.URLParam(r, "id") != "" {
		rec, ok := s.routeFromPath(w, r)
		if !ok {
			return
		}
		routeRuleID = rec.RouteRuleID
	}

	result, err := s.routeDiag.Test(r.Context(), routeRuleID, params)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRouteAnalyze(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	var params route.AnalyzeParams
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &params) {
			return
		}
	}

	result, err := s.routeDiag.Analyze(r.Context(), rec.RouteRuleID, params)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRouteConnections(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	list, err := s.routeDiag.Connections(r.Context(), rec.RouteRuleID, intQuery(r, "limit", 200))
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// handleRouteDestinationHealth reports what the monitor has found about each of
// a rule's destinations.
//
// A panel with no monitor answers with an empty list rather than a 503: the
// question "what does monitoring say" has an honest answer on an installation
// that does no monitoring, and it is "nothing".
func (s *Server) handleRouteDestinationHealth(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	health := []route.DestinationHealth{}
	if s.routeMonitor != nil {
		health = s.routeMonitor.Health(rec.RouteRuleID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"route_rule_id": rec.RouteRuleID,
		"destinations":  health,
		"monitoring":    s.routeMonitor != nil,
	})
}

func (s *Server) handleRouteCounters(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.routeFromPath(w, r)
	if !ok {
		return
	}
	report, err := s.routeDiag.Counters(r.Context(), rec.RouteRuleID)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// ---------------------------------------------------------------- system

// handleForwarding reports the kernel's forwarding state, the connection
// tracking table, the active netfilter backend and the other software found
// managing netfilter here (§11).
func (s *Server) handleForwarding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	forwarding := s.routes.Forwarding()
	if forwarding == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"The kernel forwarding parameters are not managed on this instance.", "", nil)
		return
	}

	desired, err := s.routes.Repo().Desired(ctx)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}
	warnPercent := s.settings.Float("routes.warn_conntrack_usage_percent")
	status := forwarding.Status(ctx, desired.HasIPv6(), len(desired.Routes), warnPercent)

	backend := s.routes.Backend()
	status.Backend = backend.Name()
	status.Namespace = backend.Capabilities().Namespace

	body := map[string]any{
		"forwarding": status,
		"warnings":   warningsOf(status.Warnings),
		"backend":    s.ruleBackendCapability(),
	}
	// The other software managing netfilter here, which is what turns "my rule
	// does nothing" into an answer.
	if view, err := backend.Foreign(ctx); err == nil {
		body["foreign"] = map[string]any{
			"readable": view.Readable,
			"managers": view.Managers,
			"rules":    view.Rules,
			"total":    len(view.Rules),
		}
	} else {
		body["foreign"] = map[string]any{
			"readable": false,
			"detail":   "the rest of this host's netfilter rules could not be read: " + err.Error(),
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// forwardingRequest turns forwarding on, or asks for the panel's own change to
// be put back.
type forwardingRequest struct {
	// Revert asks for the parameters the panel changed to be restored and its
	// sysctl file removed. The panel offers this and never does it by itself
	// (§2.3).
	Revert bool `json:"revert,omitempty"`
}

func (s *Server) handleEnableForwarding(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req forwardingRequest
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}

	forwarding := s.routes.Forwarding()
	if forwarding == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"The kernel forwarding parameters are not managed on this instance.", "", nil)
		return
	}

	ctx := r.Context()
	desired, err := s.routes.Repo().Desired(ctx)
	if err != nil {
		s.writeRouteError(w, r, err)
		return
	}

	action, note := "enable", "IP forwarding is on and recorded in the panel's own sysctl file."
	if req.Revert {
		action = "revert"
		note = "The kernel parameters the panel changed have been put back and its sysctl file removed."
		err = forwarding.Revert(ctx)
	} else {
		err = forwarding.Enable(ctx, desired.HasIPv6(),
			s.settings.Bool("routes.count_connection_bytes"))
	}
	if err != nil {
		s.auditRoute(r, model.AuditActionSettingUpdate, "ip_forward", req, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}

	s.auditRoute(r, model.AuditActionSettingUpdate, "ip_forward", req, nil, nil, start)
	status := forwarding.Status(ctx, desired.HasIPv6(), len(desired.Routes),
		s.settings.Float("routes.warn_conntrack_usage_percent"))
	writeJSON(w, http.StatusOK, map[string]any{
		"action":     action,
		"forwarding": status,
		"warnings":   warningsOf(status.Warnings),
		"note":       note,
	})
}

// handleTunnelRoutes lists the forwarding rules that relay over one tunnel, for
// the tunnel detail page (§10).
func (s *Server) handleTunnelRoutes(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	dependants, err := s.tunnels.DependentRoutes(r.Context(), rec.TunnelID)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	if dependants == nil {
		dependants = []tunnel.DependentRoute{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnel_id": rec.TunnelID,
		"interface": rec.InterfaceName,
		// The address at the far end, which is what a new rule's destination is
		// prefilled with when the operator chooses "send to a tunnel" (§10).
		"peer_address": tunnel.PeerAddressOf(rec),
		"routes":       dependants,
		"total":        len(dependants),
		"note": "These forwarding rules send their traffic through this tunnel. Taking it down leaves " +
			"their rules installed and removes the path they use.",
	})
}

// ---------------------------------------------------------------- helpers

// routeFromPath resolves {id} and writes the error response itself when it
// cannot.
func (s *Server) routeFromPath(w http.ResponseWriter, r *http.Request) (route.Record, bool) {
	raw := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"The forwarding rule identifier in the path is not a number.", "id", nil)
		return route.Record{}, false
	}
	rec, err := s.routes.Repo().ByID(r.Context(), id)
	if err != nil {
		s.writeRouteError(w, r, err)
		return route.Record{}, false
	}
	return rec, true
}

// intQuery reads a whole-number query parameter with a fallback.
func intQuery(r *http.Request, name string, fallback int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

// auditRoute records one mutating request with its actor, its client address,
// and the exact operations performed (§18).
func (s *Server) auditRoute(r *http.Request, actionID int64, target string, request any,
	operations []audit.Operation, err error, start time.Time) {

	entry := audit.Entry{
		ActionID: actionID, TargetType: "RouteRule", TargetID: target,
		Request: request, Operations: operations,
		IsSuccess: err == nil, Duration: time.Since(start), ClientIP: ClientIP(r),
	}
	if user := UserFromContext(r.Context()); user != nil {
		id := user.UserID
		entry.UserID = &id
	}
	if err != nil {
		entry.ErrorMessage = err.Error()
	}
	s.audit.Write(r.Context(), entry)
}
