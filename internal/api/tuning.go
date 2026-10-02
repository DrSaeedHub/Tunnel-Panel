package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/tuning"
	"github.com/drs/gre-panel/internal/validate"
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
				i18n.T(r.Context(), "Kernel tuning is not available on this instance."), "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleTuning(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.tuningReport(r))
}

// tuningReport is the report as the operator reads it: each parameter's title,
// explanation, unit and choice notes said in the language of the request. The
// keys, values and recommendations are the kernel's and stay as they are.
func (s *Server) tuningReport(r *http.Request) tuning.Report {
	report := s.tuning.Report(s.liveConnections())
	ctx := r.Context()
	for i := range report.Readings {
		reading := &report.Readings[i]
		reading.Title = i18n.Tr(ctx, reading.Title)
		reading.Explain = i18n.Tr(ctx, reading.Explain)
		reading.Unit = i18n.Tr(ctx, reading.Unit)
		// Every report builds its own list of choices, so they can be said in
		// place.
		for j := range reading.Choices {
			reading.Choices[j].Detail = i18n.Tr(ctx, reading.Choices[j].Detail)
		}
	}
	return report
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
		"tuning":  s.tuningReport(r),
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
		"tuning":   s.tuningReport(r),
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

// tuningRequest is the parameters an operator set by hand.
//
// A parameter absent from the map is left exactly as it is, so the interface
// can send only the fields somebody touched rather than the whole page. A
// parameter present with an empty value asks the panel to stop keeping it.
type tuningRequest struct {
	Values map[string]string `json:"values"`
}

// handleSetTuning keeps the values an operator chose.
//
// Every value is checked before anything is written, and all the bad ones are
// reported at once: someone correcting a form should see every field that is
// wrong, not discover them one save at a time.
func (s *Server) handleSetTuning(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req tuningRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Values) == 0 {
		writeError(w, http.StatusBadRequest, CodeValidationFailed,
			i18n.T(r.Context(), "No parameters were sent."), "values", nil)
		return
	}

	errs := &validate.Errors{}
	for _, key := range sortedKeys(req.Values) {
		value := req.Values[key]
		if _, known := tuning.ParameterFor(key); !known {
			errs.Add("values."+key, CodeValidationFailed,
				i18n.T(r.Context(), "%s is not a parameter the panel knows.", key), nil)
			continue
		}
		if strings.TrimSpace(value) == "" {
			// Asking the panel to stop keeping a parameter is not a value to
			// be validated.
			continue
		}
		// The reason is a whole sentence naming the parameter, already in the
		// request's language.
		if err := s.tuning.Validate(r.Context(), key, value); err != nil {
			errs.Add("values."+key, CodeValidationFailed, err.Error(), nil)
		}
	}
	if !errs.Empty() {
		s.writeRouteError(w, r, errs)
		return
	}

	applied, err := s.tuning.Set(r.Context(), req.Values)
	if err != nil {
		s.auditRoute(r, model.AuditActionSettingUpdate, "tuning", nil, nil, err, start)
		s.writeRouteError(w, r, err)
		return
	}
	s.auditRoute(r, model.AuditActionSettingUpdate, "tuning",
		map[string]any{"applied": applied, "values": req.Values}, nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{
		"applied": applied,
		"tuning":  s.tuningReport(r),
	})
}

// sortedKeys keeps the order of reported failures stable, so two saves of the
// same bad form say the same thing in the same order.
func sortedKeys(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
