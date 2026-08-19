package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/sourcelist"
)

// The named address lists a forwarding rule allows traffic from.
//
// They are their own resource rather than a shape of a rule because that is
// what they are for: one list, several rules, edited in one place. The rules
// pointing at a list are reinstalled when it changes, which is the whole reason
// an operator keeps the ranges here instead of in each rule.

// sourceListRequest is the body for creating and replacing a list.
//
// Entries is the whole list rather than an addition, and it is a single string
// rather than an array because that is how it arrives: pasted out of a text
// box, or read from a file an operator uploaded. Splitting it is the server's
// job, since the separators vary and the client should not have to guess.
type sourceListRequest struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Entries     string `json:"entries"`
}

func (s *Server) requireSourceLists(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.sourceLists == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Source lists are not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleSourceLists(w http.ResponseWriter, r *http.Request) {
	lists, err := s.sourceLists.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternal, err.Error(), "", nil)
		return
	}
	if lists == nil {
		lists = []sourcelist.Record{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"source_lists": lists, "total": len(lists)})
}

func (s *Server) handleSourceList(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.sourceListFromPath(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"source_list": rec})
}

func (s *Server) handleCreateSourceList(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req sourceListRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	rec, err := s.sourceLists.Create(r.Context(), sourcelist.Input{
		Name: req.Name, Description: req.Description, Entries: []string{req.Entries},
	})
	if err != nil {
		s.writeSourceListError(w, err)
		return
	}
	s.auditRoute(r, model.AuditActionSettingUpdate, "source_list:"+rec.Name, req, nil, nil, start)
	writeJSON(w, http.StatusCreated, map[string]any{"source_list": rec})
}

func (s *Server) handleUpdateSourceList(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.sourceListFromPath(w, r)
	if !ok {
		return
	}
	var req sourceListRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = rec.Name
	}

	updated, err := s.sourceLists.Update(r.Context(), rec.SourceListID, sourcelist.Input{
		Name: req.Name, Description: req.Description, Entries: []string{req.Entries},
	})
	if err != nil {
		s.writeSourceListError(w, err)
		return
	}
	s.auditRoute(r, model.AuditActionSettingUpdate, "source_list:"+updated.Name, req, nil, nil, start)

	// A list is only worth keeping in one place if editing it reaches the rules
	// that allow it. The rebuild is the whole ruleset in one transaction, the
	// same as any other change, and it happens whether the panel is being
	// watched or not.
	applied := s.reapplyForSourceList(r, updated.SourceListID)
	writeJSON(w, http.StatusOK, map[string]any{
		"source_list": updated,
		// reapplied says how many rules were reinstalled, so an operator editing
		// a list they thought nothing used finds out that four rules changed.
		"reapplied": applied,
	})
}

func (s *Server) handleDeleteSourceList(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.sourceListFromPath(w, r)
	if !ok {
		return
	}
	if err := s.sourceLists.Delete(r.Context(), rec.SourceListID); err != nil {
		s.writeSourceListError(w, err)
		return
	}
	s.auditRoute(r, model.AuditActionSettingUpdate, "source_list:"+rec.Name,
		map[string]any{"deleted": true}, nil, nil, start)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "source_list": rec})
}

// reapplyForSourceList reinstalls the rules that allow a list. It reports how
// many there were; a failure is logged and reported as zero rather than failing
// the edit, because the list is stored either way and refusing to acknowledge
// that would leave the operator unsure what happened.
func (s *Server) reapplyForSourceList(r *http.Request, id int64) int {
	if s.routes == nil {
		return 0
	}
	ids, err := s.sourceLists.RuleIDs(r.Context(), id)
	if err != nil || len(ids) == 0 {
		return 0
	}
	if _, err := s.routes.ApplyAll(r.Context(), route.Request{ClientIP: ClientIP(r)}); err != nil {
		s.log.Error("reinstalling the rules that allow a source list failed",
			"source_list", id, "rules", len(ids), "error", err)
		return 0
	}
	return len(ids)
}

func (s *Server) sourceListFromPath(w http.ResponseWriter, r *http.Request) (sourcelist.Record, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, CodeValidationFailed,
			"That is not a source list identifier.", "id", nil)
		return sourcelist.Record{}, false
	}
	rec, err := s.sourceLists.ByID(r.Context(), id)
	if err != nil {
		s.writeSourceListError(w, err)
		return sourcelist.Record{}, false
	}
	return rec, true
}

func (s *Server) writeSourceListError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sourcelist.ErrNotFound):
		writeError(w, http.StatusNotFound, CodeNotFound, capitalise(err.Error())+".", "", nil)
	case errors.Is(err, sourcelist.ErrNameTaken):
		writeError(w, http.StatusConflict, CodeValidationFailed, capitalise(err.Error())+".", "name", nil)
	case errors.Is(err, sourcelist.ErrInUse):
		writeError(w, http.StatusConflict, CodeValidationFailed, capitalise(err.Error())+".", "", nil)
	default:
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			capitalise(err.Error())+".", "", nil)
	}
}
