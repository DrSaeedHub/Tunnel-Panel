package api

import (
	"errors"
	"net/http"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/update"
)

// updateResponse is the body of GET /system/update and of both of its POSTs.
//
// One shape for all three, because they are one question asked at different
// moments: what is running, what is being served, whether this installation can
// close the gap, and where the last attempt got to. A client that polls during
// an update reads exactly what it read before pressing the button.
type updateResponse struct {
	update.Status
	// State is the last update this panel started, including one that is still
	// going. It survives the restart in the middle of an update, which is the
	// only reason the browser can report the outcome at all.
	State update.State `json:"state"`
	// CanApply reports whether the update button does anything here, and
	// Reason says why it does not. A development panel, a container without
	// systemd and an install whose CLI was removed are all real, and each one
	// deserves the reason rather than a button that fails when pressed.
	CanApply bool   `json:"can_apply"`
	Reason   string `json:"reason,omitempty"`
}

// requireUpdates answers clearly when the update subsystem is not wired, rather
// than letting a nil dereference become a 500. In practice this only happens in
// a test that builds the HTTP layer on its own.
func (s *Server) requireUpdates(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.updates == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Update checking is not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleUpdateStatus reports what is known, refreshing in the background when
// the last answer has aged past the check interval.
//
// It never waits on the release host. The panel is frequently installed on a
// server with no outbound access at all, where every check ends in a timeout,
// and a status endpoint that inherited that timeout would make the dashboard
// footer the slowest thing on the page.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.updateResponse(r))
}

// handleUpdateCheck asks the release host now.
//
// This one does wait: an operator who pressed "check again" is owed the answer
// to the question they asked, not the answer from before they asked it.
func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	status := s.updates.Checker.Refresh(r.Context())
	writeJSON(w, http.StatusOK, s.buildUpdateResponse(r, status))
}

// updateRequest is the optional body of POST /system/update.
type updateRequest struct {
	// Version is a release tag, or empty for whatever the release host is
	// currently serving as its latest.
	Version string `json:"version"`
}

// handleUpdateStart installs a new version.
//
// The answer goes out before anything restarts, for the same reason the address
// change and the database restore do: the connection carrying it is one of the
// ones the restart ends, and a client that never got a reply cannot tell a
// refused update from a started one. From here the browser polls the status
// endpoint, which fails while the panel is down — that failure is the restart,
// and it is what the progress dialog is watching for.
func (s *Server) handleUpdateStart(w http.ResponseWriter, r *http.Request) {
	var req updateRequest
	// A body is optional here; an empty request means "whatever is latest".
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}

	actor := ""
	if user := UserFromContext(r.Context()); user != nil {
		actor = user.Username
	}

	state, err := s.updates.Applier.Start(r.Context(), req.Version, actor)
	if err != nil {
		var unavailable *update.Unavailable
		switch {
		case errors.As(err, &unavailable):
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable, unavailable.Reason, "", nil)
		case errors.Is(err, update.ErrUpdateRunning):
			writeError(w, http.StatusConflict, CodeConflict,
				"An update is already running. Watch this one rather than starting a second.", "", nil)
		default:
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed, err.Error(), "version", nil)
		}
		return
	}

	// Recorded before the response, because what happens next is the panel
	// being replaced: an audit entry written afterwards may never be written.
	s.writeAudit(r, model.AuditActionPanelUpdate, "Panel", state.TargetVersion, map[string]any{
		"from_version": state.FromVersion,
		"to_version":   state.TargetVersion,
		"unit":         state.Unit,
	})

	response := s.buildUpdateResponse(r, s.updates.Checker.Status(r.Context()))
	response.State = state
	writeJSON(w, http.StatusAccepted, response)
}

// updateResponse assembles the current picture.
func (s *Server) updateResponse(r *http.Request) updateResponse {
	return s.buildUpdateResponse(r, s.updates.Checker.Status(r.Context()))
}

func (s *Server) buildUpdateResponse(r *http.Request, status update.Status) updateResponse {
	out := updateResponse{Status: status, State: s.updates.Applier.State(r.Context())}
	if err := s.updates.Applier.Available(); err != nil {
		out.Reason = err.Error()
		return out
	}
	out.CanApply = true
	return out
}
