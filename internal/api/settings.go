package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/settings"
)

// settingsResponse is the body of GET /settings: the effective value of every
// setting, keyed by setting key.
type settingsResponse struct {
	Settings map[string]any `json:"settings"`
}

// schemaResponse is the body of GET /settings/schema. It carries the full
// metadata for every setting alongside its current value, so the frontend can
// render the settings screen generically from one request (§5.3).
type schemaResponse struct {
	Settings   []settings.SchemaEntry `json:"settings"`
	Categories []string               `json:"categories"`
}

// resetRequest is the body of POST /settings/reset. An empty or absent key list
// resets every setting.
type resetRequest struct {
	Keys []string `json:"keys,omitempty"`
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, settingsResponse{Settings: s.settings.All()})
}

func (s *Server) handleGetSettingsSchema(w http.ResponseWriter, r *http.Request) {
	entries := s.settings.Schema()

	// Categories are returned in first-appearance order, which is the
	// specification order, so the UI does not have to invent a grouping.
	seen := map[string]bool{}
	categories := make([]string, 0, 9)
	for _, e := range entries {
		if !seen[e.Category] {
			seen[e.Category] = true
			categories = append(categories, e.Category)
		}
	}
	writeJSON(w, http.StatusOK, schemaResponse{Settings: entries, Categories: categories})
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	user := UserFromContext(r.Context())

	var updates map[string]any
	if !decodeJSON(w, r, &updates) {
		return
	}
	if len(updates) == 0 {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"Supply at least one setting to change.", "", nil)
		return
	}

	changed, err := s.settings.Update(r.Context(), updates, &user.UserID)
	if err != nil {
		var verr *settings.ValidationError
		if errors.As(err, &verr) {
			// One message per rejected key, so the frontend can mark each field
			// rather than showing a single opaque failure (§5.3).
			details := make(map[string]any, len(verr.Errors))
			for k, msg := range verr.Errors {
				details[k] = msg
			}
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
				"Some settings could not be saved.", "", details)
			return
		}
		s.log.Error("updating settings failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The settings could not be saved.", "", nil)
		return
	}

	s.auditSettingChange(w, r, user.UserID, updates, changed, start)
}

func (s *Server) handleResetSettings(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	user := UserFromContext(r.Context())

	req := resetRequest{}
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}

	changed, err := s.settings.Reset(r.Context(), req.Keys)
	if err != nil {
		var verr *settings.ValidationError
		if errors.As(err, &verr) {
			details := make(map[string]any, len(verr.Errors))
			for k, msg := range verr.Errors {
				details[k] = msg
			}
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
				"Some settings could not be reset.", "", details)
			return
		}
		s.log.Error("resetting settings failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The settings could not be reset.", "", nil)
		return
	}

	s.auditSettingChange(w, r, user.UserID, map[string]any{"reset": req.Keys}, changed, start)
}

// auditSettingChange records the change and returns the resulting state, plus
// the keys whose new value needs a restart to take effect. Nothing in the
// current schema does, but the frontend reads the flag generically so a future
// setting that does will surface without a frontend change.
func (s *Server) auditSettingChange(w http.ResponseWriter, r *http.Request, userID int64, request any, changed []string, start time.Time) {
	restartRequired := make([]string, 0)
	for _, key := range changed {
		if def, ok := settings.Lookup(key); ok && def.RestartRequired {
			restartRequired = append(restartRequired, key)
		}
	}

	s.audit.Write(r.Context(), audit.Entry{
		ActionID: model.AuditActionSettingUpdate, UserID: &userID,
		TargetType: "AppSetting", TargetID: strings.Join(changed, ","),
		Request:   request,
		IsSuccess: true, Duration: time.Since(start), ClientIP: ClientIP(r),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"settings":         s.settings.All(),
		"changed":          changed,
		"restart_required": restartRequired,
	})
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// capitalise upper-cases the first letter of a message so an error string reads
// as a sentence in the API response.
func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
