package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/model"
)

// auditEntry is one audited request as the API reports it.
type auditEntry struct {
	AuditLogID    int64  `json:"audit_log_id"`
	AuditActionID int64  `json:"audit_action_id"`
	Action        string `json:"action"`
	UserID        *int64 `json:"user_id"`
	Username      string `json:"username,omitempty"`
	TargetType    string `json:"target_type"`
	TargetID      string `json:"target_id"`
	// Request and Operations are decoded rather than passed through as strings,
	// so the response is real JSON. Secrets were redacted before they were
	// stored (§17.5).
	Request      any    `json:"request"`
	Operations   any    `json:"operations"`
	IsSuccess    bool   `json:"is_success"`
	ErrorMessage string `json:"error_message,omitempty"`
	DurationMs   int64  `json:"duration_ms"`
	ClientIp     string `json:"client_ip"`
	CreatedDate  string `json:"created_date"`
}

// auditActionNames maps the lookup identifiers onto the names a filter accepts
// and the history page renders.
//
// It is read off the declared lookup table rather than written out again here.
// The hand-written copy it replaces had fallen fourteen actions behind: every
// forwarding-rule action, the panel address change, the password reset and both
// database actions were recorded with an identifier the response then rendered
// as an empty name, so the history page showed a blank Action column for them
// and the filter did not offer them at all. A list maintained in two places
// drifts; this one cannot.
var auditActionNames = declaredAuditActions()

func declaredAuditActions() map[int64]string {
	out := map[int64]string{}
	for _, table := range model.LookupTables() {
		if table.Name != "AuditAction" {
			continue
		}
		for _, value := range table.Values {
			out[value.ID] = value.Title
		}
	}
	return out
}

func auditActionByName(name string) (int64, bool) {
	for id, candidate := range auditActionNames {
		if strings.EqualFold(candidate, name) {
			return id, true
		}
	}
	return 0, false
}

// handleAudit lists audited requests, filterable and paginated (§15).
//
// Every mutating request is here with its actor, its client address and the
// exact operations performed, which is what makes a panel that runs as root
// accountable.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)

	where := []string{"1 = 1"}
	args := []any{}

	if raw := r.URL.Query().Get("action"); raw != "" {
		id, ok := auditActionByName(raw)
		if !ok {
			if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil {
				id, ok = parsed, true
			}
		}
		if !ok {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"That is not a known audit action.", "action",
				map[string]any{"known": sortedActionNames()})
			return
		}
		where = append(where, "a.AuditActionID = ?")
		args = append(args, id)
	}
	if raw := r.URL.Query().Get("user_id"); raw != "" {
		if id, err := strconv.ParseInt(raw, 10, 64); err == nil {
			where = append(where, "a.UserID = ?")
			args = append(args, id)
		}
	}
	if raw := r.URL.Query().Get("target_type"); raw != "" {
		where = append(where, "a.TargetType = ?")
		args = append(args, raw)
	}
	if raw := r.URL.Query().Get("target_id"); raw != "" {
		where = append(where, "a.TargetID = ?")
		args = append(args, raw)
	}
	if raw := r.URL.Query().Get("success"); raw != "" {
		if value, err := strconv.ParseBool(raw); err == nil {
			where = append(where, "a.IsSuccess = ?")
			args = append(args, boolToInt(value))
		}
	}
	if raw := r.URL.Query().Get("from"); raw != "" {
		if parsed, err := parseTimeParam(raw); err == nil {
			where = append(where, "a.CreatedDate >= ?")
			args = append(args, model.FormatTime(parsed))
		}
	}
	if raw := r.URL.Query().Get("to"); raw != "" {
		if parsed, err := parseTimeParam(raw); err == nil {
			where = append(where, "a.CreatedDate <= ?")
			args = append(args, model.FormatTime(parsed))
		}
	}
	clause := " WHERE " + strings.Join(where, " AND ")

	var total int
	if err := s.db.Read.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM AuditLog a`+clause, args...).Scan(&total); err != nil {
		s.log.Error("counting audit entries failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The audit log could not be read.", "", nil)
		return
	}

	rows, err := s.db.Read.QueryContext(r.Context(), `
		SELECT a.AuditLogID, a.AuditActionID, a.UserID, u.Username, a.TargetType, a.TargetID,
		       a.RequestJson, a.OperationsJson, a.IsSuccess, a.ErrorMessage, a.DurationMs,
		       a.ClientIp, a.CreatedDate
		FROM AuditLog a LEFT JOIN AppUser u ON u.UserID = a.UserID`+clause+`
		ORDER BY a.CreatedDate DESC, a.AuditLogID DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		s.log.Error("reading audit entries failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The audit log could not be read.", "", nil)
		return
	}
	defer rows.Close()

	entries := []auditEntry{}
	for rows.Next() {
		var (
			entry      auditEntry
			userID     sql.NullInt64
			username   sql.NullString
			requestRaw string
			opsRaw     string
			errMessage sql.NullString
			success    int64
		)
		if err := rows.Scan(&entry.AuditLogID, &entry.AuditActionID, &userID, &username,
			&entry.TargetType, &entry.TargetID, &requestRaw, &opsRaw, &success,
			&errMessage, &entry.DurationMs, &entry.ClientIp, &entry.CreatedDate); err != nil {
			s.log.Error("reading an audit entry failed", "error", err)
			writeError(w, http.StatusInternalServerError, CodeInternal,
				"The audit log could not be read.", "", nil)
			return
		}
		if userID.Valid {
			id := userID.Int64
			entry.UserID = &id
		}
		entry.Username = username.String
		entry.IsSuccess = success != 0
		entry.ErrorMessage = errMessage.String
		entry.Action = auditActionNames[entry.AuditActionID]

		var request any
		if err := json.Unmarshal([]byte(requestRaw), &request); err == nil {
			entry.Request = request
		}
		var operations any
		if err := json.Unmarshal([]byte(opsRaw), &operations); err == nil {
			entry.Operations = operations
		}
		entries = append(entries, entry)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"actions": sortedActionNames(),
	})
}

func sortedActionNames() []string {
	ids := make([]int64, 0, len(auditActionNames))
	for id := range auditActionNames {
		ids = append(ids, id)
	}
	// The identifiers are spaced by ten in specification order, so sorting by
	// them gives the list the order the specification lists it in.
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, auditActionNames[id])
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
