// Package audit records every mutating request with its actor, client address,
// and the exact operations performed (§18).
//
// Secrets are redacted before anything is written. A panel that runs as root
// and configures kernel networking must be auditable, and an audit trail that
// leaks the password it was auditing is worse than none.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Redacted replaces the value of any field whose name suggests a secret.
const Redacted = "[redacted]"

// secretFieldFragments are matched case-insensitively against field names.
//
// Note the deliberate absence of a bare "key": IKey and OKey are GRE
// configuration, not credentials, and redacting them would make the audit trail
// useless for diagnosing the single most common misconfiguration.
var secretFieldFragments = []string{
	"password", "passwd", "secret", "token", "authorization", "cookie",
	"csrf", "credential", "private_key", "privatekey", "apikey", "api_key",
	"session", "bearer",
}

// IsSecretField reports whether a field name looks like it holds a secret.
func IsSecretField(name string) bool {
	lower := strings.ToLower(name)
	for _, frag := range secretFieldFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// Redact walks a decoded JSON value and replaces every secret-looking field
// with the redaction marker, leaving structure and non-secret values intact.
func Redact(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, item := range value {
			if IsSecretField(k) {
				out[k] = Redacted
				continue
			}
			out[k] = Redact(item)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = Redact(item)
		}
		return out
	default:
		return v
	}
}

// RedactJSON redacts a raw JSON document, returning "{}" if it cannot be parsed
// rather than risking storing an unredacted body.
func RedactJSON(raw []byte) string {
	if len(raw) == 0 {
		return "{}"
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return `{"_note":"request body was not valid JSON and has been discarded"}`
	}
	encoded, err := json.Marshal(Redact(decoded))
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

// Operation is one netlink call or command executed while serving a request.
// The apply pipeline appends these so the audit trail shows exactly what was
// done to the system, not merely what was asked for (§8.2).
type Operation struct {
	Kind       string   `json:"kind"`
	Argv       []string `json:"argv,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	ExitCode   *int     `json:"exit_code,omitempty"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	DurationMs int64    `json:"duration_ms"`
	Error      string   `json:"error,omitempty"`
}

// Entry is one audit record awaiting a write.
type Entry struct {
	ActionID     int64
	UserID       *int64
	TargetType   string
	TargetID     string
	Request      any
	Operations   []Operation
	IsSuccess    bool
	ErrorMessage string
	Duration     time.Duration
	ClientIP     string
}

// Writer persists audit entries.
type Writer struct {
	database *db.DB
	log      *slog.Logger
}

// New returns a Writer backed by the given database.
func New(database *db.DB, log *slog.Logger) *Writer {
	if log == nil {
		log = slog.Default()
	}
	return &Writer{database: database, log: log}
}

// Write stores one entry. A failure to audit is logged rather than returned:
// the request it describes has already happened, and refusing to report that to
// the caller would be a second, worse failure.
func (w *Writer) Write(ctx context.Context, e Entry) {
	if w == nil || w.database == nil {
		return
	}

	requestJSON := "{}"
	if e.Request != nil {
		if encoded, err := json.Marshal(Redact(e.Request)); err == nil {
			requestJSON = string(encoded)
		}
	}
	operationsJSON := "[]"
	if len(e.Operations) > 0 {
		if encoded, err := json.Marshal(e.Operations); err == nil {
			operationsJSON = string(encoded)
		}
	}
	var errMessage sql.NullString
	if e.ErrorMessage != "" {
		errMessage = sql.NullString{String: e.ErrorMessage, Valid: true}
	}

	const stmt = `
		INSERT INTO AuditLog
			(AuditActionID, UserID, TargetType, TargetID, RequestJson, OperationsJson,
			 IsSuccess, ErrorMessage, DurationMs, ClientIp, CreatedDate)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	success := 0
	if e.IsSuccess {
		success = 1
	}
	if _, err := w.database.Write.ExecContext(ctx, stmt,
		e.ActionID, e.UserID, e.TargetType, e.TargetID, requestJSON, operationsJSON,
		success, errMessage, e.Duration.Milliseconds(), e.ClientIP, model.NowUTC(),
	); err != nil {
		w.log.Error("writing audit entry failed",
			"action_id", e.ActionID, "target_type", e.TargetType, "error", err)
	}
}

// Prune deletes audit entries older than the retention window.
func (w *Writer) Prune(ctx context.Context, retentionDays int64) (int64, error) {
	if w == nil || w.database == nil || retentionDays <= 0 {
		return 0, nil
	}
	cutoff := model.FormatTime(time.Now().AddDate(0, 0, -int(retentionDays)))
	res, err := w.database.Write.ExecContext(ctx,
		`DELETE FROM AuditLog WHERE CreatedDate < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
