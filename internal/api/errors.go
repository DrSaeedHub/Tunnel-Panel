// Package api is the HTTP layer: the chi router, its middleware, the handlers,
// and the SSE helpers.
//
// Handlers translate between HTTP and the service packages. They contain no
// kernel calls and no business rules of their own (§4).
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Machine-readable error codes. The frontend switches on these, so they are
// part of the contract and must stay stable.
const (
	CodeSetupRequired      = "SETUP_REQUIRED"
	CodeSetupComplete      = "SETUP_ALREADY_COMPLETE"
	CodeUnauthenticated    = "UNAUTHENTICATED"
	CodeForbidden          = "FORBIDDEN"
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeAccountLocked      = "ACCOUNT_LOCKED"
	CodeAccountInactive    = "ACCOUNT_INACTIVE"
	CodeRateLimited        = "RATE_LIMITED"
	CodeCSRFRequired       = "CSRF_TOKEN_INVALID"
	CodeValidationFailed   = "VALIDATION_FAILED"
	CodeInvalidRequest     = "INVALID_REQUEST"
	CodeNotFound           = "NOT_FOUND"
	CodeMethodNotAllowed   = "METHOD_NOT_ALLOWED"
	CodeConflict           = "CONFLICT"
	CodeInternal           = "INTERNAL_ERROR"
	CodeUnavailable        = "SERVICE_UNAVAILABLE"
	CodeOriginNotAllowed   = "ORIGIN_NOT_ALLOWED"
	// Refusals when moving the panel's own address. They are distinct because
	// the interface has to explain them differently: a port something else
	// holds is a matter of choosing another, while a protected port is a
	// refusal on safety grounds and naming the daemon is the useful part.
	CodePortInUse     = "PORT_IN_USE"
	CodeProtectedPort = "PROTECTED_PORT"
)

// ErrorBody is the inner object of the error envelope. Every field is always
// present so the frontend never has to test for absence (§15).
type ErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Field   string         `json:"field"`
	Details map[string]any `json:"details"`
}

// ErrorEnvelope is the exact error shape of §15:
// {"error":{"code":"...","message":"...","field":"...","details":{}}}
type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}

// Warning accompanies a successful response that the operator should still
// read: a public address range, an MTU mismatch, runtime-only persistence.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// writeJSON serialises v with the given status. It is the only place a response
// body is written, so the content type and encoding settings stay consistent.
func writeJSON(w http.ResponseWriter, status int, v any) {
	// A nil slice marshals to null, and the interface calls .map on these. Doing
	// it here means a handler cannot forget, and a new response type inherits it.
	body, err := json.Marshal(normaliseNilLists(v))
	if err != nil {
		// Falling back to a hand-written envelope keeps the contract intact even
		// when the payload itself is what failed.
		slog.Error("encoding response failed", "error", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL_ERROR","message":"The response could not be encoded.","field":"","details":{}}}`))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError emits the error envelope. Messages are written for an operator to
// read; internal detail and stack traces never reach the client (§15).
func writeError(w http.ResponseWriter, status int, code, message, field string, details map[string]any) {
	if details == nil {
		details = map[string]any{}
	}
	writeJSON(w, status, ErrorEnvelope{Error: ErrorBody{
		Code:    code,
		Message: message,
		Field:   field,
		Details: details,
	}})
}

// decodeJSON reads a JSON request body with a size limit and rejects unknown
// fields, so a typo in a field name is reported instead of silently ignored.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	const maxBody = 1 << 20 // 1 MiB is far more than any request this API takes
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"The request body is not valid JSON for this endpoint: "+err.Error(), "", nil)
		return false
	}
	return true
}
