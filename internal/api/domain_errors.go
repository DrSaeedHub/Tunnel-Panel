package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/drs/gre-panel/internal/reconcile"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// Error codes the tunnel endpoints add to the ones in errors.go. They are part
// of the contract: the frontend renders a different screen for each.
const (
	CodeAdoptable        = "ADOPTABLE"
	CodeRecreateRequired = "CONFIRM_RECREATE_REQUIRED"
	CodeInconsistent     = "TUNNEL_INCONSISTENT"
	CodeApplyFailed      = "APPLY_FAILED"
	CodeAllocation       = "ALLOCATION_FAILED"
)

// writeDomainError translates an error from the service layer into the API's
// envelope. Every branch here is a distinct thing that can go wrong and a
// distinct thing the operator can do about it, which is why they are not
// collapsed into one generic failure.
func (s *Server) writeDomainError(w http.ResponseWriter, r *http.Request, err error) {
	var verrs *validate.Errors
	if errors.As(err, &verrs) {
		details := map[string]any{"fields": verrs.Fields}
		for _, f := range verrs.Fields {
			details[f.Field] = f.Message
		}
		first := verrs.First()
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			first.Message, first.Field, details)
		return
	}

	var adoptable *validate.AdoptableError
	if errors.As(err, &adoptable) {
		writeError(w, http.StatusConflict, CodeAdoptable, adoptable.Reason, "interface_name",
			map[string]any{
				"interface_name": adoptable.InterfaceName,
				"adopt_path":     adoptable.AdoptPath,
				"observed":       adoptable.Observed,
			})
		return
	}

	var violation *safety.Violation
	if errors.As(err, &violation) {
		// A safety refusal is a conflict with the state of the host, not a
		// malformed request: the request was understood and declined.
		writeError(w, http.StatusConflict, violation.Code, violation.Message, violation.Field,
			violation.Details)
		return
	}

	var recreate *tunnel.RecreateRequiredError
	if errors.As(err, &recreate) {
		writeError(w, http.StatusConflict, CodeRecreateRequired,
			"This change cannot be made to the running interface. Confirm that it may be deleted and "+
				"rebuilt, which briefly interrupts the tunnel.",
			"confirm_recreate",
			map[string]any{"interface_name": recreate.Interface, "reasons": recreate.Reasons})
		return
	}

	var inconsistent *tunnel.InconsistentError
	if errors.As(err, &inconsistent) {
		// The panel could not configure the tunnel and could not clean up either.
		// Saying so plainly, with the commands to fix it, is the only honest
		// answer available (§9.3).
		writeError(w, http.StatusConflict, CodeInconsistent, inconsistent.Error(), "",
			map[string]any{
				"interface_name": inconsistent.Interface,
				"tunnel_id":      inconsistent.TunnelID,
				"apply_error":    inconsistent.ApplyError,
				"rollback_error": inconsistent.RollbackError,
				"remediation":    inconsistent.Remediation,
				"journal":        inconsistent.Journal,
			})
		return
	}

	var apply *tunnel.ApplyError
	if errors.As(err, &apply) {
		details := map[string]any{
			"interface_name": apply.Interface,
			"cause":          apply.Cause,
			"rolled_back":    apply.RolledBack,
			"verification":   apply.Verify,
		}
		if apply.Journal != "" {
			details["journal"] = apply.Journal
		}
		writeError(w, http.StatusConflict, CodeApplyFailed, apply.Error(), "", details)
		return
	}

	if errors.Is(err, tunnel.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeNotFound, err.Error(), "", nil)
		return
	}

	s.log.Error("a tunnel operation failed", "error", err,
		"path", r.URL.Path, "request_id", RequestIDFromContext(r.Context()))
	writeError(w, http.StatusInternalServerError, CodeInternal,
		"The operation could not be completed.", "", nil)
}

// Error codes the forwarding endpoints add. Like the tunnel ones they are part
// of the contract: the frontend renders a different screen for each.
const (
	CodeRulesInconsistent = "FORWARDING_RULES_INCONSISTENT"
	CodeRulesApplyFailed  = "FORWARDING_APPLY_FAILED"
)

// writeRouteError translates an error from the forwarding service into the
// API's envelope.
//
// It shares every branch of the tunnel translation — validation failures,
// safety refusals, not-found — and adds the two that are specific to a
// netfilter transaction: an apply that failed and was rolled back, and one that
// failed and could not be rolled back either.
func (s *Server) writeRouteError(w http.ResponseWriter, r *http.Request, err error) {
	var inconsistent *route.InconsistentError
	if errors.As(err, &inconsistent) {
		// The panel could neither install the ruleset nor put the previous one
		// back. Saying so plainly, with the commands to fix it, is the only
		// honest answer available (§7).
		writeError(w, http.StatusConflict, CodeRulesInconsistent, inconsistent.Error(), "",
			map[string]any{
				"operation":      inconsistent.Operation,
				"apply_error":    inconsistent.ApplyError,
				"rollback_error": inconsistent.RollbackError,
				"remediation":    inconsistent.Remediation,
			})
		return
	}

	var apply *route.ApplyError
	if errors.As(err, &apply) {
		writeError(w, http.StatusConflict, CodeRulesApplyFailed, apply.Error(), "",
			map[string]any{
				"operation":    apply.Operation,
				"title":        apply.Title,
				"cause":        apply.Cause,
				"stderr":       apply.Stderr,
				"rolled_back":  apply.RolledBack,
				"verification": apply.Verify,
			})
		return
	}

	if errors.Is(err, route.ErrNotFound) {
		writeError(w, http.StatusNotFound, CodeNotFound, err.Error(), "", nil)
		return
	}
	if errors.Is(err, rules.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"No netfilter backend is available on this host, so forwarding rules cannot be applied "+
				"here. Install nftables or iptables.", "", nil)
		return
	}
	if errors.Is(err, rules.ErrUnsupported) || errors.Is(err, rules.ErrRangeWidth) ||
		errors.Is(err, rules.ErrNoDestination) {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			capitalise(strings.TrimPrefix(err.Error(), "rules: "))+".", "", nil)
		return
	}

	// Everything else is shared with the tunnel path: validation errors, safety
	// refusals, and the generic failure.
	s.writeDomainError(w, r, err)
}

// warningsOf normalises the warning shape the services return into the response
// envelope's own (§15).
func warningsOf(list []validate.Warning) []Warning {
	out := make([]Warning, 0, len(list))
	for _, w := range list {
		out = append(out, Warning{Code: w.Code, Message: w.Message, Field: w.Field})
	}
	return out
}

// reconcileWarnings is the same for the adoption path.
func reconcileWarnings(result reconcile.AdoptResult) []Warning {
	return warningsOf(result.Warnings)
}
