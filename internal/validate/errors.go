// Package validate holds every input and conflict rule of §7.
//
// The rule this package exists to enforce is that no operation reaches the
// kernel with unvalidated input. The script this panel replaces checked only
// that its endpoint fields were non-empty; given `not-an-ip` it wrote an
// enabled systemd unit, printed success, and exited zero. Every rule here
// returns a structured, field-level error instead.
//
// Validation runs in two phases. ValidateStatic is pure: it needs no kernel and
// no database, and it rejects malformed input before anything is read. Only
// input that survives it is checked against live state.
package validate

import (
	"fmt"
	"sort"
	"strings"
)

// Machine-readable error codes. The frontend switches on these, so they are
// part of the API contract and must stay stable (§15).
const (
	CodeInvalidName        = "INVALID_INTERFACE_NAME"
	CodeNameReserved       = "INTERFACE_NAME_RESERVED"
	CodeNameConflict       = "TUNNEL_NAME_CONFLICT"
	CodeInvalidEndpoint    = "INVALID_ENDPOINT"
	CodeEndpointFamily     = "ENDPOINT_FAMILY_MISMATCH"
	CodeEndpointsIdentical = "ENDPOINTS_IDENTICAL"
	CodeEndpointConflict   = "TUNNEL_ENDPOINT_CONFLICT"
	CodeInvalidMtu         = "INVALID_MTU"
	CodeInvalidTtl         = "INVALID_TTL"
	CodeInvalidTos         = "INVALID_TOS"
	CodeInvalidKey         = "INVALID_GRE_KEY"
	CodeInvalidFwMark      = "INVALID_FWMARK"
	CodeInvalidNumber      = "INVALID_TUNNEL_NUMBER"
	CodeInvalidQueueLength = "INVALID_QUEUE_LENGTH"
	// CodeInvalidMonitorOverride covers a per-tunnel monitoring value outside
	// the bounds the global setting it overrides declares.
	CodeInvalidMonitorOverride = "INVALID_MONITOR_OVERRIDE"
	CodeInvalidAddress     = "INVALID_ADDRESS"
	CodeInvalidPrefixLen   = "INVALID_PREFIX_LENGTH"
	CodeAddressConflict    = "ADDRESS_CONFLICT"
	CodeRouteOverlap       = "ROUTE_OVERLAP"
	CodePublicRange        = "PUBLIC_RANGE_NOT_ALLOWED"
	CodeInvalidType        = "INVALID_TUNNEL_TYPE"
	CodeInvalidSide        = "INVALID_TUNNEL_SIDE"
	CodeInvalidPersistence = "INVALID_PERSISTENCE_TYPE"
	CodeMissingAddress     = "NO_ADDRESS"
	CodeUnknownPool        = "UNKNOWN_ADDRESS_POOL"
	// CodeAdoptable is the structured answer of §7.5: an interface matching the
	// request already exists on the system but is not in the database, so the
	// right move is adoption rather than a blind failure.
	CodeAdoptable = "ADOPTABLE"
)

// Error codes for forwarding rules (§6.1 and §6.2 of the port forwarding
// specification). They are part of the same stable contract as the codes above.
const (
	CodeInvalidRouteTitle      = "INVALID_ROUTE_TITLE"
	CodeRouteTitleConflict     = "ROUTE_TITLE_CONFLICT"
	CodeInvalidRouteProtocol   = "INVALID_ROUTE_PROTOCOL"
	CodeInvalidNatMode         = "INVALID_NAT_MODE"
	CodeInvalidLoadBalanceMode = "INVALID_LOAD_BALANCE_MODE"
	CodeInvalidAddressFamily   = "INVALID_ADDRESS_FAMILY"
	CodeInvalidBindAddress     = "INVALID_BIND_ADDRESS"
	CodeInvalidDestination     = "INVALID_DESTINATION"
	CodeAddressFamilyMismatch  = "ADDRESS_FAMILY_MISMATCH"
	CodeInvalidPort            = "INVALID_PORT"
	CodeInvalidPortRange       = "INVALID_PORT_RANGE"
	CodePortRangeWidthMismatch = "PORT_RANGE_WIDTH_MISMATCH"
	CodeRoutePortConflict      = "ROUTE_PORT_CONFLICT"
	// CodePortInUse is the refusal of §6.2: a local service is already
	// listening on the port the rule would forward, and forwarding it would
	// break that service with no error anywhere.
	CodePortInUse              = "PORT_IN_USE"
	CodeSnatAddressRequired    = "SNAT_ADDRESS_REQUIRED"
	CodeInvalidSnatAddress     = "INVALID_SNAT_ADDRESS"
	CodeSnatAddressNotOnHost   = "SNAT_ADDRESS_NOT_ON_HOST"
	CodeSnatAddressUnused      = "SNAT_ADDRESS_UNUSED"
	CodeLoopbackDestination    = "LOOPBACK_DESTINATION"
	CodeInvalidCidr            = "INVALID_CIDR"
	CodeInvalidWeight          = "INVALID_WEIGHT"
	CodeInvalidConnectionLimit = "INVALID_CONNECTION_LIMIT"
	CodeInterfaceNotFound      = "INTERFACE_NOT_FOUND"
	CodeUnknownTunnel          = "UNKNOWN_TUNNEL"
)

// Warning codes accompany a successful response (§15).
const (
	WarnLocalEndpointNotFound = "LOCAL_ENDPOINT_NOT_FOUND"
	WarnPublicRange           = "PUBLIC_RANGE_WARNING"
	WarnMtuAdvisory           = "MTU_ADVISORY"
	WarnRouteOverlap          = "ROUTE_OVERLAP_WARNING"
	WarnRuntimeOnly           = "RUNTIME_ONLY_PERSISTENCE"
	WarnKeyMismatch           = "GRE_KEY_ASYMMETRIC"
	WarnNoKey                 = "NO_GRE_KEY"
	WarnLegacyDefaultKey      = "LEGACY_DEFAULT_GRE_KEY"
)

// Warning codes for forwarding rules.
const (
	WarnBindAnyAddress      = "BIND_ANY_ADDRESS"
	WarnBindAddressNotFound = "BIND_ADDRESS_NOT_FOUND"
	WarnNatHidesClient      = "NAT_HIDES_CLIENT_ADDRESS"
	WarnNatPreservesClient  = "NAT_PRESERVES_CLIENT_ADDRESS"
	WarnMssClampRecommended = "MSS_CLAMP_RECOMMENDED"
	WarnLoopbackDestination = "LOOPBACK_DESTINATION_FORCED"
	WarnPortInUse           = "PORT_IN_USE_FORCED"
)

// FieldError is one field-level failure. Field names the request field so the
// frontend can mark exactly the input that is wrong.
type FieldError struct {
	Field   string         `json:"field"`
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (e FieldError) Error() string {
	if e.Field == "" {
		return e.Message
	}
	return e.Field + ": " + e.Message
}

// Errors collects every field-level failure of one validation pass. Validation
// does not stop at the first problem: an operator filling in a form deserves to
// see all of them at once.
type Errors struct {
	Fields []FieldError `json:"fields"`
}

// Add appends one failure.
func (e *Errors) Add(field, code, message string, details map[string]any) {
	e.Fields = append(e.Fields, FieldError{Field: field, Code: code, Message: message, Details: details})
}

// Addf appends one failure with a formatted message.
func (e *Errors) Addf(field, code, format string, args ...any) {
	e.Add(field, code, fmt.Sprintf(format, args...), nil)
}

// Empty reports whether anything was rejected.
func (e *Errors) Empty() bool { return e == nil || len(e.Fields) == 0 }

// Has reports whether a specific field was rejected.
func (e *Errors) Has(field string) bool {
	if e == nil {
		return false
	}
	for _, f := range e.Fields {
		if f.Field == field {
			return true
		}
	}
	return false
}

// Codes returns the failure codes in sorted order, which makes a test assertion
// independent of the order rules happen to run in.
func (e *Errors) Codes() []string {
	if e == nil {
		return nil
	}
	out := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		out = append(out, f.Code)
	}
	sort.Strings(out)
	return out
}

// First returns the first failure, which is the one the error envelope reports
// in its top-level field and message.
func (e *Errors) First() FieldError {
	if e == nil || len(e.Fields) == 0 {
		return FieldError{}
	}
	return e.Fields[0]
}

func (e *Errors) Error() string {
	if e.Empty() {
		return "no validation errors"
	}
	if len(e.Fields) == 1 {
		return e.Fields[0].Error()
	}
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Error())
	}
	return fmt.Sprintf("%d fields are invalid: %s", len(e.Fields), strings.Join(parts, "; "))
}

// OrNil returns the collection as an error, or nil when nothing was rejected.
// Returning a typed nil pointer as an error is a classic Go trap, so this is
// the only way callers turn an Errors into an error value.
func (e *Errors) OrNil() error {
	if e.Empty() {
		return nil
	}
	return e
}

// Warning is a condition the operator should read but which does not stop the
// operation. Overridable warnings are cleared by `force: true` (§15).
type Warning struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Field   string         `json:"field,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

// AdoptableError is the structured answer of §7.5. It is not a plain conflict:
// the interface exists and matches, so the operator is pointed at adoption
// rather than told to pick another name.
type AdoptableError struct {
	InterfaceName string         `json:"interface_name"`
	Reason        string         `json:"reason"`
	AdoptPath     string         `json:"adopt_path"`
	Observed      map[string]any `json:"observed"`
}

func (e *AdoptableError) Error() string {
	return fmt.Sprintf("%s already exists on this system but is not managed by the panel; adopt it instead",
		e.InterfaceName)
}
