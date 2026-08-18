package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/address"
	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/model"
)

// AddressSources records where each half of the running address came from, so
// the interface can say "this is what the environment file asked for" rather
// than only reporting a number.
type AddressSources struct {
	Port    string `json:"port"`
	WebPath string `json:"web_path"`
}

// addressResponse is GET /system/address.
type addressResponse struct {
	BindHost string `json:"bind_host"`
	Port     int    `json:"port"`
	// WebPath is empty when the panel is served at the root, which is a
	// supported configuration rather than a missing value.
	WebPath  string            `json:"web_path"`
	BasePath string            `json:"base_path"`
	URL      string            `json:"url"`
	Sources  AddressSources    `json:"sources"`
	Fallback *address.Fallback `json:"fallback,omitempty"`
	// CanApply is false when the panel could not bring itself back after a
	// restart, so the interface can explain instead of offering a control that
	// would take the panel down.
	CanApply       bool   `json:"can_apply"`
	CannotApplyWhy string `json:"cannot_apply_why,omitempty"`
	// ProtectedPorts are the ports a change will be refused for, listed up
	// front so the form can say so before the operator submits.
	ProtectedPorts []protectedPortInfo `json:"protected_ports"`
	// EnvFile is what /etc/gre-panel.env still says. It is reported because the
	// panel cannot write that file, so a change made here leaves it behind, and
	// an operator reading it would otherwise be misled.
	EnvFile addressEnvInfo `json:"env_file"`
}

type protectedPortInfo struct {
	Port    int    `json:"port"`
	Reason  string `json:"reason"`
	Process string `json:"process,omitempty"`
}

type addressEnvInfo struct {
	Path      string `json:"path"`
	Port      int    `json:"port"`
	WebPath   string `json:"web_path"`
	Disagrees bool   `json:"disagrees"`
}

// panelAddressRequest is POST /system/address. Both fields are optional; what is
// absent keeps its current value, so changing the port does not silently move
// the web path.
type panelAddressRequest struct {
	Port    *int    `json:"port"`
	WebPath *string `json:"web_path"`
}

// addressChangeResponse is answered before anything is applied.
//
// That ordering is the point. The connection carrying this response is the one
// the restart is about to break, so the destination has to be in the operator's
// hands before the panel moves. A response sent afterwards would arrive at a
// socket that no longer exists.
type addressChangeResponse struct {
	URL         string `json:"url"`
	PreviousURL string `json:"previous_url"`
	Port        int    `json:"port"`
	WebPath     string `json:"web_path"`
	// HealthURL is what the browser should poll to know the panel is back. It
	// is given rather than assembled by the frontend so there is one place that
	// knows an empty web path must not produce a double slash.
	HealthURL string `json:"health_url"`
	// Restarting is false when the values were stored but nothing could apply
	// them, which happens when the panel is not running under systemd.
	Restarting bool `json:"restarting"`
	// SessionSurvives is false when the change moves the cookie path, so the
	// interface can warn that signing in again will be necessary rather than
	// letting it look like a failure.
	SessionSurvives bool   `json:"session_survives"`
	Detail          string `json:"detail"`
}

// handleGetAddress reports where the panel is listening and what a change would
// be refused for.
func (s *Server) handleGetAddress(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.addressSnapshot(r.Context()))
}

func (s *Server) addressSnapshot(ctx context.Context) addressResponse {
	out := addressResponse{
		BindHost:       s.cfg.BindHost,
		Port:           s.cfg.BindPort,
		WebPath:        s.cfg.WebPath,
		BasePath:       s.cfg.BasePath(),
		URL:            address.URL("http", s.publicHost(), s.cfg.BindPort, s.cfg.WebPath),
		Sources:        s.addressSources,
		Fallback:       s.addressFallback,
		CanApply:       s.underSystemd,
		ProtectedPorts: []protectedPortInfo{},
		EnvFile: addressEnvInfo{
			Path:      config.EnvFilePath,
			Port:      s.cfg.SeedBindPort,
			WebPath:   s.cfg.SeedWebPath,
			Disagrees: s.cfg.SeedBindPort != s.cfg.BindPort || s.cfg.SeedWebPath != s.cfg.WebPath,
		},
	}
	if !out.CanApply {
		out.CannotApplyWhy = "This panel was not started by systemd, so it cannot restart itself. " +
			"A change made here is stored and takes effect the next time the panel starts."
	}
	if s.routeGuard != nil {
		for _, p := range s.routeGuard.ProtectedPorts(ctx) {
			// The panel's own port is not a refusal for this form: moving the
			// panel to where the panel already is is a no-op, not a hazard.
			if p.Port == s.cfg.BindPort {
				continue
			}
			out.ProtectedPorts = append(out.ProtectedPorts, protectedPortInfo{
				Port: p.Port, Reason: p.Reason, Process: p.Process,
			})
		}
	}
	return out
}

// publicHost is the address to put in a URL an operator will click. A wildcard
// bind is not a destination, so the host's own first address stands in for it.
func (s *Server) publicHost() string {
	switch s.cfg.BindHost {
	case "0.0.0.0", "::", "":
		if addr := firstNonLoopbackAddress(); addr != "" {
			return addr
		}
		return "127.0.0.1"
	}
	return s.cfg.BindHost
}

func firstNonLoopbackAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}

// handleSetAddress changes the port, the web path, or both.
//
// The order is: validate everything, including a real bind of the requested
// port; store; answer with the new URL; and only then restart. A port that
// cannot be bound is refused here with the reason rather than written down and
// discovered at the next start, when the panel would be answering somewhere
// nobody expects.
func (s *Server) handleSetAddress(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req panelAddressRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), "", nil)
		return
	}
	if req.Port == nil && req.WebPath == nil {
		writeError(w, http.StatusBadRequest, CodeValidationFailed,
			"Give a port, a web path, or both.", "", nil)
		return
	}

	port := s.cfg.BindPort
	if req.Port != nil {
		port = *req.Port
	}
	webPath := s.cfg.WebPath
	if req.WebPath != nil {
		normalised, err := config.NormalizeWebPath(*req.WebPath)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed, err.Error(), "web_path", nil)
			return
		}
		webPath = normalised
	}

	if port == s.cfg.BindPort && webPath == s.cfg.WebPath {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			"The panel is already at that address, so there is nothing to change.", "", nil)
		return
	}

	if err := s.validateNewPort(r.Context(), port); err != nil {
		var v *addressRefusal
		if errors.As(err, &v) {
			writeError(w, http.StatusUnprocessableEntity, v.Code, v.Message, "port",
				map[string]any{"port": port})
			return
		}
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed, err.Error(), "port", nil)
		return
	}

	// The seed recorded is the environment file as this process read it at
	// startup, which is the file this panel has actually seen.
	if err := address.Set(r.Context(), s.db, port, webPath,
		address.Seed{Port: s.cfg.SeedBindPort, WebPath: s.cfg.SeedWebPath, PortProvided: s.cfg.SeedBindPortSet, WebPathProvided: s.cfg.SeedWebPathSet}); err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	// A cookie is scoped to a path and not to a port, so moving the port keeps
	// the session and moving the web path does not — unless the panel is moving
	// out from the root, whose cookies are sent everywhere below it.
	sessionSurvives := webPath == s.cfg.WebPath || s.cfg.WebPath == ""

	response := addressChangeResponse{
		URL:             address.URL("http", s.publicHost(), port, webPath),
		PreviousURL:     address.URL("http", s.publicHost(), s.cfg.BindPort, s.cfg.WebPath),
		Port:            port,
		WebPath:         webPath,
		HealthURL:       address.HealthURL("http", s.publicHost(), port, webPath),
		Restarting:      s.underSystemd,
		SessionSurvives: sessionSurvives,
	}
	if s.underSystemd {
		response.Detail = "The panel is restarting and will answer at the new address."
	} else {
		response.Detail = "The new address was stored. This panel was not started by systemd, " +
			"so it cannot restart itself; restart it to apply the change."
	}

	if s.audit != nil {
		entry := audit.Entry{
			ActionID:   model.AuditActionPanelAddressChange,
			TargetType: "PanelAddress",
			TargetID:   fmt.Sprintf("%d%s", port, s.cfg.BasePath()),
			Request: map[string]any{
				"port": port, "web_path": webPath,
				"previous_port": s.cfg.BindPort, "previous_web_path": s.cfg.WebPath,
				"actor": "panel",
			},
			IsSuccess: true, Duration: time.Since(start), ClientIP: ClientIP(r),
		}
		if user := UserFromContext(r.Context()); user != nil {
			entry.UserID = &user.UserID
		}
		s.audit.Write(r.Context(), entry)
	}

	writeJSON(w, http.StatusOK, response)

	if s.underSystemd && s.restart != nil {
		s.restart(fmt.Sprintf("the panel address changed to %s", response.URL))
	}
}

// addressRefusal is a validation failure that carries its own code, so the
// interface can tell "that port is taken" from "that port is protected".
type addressRefusal struct {
	Code    string
	Message string
}

func (e *addressRefusal) Error() string { return e.Message }

// validateNewPort is the check that runs before anything is stored.
func (s *Server) validateNewPort(ctx context.Context, port int) error {
	if port < 1 || port > 65535 {
		return &addressRefusal{CodeValidationFailed,
			fmt.Sprintf("A port must be between 1 and 65535; %d is not.", port)}
	}
	if port == s.cfg.BindPort {
		return nil // already ours, and the bind test below would refuse it
	}

	if s.routeGuard != nil {
		for _, p := range s.routeGuard.ProtectedPorts(ctx) {
			if p.Port != port || p.Port == s.cfg.BindPort {
				continue
			}
			return &addressRefusal{CodeProtectedPort,
				fmt.Sprintf("Port %d cannot be used: %s.", port, p.Reason)}
		}
	}

	if err := address.Probe(s.cfg.BindHost, port); err != nil {
		return &addressRefusal{CodePortInUse,
			fmt.Sprintf("Port %d cannot be bound on %s, so the panel would not come back on it: %s.",
				port, s.cfg.BindHost, cleanBindError(err))}
	}
	return nil
}

// cleanBindError trims Go's layered address text down to the part an operator
// needs. "listen tcp 0.0.0.0:22: bind: permission denied" becomes
// "permission denied".
func cleanBindError(err error) string {
	text := err.Error()
	if at := strings.LastIndex(text, ": "); at >= 0 && at+2 < len(text) {
		return text[at+2:]
	}
	return text
}

// decodeStrict refuses unknown fields, so a misspelled key is an error rather
// than a change that silently does not happen.
func decodeStrict(r *http.Request, into any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	return nil
}
