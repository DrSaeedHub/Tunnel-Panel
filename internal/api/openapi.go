package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// routeSummary describes one endpoint for the OpenAPI document.
type routeSummary struct {
	Summary     string
	Description string
	Tag         string
}

// routeDescriptions is the hand-written half of the document. The other half —
// which endpoints exist — is read off the router itself, so the document can
// never claim a route the panel does not serve, and a new route shows up in it
// whether or not anyone remembered to describe it.
var routeDescriptions = map[string]routeSummary{
	"POST /api/v1/auth/setup":   {"Create the first operator account", "Available only while no account exists. Every other endpoint answers 503 SETUP_REQUIRED until it has been used.", "auth"},
	"POST /api/v1/auth/login":   {"Sign in", "Sets httpOnly session cookies and a CSRF token.", "auth"},
	"POST /api/v1/auth/refresh": {"Renew the session", "Exchanges the refresh cookie for a new access token.", "auth"},
	"POST /api/v1/auth/logout":  {"Sign out", "Clears the session cookies.", "auth"},
	"GET /api/v1/auth/me":       {"The signed-in operator", "", "auth"},
	"PUT /api/v1/auth/me":       {"Change the operator's username or password", "Changing the password invalidates every existing session.", "auth"},

	"GET /api/v1/tunnels":                    {"List tunnels", "Returns the stored desired state and the live kernel state as separate fields.", "tunnels"},
	"POST /api/v1/tunnels":                   {"Create a tunnel", "Validates, plans, applies and verifies. Any verification failure rolls the change back.", "tunnels"},
	"POST /api/v1/tunnels/preview":           {"Preview a create or an update", "Runs validation and planning only. Returns the exact operations and unit file bodies without touching anything.", "tunnels"},
	"GET /api/v1/tunnels/side-info":          {"What the A and B sides mean", "The canonical explanation, owned by the backend so both ends of an install give the same answer.", "tunnels"},
	"POST /api/v1/tunnels/from-pairing-code": {"Decode a pairing code", "Returns a prefilled create payload with the side flipped. Creates nothing.", "tunnels"},
	"GET /api/v1/tunnels/{id}":               {"One tunnel", "", "tunnels"},
	"PATCH /api/v1/tunnels/{id}":             {"Change a tunnel", "A partial update: what is absent keeps its current value. Changes the kernel cannot make in place need confirm_recreate.", "tunnels"},
	"DELETE /api/v1/tunnels/{id}":            {"Delete a tunnel", "Idempotent, and reports exactly what was and was not found.", "tunnels"},
	"POST /api/v1/tunnels/{id}/up":           {"Bring a tunnel up", "", "tunnels"},
	"POST /api/v1/tunnels/{id}/down":         {"Take a tunnel down", "Leaves the interface in place and stops it returning after a reboot.", "tunnels"},
	"POST /api/v1/tunnels/{id}/restart":      {"Restart a tunnel", "", "tunnels"},
	"POST /api/v1/tunnels/{id}/reapply":      {"Reapply a tunnel from its stored state", "The remedy for drift.", "tunnels"},
	"GET /api/v1/tunnels/{id}/addresses":     {"A tunnel's addresses", "", "tunnels"},
	"POST /api/v1/tunnels/{id}/addresses":    {"Add an address", "Goes through the ordinary update pipeline, so it is validated, applied and verified.", "tunnels"},
	"DELETE /api/v1/tunnels/{id}/addresses":  {"Remove an address", "", "tunnels"},
	"GET /api/v1/tunnels/{id}/pairing-code":  {"A pairing code for the other end", "Configuration, not a credential, but not for posting publicly either.", "tunnels"},

	"GET /api/v1/tunnels/{id}/status":           {"One tunnel's live monitoring state", "Includes the recent state changes that explain how it got there.", "monitor"},
	"GET /api/v1/tunnels/{id}/history":          {"Stored monitoring history", "Supports a time range and a downsampling resolution. Downsampling keeps the worst state in each range, so an outage cannot be smoothed away.", "monitor"},
	"POST /api/v1/tunnels/{id}/monitor/enable":  {"Start monitoring a tunnel", "Takes effect immediately.", "monitor"},
	"POST /api/v1/tunnels/{id}/monitor/disable": {"Stop monitoring a tunnel", "", "monitor"},
	"GET /api/v1/monitor/summary":               {"Every tunnel's monitoring state", "", "monitor"},
	"GET /api/v1/monitor/stream":                {"Live monitoring stream", "Server-sent events. Sends the current picture first, then each change, with heartbeats so intermediaries do not close an idle connection.", "monitor"},

	"GET /api/v1/system/metrics":         {"This server's health", "Raw bytes and bytes per second throughout; unit conversion belongs to the frontend.", "metrics"},
	"GET /api/v1/system/metrics/stream":  {"Live metrics stream", "Server-sent events, one per sampling interval.", "metrics"},
	"GET /api/v1/system/metrics/history": {"Recent readings", "The in-memory ring buffer, for sparklines.", "metrics"},

	"POST /api/v1/tunnels/{id}/diagnostics/ping":       {"High-precision ping", "Streams each packet as it is decided. Delete the run to stop it.", "diagnostics"},
	"POST /api/v1/tunnels/{id}/diagnostics/mtu-probe":  {"Path MTU probe", "Binary search with the Don't-Fragment bit set. Returns the recommended tunnel MTU and how to apply it.", "diagnostics"},
	"POST /api/v1/tunnels/{id}/diagnostics/traceroute": {"Trace the path", "", "diagnostics"},
	"POST /api/v1/tunnels/{id}/diagnostics/analyze":    {"Diagnose a tunnel", "Returns a specific verdict with the evidence it rests on and the fixes worth trying, in order.", "diagnostics"},
	"GET /api/v1/tunnels/{id}/counters":                {"Interface counters and their movement", "", "diagnostics"},
	"GET /api/v1/diagnostics/runs":                     {"Stored diagnostic runs", "", "diagnostics"},
	"GET /api/v1/diagnostics/runs/{id}":                {"One diagnostic run", "", "diagnostics"},
	"DELETE /api/v1/diagnostics/runs/{id}":             {"Delete a run", "Cancels it first if it is still going.", "diagnostics"},

	"GET /api/v1/reconcile":               {"Compare stored state against the host", "Classifies every tunnel and every unmanaged tunnel interface.", "reconcile"},
	"POST /api/v1/reconcile/adopt":        {"Adopt an existing interface", "Imports its parameters from the kernel without renaming or bouncing it.", "reconcile"},
	"POST /api/v1/reconcile/ignore":       {"Stop reporting an unmanaged interface", "", "reconcile"},
	"POST /api/v1/reconcile/{id}/reapply": {"Rebuild a tunnel from its stored state", "", "reconcile"},
	"POST /api/v1/reconcile/{id}/forget":  {"Drop the panel's record of a tunnel", "Leaves the interface alone.", "reconcile"},

	"GET /api/v1/settings":        {"Every setting's effective value", "", "settings"},
	"GET /api/v1/settings/schema": {"Setting metadata", "Type, default, constraints, category and restart flag, so the settings screen renders generically.", "settings"},
	"PUT /api/v1/settings":        {"Change settings", "Validated as a batch; invalid keys are reported individually and nothing is written.", "settings"},
	"POST /api/v1/settings/reset": {"Reset settings to their defaults", "", "settings"},

	"GET /api/v1/pools":                {"Address pools", "With the capacity each one can hold at the configured subnet size.", "pools"},
	"POST /api/v1/pools":               {"Create an address pool", "", "pools"},
	"GET /api/v1/pools/{id}":           {"One address pool", "", "pools"},
	"PUT /api/v1/pools/{id}":           {"Change an address pool", "", "pools"},
	"DELETE /api/v1/pools/{id}":        {"Delete an address pool", "Refused while a tunnel still uses it.", "pools"},
	"GET /api/v1/pools/{id}/next-free": {"The next free subnet in a pool", "Allocates nothing.", "pools"},

	"GET /api/v1/system/info":         {"Build, runtime and resolved paths", "", "system"},
	"GET /api/v1/system/capabilities": {"What this kernel and build can do", "Per tunnel type and per persistence backend, probed live.", "system"},
	"GET /api/v1/system/interfaces":   {"Every interface on the host", "Classified physical, tunnel, loopback or other.", "system"},
	"GET /api/v1/system/routes":       {"The routing table", "", "system"},
	"GET /api/v1/system/address": {"Where the panel is served",
		"The port and web path in effect, where each came from, and whether the configured port " +
			"could actually be bound. An empty web path means the panel is served at the root.", "system"},
	"POST /api/v1/system/address": {"Move the panel to a new port or web path",
		"The port is bind-tested and checked against the protected ports before anything is stored. " +
			"The response carries the new URL and is sent before the restart, because the connection " +
			"asking the question is the one the restart breaks.", "system"},
	"GET /api/v1/system/health":       {"Component health", "Unauthenticated and reachable before setup, for the installer's readiness poll.", "system"},

	"GET /api/v1/system/update": {"Whether a newer panel is being served",
		"Answers from a cached lookup and refreshes in the background when it has aged past the " +
			"check interval, so a server with no outbound access never makes this the slowest " +
			"endpoint on the page. Carries the last update run, including one still going.", "system"},
	"POST /api/v1/system/update/check": {"Ask the release host now",
		"The explicit check, which waits for the answer rather than serving the cached one.", "system"},
	"POST /api/v1/system/update": {"Install a newer panel",
		"Runs the installer in a transient systemd unit, so the restart of the panel in the middle " +
			"of it does not kill the update. The response is sent before that restart; progress is " +
			"read back from GET /system/update, which survives it.", "system"},

	"GET /api/v1/audit": {"The audit log", "Every mutating request with its actor, client address and the exact operations performed. Secrets are redacted.", "audit"},

	"GET /api/v1/backup/export":  {"Export the configuration", "Settings, pools and tunnels. Carries no accounts, no password hashes and no signing key.", "backup"},
	"POST /api/v1/backup/import": {"Import a configuration", "Supports dry_run, which reports what would change without changing anything.", "backup"},

	"GET /api/v1/routes":                         {"List forwarding rules", "Returns the stored rule, its health and its live traffic as separate fields. Supports search and filtering by protocol, NAT mode, tunnel and enabled state.", "routes"},
	"POST /api/v1/routes":                        {"Create a forwarding rule", "Validates, plans, applies the whole ruleset as one transaction and reads it back from the kernel. Any verification failure restores the previous ruleset.", "routes"},
	"POST /api/v1/routes/preview":                {"Preview a create or an update", "Returns the exact netfilter payload that would be submitted, without applying it or storing anything.", "routes"},
	"POST /api/v1/routes/reorder":                {"Set the emission order", "Rules are emitted in this order and overlapping matches resolve first-match-wins, so the order is user-visible behaviour.", "routes"},
	"POST /api/v1/routes/apply-all":              {"Reinstall every enabled rule", "One transaction, not one per rule.", "routes"},
	"GET /api/v1/routes/{id}":                    {"One forwarding rule", "", "routes"},
	"PATCH /api/v1/routes/{id}":                  {"Change a forwarding rule", "A partial update: what is absent keeps its current value.", "routes"},
	"DELETE /api/v1/routes/{id}":                 {"Delete a forwarding rule", "Rebuilds the ruleset without it. Offers to revert IP forwarding when it was the last rule and the panel turned it on; never reverts it by itself.", "routes"},
	"POST /api/v1/routes/{id}/enable":            {"Enable a forwarding rule", "", "routes"},
	"POST /api/v1/routes/{id}/disable":           {"Disable a forwarding rule without deleting it", "", "routes"},
	"POST /api/v1/routes/{id}/reapply":           {"Reinstall a rule from its stored state", "The remedy for drift.", "routes"},
	"POST /api/v1/routes/{id}/duplicate":         {"Copy a rule as a starting point", "The copy is created disabled and with a free name, because an exact copy would claim the same listener.", "routes"},
	"GET /api/v1/routes/{id}/destinations":       {"A rule's destinations", "A rule with one destination is load balancing across a set of size one.", "routes"},
	"POST /api/v1/routes/{id}/destinations":      {"Add a destination", "Goes through the ordinary update pipeline, so it is validated, applied and verified.", "routes"},
	"DELETE /api/v1/routes/{id}/destinations":    {"Remove a destination", "", "routes"},
	"GET /api/v1/routes/{id}/allowed-sources":    {"A rule's source allowlist", "An empty allowlist means any source that can reach the bind address may use the relay.", "routes"},
	"POST /api/v1/routes/{id}/allowed-sources":   {"Add an allowlist entry", "", "routes"},
	"DELETE /api/v1/routes/{id}/allowed-sources": {"Remove an allowlist entry", "", "routes"},
	"GET /api/v1/tunnels/{id}/routes":            {"The forwarding rules crossing a tunnel", "Taking the tunnel down leaves their rules installed and removes the path they use.", "routes"},

	"GET /api/v1/routes/{id}/traffic":         {"One rule's live traffic", "Carries the kernel's own counters and the panel's cumulative totals separately: the first are zeroed by every rebuild of the ruleset, the second survive them. They are never added together.", "traffic"},
	"GET /api/v1/routes/{id}/traffic/history": {"Stored traffic history", "Aggregate buckets; each row holds the bytes that moved in one interval rather than a running total.", "traffic"},
	"GET /api/v1/routes/traffic/summary":      {"Relay traffic across every rule", "Live values are also multiplexed into the metrics stream rather than carried on a stream of their own.", "traffic"},

	"POST /api/v1/routes/diagnostics/test":         {"Test a destination before creating a rule", "The pre-flight: takes an address and a port, so the answer arrives before the rule exists.", "diagnostics"},
	"POST /api/v1/routes/{id}/diagnostics/test":    {"Test a rule's destination", "TCP connect, or a UDP probe whose silence is reported as proving nothing rather than as unreachable.", "diagnostics"},
	"POST /api/v1/routes/{id}/diagnostics/analyze": {"Diagnose a forwarding rule", "Returns a specific verdict with the evidence it rests on, including the state of the tunnel the rule relays over.", "diagnostics"},
	"GET /api/v1/routes/{id}/connections":          {"Live connections through a rule", "From connection tracking: source, state, age and bytes. An empty list from an unreadable table says so rather than reporting that nobody is using it.", "diagnostics"},
	"GET /api/v1/routes/{id}/counters":             {"A rule's hit counters", "Read from the accounting rules in the filter hooks, never from a nat chain: a nat hook sees only the first packet of a connection. A rule that also relays traffic this server originates is counted on the output and input hooks too, since such traffic is never forwarded.", "diagnostics"},

	"GET /api/v1/system/forwarding":         {"Kernel forwarding and the netfilter picture", "IP forwarding, the connection tracking table, the active backend, and the other software found managing netfilter on this host.", "system"},
	"POST /api/v1/system/forwarding/enable": {"Turn IP forwarding on", "Writes the panel's own sysctl file and records what each parameter was before. Send revert to put those values back; the panel offers that and never does it by itself.", "system"},
}

// handleOpenAPI serves the API description (§15).
//
// The path list is walked off the live router rather than maintained by hand,
// which is the only way a document like this stays true. A route with no
// description still appears, marked as undocumented, so the gap is visible
// instead of the endpoint being invisible.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	paths := map[string]map[string]any{}
	tags := map[string]bool{}

	walk := func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		route = normaliseRoute(route)
		if !strings.HasPrefix(route, "/api/") {
			return nil
		}
		method = strings.ToUpper(method)

		key := method + " " + route
		summary, described := routeDescriptions[key]
		if !described {
			summary = routeSummary{
				Summary: "Undocumented endpoint",
				Description: "This route is served but has no description. The list of paths is read " +
					"from the router, so an endpoint can never be missing from this document.",
				Tag: "other",
			}
		}
		tags[summary.Tag] = true

		operation := map[string]any{
			"summary":     summary.Summary,
			"operationId": operationID(method, route),
			"tags":        []string{summary.Tag},
			"responses": map[string]any{
				"200": map[string]any{"description": "Success"},
				"401": map[string]any{"description": "Authentication is required"},
				"422": map[string]any{"description": "Validation failed; details carry one message per field"},
				"503": map[string]any{"description": "The panel is not set up, or the feature is unavailable"},
			},
		}
		if summary.Description != "" {
			operation["description"] = summary.Description
		}
		if parameters := pathParameters(route); len(parameters) > 0 {
			operation["parameters"] = parameters
		}

		if paths[route] == nil {
			paths[route] = map[string]any{}
		}
		paths[route][strings.ToLower(method)] = operation
		return nil
	}

	if err := chi.Walk(s.router, walk); err != nil {
		s.log.Error("walking the router failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The API description could not be built.", "", nil)
		return
	}

	tagList := make([]map[string]any, 0, len(tags))
	names := make([]string, 0, len(tags))
	for name := range tags {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		tagList = append(tagList, map[string]any{"name": name})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":   "GRE Tunnel Web Panel",
			"version": s.build.Version,
			"description": "The panel's HTTP API. Every path below is read from the running router, " +
				"so this document describes what this build actually serves.",
		},
		"servers": []map[string]any{{"url": s.cfg.PathPrefix() + "/"}},
		"tags":    tagList,
		"paths":   paths,
		"components": map[string]any{
			"schemas": map[string]any{
				"Error": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"error": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"code":    map[string]any{"type": "string"},
								"message": map[string]any{"type": "string"},
								"field":   map[string]any{"type": "string"},
								"details": map[string]any{"type": "object"},
							},
						},
					},
				},
				"Warning": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"code":    map[string]any{"type": "string"},
						"message": map[string]any{"type": "string"},
						"field":   map[string]any{"type": "string"},
					},
				},
			},
			"securitySchemes": map[string]any{
				"session": map[string]any{
					"type": "apiKey", "in": "cookie", "name": "gre_panel_access",
					"description": "The session cookie set by /auth/login. Mutating requests also need " +
						"the CSRF token from the gre_panel_csrf cookie in the X-CSRF-Token header.",
				},
			},
		},
		"security": []map[string]any{{"session": []string{}}},
	})
}

// normaliseRoute turns chi's route pattern into an OpenAPI path.
func normaliseRoute(route string) string {
	route = strings.ReplaceAll(route, "/*", "")
	if len(route) > 1 {
		route = strings.TrimSuffix(route, "/")
	}
	if route == "" {
		route = "/"
	}
	return route
}

// pathParameters declares the {id} placeholders a path carries.
func pathParameters(route string) []map[string]any {
	var out []map[string]any
	for _, segment := range strings.Split(route, "/") {
		if !strings.HasPrefix(segment, "{") || !strings.HasSuffix(segment, "}") {
			continue
		}
		name := strings.Trim(segment, "{}")
		out = append(out, map[string]any{
			"name": name, "in": "path", "required": true,
			"schema": map[string]any{"type": "integer", "format": "int64"},
		})
	}
	return out
}

// operationID builds a stable identifier from the method and path.
func operationID(method, route string) string {
	cleaned := strings.NewReplacer("/api/v1/", "", "/", "_", "{", "", "}", "", "-", "_").Replace(route)
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		cleaned = "root"
	}
	return strings.ToLower(method) + "_" + cleaned
}

// RoutedPaths returns every method and path the router serves, which a test
// uses to assert that the whole specified surface exists.
func (s *Server) RoutedPaths() []string {
	var out []string
	_ = chi.Walk(s.router, func(method, route string, handler http.Handler,
		middlewares ...func(http.Handler) http.Handler) error {
		out = append(out, strings.ToUpper(method)+" "+normaliseRoute(route))
		return nil
	})
	sort.Strings(out)
	return out
}
