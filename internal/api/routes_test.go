package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
)

// nftSimulator stands in for nft: it accepts the payloads the backend writes,
// remembers the last one as what the kernel holds, and answers a read-back and
// a counter listing from it.
//
// It is deliberately not a stub that always says yes. Applying makes the rules
// live and reading back returns what was applied, which is what lets these
// tests prove the endpoints verify against the kernel rather than against an
// exit code.
type nftSimulator struct {
	*exec.FakeRunner

	mu       sync.Mutex
	live     string
	counters map[int64]rules.Counter
}

func newNftSimulator() *nftSimulator {
	sim := &nftSimulator{FakeRunner: exec.NewFakeRunner(), counters: map[int64]rules.Counter{}}
	sim.Handler = func(argv []string) (exec.Result, error) {
		line := strings.Join(argv, " ")
		sim.mu.Lock()
		defer sim.mu.Unlock()

		switch {
		case strings.Contains(line, "-f "):
			content, err := os.ReadFile(argv[len(argv)-1])
			if err != nil {
				return exec.Result{ExitCode: 1, Stderr: err.Error()}, err
			}
			sim.live = string(content)
			return exec.Result{}, nil

		case strings.Contains(line, "list counters"):
			return exec.Result{Stdout: sim.counterJSON()}, nil

		case strings.Contains(line, "list ruleset"):
			return exec.Result{Stdout: sim.live}, nil

		case strings.Contains(line, "list table"):
			if sim.live == "" {
				return exec.Result{ExitCode: 1, Stderr: "Error: No such file or directory"},
					errors.New("nft exited 1")
			}
			return exec.Result{Stdout: sim.live}, nil

		case strings.Contains(line, "delete table"):
			sim.live = ""
			return exec.Result{}, nil
		}
		return exec.Result{}, nil
	}
	return sim
}

// SetCounters seeds the counters the listing reports, which is how a test
// drives the accounting without traffic.
func (s *nftSimulator) SetCounters(counters map[int64]rules.Counter) {
	s.mu.Lock()
	s.counters = counters
	s.mu.Unlock()
}

// counterJSON renders the seeded counters the way `nft -j list counters` does.
// The caller holds the lock.
func (s *nftSimulator) counterJSON() string {
	type counter struct {
		Family  string `json:"family"`
		Name    string `json:"name"`
		Table   string `json:"table"`
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	}
	type entry struct {
		Counter *counter `json:"counter,omitempty"`
	}
	document := struct {
		Nftables []entry `json:"nftables"`
	}{}

	ids := make([]int64, 0, len(s.counters))
	for id := range s.counters {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		c := s.counters[id]
		document.Nftables = append(document.Nftables,
			entry{Counter: &counter{Family: "inet", Table: "gre_panel",
				Name: fmt.Sprintf("route_%d_rx", id), Packets: c.RxPackets, Bytes: c.RxBytes}},
			entry{Counter: &counter{Family: "inet", Table: "gre_panel",
				Name: fmt.Sprintf("route_%d_tx", id), Packets: c.TxPackets, Bytes: c.TxBytes}},
		)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return `{"nftables":[]}`
	}
	return string(encoded)
}

// routePayload is a plain, valid forwarding rule.
func routePayload(title string, port int, extra map[string]any) map[string]any {
	payload := map[string]any{
		"route_rule_title":    title,
		"route_protocol_id":   model.RouteProtocolTCP,
		"bind_address":        "203.0.113.10",
		"bind_port":           port,
		"destination_address": "198.51.100.20",
		"destination_port":    port,
		"nat_mode_id":         model.NatModeMasquerade,
		"is_enabled":          true,
	}
	for k, v := range extra {
		payload[k] = v
	}
	return payload
}

// createRoute asks the API for a forwarding rule and returns the decoded body.
func createRoute(t *testing.T, c *client, api string, payload map[string]any) map[string]any {
	t.Helper()
	resp, body := c.request(http.MethodPost, api+"/routes", payload)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /routes = %d, want 201\nbody: %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decoding the response failed: %v\nbody: %s", err, body)
	}
	return out
}

func routeID(t *testing.T, created map[string]any) int64 {
	t.Helper()
	rule, ok := created["route"].(map[string]any)
	if !ok {
		t.Fatalf("the response carries no rule: %+v", created)
	}
	id, ok := rule["route_rule_id"].(float64)
	if !ok || id == 0 {
		t.Fatalf("the rule has no identifier: %+v", rule)
	}
	return int64(id)
}

// TestRouteEndpointsRequireAuthentication: every forwarding endpoint sits
// behind the session guard, and an unauthenticated request gets the error
// envelope rather than a stack trace or an empty body (§15).
func TestRouteEndpointsRequireAuthentication(t *testing.T) {
	h := newHarness(t, testWebPath)
	// Setup is done, so the panel is past SETUP_REQUIRED and the auth guard is
	// the one answering.
	c, api := session(t, h)
	created := createRoute(t, c, api, routePayload("Web relay", 2044, nil))
	id := routeID(t, created)

	anonymous := newClient(t, h)
	endpoints := []struct{ method, path string }{
		{http.MethodGet, "/routes"},
		{http.MethodPost, "/routes"},
		{http.MethodPost, "/routes/preview"},
		{http.MethodPost, "/routes/reorder"},
		{http.MethodPost, "/routes/apply-all"},
		{http.MethodGet, "/routes/traffic/summary"},
		{http.MethodPost, "/routes/diagnostics/test"},
		{http.MethodGet, "/routes/1"},
		{http.MethodPatch, "/routes/1"},
		{http.MethodDelete, "/routes/1"},
		{http.MethodPost, "/routes/1/enable"},
		{http.MethodPost, "/routes/1/disable"},
		{http.MethodPost, "/routes/1/reapply"},
		{http.MethodPost, "/routes/1/duplicate"},
		{http.MethodGet, "/routes/1/destinations"},
		{http.MethodPost, "/routes/1/destinations"},
		{http.MethodDelete, "/routes/1/destinations"},
		{http.MethodGet, "/routes/1/allowed-sources"},
		{http.MethodPost, "/routes/1/allowed-sources"},
		{http.MethodDelete, "/routes/1/allowed-sources"},
		{http.MethodGet, "/routes/1/traffic"},
		{http.MethodGet, "/routes/1/traffic/history"},
		{http.MethodPost, "/routes/1/diagnostics/test"},
		{http.MethodPost, "/routes/1/diagnostics/analyze"},
		{http.MethodGet, "/routes/1/connections"},
		{http.MethodGet, "/routes/1/counters"},
		{http.MethodGet, "/system/forwarding"},
		{http.MethodPost, "/system/forwarding/enable"},
	}

	for _, endpoint := range endpoints {
		resp, body := anonymous.request(endpoint.method, api+endpoint.path, nil)

		// A read is refused by the session guard; a mutation is refused by the
		// CSRF guard, which runs first. Either way the request never reaches a
		// handler, and either way the answer is the error envelope.
		wantCode := CodeUnauthenticated
		wantStatus := http.StatusUnauthorized
		if endpoint.method != http.MethodGet {
			wantCode, wantStatus = CodeCSRFRequired, http.StatusForbidden
		}
		if resp.StatusCode != wantStatus {
			t.Errorf("%s %s without a session = %d, want %d\nbody: %s",
				endpoint.method, endpoint.path, resp.StatusCode, wantStatus, body)
			continue
		}
		var envelope ErrorEnvelope
		if err := json.Unmarshal(body, &envelope); err != nil {
			t.Errorf("%s %s did not answer with the error envelope: %s",
				endpoint.method, endpoint.path, body)
			continue
		}
		if envelope.Error.Code != wantCode {
			t.Errorf("%s %s answered %q, want %q",
				endpoint.method, endpoint.path, envelope.Error.Code, wantCode)
		}
		if envelope.Error.Details == nil {
			t.Errorf("%s %s left details null; every field of the envelope is always present",
				endpoint.method, endpoint.path)
		}
	}
	if id == 0 {
		t.Error("the rule the guard was tested against was not created")
	}
}

// TestRouteLifecycleOverTheApi walks the whole set of operations the way the
// frontend does.
func TestRouteLifecycleOverTheApi(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	// Create.
	created := createRoute(t, c, api, routePayload("Web relay", 2044, nil))
	id := routeID(t, created)
	verification, _ := created["verification"].(map[string]any)
	if ok, _ := verification["ok"].(bool); !ok {
		t.Fatalf("the create was not verified against the kernel: %+v", verification)
	}
	if _, ok := created["plan"]; !ok {
		t.Error("the response carries no plan")
	}

	// Read.
	resp, body := c.request(http.MethodGet, api+"/routes", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /routes = %d\nbody: %s", resp.StatusCode, body)
	}
	var list struct {
		Routes []struct {
			Route  map[string]any `json:"route"`
			Health route.Health   `json:"health"`
		} `json:"routes"`
		Total int    `json:"total"`
		Note  string `json:"note"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decoding the list failed: %v", err)
	}
	if list.Total != 1 {
		t.Fatalf("GET /routes reported %d rules, want 1", list.Total)
	}
	if list.Routes[0].Health.State != route.HealthHealthy {
		t.Errorf("the rule's health is %q: %s", list.Routes[0].Health.State, list.Routes[0].Health.Detail)
	}
	if !strings.Contains(list.Note, "never added together") {
		t.Error("the list does not carry the note separating the two byte figures")
	}

	// Update: one field, and nothing else changes.
	resp, body = c.request(http.MethodPatch, api+"/routes/1",
		map[string]any{"is_clamp_mss_to_pmtu": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PATCH /routes/1 = %d\nbody: %s", resp.StatusCode, body)
	}
	var updated struct {
		Route map[string]any `json:"route"`
	}
	if err := json.Unmarshal(body, &updated); err != nil {
		t.Fatal(err)
	}
	if clamp, _ := updated.Route["is_clamp_mss_to_pmtu"].(bool); !clamp {
		t.Error("the update did not take")
	}
	if title, _ := updated.Route["route_rule_title"].(string); title != "Web relay" {
		t.Errorf("a one-field update changed the name to %q", title)
	}
	if port, _ := updated.Route["bind_port"].(float64); int(port) != 2044 {
		t.Errorf("a one-field update changed the bind port to %v", port)
	}

	// Disable and enable.
	for _, action := range []string{"disable", "enable"} {
		resp, body = c.request(http.MethodPost, api+"/routes/1/"+action, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /routes/1/%s = %d\nbody: %s", action, resp.StatusCode, body)
		}
	}

	// Duplicate: disabled, with a free name.
	resp, body = c.request(http.MethodPost, api+"/routes/1/duplicate", nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /routes/1/duplicate = %d\nbody: %s", resp.StatusCode, body)
	}
	var copied struct {
		Route map[string]any `json:"route"`
		Note  string         `json:"note"`
	}
	if err := json.Unmarshal(body, &copied); err != nil {
		t.Fatal(err)
	}
	copyID := int64(copied.Route["route_rule_id"].(float64))
	if enabled, _ := copied.Route["is_enabled"].(bool); enabled {
		t.Error("the copy is enabled, so it would claim the original's listener")
	}
	if copied.Note == "" {
		t.Error("the copy was returned without saying why it is disabled")
	}

	// Reorder.
	resp, body = c.request(http.MethodPost, api+"/routes/reorder",
		map[string]any{"route_rule_ids": []int64{copyID, id}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /routes/reorder = %d\nbody: %s", resp.StatusCode, body)
	}

	// Bulk apply.
	resp, body = c.request(http.MethodPost, api+"/routes/apply-all", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /routes/apply-all = %d\nbody: %s", resp.StatusCode, body)
	}
	var applied struct {
		RulesApplied int `json:"rules_applied"`
	}
	if err := json.Unmarshal(body, &applied); err != nil {
		t.Fatal(err)
	}
	if applied.RulesApplied != 1 {
		t.Errorf("apply-all covered %d rules, want the one enabled rule", applied.RulesApplied)
	}

	// Delete.
	resp, body = c.request(http.MethodDelete, api+"/routes/1", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /routes/1 = %d\nbody: %s", resp.StatusCode, body)
	}
	resp, _ = c.request(http.MethodGet, api+"/routes/1", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET a deleted rule = %d, want 404", resp.StatusCode)
	}
}

// TestRoutePreviewChangesNothing is the trust model of §7 at the HTTP layer.
func TestRoutePreviewChangesNothing(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/routes/preview", routePayload("Web relay", 2044, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /routes/preview = %d\nbody: %s", resp.StatusCode, body)
	}
	var preview struct {
		Payload string         `json:"payload"`
		Plan    map[string]any `json:"plan"`
		Note    string         `json:"note"`
	}
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.Payload, "dnat") || !strings.Contains(preview.Payload, "198.51.100.20") {
		t.Errorf("the preview payload is not the ruleset:\n%s", preview.Payload)
	}
	if preview.Note == "" {
		t.Error("the preview does not say that nothing was applied")
	}

	resp, body = c.request(http.MethodGet, api+"/routes", nil)
	var list struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 0 {
		t.Errorf("the preview stored the rule: %d rules exist", list.Total)
	}
}

// TestRouteValidationUsesTheErrorEnvelope: a malformed rule is refused with the
// field named, which is what makes inline validation possible.
func TestRouteValidationUsesTheErrorEnvelope(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/routes",
		routePayload("Bad relay", 2044, map[string]any{"destination_address": "not-an-ip"}))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST /routes with a bad address = %d, want 422\nbody: %s", resp.StatusCode, body)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("the refusal is not the error envelope: %s", body)
	}
	if envelope.Error.Code != CodeValidationFailed {
		t.Errorf("code %q, want %q", envelope.Error.Code, CodeValidationFailed)
	}
	if envelope.Error.Field == "" {
		t.Error("the refusal does not name the field")
	}
	if envelope.Error.Details["fields"] == nil {
		t.Errorf("the refusal carries no field list: %+v", envelope.Error.Details)
	}
}

// TestASafetyInvariantIsRefusedThroughTheApiAndForceDoesNotHelp is §6.3 at the
// HTTP layer: no flag reaches the panel's own port.
func TestASafetyInvariantIsRefusedThroughTheApiAndForceDoesNotHelp(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	payload := routePayload("Take the panel down", h.cfg.BindPort, map[string]any{"force": true})
	resp, body := c.request(http.MethodPost, api+"/routes", payload)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("POST /routes on the panel's own port = %d, want 409\nbody: %s", resp.StatusCode, body)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(envelope.Error.Message), "panel") {
		t.Errorf("the refusal does not explain itself: %+v", envelope.Error)
	}
}

// TestRouteWarningsReachTheClient: a rule that binds every address is accepted
// and says so, because that is a decision an operator should see rather than a
// refusal.
func TestRouteWarningsReachTheClient(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	created := createRoute(t, c, api,
		routePayload("Open relay", 2044, map[string]any{"bind_address": "0.0.0.0"}))

	warnings, ok := created["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("binding every address produced no warning: %+v", created["warnings"])
	}
	found := false
	for _, raw := range warnings {
		warning, _ := raw.(map[string]any)
		code, _ := warning["code"].(string)
		message, _ := warning["message"].(string)
		if message == "" {
			t.Errorf("warning %q has no message", code)
		}
		if strings.Contains(strings.ToUpper(code), "BIND") || strings.Contains(message, "every") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning mentions binding every address: %+v", warnings)
	}
}

// TestNestedDestinationsAndAllowlist covers the nested CRUD of §11, which goes
// through the ordinary update path so a change there is applied and verified
// like any other.
func TestNestedDestinationsAndAllowlist(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createRoute(t, c, api, routePayload("Web relay", 2044,
		map[string]any{"load_balance_mode_id": model.LoadBalanceModeRoundRobin}))

	// A second destination.
	resp, body := c.request(http.MethodPost, api+"/routes/1/destinations", map[string]any{
		"address": "198.51.100.21", "port": 2044, "weight": 1, "is_enabled": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST destinations = %d\nbody: %s", resp.StatusCode, body)
	}

	resp, body = c.request(http.MethodGet, api+"/routes/1/destinations", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET destinations = %d\nbody: %s", resp.StatusCode, body)
	}
	var destinations struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &destinations); err != nil {
		t.Fatal(err)
	}
	if destinations.Total != 2 {
		t.Fatalf("the rule has %d destinations, want 2", destinations.Total)
	}

	resp, body = c.request(http.MethodDelete, api+"/routes/1/destinations",
		map[string]any{"address": "198.51.100.21", "port": 2044})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE destinations = %d\nbody: %s", resp.StatusCode, body)
	}

	// The allowlist.
	resp, body = c.request(http.MethodPost, api+"/routes/1/allowed-sources",
		map[string]any{"cidr": "192.0.2.0/24", "description": "office"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST allowed-sources = %d\nbody: %s", resp.StatusCode, body)
	}
	resp, body = c.request(http.MethodGet, api+"/routes/1/allowed-sources", nil)
	var allowlist struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &allowlist); err != nil {
		t.Fatal(err)
	}
	if allowlist.Total != 1 {
		t.Fatalf("the allowlist has %d entries, want 1\nbody: %s", allowlist.Total, body)
	}

	// A malformed entry is refused on its field rather than stored.
	resp, body = c.request(http.MethodPost, api+"/routes/1/allowed-sources",
		map[string]any{"cidr": "not-a-cidr"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("POST a bad CIDR = %d, want 422\nbody: %s", resp.StatusCode, body)
	}

	resp, body = c.request(http.MethodDelete, api+"/routes/1/allowed-sources",
		map[string]any{"cidr": "192.0.2.0/24"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE allowed-sources = %d\nbody: %s", resp.StatusCode, body)
	}
}

// TestTrafficAndDiagnosticsEndpoints.
func TestTrafficAndDiagnosticsEndpoints(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createRoute(t, c, api, routePayload("Web relay", 2044, nil))

	for _, path := range []string{
		"/routes/1/traffic", "/routes/1/traffic/history", "/routes/traffic/summary",
		"/routes/1/connections", "/routes/1/counters",
	} {
		resp, body := c.request(http.MethodGet, api+path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d\nbody: %s", path, resp.StatusCode, body)
		}
	}

	// The pre-flight runs with no rule at all, which is the point of it.
	resp, body := c.request(http.MethodPost, api+"/routes/diagnostics/test",
		map[string]any{"address": "198.51.100.20", "port": 2044, "protocol": "tcp"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /routes/diagnostics/test = %d\nbody: %s", resp.StatusCode, body)
	}
	var probe route.ReachabilityResult
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatal(err)
	}
	if probe.Detail == "" {
		t.Error("the probe explains nothing")
	}

	// And analyze returns a verdict with its evidence.
	resp, body = c.request(http.MethodPost, api+"/routes/1/diagnostics/analyze", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST analyze = %d\nbody: %s", resp.StatusCode, body)
	}
	var analysis route.AnalyzeResult
	if err := json.Unmarshal(body, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Verdict == "" {
		t.Error("the analysis returned no verdict")
	}
	if len(analysis.Evidence) == 0 {
		t.Error("the verdict rests on no evidence")
	}
}

// TestForwardingEndpointReportsTheKernelAndTheBackend.
func TestForwardingEndpointReportsTheKernelAndTheBackend(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	resp, body := c.request(http.MethodGet, api+"/system/forwarding", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/forwarding = %d\nbody: %s", resp.StatusCode, body)
	}
	var report struct {
		Forwarding struct {
			IPv4Forwarding bool   `json:"ipv4_forwarding"`
			Backend        string `json:"backend"`
			SysctlPath     string `json:"sysctl_path"`
		} `json:"forwarding"`
		Foreign map[string]any `json:"foreign"`
		Backend map[string]any `json:"backend"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if !report.Forwarding.IPv4Forwarding {
		t.Error("the fixture kernel forwards and the endpoint says it does not")
	}
	if report.Forwarding.Backend == "" || report.Forwarding.SysctlPath == "" {
		t.Errorf("the report does not name what is carrying the rules: %+v", report.Forwarding)
	}
	if report.Foreign == nil {
		t.Error("the report does not cover the other software managing netfilter here")
	}

	// Turning it on is idempotent and records what it changed.
	resp, body = c.request(http.MethodPost, api+"/system/forwarding/enable", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /system/forwarding/enable = %d\nbody: %s", resp.StatusCode, body)
	}
}

// TestTunnelRoutesListsWhatWouldBreak is §10 at the HTTP layer.
func TestTunnelRoutesListsWhatWouldBreak(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	created := createTunnel(t, c, api, nil)
	rec, ok := created["tunnel"].(map[string]any)
	if !ok {
		t.Fatalf("the response carries no tunnel: %+v", created)
	}
	id := int64(rec["tunnel_id"].(float64))
	createRoute(t, c, api, routePayload("Relay over the tunnel", 2044,
		map[string]any{"tunnel_id": id}))

	resp, body := c.request(http.MethodGet, api+"/tunnels/1/routes", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /tunnels/1/routes = %d\nbody: %s", resp.StatusCode, body)
	}
	var dependants struct {
		Routes []map[string]any `json:"routes"`
		Total  int              `json:"total"`
		Note   string           `json:"note"`
	}
	if err := json.Unmarshal(body, &dependants); err != nil {
		t.Fatal(err)
	}
	if dependants.Total != 1 {
		t.Fatalf("the tunnel reports %d dependent rules, want 1\nbody: %s", dependants.Total, body)
	}
	if dependants.Note == "" {
		t.Error("the list does not say what taking the tunnel down would do")
	}

	// And taking it down warns with them named.
	resp, body = c.request(http.MethodPost, api+"/tunnels/1/down", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /tunnels/1/down = %d\nbody: %s", resp.StatusCode, body)
	}
	var down struct {
		Warnings []Warning `json:"warnings"`
	}
	if err := json.Unmarshal(body, &down); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range down.Warnings {
		if warning.Code == "TUNNEL_HAS_DEPENDENT_ROUTES" &&
			strings.Contains(warning.Message, "Relay over the tunnel") {
			found = true
		}
	}
	if !found {
		t.Errorf("taking the tunnel down did not warn about the rules crossing it: %+v", down.Warnings)
	}
}

// TestReconcileReportCoversRoutes: the forwarding half rides the existing
// report rather than an endpoint of its own (§9).
func TestReconcileReportCoversRoutes(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createRoute(t, c, api, routePayload("Web relay", 2044, nil))

	resp, body := c.request(http.MethodGet, api+"/reconcile", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /reconcile = %d\nbody: %s", resp.StatusCode, body)
	}
	var report struct {
		Routes []struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"routes"`
		RouteCounts   map[string]int `json:"route_counts"`
		RouteFindings struct {
			Backend  string `json:"backend"`
			Readable bool   `json:"readable"`
		} `json:"route_findings"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if len(report.Routes) != 1 {
		t.Fatalf("the report covers %d forwarding rules, want 1\nbody: %s", len(report.Routes), body)
	}
	if report.Routes[0].Status != "InSync" {
		t.Errorf("the rule is %s: %s", report.Routes[0].Status, report.Routes[0].Detail)
	}
	if !report.RouteFindings.Readable || report.RouteFindings.Backend == "" {
		t.Errorf("the findings do not say what was read: %+v", report.RouteFindings)
	}
	if report.RouteCounts["InSync"] != 1 {
		t.Errorf("the counts are %v", report.RouteCounts)
	}
}

// TestRouteTrafficRidesTheMetricsStream: §5.4 asks for the live relay values to
// be multiplexed into the stream the frontend already subscribes to, rather
// than carried on a second endpoint and a second connection.
func TestRouteTrafficRidesTheMetricsStream(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createRoute(t, c, api, routePayload("Web relay", 2044, nil))

	// Two readings, so there is a rate and not only a total.
	ctx := context.Background()
	h.nft.SetCounters(map[int64]rules.Counter{
		1: {RouteRuleID: 1, RxBytes: 1_000, TxBytes: 2_000, RxPackets: 10, TxPackets: 20},
	})
	h.accounting.Sample(ctx)
	h.nft.SetCounters(map[int64]rules.Counter{
		1: {RouteRuleID: 1, RxBytes: 5_000, TxBytes: 9_000, RxPackets: 50, TxPackets: 90},
	})
	h.accounting.Sample(ctx)
	h.metrics.Sample(ctx)

	resp, body := c.request(http.MethodGet, api+"/system/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/metrics = %d\nbody: %s", resp.StatusCode, body)
	}
	var snapshot struct {
		Routes []struct {
			RouteRuleID          int64   `json:"route_rule_id"`
			Title                string  `json:"title"`
			RxBytesSinceBoot     uint64  `json:"rx_bytes_since_boot"`
			RxBytesSinceCreation uint64  `json:"rx_bytes_since_creation"`
			TxBytesPerSecond     float64 `json:"tx_bytes_per_second"`
		} `json:"routes"`
		RouteTotals struct {
			Routes int `json:"routes"`
		} `json:"route_totals"`
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Routes) != 1 {
		t.Fatalf("the metrics snapshot carries %d rules, want 1\nbody: %s", len(snapshot.Routes), body)
	}
	relay := snapshot.Routes[0]
	if relay.RouteRuleID != 1 || relay.Title != "Web relay" {
		t.Errorf("the rule is not named in the stream: %+v", relay)
	}
	// The kernel's figure and the panel's are both there and are different,
	// which is the point of keeping them apart.
	if relay.RxBytesSinceBoot != 5_000 {
		t.Errorf("since boot is %d, want the kernel's 5000", relay.RxBytesSinceBoot)
	}
	if relay.RxBytesSinceCreation != 4_000 {
		t.Errorf("since creation is %d, want the 4000 the panel accumulated",
			relay.RxBytesSinceCreation)
	}
	if relay.TxBytesPerSecond <= 0 {
		t.Errorf("no rate was computed: %+v", relay)
	}
	if snapshot.RouteTotals.Routes != 1 {
		t.Errorf("the relay totals are missing: %+v", snapshot.RouteTotals)
	}
}
