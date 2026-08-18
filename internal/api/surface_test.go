package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
)

// specifiedEndpoints is the whole API surface of §15, transcribed from the
// specification. The test below walks the live router and compares, so an
// endpoint that was specified but never routed fails here rather than being
// discovered by whoever tries to use it.
var specifiedEndpoints = []string{
	// Auth
	"POST /api/v1/auth/setup",
	"POST /api/v1/auth/login",
	"POST /api/v1/auth/refresh",
	"POST /api/v1/auth/logout",
	"GET /api/v1/auth/me",
	"PUT /api/v1/auth/me",

	// Tunnels
	"GET /api/v1/tunnels",
	"POST /api/v1/tunnels",
	"POST /api/v1/tunnels/preview",
	"GET /api/v1/tunnels/{id}",
	"PATCH /api/v1/tunnels/{id}",
	"DELETE /api/v1/tunnels/{id}",
	"POST /api/v1/tunnels/{id}/up",
	"POST /api/v1/tunnels/{id}/down",
	"POST /api/v1/tunnels/{id}/restart",
	"POST /api/v1/tunnels/{id}/reapply",
	"GET /api/v1/tunnels/{id}/addresses",
	"POST /api/v1/tunnels/{id}/addresses",
	"DELETE /api/v1/tunnels/{id}/addresses",
	"GET /api/v1/tunnels/{id}/pairing-code",
	"POST /api/v1/tunnels/from-pairing-code",
	"GET /api/v1/tunnels/side-info",

	// Monitor
	"GET /api/v1/tunnels/{id}/status",
	"GET /api/v1/tunnels/{id}/history",
	"POST /api/v1/tunnels/{id}/monitor/enable",
	"POST /api/v1/tunnels/{id}/monitor/disable",
	"GET /api/v1/monitor/stream",
	"GET /api/v1/monitor/summary",

	// Metrics
	"GET /api/v1/system/metrics",
	"GET /api/v1/system/metrics/stream",
	"GET /api/v1/system/metrics/history",

	// Diagnostics
	"POST /api/v1/tunnels/{id}/diagnostics/ping",
	"POST /api/v1/tunnels/{id}/diagnostics/mtu-probe",
	"POST /api/v1/tunnels/{id}/diagnostics/traceroute",
	"POST /api/v1/tunnels/{id}/diagnostics/analyze",
	"GET /api/v1/tunnels/{id}/counters",
	"GET /api/v1/diagnostics/runs",
	"GET /api/v1/diagnostics/runs/{id}",
	"DELETE /api/v1/diagnostics/runs/{id}",

	// Reconcile
	"GET /api/v1/reconcile",
	"POST /api/v1/reconcile/adopt",
	"POST /api/v1/reconcile/{id}/reapply",
	"POST /api/v1/reconcile/{id}/forget",

	// Settings
	"GET /api/v1/settings",
	"GET /api/v1/settings/schema",
	"PUT /api/v1/settings",
	"POST /api/v1/settings/reset",

	// Pools
	"GET /api/v1/pools",
	"POST /api/v1/pools",
	"GET /api/v1/pools/{id}",
	"PUT /api/v1/pools/{id}",
	"DELETE /api/v1/pools/{id}",
	"GET /api/v1/pools/{id}/next-free",

	// System
	"GET /api/v1/system/info",
	"GET /api/v1/system/capabilities",
	"GET /api/v1/system/interfaces",
	"GET /api/v1/system/routes",
	"GET /api/v1/system/health",
	"GET /api/v1/system/address",
	"POST /api/v1/system/address",

	// Audit
	"GET /api/v1/audit",

	// Backup
	"GET /api/v1/backup/export",
	"POST /api/v1/backup/import",

	// Port forwarding: the whole of §11 of the port forwarding specification,
	// transcribed the same way, so an endpoint that was specified and never
	// routed fails here rather than being found by whoever tries to use it.
	"GET /api/v1/routes",
	"POST /api/v1/routes",
	"POST /api/v1/routes/preview",
	"GET /api/v1/routes/{id}",
	"PATCH /api/v1/routes/{id}",
	"DELETE /api/v1/routes/{id}",
	"POST /api/v1/routes/{id}/enable",
	"POST /api/v1/routes/{id}/disable",
	"POST /api/v1/routes/{id}/reapply",
	"POST /api/v1/routes/{id}/duplicate",
	"POST /api/v1/routes/reorder",
	"POST /api/v1/routes/apply-all",

	// Destinations and allowlist.
	"GET /api/v1/routes/{id}/destinations",
	"POST /api/v1/routes/{id}/destinations",
	"DELETE /api/v1/routes/{id}/destinations",
	"GET /api/v1/routes/{id}/allowed-sources",
	"POST /api/v1/routes/{id}/allowed-sources",
	"DELETE /api/v1/routes/{id}/allowed-sources",

	// Traffic. There is deliberately no stream endpoint: live values are
	// multiplexed into the metrics stream above.
	"GET /api/v1/routes/{id}/traffic",
	"GET /api/v1/routes/{id}/traffic/history",
	"GET /api/v1/routes/traffic/summary",

	// Forwarding diagnostics.
	"POST /api/v1/routes/{id}/diagnostics/test",
	"POST /api/v1/routes/{id}/diagnostics/analyze",
	"GET /api/v1/routes/{id}/connections",
	"GET /api/v1/routes/{id}/counters",
	// The pre-flight, which runs before any rule exists.
	"POST /api/v1/routes/diagnostics/test",

	// Forwarding system state.
	"GET /api/v1/system/forwarding",
	"POST /api/v1/system/forwarding/enable",

	// The routes traversing one tunnel, for its detail page (§10).
	"GET /api/v1/tunnels/{id}/routes",

	// The API description.
	"GET /api/docs",
}

// TestEverySpecifiedEndpointIsRouted walks the router rather than making
// requests, so it proves the route exists regardless of what it answers.
func TestEverySpecifiedEndpointIsRouted(t *testing.T) {
	h := newHarness(t, testWebPath)

	routed := map[string]bool{}
	for _, route := range h.server.RoutedPaths() {
		routed[route] = true
	}

	for _, endpoint := range specifiedEndpoints {
		if !routed[endpoint] {
			t.Errorf("the specification lists %s but the router does not serve it", endpoint)
		}
	}
}

// The API description is generated from the router, so it can never claim an
// endpoint the panel does not serve (§15).
func TestOpenApiDescribesWhatIsActuallyRouted(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, _ := session(t, h)

	resp, body := c.request(http.MethodGet, "/"+testWebPath+"/api/docs", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/docs = %d\nbody: %s", resp.StatusCode, body)
	}

	var document struct {
		OpenAPI string                            `json:"openapi"`
		Info    map[string]any                    `json:"info"`
		Paths   map[string]map[string]interface{} `json:"paths"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("the description is not JSON: %v", err)
	}
	if document.OpenAPI == "" || len(document.Paths) == 0 {
		t.Fatalf("the description is empty: %+v", document)
	}

	// Every routed path appears, and nothing else does.
	routed := map[string]bool{}
	for _, route := range h.server.RoutedPaths() {
		method, path, _ := strings.Cut(route, " ")
		routed[strings.ToLower(method)+" "+path] = true
	}
	for path, operations := range document.Paths {
		for method := range operations {
			if !routed[method+" "+path] {
				t.Errorf("the description claims %s %s, which the router does not serve", method, path)
			}
		}
	}
	for _, endpoint := range specifiedEndpoints {
		method, path, _ := strings.Cut(endpoint, " ")
		operations, ok := document.Paths[path]
		if !ok {
			t.Errorf("the description omits %s", path)
			continue
		}
		if _, ok := operations[strings.ToLower(method)]; !ok {
			t.Errorf("the description omits %s on %s", method, path)
		}
	}
}

func TestApiDocsRequireAuthentication(t *testing.T) {
	h := newHarness(t, testWebPath)

	// Before setup, everything but health and setup answers SETUP_REQUIRED.
	rec := h.do(t, http.MethodGet, "/"+testWebPath+"/api/docs", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/docs before setup = %d, want 503", rec.Code)
	}

	// After setup but without a session it is unauthenticated, not public.
	c, api := session(t, h)
	resp, _ := c.request(http.MethodPost, api+"/auth/logout", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d", resp.StatusCode)
	}
	resp, body := c.request(http.MethodGet, "/"+testWebPath+"/api/docs", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /api/docs signed out = %d, want 401\nbody: %s", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------- monitoring

func TestMonitorEndpoints(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	resp, body := c.request(http.MethodGet, api+"/monitor/summary", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /monitor/summary = %d\nbody: %s", resp.StatusCode, body)
	}

	resp, body = c.request(http.MethodGet, api+"/tunnels/"+id+"/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d\nbody: %s", resp.StatusCode, body)
	}
	var status struct {
		TunnelID       int64           `json:"tunnel_id"`
		MonitorStateID int64           `json:"monitor_state_id"`
		State          string          `json:"state"`
		Reason         string          `json:"reason"`
		Events         []monitor.Event `json:"events"`
	}
	if err := json.Unmarshal(body, &status); err != nil {
		t.Fatal(err)
	}
	// Nothing has been measured yet, and saying Unknown with a reason is more
	// useful than an empty response or a confident guess.
	if status.State == "" || status.Reason == "" {
		t.Fatalf("status = %+v", status)
	}
	if status.Events == nil {
		t.Fatal("the status must carry the recent transitions, even when there are none")
	}

	resp, body = c.request(http.MethodGet, api+"/tunnels/"+id+"/history?resolution_seconds=60", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET history = %d\nbody: %s", resp.StatusCode, body)
	}

	// Switching monitoring off is recorded on the tunnel and acted on at once.
	resp, body = c.request(http.MethodPost, api+"/tunnels/"+id+"/monitor/disable", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST monitor/disable = %d\nbody: %s", resp.StatusCode, body)
	}
	stored, err := h.repo.ByID(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored.IsMonitorEnabled == nil || *stored.IsMonitorEnabled {
		t.Fatalf("the override was not recorded: %v", stored.IsMonitorEnabled)
	}

	resp, _ = c.request(http.MethodPost, api+"/tunnels/"+id+"/monitor/enable", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST monitor/enable = %d", resp.StatusCode)
	}
	stored, _ = h.repo.ByID(context.Background(), 1)
	if stored.IsMonitorEnabled == nil || !*stored.IsMonitorEnabled {
		t.Fatalf("the override was not updated: %v", stored.IsMonitorEnabled)
	}
}

// The live stream delivers events and every goroutine exits when the client
// disconnects. Run with -race this also proves the fan-out is free of races
// (§10.5).
func TestMonitorStreamDeliversAndCleansUp(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	const subscribers = 4
	var wg sync.WaitGroup
	events := make([]atomic.Int64, subscribers)
	cancels := make([]context.CancelFunc, subscribers)

	for i := 0; i < subscribers; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels[i] = cancel

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+api+"/monitor/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatalf("opening the stream failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /monitor/stream = %d", resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
			t.Fatalf("content type = %q", got)
		}

		wg.Add(1)
		go func(i int, resp *http.Response) {
			defer wg.Done()
			defer resp.Body.Close()
			buffer := make([]byte, 4096)
			for {
				n, err := resp.Body.Read(buffer)
				if n > 0 {
					events[i].Add(int64(strings.Count(string(buffer[:n]), "event: ")))
				}
				if err != nil {
					return
				}
			}
		}(i, resp)
	}

	// Every subscriber is sent the current picture as soon as it connects, so
	// waiting for that is what proves the fan-out reached all of them.
	waitFor(t, "every subscriber to receive the opening picture", func() bool {
		for i := range events {
			if events[i].Load() == 0 {
				return false
			}
		}
		return true
	})
	if got := h.monitor.Hub().Subscribers(); got != subscribers {
		t.Fatalf("the hub has %d subscribers, want %d", got, subscribers)
	}

	// Then a change reaches all of them too.
	before := make([]int64, subscribers)
	for i := range events {
		before[i] = events[i].Load()
	}
	for i := 0; i < 3; i++ {
		h.monitor.Hub().Publish(monitor.Snapshot{
			TunnelID: 1, State: "Up", MonitorStateID: model.MonitorStateUp,
		})
	}
	waitFor(t, "every subscriber to receive the change", func() bool {
		for i := range events {
			if events[i].Load() <= before[i] {
				return false
			}
		}
		return true
	})

	// Disconnecting must end every handler and free every subscription.
	for _, cancel := range cancels {
		cancel()
	}
	wg.Wait()

	waitFor(t, "the subscriptions to be released", func() bool {
		return h.monitor.Hub().Subscribers() == 0
	})
}

// waitFor polls until the condition holds or the deadline passes.
func waitFor(t *testing.T, why string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", why)
}

// ---------------------------------------------------------------- metrics

func TestMetricsEndpoints(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	// Two readings, so the second has a baseline to compute utilisation from.
	h.metrics.Sample(context.Background())
	h.metrics.Sample(context.Background())

	resp, body := c.request(http.MethodGet, api+"/system/metrics", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/metrics = %d\nbody: %s", resp.StatusCode, body)
	}
	var snapshot struct {
		Cpu    []map[string]any `json:"cpu"`
		Memory struct {
			TotalBytes uint64 `json:"total_bytes"`
			UsedBytes  uint64 `json:"used_bytes"`
		} `json:"memory"`
		Swap struct {
			Configured bool `json:"configured"`
		} `json:"swap"`
		Network struct {
			Interfaces []map[string]any `json:"interfaces"`
			Totals     map[string]any   `json:"totals"`
		} `json:"network"`
	}
	if err := json.Unmarshal(body, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Cpu) == 0 || snapshot.Memory.TotalBytes == 0 {
		t.Fatalf("the reading is empty: %s", body)
	}
	if len(snapshot.Network.Interfaces) == 0 {
		t.Fatal("the reading has no interfaces")
	}
	// Raw numbers only: nothing pre-formatted for display (§11.2).
	if _, ok := snapshot.Network.Totals["rx_bytes_per_second"].(float64); !ok {
		t.Fatalf("the totals must be raw numbers: %+v", snapshot.Network.Totals)
	}
	for _, iface := range snapshot.Network.Interfaces {
		for _, key := range []string{"rx_bytes_since_boot", "rx_bytes_since_install"} {
			if _, ok := iface[key]; !ok {
				t.Fatalf("since boot and since install must be separate fields: %+v", iface)
			}
		}
	}

	resp, body = c.request(http.MethodGet, api+"/system/metrics/history?limit=2", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/metrics/history = %d\nbody: %s", resp.StatusCode, body)
	}
	var history struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &history); err != nil {
		t.Fatal(err)
	}
	if history.Total == 0 {
		t.Fatal("the history is empty after two readings")
	}
}

func TestMetricsStreamDeliversAndCleansUp(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	h.metrics.Sample(context.Background())

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+api+"/system/metrics/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("opening the stream failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/metrics/stream = %d", resp.StatusCode)
	}

	var count atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer resp.Body.Close()
		buffer := make([]byte, 8192)
		for {
			n, err := resp.Body.Read(buffer)
			if n > 0 {
				count.Add(int64(strings.Count(string(buffer[:n]), "event: metrics")))
			}
			if err != nil {
				return
			}
		}
	}()

	waitFor(t, "the subscription to register", func() bool {
		return h.metrics.Hub().Subscribers() == 1
	})
	// The opening reading has been sent already; a fresh sample sends another.
	waitFor(t, "the subscriber to receive a reading", func() bool {
		h.metrics.Sample(context.Background())
		return count.Load() > 0
	})

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the stream handler did not exit when the client disconnected")
	}
	waitFor(t, "the subscription to be released", func() bool {
		return h.metrics.Hub().Subscribers() == 0
	})
}

// ---------------------------------------------------------------- diagnostics

func TestDiagnosticsEndpoints(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	// The ping streams, so it is read as an event stream rather than one body.
	resp, body := c.request(http.MethodPost, api+"/tunnels/"+id+"/diagnostics/ping",
		map[string]any{"count": 3, "interval_seconds": 0.01, "timeout_seconds": 0.5})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST diagnostics/ping = %d\nbody: %s", resp.StatusCode, body)
	}
	text := string(body)
	for _, event := range []string{"event: run", "event: packet", "event: summary"} {
		if !strings.Contains(text, event) {
			t.Fatalf("the ping stream is missing %q:\n%s", event, text)
		}
	}

	resp, body = c.request(http.MethodPost, api+"/tunnels/"+id+"/diagnostics/analyze",
		map[string]any{"sample_seconds": 0.05})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST diagnostics/analyze = %d\nbody: %s", resp.StatusCode, body)
	}
	var analysis struct {
		Result struct {
			Verdict      string           `json:"verdict"`
			Summary      string           `json:"summary"`
			Evidence     []map[string]any `json:"evidence"`
			SuggestedFix []string         `json:"suggested_fix"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &analysis); err != nil {
		t.Fatal(err)
	}
	if analysis.Result.Verdict == "" || analysis.Result.Summary == "" {
		t.Fatalf("the analysis is empty: %s", body)
	}
	if len(analysis.Result.Evidence) == 0 {
		t.Fatal("a verdict must carry the evidence it rests on, never a bare status word")
	}

	resp, body = c.request(http.MethodGet, api+"/tunnels/"+id+"/counters?sample_seconds=0.05", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET counters = %d\nbody: %s", resp.StatusCode, body)
	}

	// The runs are listed, readable and deletable.
	resp, body = c.request(http.MethodGet, api+"/diagnostics/runs", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /diagnostics/runs = %d\nbody: %s", resp.StatusCode, body)
	}
	var runs struct {
		Runs []struct {
			DiagnosticRunID int64  `json:"diagnostic_run_id"`
			Type            string `json:"type"`
		} `json:"runs"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(body, &runs); err != nil {
		t.Fatal(err)
	}
	if runs.Total < 2 {
		t.Fatalf("the ping and the analysis should both be recorded: %d", runs.Total)
	}

	runID := jsonNumber(float64(runs.Runs[0].DiagnosticRunID))
	resp, body = c.request(http.MethodGet, api+"/diagnostics/runs/"+runID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET one run = %d\nbody: %s", resp.StatusCode, body)
	}
	resp, body = c.request(http.MethodDelete, api+"/diagnostics/runs/"+runID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE a run = %d\nbody: %s", resp.StatusCode, body)
	}
	resp, _ = c.request(http.MethodGet, api+"/diagnostics/runs/"+runID, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET a deleted run = %d, want 404", resp.StatusCode)
	}
}

func TestMtuProbeReturnsAnApplyPath(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	id := tunnelID(t, createTunnel(t, c, api, nil))

	resp, body := c.request(http.MethodPost, api+"/tunnels/"+id+"/diagnostics/mtu-probe",
		map[string]any{"min": 1200, "max": 1300, "timeout_seconds": 0.1})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST mtu-probe = %d\nbody: %s", resp.StatusCode, body)
	}
	var probe struct {
		Result struct {
			DiscoveredPathMtu    int `json:"discovered_path_mtu"`
			RecommendedTunnelMtu int `json:"recommended_tunnel_mtu"`
			Overhead             int `json:"overhead"`
		} `json:"result"`
		Apply struct {
			Method string         `json:"method"`
			Path   string         `json:"path"`
			Body   map[string]any `json:"body"`
		} `json:"apply"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatal(err)
	}
	// The loopback stand-in answers every size, so the search reaches the top.
	if probe.Result.DiscoveredPathMtu != 1300 {
		t.Fatalf("discovered = %d, want 1300", probe.Result.DiscoveredPathMtu)
	}
	if probe.Result.Overhead != 28 {
		t.Fatalf("overhead = %d, want 28 for IPv4 GRE with a key", probe.Result.Overhead)
	}
	// The one-click apply: exactly what to send back.
	if probe.Apply.Method != http.MethodPatch || !strings.HasSuffix(probe.Apply.Path, "/tunnels/"+id) {
		t.Fatalf("apply = %+v", probe.Apply)
	}
	if mtu, ok := probe.Apply.Body["mtu"].(float64); !ok || int(mtu) != probe.Result.RecommendedTunnelMtu {
		t.Fatalf("the apply body must carry the recommendation: %+v", probe.Apply.Body)
	}
}

// ---------------------------------------------------------------- audit

func TestAuditRecordsMutationsAndFilters(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createTunnel(t, c, api, nil)

	resp, body := c.request(http.MethodGet, api+"/audit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit = %d\nbody: %s", resp.StatusCode, body)
	}
	var log struct {
		Entries []auditEntry `json:"entries"`
		Total   int          `json:"total"`
		Actions []string     `json:"actions"`
	}
	if err := json.Unmarshal(body, &log); err != nil {
		t.Fatal(err)
	}
	if log.Total == 0 {
		t.Fatal("creating a tunnel must be audited")
	}
	if len(log.Actions) == 0 {
		t.Fatal("the response must list the actions a filter accepts")
	}

	var create *auditEntry
	for i := range log.Entries {
		if log.Entries[i].AuditActionID == model.AuditActionTunnelCreate {
			create = &log.Entries[i]
		}
	}
	if create == nil {
		t.Fatalf("no create entry: %+v", log.Entries)
	}
	if create.Username != testUser {
		t.Fatalf("the entry must name the actor, got %q", create.Username)
	}
	if create.ClientIp == "" {
		t.Fatal("the entry must record the client address")
	}
	if create.Request == nil {
		t.Fatal("the entry must record what was requested")
	}
	if !create.IsSuccess {
		t.Fatalf("the create succeeded but was audited as a failure: %+v", create)
	}

	// Filtering by action narrows it.
	resp, body = c.request(http.MethodGet, api+"/audit?action=TunnelCreate", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filtered audit = %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &log); err != nil {
		t.Fatal(err)
	}
	for _, entry := range log.Entries {
		if entry.AuditActionID != model.AuditActionTunnelCreate {
			t.Fatalf("the filter returned a %s entry", entry.Action)
		}
	}

	// An unknown action is rejected with the list of known ones rather than
	// silently returning everything.
	resp, body = c.request(http.MethodGet, api+"/audit?action=NotAnAction", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("an unknown action filter = %d, want 400\nbody: %s", resp.StatusCode, body)
	}
}

// Secrets never reach the audit log (§17.5).
func TestAuditNeverStoresASecret(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)

	// Change the password, which is the request most likely to leak one.
	resp, _ := c.request(http.MethodPut, api+"/auth/me", map[string]any{
		"current_password": testPassword,
		"new_password":     "a completely different long password",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /auth/me = %d", resp.StatusCode)
	}

	var count int
	if err := h.db.Read.QueryRow(
		`SELECT COUNT(*) FROM AuditLog WHERE RequestJson LIKE '%password%battery%'
		    OR RequestJson LIKE '%completely different%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("%d audit entries carry a password", count)
	}
}

// ---------------------------------------------------------------- backup

func TestBackupExportAndImport(t *testing.T) {
	h := newHarness(t, testWebPath)
	c, api := session(t, h)
	createTunnel(t, c, api, nil)

	resp, body := c.request(http.MethodGet, api+"/backup/export", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /backup/export = %d\nbody: %s", resp.StatusCode, body)
	}
	var backup Backup
	if err := json.Unmarshal(body, &backup); err != nil {
		t.Fatalf("the export is not a backup: %v", err)
	}
	if backup.Version != BackupVersion {
		t.Fatalf("version = %d", backup.Version)
	}
	if len(backup.Tunnels) != 1 || len(backup.Pools) != 4 || len(backup.Settings) == 0 {
		t.Fatalf("the export is incomplete: %d tunnels, %d pools, %d settings",
			len(backup.Tunnels), len(backup.Pools), len(backup.Settings))
	}
	// A backup travels, so it must carry nothing that grants access.
	text := strings.ToLower(string(body))
	for _, forbidden := range []string{"passwordhash", "password_hash", "tokenversion", "argon2"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("the export contains %q", forbidden)
		}
	}

	// A dry run says what would happen and changes nothing.
	before, _ := h.repo.List(context.Background())
	resp, body = c.request(http.MethodPost, api+"/backup/import",
		map[string]any{"backup": backup, "dry_run": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dry-run import = %d\nbody: %s", resp.StatusCode, body)
	}
	var report struct {
		DryRun  bool `json:"dry_run"`
		Actions []struct {
			Kind   string `json:"kind"`
			Target string `json:"target"`
			Action string `json:"action"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if !report.DryRun || len(report.Actions) == 0 {
		t.Fatalf("the dry run reported nothing: %s", body)
	}
	after, _ := h.repo.List(context.Background())
	if len(after) != len(before) {
		t.Fatal("the dry run changed the tunnels")
	}

	// The tunnel already exists here, so importing it is a skip rather than a
	// second copy.
	var skipped bool
	for _, action := range report.Actions {
		if action.Kind == "tunnel" && action.Action == "skip" {
			skipped = true
		}
	}
	if !skipped {
		t.Fatalf("importing a tunnel that already exists must skip it: %+v", report.Actions)
	}

	// A version this build does not understand is refused rather than guessed.
	bad := backup
	bad.Version = 99
	resp, body = c.request(http.MethodPost, api+"/backup/import", map[string]any{"backup": bad})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown backup version = %d, want 422\nbody: %s", resp.StatusCode, body)
	}
}

func TestBackupImportAppliesToACleanPanel(t *testing.T) {
	source := newHarness(t, testWebPath)
	sourceClient, sourceApi := session(t, source)
	createTunnel(t, sourceClient, sourceApi, nil)

	_, body := sourceClient.request(http.MethodGet, sourceApi+"/backup/export", nil)
	var backup Backup
	if err := json.Unmarshal(body, &backup); err != nil {
		t.Fatal(err)
	}

	// A different panel, with nothing on it.
	target := newHarness(t, testWebPath)
	targetClient, targetApi := session(t, target)

	resp, body := targetClient.request(http.MethodPost, targetApi+"/backup/import",
		map[string]any{"backup": backup})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import = %d\nbody: %s", resp.StatusCode, body)
	}

	records, err := target.repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("the import created %d tunnels, want 1", len(records))
	}
	if records[0].InterfaceName != "gre-a-1" {
		t.Fatalf("the imported tunnel is %q", records[0].InterfaceName)
	}
	// It went through the ordinary pipeline, so it is really applied.
	if records[0].ApplyStatusID != model.ApplyStatusApplied {
		t.Fatalf("apply status = %d; an import must apply and verify like any create",
			records[0].ApplyStatusID)
	}
	if _, err := target.links.Get(context.Background(), "gre-a-1"); err != nil {
		t.Fatal("the imported tunnel was not created in the kernel")
	}
}

// ---------------------------------------------------------------- health

func TestHealthReportsEverySubsystemComponent(t *testing.T) {
	h := newHarness(t, testWebPath)
	h.metrics.Sample(context.Background())

	rec := h.do(t, http.MethodGet, h.api("/system/health"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /system/health = %d\nbody: %s", rec.Code, rec.Body.String())
	}
	var health struct {
		Components []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"components"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}

	seen := map[string]string{}
	for _, component := range health.Components {
		seen[component.Name] = component.Status
	}
	for _, name := range []string{ComponentDatabase, ComponentNetlink, ComponentKernelModule,
		ComponentMonitor, ComponentMetrics} {
		if _, ok := seen[name]; !ok {
			t.Fatalf("the health response omits %s: %+v", name, seen)
		}
	}
	if seen[ComponentMonitor] != StatusOK {
		t.Fatalf("the monitor supervisor is %q", seen[ComponentMonitor])
	}
	if seen[ComponentMetrics] != StatusOK {
		t.Fatalf("the metrics sampler is %q after a reading", seen[ComponentMetrics])
	}
}
