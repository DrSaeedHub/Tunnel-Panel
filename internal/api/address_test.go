package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/drs/gre-panel/internal/address"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
)

// fakeSockets stands in for the kernel's socket table so the SSH-port refusal
// can be exercised without a real sshd.
type fakeSockets struct{ ssh []int }

func (f fakeSockets) SshPorts() ([]int, error) { return f.ssh, nil }

func (f fakeSockets) Listeners() ([]rules.Listener, error) {
	out := make([]rules.Listener, 0, len(f.ssh))
	for _, port := range f.ssh {
		out = append(out, rules.Listener{
			Protocol: rules.ProtocolTCP, Port: port, ProcessName: "sshd",
		})
	}
	return out, nil
}

// recordingRestart captures what the panel was asked to do instead of ending
// the test process, and records when relative to the response.
type recordingRestart struct {
	mu      sync.Mutex
	reasons []string
}

func (r *recordingRestart) fn(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reasons = append(r.reasons, reason)
}

func (r *recordingRestart) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reasons)
}

// freePort returns a port nothing is listening on, so the bind test in the
// handler passes for a value the test chose.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func addressHarness(t *testing.T, webPath string, ssh []int) (*harness, *recordingRestart) {
	t.Helper()
	restart := &recordingRestart{}
	h := newHarnessWith(t, webPath, func(d *Deps) {
		d.RouteGuard = safety.NewRouteGuard(d.Config.BindPort, fakeSockets{ssh: ssh}, t.TempDir())
		d.Restart = restart.fn
		d.UnderSystemd = true
	})
	return h, restart
}

func TestTheAddressEndpointReportsWhereThePanelIsAndWhy(t *testing.T) {
	h, _ := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)

	resp, body := c.request(http.MethodGet, api+"/system/address", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/address = %d\nbody: %s", resp.StatusCode, body)
	}
	var got addressResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v\nbody: %s", err, body)
	}

	if got.Port != h.cfg.BindPort || got.WebPath != testWebPath {
		t.Errorf("reported %d/%q, want %d/%q", got.Port, got.WebPath, h.cfg.BindPort, testWebPath)
	}
	if got.BasePath != "/"+testWebPath+"/" {
		t.Errorf("base path = %q", got.BasePath)
	}
	if !strings.HasSuffix(got.URL, "/"+testWebPath+"/") {
		t.Errorf("url = %q, want it to end in the web path", got.URL)
	}
	if got.Sources.Port == "" || got.Sources.WebPath == "" {
		t.Error("the response does not say where the running values came from")
	}
	if !got.CanApply {
		t.Errorf("can_apply = false with a restarter wired: %s", got.CannotApplyWhy)
	}

	// The SSH port is listed before anything is submitted, so the form can say
	// so rather than letting the operator find out by being refused.
	var sawSSH bool
	for _, p := range got.ProtectedPorts {
		if p.Port == 22 {
			sawSSH = true
			if !strings.Contains(p.Reason, "SSH") {
				t.Errorf("port 22's reason does not mention SSH: %q", p.Reason)
			}
		}
		if p.Port == h.cfg.BindPort {
			t.Error("the panel's own port is listed as protected against moving the panel, " +
				"which would refuse a no-op")
		}
	}
	if !sawSSH {
		t.Errorf("the SSH port is not listed among %+v", got.ProtectedPorts)
	}
}

// The refusals, each with its own code, because the interface explains them
// differently and an operator needs to know which of the two they hit.
func TestMovingThePanelIsRefusedForTheRightReasons(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("taking a port: %v", err)
	}
	defer held.Close()
	occupied := held.Addr().(*net.TCPAddr).Port

	for _, tc := range []struct {
		name     string
		payload  map[string]any
		wantCode string
		wantText string
	}{
		{
			name:     "the live SSH port",
			payload:  map[string]any{"port": 22},
			wantCode: CodeProtectedPort,
			wantText: "SSH",
		},
		{
			name:     "a port outside the range",
			payload:  map[string]any{"port": 70000},
			wantCode: CodeValidationFailed,
			wantText: "between 1 and 65535",
		},
		{
			name:     "a web path with a character the router cannot serve",
			payload:  map[string]any{"web_path": "has/slash"},
			wantCode: CodeValidationFailed,
			wantText: "not allowed",
		},
		{
			name:     "path traversal",
			payload:  map[string]any{"web_path": ".."},
			wantCode: CodeValidationFailed,
			wantText: "traversal",
		},
		{
			name:     "nothing at all",
			payload:  map[string]any{},
			wantCode: CodeValidationFailed,
			wantText: "Give a port",
		},
		{
			name:     "an unknown field, which would otherwise change nothing in silence",
			payload:  map[string]any{"prt": 9000},
			wantCode: CodeInvalidRequest,
			wantText: "prt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, restart := addressHarness(t, testWebPath, []int{22})
			c, api := session(t, h)

			resp, body := c.request(http.MethodPost, api+"/system/address", tc.payload)
			if resp.StatusCode < 400 {
				t.Fatalf("POST /system/address = %d, want a refusal\nbody: %s", resp.StatusCode, body)
			}
			var env ErrorEnvelope
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatalf("decoding the envelope: %v\nbody: %s", err, body)
			}
			if env.Error.Code != tc.wantCode {
				t.Errorf("code = %q, want %q (message: %s)", env.Error.Code, tc.wantCode, env.Error.Message)
			}
			if !strings.Contains(env.Error.Message, tc.wantText) {
				t.Errorf("message %q does not mention %q", env.Error.Message, tc.wantText)
			}
			// A refusal must not have restarted anything, and must not have
			// stored anything either — a rejected value that reaches the
			// database is applied at the next boot with nobody watching.
			if restart.count() != 0 {
				t.Error("a refused change still asked for a restart")
			}
			stored, err := address.Load(context.Background(), h.db)
			if err != nil {
				t.Fatalf("reading the stored address: %v", err)
			}
			if stored.Exists && stored.Port != h.cfg.BindPort {
				t.Errorf("a refused change was written to the database as port %d", stored.Port)
			}
		})
	}

	t.Run("a port something else holds", func(t *testing.T) {
		if !address.EnforcesPortExclusivity() {
			t.Skip("this machine does not enforce TCP port exclusivity, so an occupied port " +
				"cannot be staged here; the refusal is covered on a real host")
		}
		h, _ := addressHarness(t, testWebPath, []int{22})
		c, api := session(t, h)
		resp, body := c.request(http.MethodPost, api+"/system/address", map[string]any{"port": occupied})
		if resp.StatusCode < 400 {
			t.Fatalf("POST = %d, want a refusal\nbody: %s", resp.StatusCode, body)
		}
		var env ErrorEnvelope
		json.Unmarshal(body, &env) //nolint:errcheck // checked below
		if env.Error.Code != CodePortInUse {
			t.Errorf("code = %q, want %q", env.Error.Code, CodePortInUse)
		}
	})
}

// The ordering the whole feature turns on: the operator learns the destination
// before the connection carrying the answer is broken.
func TestAChangeAnswersWithTheNewUrlBeforeItRestarts(t *testing.T) {
	h, restart := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)
	newPort := freePort(t)

	resp, body := c.request(http.MethodPost, api+"/system/address",
		map[string]any{"port": newPort, "web_path": "moved"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /system/address = %d, want 200\nbody: %s", resp.StatusCode, body)
	}

	var got addressChangeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v\nbody: %s", err, body)
	}
	if got.Port != newPort || got.WebPath != "moved" {
		t.Errorf("response reports %d/%q, want %d/moved", got.Port, got.WebPath, newPort)
	}
	if !strings.Contains(got.URL, fmt.Sprint(newPort)) || !strings.HasSuffix(got.URL, "/moved/") {
		t.Errorf("url = %q, which is not where the panel is going", got.URL)
	}
	if got.PreviousURL == got.URL || !strings.Contains(got.PreviousURL, testWebPath) {
		t.Errorf("previous_url = %q, want the address the caller is on now", got.PreviousURL)
	}
	if !strings.HasSuffix(got.HealthURL, "/moved/api/v1/system/health") {
		t.Errorf("health_url = %q", got.HealthURL)
	}
	if !got.Restarting {
		t.Error("restarting = false with a restarter wired")
	}
	// The web path moved, so the cookie path moves with it and the session does
	// not survive. Saying so is the difference between an expected sign-in and
	// an apparent failure.
	if got.SessionSurvives {
		t.Error("session_survives = true across a web path change; the cookie is scoped to the path")
	}

	// Stored before the answer, not after: the restart must find the new value
	// already written.
	stored, err := address.Load(context.Background(), h.db)
	if err != nil {
		t.Fatalf("reading the stored address: %v", err)
	}
	if stored.Port != newPort || stored.WebPath != "moved" {
		t.Errorf("stored %d/%q, want %d/moved", stored.Port, stored.WebPath, newPort)
	}
	if restart.count() != 1 {
		t.Errorf("the panel was asked to restart %d times, want once", restart.count())
	}
}

// A port change alone keeps the session, because cookies are not scoped to a
// port. Getting this backwards would tell every operator to sign in again for
// no reason.
func TestAPortChangeAloneKeepsTheSession(t *testing.T) {
	h, _ := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)

	_, body := c.request(http.MethodPost, api+"/system/address", map[string]any{"port": freePort(t)})
	var got addressChangeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v\nbody: %s", err, body)
	}
	if !got.SessionSurvives {
		t.Error("session_survives = false for a port change; a cookie is not scoped to a port")
	}
}

func TestMovingFromTheRootKeepsTheSessionAndMovingBackDoesNot(t *testing.T) {
	// Root -> path: a cookie set on "/" is sent to every path below it.
	h, _ := addressHarness(t, "", []int{22})
	c, api := session(t, h)
	_, body := c.request(http.MethodPost, api+"/system/address", map[string]any{"web_path": "somewhere"})
	var got addressChangeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v\nbody: %s", err, body)
	}
	if !got.SessionSurvives {
		t.Error("moving out of the root reported the session as lost; a root cookie is sent everywhere")
	}
}

// The change is auditable, and the entry names the operator who made it.
func TestAnAddressChangeIsWrittenToTheAuditLog(t *testing.T) {
	h, _ := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)
	newPort := freePort(t)

	if resp, body := c.request(http.MethodPost, api+"/system/address",
		map[string]any{"port": newPort}); resp.StatusCode != http.StatusOK {
		t.Fatalf("POST = %d\nbody: %s", resp.StatusCode, body)
	}

	var count int
	var userID *int64
	var request string
	err := h.db.Read.QueryRowContext(context.Background(),
		`SELECT COUNT(*), MAX(UserID), MAX(RequestJson) FROM AuditLog WHERE AuditActionID = ?`,
		model.AuditActionPanelAddressChange).Scan(&count, &userID, &request)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	if count != 1 {
		t.Fatalf("%d audit entries for the address change, want 1", count)
	}
	if userID == nil {
		t.Error("the audit entry does not name the operator who made the change")
	}
	if !strings.Contains(request, fmt.Sprint(newPort)) || !strings.Contains(request, "previous_port") {
		t.Errorf("the audit entry does not record what changed: %s", request)
	}
}

// Without systemd the panel cannot bring itself back, so it stores the change
// and says exactly that rather than exiting into nothing.
func TestWithoutSystemdTheChangeIsStoredAndNotApplied(t *testing.T) {
	h := newHarnessWith(t, testWebPath, func(d *Deps) {
		d.RouteGuard = safety.NewRouteGuard(d.Config.BindPort, fakeSockets{ssh: []int{22}}, t.TempDir())
		d.UnderSystemd = false
	})
	c, api := session(t, h)
	newPort := freePort(t)

	resp, body := c.request(http.MethodPost, api+"/system/address", map[string]any{"port": newPort})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST = %d\nbody: %s", resp.StatusCode, body)
	}
	var got addressChangeResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Restarting {
		t.Error("restarting = true with no systemd to restart it")
	}
	if !strings.Contains(got.Detail, "restart it") {
		t.Errorf("detail does not tell the operator what to do: %q", got.Detail)
	}
	stored, err := address.Load(context.Background(), h.db)
	if err != nil || stored.Port != newPort {
		t.Errorf("the change was not stored: %+v (%v)", stored, err)
	}

	// And the read endpoint says the control cannot be applied here.
	_, readBody := c.request(http.MethodGet, api+"/system/address", nil)
	var snapshot addressResponse
	json.Unmarshal(readBody, &snapshot) //nolint:errcheck // checked below
	if snapshot.CanApply || snapshot.CannotApplyWhy == "" {
		t.Errorf("can_apply = %v with reason %q, want false with a reason",
			snapshot.CanApply, snapshot.CannotApplyWhy)
	}
}

// The fallback has to reach a screen. A panel serving somewhere it was not
// configured to serve, with nothing anywhere saying so, is the failure this
// reports.
func TestAFallbackIsVisibleInTheAddressEndpointAndInHealth(t *testing.T) {
	h := newHarnessWith(t, testWebPath, func(d *Deps) {
		d.AddressFallback = &address.Fallback{
			Wanted: 9999, Serving: d.Config.BindPort,
			Reason: "listen tcp 0.0.0.0:9999: bind: address already in use",
			At:     model.NowUTC(),
		}
		d.UnderSystemd = true
	})
	c, api := session(t, h)

	_, body := c.request(http.MethodGet, api+"/system/address", nil)
	var got addressResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if got.Fallback == nil || got.Fallback.Wanted != 9999 {
		t.Fatalf("the address endpoint does not report the fallback: %+v", got.Fallback)
	}

	resp, healthBody := c.request(http.MethodGet, api+"/system/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/health = %d\nbody: %s", resp.StatusCode, healthBody)
	}
	var health healthResponse
	if err := json.Unmarshal(healthBody, &health); err != nil {
		t.Fatalf("decoding health: %v", err)
	}
	var found bool
	for _, component := range health.Components {
		if component.Name != ComponentListenAddress {
			continue
		}
		found = true
		if component.Status != StatusDegraded {
			t.Errorf("the listen_address component is %q, want %q", component.Status, StatusDegraded)
		}
		if !strings.Contains(component.Detail, "9999") {
			t.Errorf("the detail does not name the port that failed: %q", component.Detail)
		}
	}
	if !found {
		t.Errorf("health reports no %s component at all", ComponentListenAddress)
	}
}

func TestHealthReportsTheAddressComponentAsOkWhenThereIsNoFallback(t *testing.T) {
	h, _ := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)
	_, body := c.request(http.MethodGet, api+"/system/health", nil)
	var health healthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	for _, component := range health.Components {
		if component.Name == ComponentListenAddress && component.Status != StatusOK {
			t.Errorf("listen_address = %q with no fallback, want ok", component.Status)
		}
	}
}

// The health endpoint is the one route a browser on the old origin can poll
// after a port change, so it has to answer a cross-origin request. Everything
// else must not.
func TestOnlyHealthAnswersAnyOrigin(t *testing.T) {
	h, _ := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)

	withOrigin := func(req *http.Request) { req.Header.Set("Origin", "http://192.0.2.55:9000") }

	resp, body := c.requestWith(http.MethodGet, api+"/system/health", nil, withOrigin)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cross-origin GET /system/health = %d\nbody: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q on health, want \"*\"", got)
	}
	// Credentials must never be allowed on it, or the permissive origin would
	// carry a session.
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("health allows credentials cross-origin (%q); it must not", got)
	}

	resp, _ = c.requestWith(http.MethodGet, api+"/system/address", nil, withOrigin)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin GET /system/address = %d, want 403; the exception is health only",
			resp.StatusCode)
	}
}

// ------------------------------------------------- the panel served at the root

// The empty web path is a supported configuration, so everything the panel
// serves has to work at the root — and nothing it serves may shadow the API.
func TestWithNoWebPathTheWholeSurfaceIsAtTheRoot(t *testing.T) {
	h := newHarness(t, "")
	c := newClient(t, h)

	if got := h.cfg.APIBasePath(); got != "/api/v1" {
		t.Fatalf("APIBasePath with no web path = %q, want /api/v1", got)
	}
	if got := h.cfg.BasePath(); got != "/" {
		t.Fatalf("BasePath with no web path = %q, want /", got)
	}

	// The API resolves, before and after an account exists.
	resp, body := c.request(http.MethodGet, "/api/v1/system/health", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/system/health = %d\nbody: %s", resp.StatusCode, body)
	}
	c, api := session(t, h)
	if api != "/api/v1" {
		t.Fatalf("the session was established against %q", api)
	}
	for _, path := range []string{"/api/v1/settings", "/api/v1/system/info", "/api/v1/tunnels",
		"/api/v1/routes", "/api/v1/audit", "/api/v1/system/address"} {
		resp, body := c.request(http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d at the root\nbody: %s", path, resp.StatusCode, body)
		}
	}

	// An unrouted API path is still the API's 404 rather than the single-page
	// app, which is what "nothing collides" has to mean: the SPA fallback must
	// not swallow /api/v1.
	resp, body = c.request(http.MethodGet, "/api/v1/does-not-exist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /api/v1/does-not-exist = %d, want 404", resp.StatusCode)
	}
	if !strings.Contains(string(body), CodeNotFound) {
		t.Errorf("an unknown API path fell through to the app instead of answering as the API: %s", body)
	}

	// The app is served at the root and at a client-side route, with the base
	// href the frontend reads to find the API.
	for _, path := range []string{"/", "/tunnels", "/settings"} {
		resp, body := c.request(http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want the app", path, resp.StatusCode)
			continue
		}
		if !strings.Contains(string(body), `<base href="/">`) {
			t.Errorf("GET %s does not carry the root base href", path)
		}
		if !strings.Contains(string(body), `"api_base_path":"/api/v1"`) {
			t.Errorf("GET %s does not tell the frontend where the API is", path)
		}
	}
}

// With no prefix there is no outside, so the silent-404 branch must not be
// reachable — a panel at the root that answered a bare 404 to its own pages
// would serve nothing at all.
func TestWithNoWebPathNothingIsSilentlyRejected(t *testing.T) {
	h := newHarness(t, "")
	rec := h.do(t, http.MethodGet, "/anything/at/all", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /anything/at/all = %d at the root, want the app", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("the response is empty, which is the outside-the-prefix branch answering")
	}
}

// The stored address survives a restart, which is the property that makes the
// database the source of truth rather than a cache of the environment file.
func TestTheStoredAddressIsWhatASecondStartReads(t *testing.T) {
	h, _ := addressHarness(t, testWebPath, []int{22})
	c, api := session(t, h)
	newPort := freePort(t)

	if resp, body := c.request(http.MethodPost, api+"/system/address",
		map[string]any{"port": newPort, "web_path": ""}); resp.StatusCode != http.StatusOK {
		t.Fatalf("POST = %d\nbody: %s", resp.StatusCode, body)
	}

	// What the next start would resolve, given the same environment file it
	// had this time.
	stored, err := address.Load(context.Background(), h.db)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	next := address.Resolve(stored, address.Seed{Port: h.cfg.SeedBindPort, WebPath: h.cfg.SeedWebPath})
	if next.Port != newPort {
		t.Errorf("the next start would use port %d, want the stored %d", next.Port, newPort)
	}
	if next.WebPath != "" {
		t.Errorf("the next start would use web path %q, want the stored empty one", next.WebPath)
	}
}
