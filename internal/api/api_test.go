package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/diag"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/metrics"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/reconcile"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

const (
	testWebPath  = "abc123"
	testUser     = "operator"
	testPassword = "correct horse battery staple"
)

type harness struct {
	server   *Server
	auth     *auth.Service
	settings *settings.Store
	db       *db.DB
	cfg      *config.Config
	links    *link.Fake
	runner   *exec.FakeRunner
	tunnels  *tunnel.Service
	repo     *tunnel.Repo
	monitor  *monitor.Supervisor
	metrics  *metrics.Sampler
	diag     *diag.Service

	routes       *route.Service
	routeRepo    *route.Repo
	routeBackend *rules.Nftables
	accounting   *route.Accounting
	routeRoot    string
	nft          *nftSimulator
}

func newHarness(t *testing.T, webPath string) *harness {
	return newHarnessWith(t, webPath, nil)
}

// newHarnessWith builds the same server and lets a test adjust the dependencies
// before it is constructed. The address tests need it: whether the panel can
// restart itself, and which ports the safety guard protects, are both
// dependencies rather than settings, and there is no other way to exercise the
// refusals without a real sshd and a real systemd.
func newHarnessWith(t *testing.T, webPath string, adjust func(*Deps)) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	cfg := &config.Config{
		DataDir:  dir,
		DBPath:   filepath.Join(dir, "panel.db"),
		BindHost: "127.0.0.1",
		BindPort: 18787,
		WebPath:  webPath,
		// What a real installation looks like on its first start: the
		// environment file said the same thing the panel is serving. Leaving
		// these zero would make every test resolve as though the file had been
		// edited to say nothing.
		SeedBindPort: 18787,
		SeedWebPath:  webPath,
		SystemdDir:   filepath.Join(dir, "units"),
		NetworkdDir:  filepath.Join(dir, "networkd"),
		LogLevel:     "error",
		DevMode:      true,
	}

	database, err := db.Open(ctx, cfg.DBPath)
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}

	store, err := settings.New(ctx, database)
	if err != nil {
		t.Fatalf("creating the settings store failed: %v", err)
	}
	signer, err := auth.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("creating the signer failed: %v", err)
	}
	authService, err := auth.NewService(ctx, database, store, signer)
	if err != nil {
		t.Fatalf("creating the auth service failed: %v", err)
	}

	// Errors only: a passing test should not print request logs.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The system interaction layer, faked end to end: the link manager models a
	// plausible host and the runner records commands without executing them.
	for _, d := range []string{cfg.SystemdDir, cfg.NetworkdDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("creating %s failed: %v", d, err)
		}
	}
	links := link.NewFakeWithHost()
	runner := exec.NewFakeRunner()
	repo := tunnel.NewRepo(database)
	persistStore := persist.NewStore(cfg.SystemdDir, cfg.NetworkdDir, "/bin/systemctl", runner)
	renderer := persist.NewRenderer("/sbin/ip", "/sbin/modprobe", "/bin/ping")

	tunnelService := tunnel.New(tunnel.Deps{
		Repo:         repo,
		Links:        links,
		Runner:       runner,
		Renderer:     renderer,
		Store:        persistStore,
		Alloc:        alloc.New(repo, links, store),
		Validator:    validate.New(links, repo.ForValidation(), store, cfg.APIBasePath()+"/reconcile/adopt"),
		Guard:        safety.New(links, cfg.SystemdDir, cfg.NetworkdDir),
		Settings:     store,
		Log:          log,
		IPBin:        "/sbin/ip",
		SystemctlBin: "/bin/systemctl",
	})
	reconcileService := reconcile.New(tunnelService, repo, links, persistStore, renderer, store)

	// The always-on subsystems, against the same fakes. The loopback dialer
	// stands in for a raw socket, which a test cannot open.
	monitorSupervisor := monitor.New(monitor.Deps{
		Tunnels: repo, Store: monitor.NewStore(database), Settings: store,
		Links: links, Log: log, Dialer: monitor.LoopbackDialer{Latency: time.Millisecond},
	})
	tunnelService.SetObserver(monitorSupervisor)
	metricsSampler := metrics.New(metrics.Deps{
		Reader: &metrics.Reader{Root: "testdata/metrics"}, Links: links,
		Counters: metrics.NewCounters(database), Settings: store, Log: log,
	})
	diagService := diag.New(diag.Deps{
		DB: database, Repo: repo, Links: links, Runner: runner, Settings: store, Log: log,
		Dialer: monitor.LoopbackDialer{Latency: time.Millisecond},
	})
	// The netfilter backend, detected the way startup detects it but against the
	// fake runner, so the capabilities endpoint reports a real decision without
	// this test needing nft or iptables on the machine running it.
	// Detection runs once at startup, so it gets its own runner: the shared one
	// records what requests do, and a version probe recorded there would look
	// like a preview having executed something.
	ruleBackend := rules.Detect(context.Background(), rules.Options{
		NftBin: "/usr/sbin/nft", Dir: filepath.Join(dir, "rules"), Runner: exec.NewFakeRunner(),
	})

	// The port forwarding subsystem, over the fake netfilter backend and a
	// fixture /proc, so the endpoints exercise the whole pipeline without
	// touching the machine running the test.
	routeRoot := filepath.Join(dir, "root")
	if err := os.MkdirAll(filepath.Join(routeRoot, "proc", "sys", "net", "ipv4"), 0o755); err != nil {
		t.Fatalf("preparing the fake /proc failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(routeRoot, "proc", "sys", "net", "ipv4", "ip_forward"),
		[]byte("1\n"), 0o644); err != nil {
		t.Fatalf("preparing the fake /proc failed: %v", err)
	}

	routeRepo := route.NewRepo(database)
	// The real nftables backend over a runner that simulates nft, so an apply
	// through the API renders, writes and reads back exactly as it would on a
	// host — the persistence and read-back checks are the point of these
	// endpoints and a backend that changed nothing would pass them vacuously.
	// It gets its own runner: the shared one records what requests do, and the
	// simulator's canned answers there would be confusing.
	routeRunner := newNftSimulator()
	routeBackend := rules.NewNftables("/usr/sbin/nft", filepath.Join(dir, "rules"), routeRunner)
	routeGuard := safety.NewRouteGuard(cfg.BindPort, nil, filepath.Join(dir, "rules"))
	routeGuard.SysctlFile = filepath.Join(routeRoot, "sysctl.conf")
	routeForwarding := &route.Forwarding{
		Root: routeRoot, SysctlPath: routeGuard.SysctlFile,
		Store: persistStore, Renderer: renderer, Guard: routeGuard,
	}
	routeAccounting := route.NewAccounting(route.AccountingDeps{
		Repo: route.NewCounterRepo(database), Routes: routeRepo, Backend: routeBackend,
		Conntrack: route.NewFakeConntrack(), Settings: store, Log: log,
	})
	routeService := route.New(route.Deps{
		Repo: routeRepo, Backend: routeBackend, Runner: runner,
		Renderer: renderer, Store: persistStore,
		Validator: validate.NewRouteValidator(links, routeRepo.ForValidation(), nil, store),
		Guard:     routeGuard, Forwarding: routeForwarding, Counters: routeAccounting,
		Settings: store, Log: log,
	})
	routeService.SetTunnels(tunnelService)
	tunnelService.SetRouteDependants(routeRepo)
	routeDiag := route.NewDiagnostics(route.DiagnosticsDeps{
		Repo: routeRepo, Backend: routeBackend, Forwarding: routeForwarding,
		Accounting: routeAccounting, Conntrack: route.NewFakeConntrack(),
		Tunnels: tunnelService, Prober: unreachableProber{}, Log: log,
	})
	reconcileService.SetRoutes(routeRepo, routeBackend, routeForwarding)
	// Relay traffic rides the metrics stream the frontend already subscribes
	// to, rather than a second one (§5.4).
	metricsSampler.SetRoutes(routeAccounting)
	// And the accounting re-reads which rules exist after every change, so a
	// deleted rule stops being sampled at once rather than at the next sweep.
	routeService.OnChange(func() {
		if err := routeAccounting.RefreshRules(context.Background()); err != nil {
			log.Error("refreshing the forwarding accounting failed", "error", err)
		}
	})

	deps := Deps{
		Config: cfg, DB: database, Settings: store, Auth: authService,
		Audit: audit.New(database, log), Log: log,
		Build:           BuildInfo{Version: "test", Commit: "abcdef", Date: "2026-01-01"},
		Tunnels:         tunnelService,
		Reconcile:       reconcileService,
		Routes:          routeService,
		RouteAccounting: routeAccounting,
		RouteDiag:       routeDiag,
		Monitor:         monitorSupervisor,
		Metrics:         metricsSampler,
		Diag:            diagService,
		Persist:         persistStore,
		RuleBackend:     ruleBackend,
		AddressSources:  AddressSources{Port: "environment", WebPath: "environment"},
	}
	if adjust != nil {
		adjust(&deps)
	}
	server, err := New(deps)
	if err != nil {
		t.Fatalf("building the server failed: %v", err)
	}
	server.RegisterCoreComponents()
	server.RegisterMonitorComponent(monitorSupervisor)
	server.RegisterMetricsComponent(metricsSampler)

	return &harness{
		server: server, auth: authService, settings: store, db: database, cfg: cfg,
		links: links, runner: runner, tunnels: tunnelService, repo: repo,
		monitor: monitorSupervisor, metrics: metricsSampler, diag: diagService,
		routes: routeService, routeRepo: routeRepo, routeBackend: routeBackend,
		accounting: routeAccounting, routeRoot: routeRoot, nft: routeRunner,
	}
}

// unreachableProber stands in for the network in tests: the destinations the
// fixtures use do not exist, and a probe that hung waiting for them would make
// every forwarding test slow.
type unreachableProber struct{}

func (unreachableProber) Probe(ctx context.Context, params route.ReachabilityParams) route.ReachabilityResult {
	return route.ReachabilityResult{
		Address: params.Address, Port: params.Port, Protocol: params.Protocol,
		Conclusive: true,
		Detail:     "the destination was not probed: this instance has no network",
	}
}

// do runs a request against the router without a network round trip.
func (h *harness) do(t *testing.T, method, path string, body any, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encoding the request body failed: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, fn := range mutate {
		fn(req)
	}
	rec := httptest.NewRecorder()
	h.server.Handler().ServeHTTP(rec, req)
	return rec
}

func (h *harness) api(path string) string { return h.cfg.APIBasePath() + path }

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decoding the error envelope failed: %v\nbody: %s", err, rec.Body.String())
	}
	return env
}

// ------------------------------------------------------------- the web path

// TestRequestsOutsideThePrefixAreSilentlyRejected covers §5.2: outside the
// prefix the panel answers 404 with nothing that identifies the software.
func TestRequestsOutsideThePrefixAreSilentlyRejected(t *testing.T) {
	h := newHarness(t, testWebPath)

	outside := []string{
		"/api/v1/system/health",
		"/api/v1/settings",
		"/",
		"/index.html",
		"/wrongprefix/api/v1/system/health",
		"/abc123x/api/v1/system/health",
		"/ABC123/api/v1/system/health", // the prefix is case sensitive
	}
	for _, path := range outside {
		rec := h.do(t, http.MethodGet, path, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
		if body := rec.Body.String(); body != "" {
			t.Errorf("GET %s returned a body %q, want it empty so nothing identifies the software", path, body)
		}
		for _, header := range []string{"Server", "X-Powered-By"} {
			if v := rec.Header().Get(header); v != "" {
				t.Errorf("GET %s set %s: %q, want it absent", path, header, v)
			}
		}
	}

	// And inside the prefix the very same API path answers.
	rec := h.do(t, http.MethodGet, h.api("/system/health"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200\nbody: %s", h.api("/system/health"), rec.Code, rec.Body.String())
	}
}

func TestBarePrefixRedirectsToItsSlashForm(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodGet, "/"+testWebPath, nil)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /%s = %d, want 301", testWebPath, rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "/"+testWebPath+"/"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestWithoutAWebPathTheApiIsAtTheRoot(t *testing.T) {
	h := newHarness(t, "")
	rec := h.do(t, http.MethodGet, "/api/v1/system/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/system/health = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}
}

// ------------------------------------------------------------- setup gating

// TestSetupRequiredGate covers §18: until an operator account exists, every
// endpoint except setup and health answers 503 SETUP_REQUIRED.
func TestSetupRequiredGate(t *testing.T) {
	h := newHarness(t, testWebPath)

	gated := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/settings"},
		{http.MethodGet, "/settings/schema"},
		{http.MethodGet, "/system/info"},
		{http.MethodGet, "/system/capabilities"},
		{http.MethodGet, "/auth/me"},
		{http.MethodPost, "/auth/login"},
		{http.MethodPost, "/auth/logout"},
		{http.MethodPost, "/auth/refresh"},
	}
	for _, tc := range gated {
		rec := h.do(t, tc.method, h.api(tc.path), nil)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s = %d before setup, want 503", tc.method, tc.path, rec.Code)
			continue
		}
		env := decodeError(t, rec)
		if env.Error.Code != CodeSetupRequired {
			t.Errorf("%s %s error code = %q, want %q", tc.method, tc.path, env.Error.Code, CodeSetupRequired)
		}
	}

	// Health stays reachable, and says so.
	rec := h.do(t, http.MethodGet, h.api("/system/health"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /system/health before setup = %d, want 200", rec.Code)
	}
	var health healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decoding the health response failed: %v", err)
	}
	if !health.SetupRequired {
		t.Error("health reports setup_required = false before any account exists")
	}

	// The single-page app is served, or the operator could never reach setup.
	rec = h.do(t, http.MethodGet, "/"+testWebPath+"/", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("GET the app root before setup = %d, want 200", rec.Code)
	}
}

func TestSetupRefusesOnceAnAccountExists(t *testing.T) {
	h := newHarness(t, testWebPath)

	rec := h.do(t, http.MethodPost, h.api("/auth/setup"),
		map[string]string{"username": testUser, "password": testPassword})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201\nbody: %s", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodPost, h.api("/auth/setup"),
		map[string]string{"username": "second", "password": testPassword})
	if rec.Code != http.StatusConflict {
		t.Fatalf("a second POST /auth/setup = %d, want 409", rec.Code)
	}
	if env := decodeError(t, rec); env.Error.Code != CodeSetupComplete {
		t.Errorf("error code = %q, want %q", env.Error.Code, CodeSetupComplete)
	}
}

func TestSetupEnforcesTheMinimumPasswordLength(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodPost, h.api("/auth/setup"),
		map[string]string{"username": testUser, "password": "short1"})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("POST /auth/setup with a short password = %d, want 422\nbody: %s", rec.Code, rec.Body.String())
	}
	env := decodeError(t, rec)
	if env.Error.Field != "password" {
		t.Errorf("error field = %q, want password", env.Error.Field)
	}
	if !strings.Contains(env.Error.Message, "8") {
		t.Errorf("error message = %q, want it to state the 8-character floor", env.Error.Message)
	}
}

// ------------------------------------------------------ the error envelope

// TestErrorEnvelopeShape checks the exact shape of §15. Every field is present
// on every error, so the frontend never has to test for absence.
func TestErrorEnvelopeShape(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodGet, h.api("/settings"), nil)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding the response failed: %v", err)
	}
	if len(raw) != 1 {
		t.Fatalf("the response has %d top-level keys, want exactly one named error", len(raw))
	}
	inner, present := raw["error"]
	if !present {
		t.Fatal(`the response has no "error" key`)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(inner, &fields); err != nil {
		t.Fatalf("decoding the error object failed: %v", err)
	}
	for _, want := range []string{"code", "message", "field", "details"} {
		if _, present := fields[want]; !present {
			t.Errorf("the error object has no %q field", want)
		}
	}
	if len(fields) != 4 {
		t.Errorf("the error object has %d fields, want exactly code, message, field and details", len(fields))
	}
	if got := string(fields["details"]); !strings.HasPrefix(got, "{") {
		t.Errorf("details = %s, want an object", got)
	}
	if rec.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", rec.Header().Get("Content-Type"))
	}

	// An error carrying no extra detail still emits an empty object, never
	// null, so the frontend never has to guard against it.
	rec = h.do(t, http.MethodGet, h.api("/no/such/endpoint"), nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding the response failed: %v", err)
	}
	if err := json.Unmarshal(raw["error"], &fields); err != nil {
		t.Fatalf("decoding the error object failed: %v", err)
	}
	if got := string(fields["details"]); got != "{}" {
		t.Errorf("details = %s, want an empty object rather than null", got)
	}
	if got := string(fields["field"]); got != `""` {
		t.Errorf("field = %s, want an empty string rather than null", got)
	}
}

func TestUnknownApiEndpointReturnsTheEnvelope(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodGet, h.api("/no/such/endpoint"), nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET an unknown API path = %d, want 404", rec.Code)
	}
	if env := decodeError(t, rec); env.Error.Code != CodeNotFound {
		t.Errorf("error code = %q, want %q", env.Error.Code, CodeNotFound)
	}
}

// ----------------------------------------------------------- security posture

func TestSecurityHeadersAreSet(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodGet, h.api("/system/health"), nil)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q, want it to forbid framing", csp)
	}
	// HSTS over plain HTTP would be ignored at best and lock an operator out at
	// worst, so it must not be sent here.
	if hsts := rec.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("Strict-Transport-Security = %q over plain HTTP, want it absent", hsts)
	}
}

// The frontend learns its web path from an inline script injected into
// index.html. A strict script-src blocks inline code unless the policy names
// its hash, and when that happens the page still renders and every asset still
// loads -- only the API base is wrong, so every request lands outside the web
// path prefix and 404s. curl never sees it because curl does not enforce CSP.
// This asserts the policy actually admits the script the page carries.
func TestContentSecurityPolicyAdmitsTheInjectedBootstrapScript(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodGet, "/"+testWebPath+"/", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET the panel root = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	const open = "<script>"
	start := strings.Index(body, open)
	if start < 0 {
		t.Fatal("index.html carries no inline script; the bootstrap injection changed")
	}
	start += len(open)
	end := strings.Index(body[start:], "</script>")
	if end < 0 {
		t.Fatal("the inline script in index.html is unterminated")
	}
	script := body[start : start+end]
	if !strings.Contains(script, "__GRE_PANEL__") {
		t.Fatalf("the first inline script is not the bootstrap: %q", script)
	}

	sum := sha256.Sum256([]byte(script))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, want) {
		t.Errorf("script-src does not admit the injected bootstrap script.\n"+
			"want the hash %s in\n  %s\nThe browser would block the script and the "+
			"frontend would call the API outside the web path.", want, csp)
	}
	if strings.Contains(csp, "'unsafe-inline'") && strings.Contains(csp, "script-src") {
		idx := strings.Index(csp, "script-src")
		endIdx := strings.Index(csp[idx:], ";")
		if endIdx < 0 {
			endIdx = len(csp) - idx
		}
		if strings.Contains(csp[idx:idx+endIdx], "'unsafe-inline'") {
			t.Error("script-src allows 'unsafe-inline'; name the script's hash instead")
		}
	}
}

func TestSessionCookiesAreHardened(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodPost, h.api("/auth/setup"),
		map[string]string{"username": testUser, "password": testPassword})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201\nbody: %s", rec.Code, rec.Body.String())
	}

	byName := map[string]*http.Cookie{}
	for _, c := range rec.Result().Cookies() {
		byName[c.Name] = c
	}
	for _, name := range []string{auth.CookieAccess, auth.CookieRefresh, auth.CookieCSRF} {
		c, present := byName[name]
		if !present {
			t.Fatalf("cookie %s was not set", name)
		}
		if c.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie %s SameSite = %v, want Strict", name, c.SameSite)
		}
		if want := "/" + testWebPath + "/"; c.Path != want {
			t.Errorf("cookie %s Path = %q, want %q so it is scoped to the panel", name, c.Path, want)
		}
		if c.Value == "" {
			t.Errorf("cookie %s has an empty value", name)
		}
	}
	// The token cookies must be unreadable from JavaScript; the CSRF cookie has
	// to be readable, because the frontend echoes it back in a header.
	if !byName[auth.CookieAccess].HttpOnly {
		t.Error("the access cookie is not httpOnly")
	}
	if !byName[auth.CookieRefresh].HttpOnly {
		t.Error("the refresh cookie is not httpOnly")
	}
	if byName[auth.CookieCSRF].HttpOnly {
		t.Error("the CSRF cookie is httpOnly, so the frontend cannot echo it back")
	}

	// The session body discloses the expiry but never the tokens themselves.
	body := rec.Body.String()
	for _, name := range []string{auth.CookieAccess, auth.CookieRefresh} {
		if strings.Contains(body, byName[name].Value) {
			t.Errorf("the %s token value appears in the response body", name)
		}
	}
}

func TestUnauthenticatedRequestsAreRejectedAfterSetup(t *testing.T) {
	h := newHarness(t, testWebPath)
	if rec := h.do(t, http.MethodPost, h.api("/auth/setup"),
		map[string]string{"username": testUser, "password": testPassword}); rec.Code != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201", rec.Code)
	}

	for _, path := range []string{"/settings", "/settings/schema", "/system/info", "/auth/me"} {
		rec := h.do(t, http.MethodGet, h.api(path), nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a session = %d, want 401", path, rec.Code)
			continue
		}
		if env := decodeError(t, rec); env.Error.Code != CodeUnauthenticated {
			t.Errorf("GET %s error code = %q, want %q", path, env.Error.Code, CodeUnauthenticated)
		}
	}
}

// ------------------------------------------------------------- the full flow

// client drives the router over a real listener with a cookie jar, so the
// cookie and CSRF handling is exercised the way a browser would.
type client struct {
	t    *testing.T
	base string
	http *http.Client
	csrf string
}

func newClient(t *testing.T, h *harness) *client {
	t.Helper()
	srv := httptest.NewServer(h.server.Handler())
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating the cookie jar failed: %v", err)
	}
	return &client{t: t, base: srv.URL, http: &http.Client{Jar: jar}}
}

func (c *client) request(method, path string, body any) (*http.Response, []byte) {
	return c.requestWith(method, path, body)
}

// requestWith is request with a chance to adjust the request first, which the
// CORS tests need: the header under test is one the client sends.
func (c *client) requestWith(method, path string, body any, mutate ...func(*http.Request)) (*http.Response, []byte) {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("encoding the request body failed: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		c.t.Fatalf("building the request failed: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set(auth.CSRFHeader, c.csrf)
	}
	for _, fn := range mutate {
		fn(req)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s failed: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("reading the response body failed: %v", err)
	}
	// Track the CSRF token the way the frontend does: read it from the cookie.
	for _, cookie := range resp.Cookies() {
		if cookie.Name == auth.CookieCSRF && cookie.Value != "" && cookie.MaxAge >= 0 {
			c.csrf = cookie.Value
		}
	}
	return resp, raw
}

// TestFullSessionFlow walks setup, an authenticated read, a settings change, a
// refresh, and a sign-out, which is the path the frontend actually takes.
func TestFullSessionFlow(t *testing.T) {
	h := newHarness(t, testWebPath)
	c := newClient(t, h)
	api := h.cfg.APIBasePath()

	resp, body := c.request(http.MethodPost, api+"/auth/setup",
		map[string]string{"username": testUser, "password": testPassword})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201\nbody: %s", resp.StatusCode, body)
	}
	var session sessionResponse
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatalf("decoding the session failed: %v", err)
	}
	if session.User.Username != testUser {
		t.Errorf("session user = %q, want %q", session.User.Username, testUser)
	}
	if session.CsrfToken == "" {
		t.Error("the session carries no CSRF token")
	}

	resp, body = c.request(http.MethodGet, api+"/auth/me", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me = %d, want 200\nbody: %s", resp.StatusCode, body)
	}

	// Reads work with the session cookie.
	resp, body = c.request(http.MethodGet, api+"/settings", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
	var got settingsResponse
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decoding the settings failed: %v", err)
	}
	if len(got.Settings) != len(settings.Keys()) {
		t.Errorf("GET /settings returned %d settings, want %d", len(got.Settings), len(settings.Keys()))
	}

	// The schema carries the metadata the settings screen renders from.
	resp, body = c.request(http.MethodGet, api+"/settings/schema", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /settings/schema = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
	var schema schemaResponse
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatalf("decoding the schema failed: %v", err)
	}
	if len(schema.Settings) != len(settings.Keys()) {
		t.Errorf("the schema has %d entries, want %d", len(schema.Settings), len(settings.Keys()))
	}
	// One category per group the settings screen renders: tunnel, addressing,
	// keepalive, monitor, diagnostics, metrics, routes, display, security and
	// system.
	if len(schema.Categories) != 10 {
		t.Errorf("the schema reports %d categories, want 10: %v", len(schema.Categories), schema.Categories)
	}
	for _, entry := range schema.Settings {
		if entry.Description == "" || entry.Category == "" || entry.Type == "" {
			t.Errorf("schema entry %q is missing metadata: %+v", entry.Key, entry)
		}
		// The settings screen builds every control from this response alone, so
		// a select box with no values in it is a control the operator cannot
		// use. Assert it on the served JSON rather than on the declarations:
		// the store serves the schema by its own path, and checking only the
		// declarations is what let an empty select reach the panel.
		if entry.Type == settings.KindLookup || entry.Type == settings.KindEnum {
			choices := len(entry.Constraints.Options) + len(entry.Constraints.EnumValues)
			if choices == 0 {
				t.Errorf("schema entry %q is a %s but offers nothing to choose from",
					entry.Key, entry.Type)
			}
		}
	}

	// A mutation with a valid CSRF token succeeds.
	resp, body = c.request(http.MethodPut, api+"/settings", map[string]any{"display.theme": "dark"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /settings = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
	if h.settings.String("display.theme") != "dark" {
		t.Errorf("display.theme = %q after the update, want dark", h.settings.String("display.theme"))
	}

	// An invalid value returns 422 with one message per key.
	resp, body = c.request(http.MethodPut, api+"/settings", map[string]any{
		"display.theme":            "neon",
		"monitor.interval_seconds": 0.01,
	})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("PUT /settings with invalid values = %d, want 422\nbody: %s", resp.StatusCode, body)
	}
	env := ErrorEnvelope{}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decoding the error envelope failed: %v", err)
	}
	if env.Error.Code != CodeValidationFailed {
		t.Errorf("error code = %q, want %q", env.Error.Code, CodeValidationFailed)
	}
	for _, key := range []string{"display.theme", "monitor.interval_seconds"} {
		if _, present := env.Error.Details[key]; !present {
			t.Errorf("details has no entry for %q: %v", key, env.Error.Details)
		}
	}
	if h.settings.String("display.theme") != "dark" {
		t.Error("a rejected update changed a setting anyway")
	}

	// Reset restores the default.
	resp, body = c.request(http.MethodPost, api+"/settings/reset", map[string]any{"keys": []string{"display.theme"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /settings/reset = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
	if h.settings.String("display.theme") != "system" {
		t.Errorf("display.theme = %q after reset, want system", h.settings.String("display.theme"))
	}

	// Refresh issues a new session from the refresh cookie.
	resp, body = c.request(http.MethodPost, api+"/auth/refresh", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/refresh = %d, want 200\nbody: %s", resp.StatusCode, body)
	}

	// System endpoints answer for an authenticated operator.
	for _, path := range []string{"/system/info", "/system/capabilities"} {
		resp, body = c.request(http.MethodGet, api+path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200\nbody: %s", path, resp.StatusCode, body)
		}
	}

	// Signing out clears the cookies, and the session stops working.
	resp, body = c.request(http.MethodPost, api+"/auth/logout", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/logout = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
	resp, _ = c.request(http.MethodGet, api+"/auth/me", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("GET /auth/me after signing out = %d, want 401", resp.StatusCode)
	}

	// And signing back in works.
	resp, body = c.request(http.MethodPost, api+"/auth/login",
		map[string]string{"username": testUser, "password": testPassword})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/login = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
	resp, _ = c.request(http.MethodGet, api+"/auth/me", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /auth/me after signing in = %d, want 200", resp.StatusCode)
	}
}

func TestLoginRejectsBadCredentialsIdentically(t *testing.T) {
	h := newHarness(t, testWebPath)
	c := newClient(t, h)
	api := h.cfg.APIBasePath()

	if resp, body := c.request(http.MethodPost, api+"/auth/setup",
		map[string]string{"username": testUser, "password": testPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201\nbody: %s", resp.StatusCode, body)
	}

	respUnknown, bodyUnknown := c.request(http.MethodPost, api+"/auth/login",
		map[string]string{"username": "nobody", "password": testPassword})
	respWrong, bodyWrong := c.request(http.MethodPost, api+"/auth/login",
		map[string]string{"username": testUser, "password": "definitely not it"})

	if respUnknown.StatusCode != http.StatusUnauthorized || respWrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("statuses = %d and %d, want both 401", respUnknown.StatusCode, respWrong.StatusCode)
	}
	if string(bodyUnknown) != string(bodyWrong) {
		t.Errorf("an unknown user and a wrong password give different answers:\n%s\n%s", bodyUnknown, bodyWrong)
	}
}

// TestCsrfIsRequiredOnMutations covers §18. Reads are unaffected; a mutation
// without the double-submit token is refused even with a valid session.
func TestCsrfIsRequiredOnMutations(t *testing.T) {
	h := newHarness(t, testWebPath)
	c := newClient(t, h)
	api := h.cfg.APIBasePath()

	if resp, body := c.request(http.MethodPost, api+"/auth/setup",
		map[string]string{"username": testUser, "password": testPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201\nbody: %s", resp.StatusCode, body)
	}

	// Drop the header the frontend would send, keeping the session cookies.
	valid := c.csrf
	c.csrf = ""
	resp, body := c.request(http.MethodPut, api+"/settings", map[string]any{"display.theme": "dark"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PUT /settings without a CSRF header = %d, want 403\nbody: %s", resp.StatusCode, body)
	}
	env := ErrorEnvelope{}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decoding the error envelope failed: %v", err)
	}
	if env.Error.Code != CodeCSRFRequired {
		t.Errorf("error code = %q, want %q", env.Error.Code, CodeCSRFRequired)
	}

	// A wrong token is refused too.
	c.csrf = "not-the-token"
	resp, _ = c.request(http.MethodPut, api+"/settings", map[string]any{"display.theme": "dark"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("PUT /settings with a wrong CSRF token = %d, want 403", resp.StatusCode)
	}

	// Reads never need it.
	c.csrf = ""
	resp, _ = c.request(http.MethodGet, api+"/settings", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /settings without a CSRF header = %d, want 200", resp.StatusCode)
	}

	c.csrf = valid
	resp, body = c.request(http.MethodPut, api+"/settings", map[string]any{"display.theme": "dark"})
	if resp.StatusCode != http.StatusOK {
		t.Errorf("PUT /settings with the right CSRF token = %d, want 200\nbody: %s", resp.StatusCode, body)
	}
}

// TestPasswordChangeEndsOtherSessions is the TokenVersion guarantee seen from
// the HTTP layer: the caller keeps working through its reissued cookies, while
// a session captured beforehand stops.
func TestPasswordChangeEndsOtherSessions(t *testing.T) {
	h := newHarness(t, testWebPath)
	changer := newClient(t, h)
	api := h.cfg.APIBasePath()

	if resp, body := changer.request(http.MethodPost, api+"/auth/setup",
		map[string]string{"username": testUser, "password": testPassword}); resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /auth/setup = %d, want 201\nbody: %s", resp.StatusCode, body)
	}

	// A second client with its own session, standing in for another browser.
	other := newClientSharingServer(t, changer.base)
	if resp, body := other.request(http.MethodPost, api+"/auth/login",
		map[string]string{"username": testUser, "password": testPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("the second client could not sign in: %d\nbody: %s", resp.StatusCode, body)
	}
	if resp, _ := other.request(http.MethodGet, api+"/auth/me", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("the second client's session does not work")
	}

	const newPassword = "an entirely different passphrase"
	resp, body := changer.request(http.MethodPut, api+"/auth/me", map[string]any{
		"current_password": testPassword,
		"new_password":     newPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /auth/me = %d, want 200\nbody: %s", resp.StatusCode, body)
	}

	// The other session is gone.
	resp, _ = other.request(http.MethodGet, api+"/auth/me", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the other session = %d after the password change, want 401", resp.StatusCode)
	}
	// The caller's own session was reissued in the same response.
	resp, _ = changer.request(http.MethodGet, api+"/auth/me", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the caller's own session = %d after changing their password, want 200", resp.StatusCode)
	}

	// A wrong current password is refused.
	resp, _ = changer.request(http.MethodPut, api+"/auth/me", map[string]any{
		"current_password": "wrong",
		"new_password":     "yet another passphrase here",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("PUT /auth/me with a wrong current password = %d, want 401", resp.StatusCode)
	}
}

func newClientSharingServer(t *testing.T, base string) *client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("creating the cookie jar failed: %v", err)
	}
	return &client{t: t, base: base, http: &http.Client{Jar: jar}}
}

// -------------------------------------------------------------- static assets

// TestSinglePageAppFallback covers §20: client-side routes fall back to
// index.html, with the web path injected so assets and the router resolve.
func TestSinglePageAppFallback(t *testing.T) {
	h := newHarness(t, testWebPath)

	for _, path := range []string{"/", "/tunnels", "/tunnels/7/diagnostics", "/index.html"} {
		full := "/" + testWebPath + path
		rec := h.do(t, http.MethodGet, full, nil)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", full, rec.Code)
			continue
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s Content-Type = %q, want text/html", full, ct)
		}
		body := rec.Body.String()
		if want := `<base href="/` + testWebPath + `/">`; !strings.Contains(body, want) {
			t.Errorf("GET %s did not inject %s\nbody: %s", full, want, body)
		}
		if !strings.Contains(body, `"api_base_path":"/`+testWebPath+`/api/v1"`) {
			t.Errorf("GET %s did not inject the API base path\nbody: %s", full, body)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store so a redeploy is picked up", full, got)
		}
	}
}

func TestSinglePageAppAtTheRootWithoutAWebPath(t *testing.T) {
	h := newHarness(t, "")
	rec := h.do(t, http.MethodGet, "/tunnels", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tunnels = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `<base href="/">`) {
		t.Errorf("the base tag was not injected for a root-mounted panel\nbody: %s", rec.Body.String())
	}
}

func TestInjectBasePathAddsTheTagAfterHead(t *testing.T) {
	rendered, hash := injectBasePath([]byte("<html><head><title>x</title></head><body></body></html>"),
		"/p/", "/p/api/v1")
	out := string(rendered)
	if !strings.HasPrefix(hash, "'sha256-") || !strings.HasSuffix(hash, "'") {
		t.Errorf("script hash = %q, want a quoted sha256- source expression", hash)
	}
	headAt := strings.Index(out, "<head>")
	baseAt := strings.Index(out, "<base ")
	titleAt := strings.Index(out, "<title>")
	if headAt < 0 || baseAt < 0 || titleAt < 0 {
		t.Fatalf("injected output is missing an expected tag: %s", out)
	}
	if !(headAt < baseAt && baseAt < titleAt) {
		t.Errorf("the base tag is not immediately inside head: %s", out)
	}
}

// -------------------------------------------------------------------- health

func TestHealthReportsEveryComponent(t *testing.T) {
	h := newHarness(t, testWebPath)
	rec := h.do(t, http.MethodGet, h.api("/system/health"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /system/health = %d, want 200\nbody: %s", rec.Code, rec.Body.String())
	}

	var health healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decoding the health response failed: %v", err)
	}

	byName := map[string]ComponentHealth{}
	for _, c := range health.Components {
		byName[c.Name] = c
	}
	for _, name := range []string{ComponentDatabase, ComponentMonitor, ComponentNetlink, ComponentKernelModule} {
		if _, present := byName[name]; !present {
			t.Errorf("health does not report the %s component", name)
		}
	}
	if byName[ComponentDatabase].Status != StatusOK {
		t.Errorf("database status = %q, want ok: %s",
			byName[ComponentDatabase].Status, byName[ComponentDatabase].Detail)
	}
	// The GRE module autoloads on first use, so a server with no tunnels yet is
	// healthy whether or not it is loaded.
	if byName[ComponentKernelModule].Status != StatusOK {
		t.Errorf("kernel module status = %q, want ok even when the module is not loaded",
			byName[ComponentKernelModule].Status)
	}
	if health.Version != "test" {
		t.Errorf("health version = %q, want the stamped build version", health.Version)
	}
}

func TestHealthReportsADeadDatabase(t *testing.T) {
	h := newHarness(t, testWebPath)
	if err := h.db.Close(); err != nil {
		t.Fatalf("closing the database failed: %v", err)
	}

	rec := h.do(t, http.MethodGet, h.api("/system/health"), nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /system/health with a dead database = %d, want 503", rec.Code)
	}
	var health healthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decoding the health response failed: %v", err)
	}
	if health.Status != StatusError {
		t.Errorf("overall status = %q, want error", health.Status)
	}
}

func TestWorseStatus(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{StatusOK, StatusOK, StatusOK},
		{StatusOK, StatusUnknown, StatusUnknown},
		{StatusUnknown, StatusDegraded, StatusDegraded},
		{StatusDegraded, StatusError, StatusError},
		{StatusError, StatusOK, StatusError},
	}
	for _, tc := range cases {
		if got := worseStatus(tc.a, tc.b); got != tc.want {
			t.Errorf("worseStatus(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------- CORS

// The probe endpoint here is deliberately not /system/health any more.
//
// Health is now the one route that answers any origin, so that a page on the
// old origin can tell when the panel has come back after a port change. Using
// it to test the allow-list would test the exception instead of the rule.
// TestOnlyHealthAnswersAnyOrigin covers the exception, including that it never
// carries credentials.
func TestCorsIsSameOriginByDefault(t *testing.T) {
	h := newHarness(t, testWebPath)

	rec := h.do(t, http.MethodGet, h.api("/system/info"), nil, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a cross-origin request with no configured origins = %d, want 403", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("Access-Control-Allow-Origin was sent for a disallowed origin")
	}

	// Configuring the origin lets it through, live, with no restart. The
	// request then meets the setup gate rather than a handler, which is beside
	// the point: what is under test is that CORS stopped refusing it.
	if _, err := h.settings.Update(context.Background(), map[string]any{
		"security.allowed_origins": []any{"https://panel.example.org"},
	}, nil); err != nil {
		t.Fatalf("configuring the allowed origin failed: %v", err)
	}
	rec = h.do(t, http.MethodGet, h.api("/system/info"), nil, func(r *http.Request) {
		r.Header.Set("Origin", "https://panel.example.org")
	})
	if rec.Code == http.StatusForbidden {
		t.Fatalf("the configured origin was still refused: %s", rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://panel.example.org" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the configured origin", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want true", got)
	}
}
