package address

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
)

func TestResolveAppliesThePrecedenceRules(t *testing.T) {
	for _, tc := range []struct {
		name        string
		stored      Stored
		seed        Seed
		wantPort    int
		wantSource  Source
		wantPath    string
		wantPathSrc Source
	}{
		{
			name:        "a first start has nothing stored, so the environment seeds it",
			stored:      Stored{},
			seed:        Seed{Port: 8443, WebPath: "abc123", PortProvided: true, WebPathProvided: true},
			wantPort:    8443,
			wantSource:  SourceEnvironment,
			wantPath:    "abc123",
			wantPathSrc: SourceEnvironment,
		},
		{
			// The case the whole design turns on. The panel was told to move to
			// 9000 and the environment file still says 8443, because the panel
			// cannot write /etc. Comparing the file against the effective value
			// would revert the change at every restart; comparing it against
			// the seed recorded last time correctly reads it as "unchanged".
			name:        "a change made through the panel survives an unchanged environment file",
			stored:      Stored{Exists: true, Port: 9000, WebPath: "moved", SeedPort: 8443, SeedWebPath: "abc123"},
			seed:        Seed{Port: 8443, WebPath: "abc123", PortProvided: true, WebPathProvided: true},
			wantPort:    9000,
			wantSource:  SourceDatabase,
			wantPath:    "moved",
			wantPathSrc: SourceDatabase,
		},
		{
			name:        "an edited environment file overrides the database",
			stored:      Stored{Exists: true, Port: 9000, WebPath: "moved", SeedPort: 8443, SeedWebPath: "abc123"},
			seed:        Seed{Port: 7000, WebPath: "rescue", PortProvided: true, WebPathProvided: true},
			wantPort:    7000,
			wantSource:  SourceEnvironment,
			wantPath:    "rescue",
			wantPathSrc: SourceEnvironment,
		},
		{
			name:        "a flag outranks both",
			stored:      Stored{Exists: true, Port: 9000, WebPath: "moved", SeedPort: 8443, SeedWebPath: "abc123"},
			seed:        Seed{Port: 6000, WebPath: "flagged", PortFromFlag: true, WebPathFromFlag: true},
			wantPort:    6000,
			wantSource:  SourceFlag,
			wantPath:    "flagged",
			wantPathSrc: SourceFlag,
		},
		{
			// One half changing must not drag the other half with it.
			name:        "the port and the web path are decided independently",
			stored:      Stored{Exists: true, Port: 9000, WebPath: "moved", SeedPort: 8443, SeedWebPath: "abc123"},
			seed:        Seed{Port: 7000, WebPath: "abc123", PortProvided: true, WebPathProvided: true},
			wantPort:    7000,
			wantSource:  SourceEnvironment,
			wantPath:    "moved",
			wantPathSrc: SourceDatabase,
		},
		{
			name:        "an empty web path is a value, not an absence",
			stored:      Stored{Exists: true, Port: 8443, WebPath: "", SeedPort: 8443, SeedWebPath: "abc123"},
			seed:        Seed{Port: 8443, WebPath: "abc123", PortProvided: true, WebPathProvided: true},
			wantPort:    8443,
			wantSource:  SourceDatabase,
			wantPath:    "",
			wantPathSrc: SourceDatabase,
		},
		{
			// Emptying the web path through the environment file is a change
			// like any other, and must not be read as "nothing was said".
			name:        "emptying the web path in the environment file is an override",
			stored:      Stored{Exists: true, Port: 8443, WebPath: "moved", SeedPort: 8443, SeedWebPath: "abc123"},
			seed:        Seed{Port: 8443, WebPath: "", PortProvided: true, WebPathProvided: true},
			wantPort:    8443,
			wantSource:  SourceDatabase,
			wantPath:    "",
			wantPathSrc: SourceEnvironment,
		},
		{
			name:        "a stored port outside the range falls back to the default",
			stored:      Stored{Exists: true, Port: 0, SeedPort: 0},
			seed:        Seed{Port: 0, PortProvided: true, WebPathProvided: true},
			wantPort:    DefaultPort,
			wantSource:  SourceDefault,
			wantPath:    "",
			wantPathSrc: SourceDatabase,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Resolve(tc.stored, tc.seed)
			if got.Port != tc.wantPort || got.PortSource != tc.wantSource {
				t.Errorf("port = %d from %s, want %d from %s",
					got.Port, got.PortSource, tc.wantPort, tc.wantSource)
			}
			if got.WebPath != tc.wantPath || got.WebPathSource != tc.wantPathSrc {
				t.Errorf("web path = %q from %s, want %q from %s",
					got.WebPath, got.WebPathSource, tc.wantPath, tc.wantPathSrc)
			}
		})
	}
}

func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database: %v", err)
	}
	return database
}

// The row has to survive the round trip, including the empty web path, which is
// the value most likely to be lost by a NOT NULL column or a COALESCE.
func TestTheStoredAddressRoundTrips(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)

	before, err := Load(ctx, database)
	if err != nil {
		t.Fatalf("loading from an empty database: %v", err)
	}
	if before.Exists {
		t.Fatal("a database with no row reported one")
	}

	if err := Save(ctx, database, Effective{Port: 8443, WebPath: "abc123"}, Seed{Port: 8443, WebPath: "abc123"}); err != nil {
		t.Fatalf("saving: %v", err)
	}
	if err := Set(ctx, database, 9000, "", Seed{Port: 8443, WebPath: "abc123"}); err != nil {
		t.Fatalf("setting: %v", err)
	}
	if err := RecordLastGood(ctx, database, 8443); err != nil {
		t.Fatalf("recording the last good port: %v", err)
	}

	after, err := Load(ctx, database)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if !after.Exists || after.Port != 9000 || after.WebPath != "" {
		t.Errorf("stored = %+v, want port 9000 and an empty web path", after)
	}
	if after.LastGoodPort != 8443 {
		t.Errorf("last good port = %d, want 8443", after.LastGoodPort)
	}
	// The seed records what the caller last read from the environment file, not
	// the value being set. Setting it to the new value would make an unchanged
	// file read as an edit at the next start and revert the change.
	if after.SeedPort != 8443 || after.SeedWebPath != "abc123" {
		t.Errorf("Set left the seed at %d/%q; it must record the environment file as 8443/\"abc123\"",
			after.SeedPort, after.SeedWebPath)
	}
}

// Set before the panel has ever started has no row to update. The CLI does
// exactly this when it is used to fix an installation that will not come up.
func TestSetWorksBeforeTheFirstStart(t *testing.T) {
	ctx := context.Background()
	database := openTestDB(t)

	if err := Set(ctx, database, 9100, "late", Seed{Port: 8443, WebPath: "abc123"}); err != nil {
		t.Fatalf("setting with no row present: %v", err)
	}
	got, err := Load(ctx, database)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if !got.Exists || got.Port != 9100 || got.WebPath != "late" {
		t.Errorf("stored = %+v, want 9100/\"late\"", got)
	}
}

func TestURLNeverCarriesADoubleSlash(t *testing.T) {
	for _, tc := range []struct{ webPath, want string }{
		{"abc123", "http://192.0.2.1:8443/abc123/"},
		{"", "http://192.0.2.1:8443/"},
	} {
		got := URL("http", "192.0.2.1", 8443, tc.webPath)
		if got != tc.want {
			t.Errorf("URL(web path %q) = %q, want %q", tc.webPath, got, tc.want)
		}
		if strings.Contains(strings.TrimPrefix(got, "http://"), "//") {
			t.Errorf("URL(web path %q) = %q, which carries a double slash", tc.webPath, got)
		}
	}
	if got, want := HealthURL("http", "127.0.0.1", 8443, ""), "http://127.0.0.1:8443/api/v1/system/health"; got != want {
		t.Errorf("HealthURL with no web path = %q, want %q", got, want)
	}
}

// refusing is a socket factory that fails for a named set of ports and
// succeeds, on an ephemeral port, for the rest. Deciding which port fails is
// the only way to test the fallback on a machine that does not enforce port
// exclusivity, and it is also the only way to test it deterministically on one
// that does.
func refusing(blocked ...int) (Opener, *[]string) {
	var attempted []string
	deny := map[int]bool{}
	for _, p := range blocked {
		deny[p] = true
	}
	return func(network, addr string) (net.Listener, error) {
		attempted = append(attempted, addr)
		_, portText, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portText)
		if deny[port] {
			return nil, fmt.Errorf("listen tcp %s: bind: address already in use", addr)
		}
		return net.Listen(network, "127.0.0.1:0")
	}, &attempted
}

// The fallback is the property that keeps one bad value from bricking the
// panel: with Restart=always, a process that exits because it cannot bind is a
// crash loop over a value only the panel can change.
func TestListenFallsBackAndSaysSo(t *testing.T) {
	open, attempted := refusing(9000)

	listener, port, fallback, err := ListenWith(open, "127.0.0.1", []int{9000, 8443, 8787})
	if err != nil {
		t.Fatalf("Listen gave up entirely: %v", err)
	}
	defer listener.Close()

	if port != 8443 {
		t.Errorf("chose port %d, want the next candidate 8443", port)
	}
	if fallback == nil {
		t.Fatal("the panel fell back to another port and reported nothing, so nothing can tell " +
			"an operator why it is not where they put it")
	}
	if fallback.Wanted != 9000 || fallback.Serving != 8443 || fallback.Reason == "" {
		t.Errorf("fallback = %+v, want wanted=9000 serving=8443 with a reason", fallback)
	}
	// The third candidate must not have been touched: falling back further than
	// necessary would leave the panel somewhere nobody expects.
	if want := []string{"127.0.0.1:9000", "127.0.0.1:8443"}; strings.Join(*attempted, " ") != strings.Join(want, " ") {
		t.Errorf("tried %v, want exactly %v", *attempted, want)
	}
}

func TestListenReportsNoFallbackWhenTheFirstChoiceWorks(t *testing.T) {
	open, attempted := refusing()

	listener, port, fallback, err := ListenWith(open, "127.0.0.1", []int{8443, 8787})
	if err != nil {
		t.Fatalf("Listen failed on a free port: %v", err)
	}
	defer listener.Close()
	if port != 8443 || fallback != nil {
		t.Errorf("port %d fallback %+v, want 8443 and no fallback", port, fallback)
	}
	if len(*attempted) != 1 {
		t.Errorf("tried %v, want only the first candidate", *attempted)
	}
}

func TestListenGivesUpWhenNothingBinds(t *testing.T) {
	open, _ := refusing(1, 2, 3)
	if _, _, _, err := ListenWith(open, "127.0.0.1", []int{1, 2, 3}); err == nil {
		t.Error("Listen reported success with no bindable candidate")
	}
}

func TestProbeRejectsAPortOutsideTheRange(t *testing.T) {
	for _, port := range []int{0, -1, 65536, 70000} {
		if err := Probe("127.0.0.1", port); err == nil {
			t.Errorf("Probe accepted port %d", port)
		}
	}
}

func TestProbeRefusesAPortSomethingElseHolds(t *testing.T) {
	if !EnforcesPortExclusivity() {
		// Not a pass. This machine lets two listeners share a port — measured
		// on WSL2, where a second net.Listen on a bound 127.0.0.1 port returns
		// no error — so the conflict this test is named after cannot be staged
		// here at all. Reporting that is the honest outcome; reporting a pass
		// would be a check that agrees with itself.
		t.Skip("this machine does not enforce TCP port exclusivity on 127.0.0.1, " +
			"so a held port cannot be used to make a bind fail; run this on a real Linux host")
	}

	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("taking a port for the test: %v", err)
	}
	defer held.Close()
	port := held.Addr().(*net.TCPAddr).Port

	if err := Probe("127.0.0.1", port); err == nil {
		t.Errorf("Probe accepted port %d while something is listening on it", port)
	}
	held.Close()
	if err := Probe("127.0.0.1", port); err != nil {
		t.Errorf("Probe refused port %d after it was released: %v", port, err)
	}
}

// Probe against an injected factory, so the refusal path is exercised wherever
// the suite runs and not only where the kernel will stage it.
func TestProbeReportsWhyABindFailed(t *testing.T) {
	open, _ := refusing(9000)
	if err := ProbeWith(open, "127.0.0.1", 9000); err == nil {
		t.Error("ProbeWith accepted a port the socket factory refused")
	}
	if err := ProbeWith(open, "127.0.0.1", 9001); err != nil {
		t.Errorf("ProbeWith refused a bindable port: %v", err)
	}
}

type stubDoer struct {
	status int
	body   string
	err    error
	calls  int
}

func (s *stubDoer) Do(req *http.Request) (*http.Response, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     http.Header{},
	}, nil
}

// The half that would otherwise pass vacuously. After a web path change the old
// panel is still listening on the same port and answers the new path with a
// bare 404; treating "something replied" as success would report the change as
// applied when the panel never moved.
func TestWaitForHealthRejectsAnythingButThePanelsOwnEnvelope(t *testing.T) {
	ctx := context.Background()
	const healthy = `{"status":"ok","uptime_seconds":12,"setup_required":false,"components":[]}`

	for _, tc := range []struct {
		name   string
		doer   *stubDoer
		wantOK bool
	}{
		{"the panel's envelope", &stubDoer{status: 200, body: healthy}, true},
		{"degraded but running is still running", &stubDoer{status: 503, body: healthy}, true},
		{"a bare 404 from outside the web path", &stubDoer{status: 404, body: ""}, false},
		{"someone else's 200", &stubDoer{status: 200, body: "<html>nginx</html>"}, false},
		{"a JSON body that is not this endpoint", &stubDoer{status: 200, body: `{"ok":true}`}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := WaitForHealth(ctx, tc.doer, "http://127.0.0.1:1/api/v1/system/health",
				60*time.Millisecond, 20*time.Millisecond)
			if tc.wantOK && err != nil {
				t.Errorf("the poll rejected a live panel: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Error("the poll accepted a response that does not prove the panel is at this address")
			}
			if tc.doer.calls == 0 {
				t.Error("the poll never made a request, so it proved nothing")
			}
		})
	}
}

// A real end-to-end poll against a real socket, so the test is not only about
// the stub.
func TestWaitForHealthAcceptsARealPanel(t *testing.T) {
	server := &http.Server{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","uptime_seconds":1,"setup_required":false,"components":[]}`)
	})
	server.Handler = mux
	go server.Serve(listener) //nolint:errcheck // closed by the deferred Close
	defer server.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	url := HealthURL("http", "127.0.0.1", port, "")
	if !strings.HasSuffix(url, strconv.Itoa(port)+"/api/v1/system/health") {
		t.Fatalf("the health URL is malformed: %s", url)
	}
	if err := WaitForHealth(context.Background(), http.DefaultClient, url, 3*time.Second, 50*time.Millisecond); err != nil {
		t.Errorf("a live panel was not recognised: %v", err)
	}
}

// An absent environment value is not an instruction.
//
// This is the regression for a host whose environment file an uninstall had
// removed. With no file, BindPort fell back to the compiled default, the
// resolver compared that default against the seed recorded at the last start,
// found them different, and concluded an operator had edited the file — so the
// default won and the panel served on 8787 while its own database said 8443.
// Measured on server B:
//
//	tnp url  ->  http://…:8787/     (stored port: 8443)
//
// The drift check is right about the case it was written for. It simply could
// not tell an edit from an absence, and those are opposite instructions.
func TestAnAbsentEnvironmentValueLosesToTheDatabase(t *testing.T) {
	stored := Stored{Exists: true, Port: 8443, WebPath: "p4nel", SeedPort: 8443, SeedWebPath: "p4nel"}

	// Nothing supplied a port or a web path: this is what no environment file
	// at all looks like, with the compiled defaults filled in.
	got := Resolve(stored, Seed{Port: DefaultPort, WebPath: ""})

	if got.Port != 8443 {
		t.Errorf("port = %d, want the stored 8443; %d is the compiled default and nobody asked for it",
			got.Port, DefaultPort)
	}
	if got.PortSource != SourceDatabase {
		t.Errorf("port source = %q, want %q", got.PortSource, SourceDatabase)
	}
	if got.WebPath != "p4nel" {
		t.Errorf("web path = %q, want the stored %q", got.WebPath, "p4nel")
	}
}

// And an edit still wins, which is the whole reason the comparison exists: it
// is the way back in when nobody can reach the panel.
func TestAnEditedEnvironmentValueStillWins(t *testing.T) {
	stored := Stored{Exists: true, Port: 8443, WebPath: "p4nel", SeedPort: 8443, SeedWebPath: "p4nel"}

	got := Resolve(stored, Seed{Port: 9000, WebPath: "moved", PortProvided: true, WebPathProvided: true})

	if got.Port != 9000 || got.PortSource != SourceEnvironment {
		t.Errorf("port = %d from %q, want 9000 from the environment", got.Port, got.PortSource)
	}
	if got.WebPath != "moved" {
		t.Errorf("web path = %q, want %q", got.WebPath, "moved")
	}
}

// An unchanged file is not an edit, so the database still wins.
func TestAnUnchangedEnvironmentFileLosesToTheDatabase(t *testing.T) {
	stored := Stored{Exists: true, Port: 9999, WebPath: "current", SeedPort: 8443, SeedWebPath: "p4nel"}

	got := Resolve(stored, Seed{Port: 8443, WebPath: "p4nel", PortProvided: true, WebPathProvided: true})

	if got.Port != 9999 || got.PortSource != SourceDatabase {
		t.Errorf("port = %d from %q, want the stored 9999 from the database", got.Port, got.PortSource)
	}
}
