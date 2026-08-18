package route

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// These tests cover the routes.* settings whose consumers live in this package.
// The coarse check in internal/api proves each key is named somewhere; these
// prove the value is honoured.
//
// None of these six is read by the frontend, so a Go-side regression here is
// invisible from the interface as well as from the coarse guard: the Settings
// page would go on describing a retention window or a sampling cadence that
// nothing applies. Each is asserted at two distinct non-default values, because
// a reader frozen at any single constant has to fail one of them.

// routeSettings answers the route Settings interface from a map.
type routeSettings map[string]any

func (s routeSettings) Bool(key string) bool     { b, _ := s[key].(bool); return b }
func (s routeSettings) Int(key string) int64     { n, _ := s[key].(int64); return n }
func (s routeSettings) Float(key string) float64 { f, _ := s[key].(float64); return f }
func (s routeSettings) String(key string) string { v, _ := s[key].(string); return v }

// accountingWith is newAccounting with settings attached and the database
// handed back, which the history tests need in order to age a row.
func accountingWith(t *testing.T, set routeSettings) (context.Context, *Accounting, *db.DB) {
	t.Helper()
	ctx, database, repo := openRepo(t)

	if _, err := repo.Insert(ctx, validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID: model.NatModeMasquerade,
		IsEnabled: true,
	}); err != nil {
		t.Fatalf("storing the rule failed: %v", err)
	}

	accounting := NewAccounting(AccountingDeps{
		Repo: NewCounterRepo(database), Routes: repo, Backend: rules.NewFake(),
		Conntrack: NewFakeConntrack(), Settings: set,
	})
	if err := accounting.Load(ctx); err != nil {
		t.Fatalf("loading the accounting failed: %v", err)
	}
	return ctx, accounting, database
}

// countingBackend counts how often the byte counters are actually read, which
// is the only honest way to observe the sampling cadence: asserting on the
// interval helper would still pass if the loop stopped calling it and ticked on
// a constant instead.
type countingBackend struct {
	rules.Backend
	mu sync.Mutex
	n  int
}

func (b *countingBackend) Counters(ctx context.Context) (map[int64]rules.Counter, error) {
	b.mu.Lock()
	b.n++
	b.mu.Unlock()
	return b.Backend.Counters(ctx)
}

func (b *countingBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.n
}

// countingConntrack does the same for the connection table.
type countingConntrack struct {
	ConntrackReader
	mu sync.Mutex
	n  int
}

func (c *countingConntrack) Flows(ctx context.Context) ([]Flow, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.ConntrackReader.Flows(ctx)
}

func (c *countingConntrack) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// runLoopFor starts the accounting loop against counting fakes and returns how
// many times each source was read in the window.
func runLoopFor(t *testing.T, set routeSettings, window time.Duration) (counters, connections int) {
	t.Helper()
	ctx, database, repo := openRepo(t)

	if _, err := repo.Insert(ctx, validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID: model.NatModeMasquerade,
		IsEnabled: true,
	}); err != nil {
		t.Fatalf("storing the rule failed: %v", err)
	}

	backend := &countingBackend{Backend: rules.NewFake()}
	conntrack := &countingConntrack{ConntrackReader: NewFakeConntrack()}
	accounting := NewAccounting(AccountingDeps{
		Repo: NewCounterRepo(database), Routes: repo, Backend: backend,
		Conntrack: conntrack, Settings: set,
	})
	if err := accounting.Start(ctx); err != nil {
		t.Fatalf("starting the accounting failed: %v", err)
	}
	time.Sleep(window)
	accounting.Stop()

	return backend.count(), conntrack.count()
}

// The counter cadence is how often the forward-hook byte counters are read. It
// is asserted against the running loop, because the loop is what consumes it.
func TestTheCounterSampleIntervalFollowsTheSetting(t *testing.T) {
	// Start always takes one reading immediately, so the first request after
	// startup has figures rather than zeroes. Every count below is that one plus
	// whatever the loop added.
	//
	// At a quarter of a second, three quarters of a second holds at least two
	// ticks on top of it; the one-second default would add none.
	counters, _ := runLoopFor(t, routeSettings{
		"routes.counter_interval_seconds":   0.25,
		"routes.conntrack_interval_seconds": 3600.0,
	}, 750*time.Millisecond)
	if counters < 3 {
		t.Fatalf("the counters were read %d times in 750ms at a 0.25s interval, want the initial "+
			"reading plus at least two ticks; the loop is ticking on something other than the "+
			"setting", counters)
	}

	// And a long interval has to hold the loop back to that initial reading
	// alone, or the assertion above would pass against a loop that simply
	// sampled as fast as it could.
	counters, _ = runLoopFor(t, routeSettings{
		"routes.counter_interval_seconds":   3600.0,
		"routes.conntrack_interval_seconds": 3600.0,
	}, 750*time.Millisecond)
	if counters != 1 {
		t.Fatalf("the counters were read %d times in 750ms at a one-hour interval, want only the "+
			"initial reading", counters)
	}
}

// Connection counts are read on their own, slower cadence: conntrack is far
// more expensive to walk than a byte counter.
func TestTheConntrackSampleIntervalFollowsTheSetting(t *testing.T) {
	// As above, the initial reading Start takes is included in every count.
	_, connections := runLoopFor(t, routeSettings{
		"routes.counter_interval_seconds":   3600.0,
		"routes.conntrack_interval_seconds": 0.25,
	}, 750*time.Millisecond)
	if connections < 3 {
		t.Fatalf("connections were counted %d times in 750ms at a 0.25s interval, want the initial "+
			"reading plus at least two ticks; the loop is ticking on something other than the "+
			"setting", connections)
	}

	_, connections = runLoopFor(t, routeSettings{
		"routes.counter_interval_seconds":   3600.0,
		"routes.conntrack_interval_seconds": 3600.0,
	}, 750*time.Millisecond)
	if connections != 1 {
		t.Fatalf("connections were counted %d times in 750ms at a one-hour interval, want only the "+
			"initial reading", connections)
	}
}

// The aggregate interval is the width of a stored history bucket.
func TestTheRouteHistoryBucketWidthFollowsTheSetting(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    time.Duration
	}{
		{30, 30 * time.Second},
		{300, 5 * time.Minute},
	} {
		_, accounting, _ := accountingWith(t, routeSettings{"routes.aggregate_interval_seconds": tc.seconds})

		if got := accounting.aggregateInterval(); got != tc.want {
			t.Fatalf("history is bucketed every %s, want the configured %s", got, tc.want)
		}
	}
}

// Retention decides what Prune deletes, so rows of a known age are the only
// honest way to observe it: a window that is not applied keeps history for ever
// on a busy relay, and one applied too aggressively silently destroys it.
func TestTheRouteHistoryRetentionFollowsTheSetting(t *testing.T) {
	seed := func(t *testing.T, database *db.DB, daysAgo int) {
		t.Helper()
		when := model.FormatTime(time.Now().UTC().AddDate(0, 0, -daysAgo))
		now := model.NowUTC()
		if _, err := database.Write.Exec(`
			INSERT INTO RouteTrafficSample
				(RouteRuleID, BucketStartDate, RxBytes, TxBytes, RxPackets, TxPackets,
				 ActiveConnections, NewConnections, CreatedDate, UpdatedDate, IsDeleted)
			VALUES (1, ?, 1, 1, 1, 1, 0, 0, ?, ?, 0)`, when, now, now); err != nil {
			t.Fatalf("seeding a %d-day-old sample failed: %v", daysAgo, err)
		}
	}
	count := func(t *testing.T, database *db.DB) int {
		t.Helper()
		var n int
		if err := database.Read.QueryRow(`SELECT COUNT(*) FROM RouteTrafficSample`).Scan(&n); err != nil {
			t.Fatalf("counting the stored samples failed: %v", err)
		}
		return n
	}

	// A thirty-day window keeps the recent row and drops the old one.
	ctx, accounting, database := accountingWith(t, routeSettings{"routes.history_retention_days": int64(30)})
	seed(t, database, 5)
	seed(t, database, 100)
	if _, err := accounting.Prune(ctx); err != nil {
		t.Fatalf("pruning failed: %v", err)
	}
	if got := count(t, database); got != 1 {
		t.Fatalf("%d samples survived a thirty-day window, want only the five-day-old one", got)
	}

	// A three-day window drops both, which the same rows must not survive.
	ctx, accounting, database = accountingWith(t, routeSettings{"routes.history_retention_days": int64(3)})
	seed(t, database, 5)
	seed(t, database, 100)
	if _, err := accounting.Prune(ctx); err != nil {
		t.Fatalf("pruning failed: %v", err)
	}
	if got := count(t, database); got != 0 {
		t.Fatalf("%d samples survived a three-day window, want none", got)
	}
}

// Turning kernel forwarding on is something the panel does to the host, so an
// operator who manages sysctl themselves can refuse it. Refusing has to mean the
// parameter is left alone — the rules are still installed, and the log says they
// will carry nothing.
func TestEnablingKernelForwardingFollowsTheSetting(t *testing.T) {
	forwardingFlag := func(t *testing.T, h *harness) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(h.dir, "proc", "sys", "net", "ipv4", "ip_forward"))
		if err != nil {
			t.Fatalf("reading the fake ip_forward failed: %v", err)
		}
		return string(body)
	}

	// Off: the step is a no-op and the kernel parameter is untouched.
	h := newHarness(t)
	h.service.settings = routeSettings{"routes.auto_enable_ip_forward": false}
	if err := h.service.runStep(h.ctx, Step{Kind: StepEnableForwarding}); err != nil {
		t.Fatalf("the step failed: %v", err)
	}
	if got := forwardingFlag(t, h); got != "0\n" {
		t.Fatalf("ip_forward = %q with the setting off, want it left at %q", got, "0\n")
	}

	// On: the same step turns forwarding on.
	h = newHarness(t)
	h.service.settings = routeSettings{"routes.auto_enable_ip_forward": true}
	if err := h.service.runStep(h.ctx, Step{Kind: StepEnableForwarding}); err != nil {
		t.Fatalf("the step failed: %v", err)
	}
	if got := forwardingFlag(t, h); got != "1\n" {
		t.Fatalf("ip_forward = %q with the setting on, want %q", got, "1\n")
	}
}

// The conntrack warning threshold decides when the panel says the table is
// filling. When it fills, new connections are dropped and nothing in the logs
// explains it, so the threshold being honoured is the whole value of the
// warning.
func TestTheConntrackWarningThresholdFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	// A table that is 50% full: 500 of 1000.
	dir := filepath.Join(h.dir, "proc", "sys", "net", "netfilter")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("preparing the fake conntrack files failed: %v", err)
	}
	for name, value := range map[string]string{
		"nf_conntrack_max": "1000\n", "nf_conntrack_count": "500\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0o644); err != nil {
			t.Fatalf("preparing %s failed: %v", name, err)
		}
	}

	warned := func() bool {
		status := h.service.forwardingStatus(h.ctx, nil)
		if status.ConntrackUsagePercent != 50 {
			t.Fatalf("the fake table reads as %.0f%% full, want 50%%", status.ConntrackUsagePercent)
		}
		for _, w := range status.Warnings {
			if w.Code == WarnConntrackUsage {
				return true
			}
		}
		return false
	}

	// A threshold above the usage is not reached.
	h.service.settings = routeSettings{"routes.warn_conntrack_usage_percent": 80.0}
	if warned() {
		t.Fatal("a table 50% full warned at an 80% threshold")
	}

	// One below it is.
	h.service.settings = routeSettings{"routes.warn_conntrack_usage_percent": 40.0}
	if !warned() {
		t.Fatal("a table 50% full did not warn at a 40% threshold")
	}
}
