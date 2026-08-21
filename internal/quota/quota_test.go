package quota

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// harness is a checker over a real database and fake counters and switches, so
// every test reads like the operations it describes: traffic moves, windows
// end, things are stopped and started.
type harness struct {
	checker *Checker
	ctx     context.Context

	now time.Time

	tunnelBytes map[string][2]uint64
	ruleBytes   map[int64][2]uint64
	destBytes   map[string][2]uint64

	tunnelEnabled map[int64]bool
	ruleEnabled   map[int64]bool
	destEnabled   map[int64]bool

	stops, starts []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatal(err)
	}

	h := &harness{
		ctx: ctx,
		now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),

		tunnelBytes:   map[string][2]uint64{},
		ruleBytes:     map[int64][2]uint64{},
		destBytes:     map[string][2]uint64{},
		tunnelEnabled: map[int64]bool{},
		ruleEnabled:   map[int64]bool{},
		destEnabled:   map[int64]bool{},
	}

	h.checker = New(Deps{
		DB: database,
		TunnelVolume: func(name string) (uint64, uint64, bool) {
			v, ok := h.tunnelBytes[name]
			return v[0], v[1], ok
		},
		RuleVolume: func(id int64) (uint64, uint64, bool) {
			v, ok := h.ruleBytes[id]
			return v[0], v[1], ok
		},
		DestinationVolume: func(ruleID int64, address string, port int64) (uint64, uint64, bool) {
			v, ok := h.destBytes[DestinationKey(address, port)]
			return v[0], v[1], ok
		},
		StopTunnel: func(_ context.Context, id int64) error {
			h.stops = append(h.stops, "tunnel")
			h.setTunnelEnabled(t, database, id, false)
			return nil
		},
		StartTunnel: func(_ context.Context, id int64) error {
			h.starts = append(h.starts, "tunnel")
			h.setTunnelEnabled(t, database, id, true)
			return nil
		},
		StopRule: func(_ context.Context, id int64) error {
			h.stops = append(h.stops, "rule")
			h.setRuleEnabled(t, database, id, false)
			return nil
		},
		StartRule: func(_ context.Context, id int64) error {
			h.starts = append(h.starts, "rule")
			h.setRuleEnabled(t, database, id, true)
			return nil
		},
		SetDestinationEnabled: func(_ context.Context, destID int64, enabled bool) error {
			if enabled {
				h.starts = append(h.starts, "destination")
			} else {
				h.stops = append(h.stops, "destination")
			}
			h.setDestEnabled(t, database, destID, enabled)
			return nil
		},
		Now: func() time.Time { return h.now },
	})

	// One tunnel, one rule with two destinations, all live.
	now := model.NowUTC()
	mustExec(t, database, `
		INSERT INTO Tunnel (TunnelID, TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName,
			LocalEndpoint, RemoteEndpoint, Ttl, Tos, Mtu, IsEnabled, IsManaged, IsNameTemplated,
			ApplyStatusID, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (1, ?, ?, ?, 'gre-b-1', '203.0.113.10', '198.51.100.20', 64, 'inherit', 1397,
			1, 1, 1, ?, ?, ?, 0)`,
		model.TunnelTypeGRE, model.TunnelSideB, model.PersistenceTypeNetworkd,
		model.ApplyStatusApplied, now, now)
	mustExec(t, database, `
		INSERT INTO RouteRule (RouteRuleID, RouteRuleTitle, Description, RouteProtocolID, AddressFamilyID,
			BindAddress, BindPort, DestinationAddress, DestinationPort, NatModeID, LoadBalanceModeID,
			IsClampMssToPmtu, IsIncludeLocalOriginated, IsLoggingEnabled, IsEnabled, ApplyStatusID,
			SortOrder, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (1, 'Relay', '', 10, 10, '203.0.113.10', 8080, '172.17.1.2', 8080, 10, 20,
			0, 0, 0, 1, 20, 1, ?, ?, 0)`, now, now)
	for i, address := range []string{"172.17.1.2", "172.17.2.2"} {
		mustExec(t, database, `
			INSERT INTO RouteDestination (RouteDestinationID, RouteRuleID, Address, Port, Weight,
				IsEnabled, SortOrder, IsSuppressed, CreatedDate, UpdatedDate, IsDeleted)
			VALUES (?, 1, ?, 8080, 1, 1, ?, 0, ?, ?, 0)`, i+1, address, i, now, now)
	}
	return h
}

func mustExec(t *testing.T, database *db.DB, stmt string, args ...any) {
	t.Helper()
	if _, err := database.Write.Exec(stmt, args...); err != nil {
		t.Fatalf("%s: %v", stmt[:40], err)
	}
}

func (h *harness) setTunnelEnabled(t *testing.T, database *db.DB, id int64, enabled bool) {
	t.Helper()
	v := 0
	if enabled {
		v = 1
	}
	mustExec(t, database, `UPDATE Tunnel SET IsEnabled = ? WHERE TunnelID = ?`, v, id)
	h.tunnelEnabled[id] = enabled
}

func (h *harness) setRuleEnabled(t *testing.T, database *db.DB, id int64, enabled bool) {
	t.Helper()
	v := 0
	if enabled {
		v = 1
	}
	mustExec(t, database, `UPDATE RouteRule SET IsEnabled = ? WHERE RouteRuleID = ?`, v, id)
	h.ruleEnabled[id] = enabled
}

func (h *harness) setDestEnabled(t *testing.T, database *db.DB, id int64, enabled bool) {
	t.Helper()
	v := 0
	if enabled {
		v = 1
	}
	mustExec(t, database, `UPDATE RouteDestination SET IsEnabled = ? WHERE RouteDestinationID = ?`, v, id)
	h.destEnabled[id] = enabled
}

const gigabyte = int64(1_000_000_000)

// A limit in warning mode is a line on a gauge and nothing more. Crossing it
// changes the report and changes the machine not at all.
func TestAWarningLimitReportsAndTouchesNothing(t *testing.T) {
	h := newHarness(t)
	h.tunnelBytes["gre-b-1"] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeTunnel, TunnelID: 1},
		Limit{LimitBytes: 10 * gigabyte, ModeID: model.TrafficLimitModeWarn}); err != nil {
		t.Fatal(err)
	}

	h.tunnelBytes["gre-b-1"] = [2]uint64{8 * uint64(gigabyte), 4 * uint64(gigabyte)}
	h.checker.Sweep(h.ctx)

	status := h.checker.TunnelStatus(1)
	if status == nil {
		t.Fatal("no status for the limited tunnel")
	}
	if !status.Exhausted {
		t.Errorf("12 GB against a 10 GB limit does not read as exhausted: %+v", status)
	}
	if status.Stopped || len(h.stops) != 0 {
		t.Errorf("a warning limit stopped something: %+v, stops %v", status, h.stops)
	}
	if status.UsedBytes != 12*gigabyte {
		t.Errorf("used %d, want 12 GB", status.UsedBytes)
	}
}

// An enforcing limit stops what crossed it, exactly once, and says so.
func TestAnEnforcingLimitStopsTheTunnelOnce(t *testing.T) {
	h := newHarness(t)
	h.tunnelBytes["gre-b-1"] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeTunnel, TunnelID: 1},
		Limit{LimitBytes: 10 * gigabyte, ModeID: model.TrafficLimitModeEnforce}); err != nil {
		t.Fatal(err)
	}

	h.tunnelBytes["gre-b-1"] = [2]uint64{11 * uint64(gigabyte), 0}
	h.checker.Sweep(h.ctx)
	h.checker.Sweep(h.ctx)
	h.checker.Sweep(h.ctx)

	if len(h.stops) != 1 {
		t.Fatalf("stopped %d times, want once: %v", len(h.stops), h.stops)
	}
	status := h.checker.TunnelStatus(1)
	if status == nil || !status.Stopped {
		t.Errorf("the status does not say the panel stopped it: %+v", status)
	}
}

// The window ending is the limit starting over: the count rebases, and what
// the panel stopped the panel starts again. An operator on a monthly plan
// should wake up on the first with everything running.
func TestTheWindowRollingOverStartsTheStoppedTunnelAgain(t *testing.T) {
	h := newHarness(t)
	h.tunnelBytes["gre-b-1"] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeTunnel, TunnelID: 1},
		Limit{LimitBytes: 10 * gigabyte, ModeID: model.TrafficLimitModeEnforce,
			PeriodID: model.TrafficPeriodMonthly}); err != nil {
		t.Fatal(err)
	}
	h.tunnelBytes["gre-b-1"] = [2]uint64{11 * uint64(gigabyte), 0}
	h.checker.Sweep(h.ctx)
	if len(h.stops) != 1 {
		t.Fatalf("the limit did not stop the tunnel")
	}

	// September the first.
	h.now = time.Date(2026, 9, 1, 0, 5, 0, 0, time.UTC)
	h.checker.Sweep(h.ctx)

	if len(h.starts) != 1 {
		t.Fatalf("the new month did not start the tunnel again: %v", h.starts)
	}
	status := h.checker.TunnelStatus(1)
	if status == nil || status.Stopped || status.Exhausted || status.UsedBytes != 0 {
		t.Errorf("the new month's status is not a fresh one: %+v", status)
	}

	// And the traffic that then flows is counted from the rollover, not from
	// the beginning of the counters.
	h.tunnelBytes["gre-b-1"] = [2]uint64{12 * uint64(gigabyte), 0}
	h.checker.Sweep(h.ctx)
	if status := h.checker.TunnelStatus(1); status.UsedBytes != gigabyte {
		t.Errorf("used %d after the rollover, want 1 GB", status.UsedBytes)
	}
}

// Resetting the usage is buying more traffic: the count starts over and what
// was stopped runs again.
func TestResetRebasesAndStartsTheSubjectAgain(t *testing.T) {
	h := newHarness(t)
	h.ruleBytes[1] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeRule, RouteRuleID: 1},
		Limit{LimitBytes: 5 * gigabyte, ModeID: model.TrafficLimitModeEnforce}); err != nil {
		t.Fatal(err)
	}
	h.ruleBytes[1] = [2]uint64{6 * uint64(gigabyte), 0}
	h.checker.Sweep(h.ctx)
	if len(h.stops) != 1 || h.ruleEnabled[1] {
		t.Fatalf("the limit did not stop the rule")
	}

	if err := h.checker.Reset(h.ctx, Subject{ScopeID: model.QuotaScopeRule, RouteRuleID: 1}); err != nil {
		t.Fatal(err)
	}
	if !h.ruleEnabled[1] {
		t.Error("the reset did not start the rule again")
	}
	if status := h.checker.RuleStatus(1); status == nil || status.UsedBytes != 0 || status.Stopped {
		t.Errorf("the reset did not zero the count: %+v", status)
	}
}

// Removing a limit removes the stopping with it.
func TestRemovingTheLimitStartsTheSubjectAgain(t *testing.T) {
	h := newHarness(t)
	h.ruleBytes[1] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeRule, RouteRuleID: 1},
		Limit{LimitBytes: 5 * gigabyte, ModeID: model.TrafficLimitModeEnforce}); err != nil {
		t.Fatal(err)
	}
	h.ruleBytes[1] = [2]uint64{6 * uint64(gigabyte), 0}
	h.checker.Sweep(h.ctx)
	if h.ruleEnabled[1] {
		t.Fatal("the limit did not stop the rule")
	}

	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeRule, RouteRuleID: 1},
		Limit{}); err != nil {
		t.Fatal(err)
	}
	if !h.ruleEnabled[1] {
		t.Error("removing the limit did not start the rule again")
	}
	h.checker.Sweep(h.ctx)
	if status := h.checker.RuleStatus(1); status != nil {
		t.Errorf("a removed limit still reports a status: %+v", status)
	}
}

// A destination's limit stops that destination and nothing else: the rule and
// the other backend keep carrying traffic.
func TestADestinationLimitStopsOnlyThatDestination(t *testing.T) {
	h := newHarness(t)
	subject := Subject{ScopeID: model.QuotaScopeDestination, RouteRuleID: 1,
		Address: "172.17.1.2", Port: 8080}
	h.destBytes["172.17.1.2:8080"] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, subject,
		Limit{LimitBytes: gigabyte, ModeID: model.TrafficLimitModeEnforce}); err != nil {
		t.Fatal(err)
	}

	h.destBytes["172.17.1.2:8080"] = [2]uint64{2 * uint64(gigabyte), 0}
	h.checker.Sweep(h.ctx)

	if enabled, ok := h.destEnabled[1]; !ok || enabled {
		t.Error("the exhausted destination was not taken out of service")
	}
	if _, touched := h.destEnabled[2]; touched {
		t.Error("the other destination was touched")
	}
	if h.ruleEnabled[1] {
		t.Error("the rule itself was touched") // never set by harness = zero value false; ensure no rule stop happened
	}
	for _, stop := range h.stops {
		if stop != "destination" {
			t.Errorf("something other than the destination was stopped: %v", h.stops)
		}
	}

	_, _, destinations := h.checker.All()
	status := destinations[1]["172.17.1.2:8080"]
	if !status.Stopped {
		t.Errorf("the destination's status does not say it was stopped: %+v", status)
	}
}

// The count starts when the limit is set: traffic carried before anybody asked
// for a limit was never against one.
func TestALimitCountsFromWhenItWasSet(t *testing.T) {
	h := newHarness(t)
	h.tunnelBytes["gre-b-1"] = [2]uint64{50 * uint64(gigabyte), 20 * uint64(gigabyte)}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeTunnel, TunnelID: 1},
		Limit{LimitBytes: 10 * gigabyte}); err != nil {
		t.Fatal(err)
	}
	h.checker.Sweep(h.ctx)
	if status := h.checker.TunnelStatus(1); status.UsedBytes != 0 {
		t.Errorf("history before the limit counts against it: %+v", status)
	}

	h.tunnelBytes["gre-b-1"] = [2]uint64{51 * uint64(gigabyte), 20 * uint64(gigabyte)}
	h.checker.Sweep(h.ctx)
	if status := h.checker.TunnelStatus(1); status.UsedBytes != gigabyte {
		t.Errorf("used %d, want the 1 GB carried since the limit", status.UsedBytes)
	}
}

// A counter that cannot be read stops nothing. A tunnel must never be brought
// down because a file failed to parse.
func TestNothingIsStoppedOnACounterThatCouldNotBeRead(t *testing.T) {
	h := newHarness(t)
	h.tunnelBytes["gre-b-1"] = [2]uint64{0, 0}
	if err := h.checker.Set(h.ctx, Subject{ScopeID: model.QuotaScopeTunnel, TunnelID: 1},
		Limit{LimitBytes: 1, ModeID: model.TrafficLimitModeEnforce}); err != nil {
		t.Fatal(err)
	}
	delete(h.tunnelBytes, "gre-b-1")
	h.checker.Sweep(h.ctx)
	if len(h.stops) != 0 {
		t.Errorf("an unreadable counter stopped something: %v", h.stops)
	}
}

// The window boundaries themselves.
func TestWindowStarts(t *testing.T) {
	at := time.Date(2026, 8, 20, 15, 30, 0, 0, time.UTC) // a Thursday
	cases := []struct {
		period int64
		want   time.Time
	}{
		{model.TrafficPeriodDaily, time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)},
		{model.TrafficPeriodWeekly, time.Date(2026, 8, 17, 0, 0, 0, 0, time.UTC)}, // Monday
		{model.TrafficPeriodMonthly, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		if got := windowStart(at, tc.period); !got.Equal(tc.want) {
			t.Errorf("period %d starts %v, want %v", tc.period, got, tc.want)
		}
	}
}
