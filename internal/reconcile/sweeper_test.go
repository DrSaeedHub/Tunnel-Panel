package reconcile

import (
	"context"
	"testing"
	"time"
)

// fakeSweepSettings is a settings store a test can move under the sweep, which
// is the point: the cadence and the drift policy are re-read every cycle so a
// change in the interface takes effect without restarting the panel.
type fakeSweepSettings struct {
	interval int64
	reapply  bool
}

func (f *fakeSweepSettings) Int(key string) int64 {
	if key == "system.reconcile_interval_seconds" {
		return f.interval
	}
	return 0
}

func (f *fakeSweepSettings) Bool(key string) bool {
	return key == "system.auto_reapply_on_drift" && f.reapply
}

// TestTheSweepIntervalComesFromTheSetting is half of the regression: the
// setting named a cadence and nothing read it, because no periodic sweep
// existed at all. Reconciliation happened only when somebody opened the report.
func TestTheSweepIntervalComesFromTheSetting(t *testing.T) {
	settings := &fakeSweepSettings{}
	sweeper := &Sweeper{Service: &Service{}, Settings: settings}

	for _, tc := range []struct {
		seconds int64
		want    time.Duration
		why     string
	}{
		{300, 5 * time.Minute, "the schema's default"},
		{60, time.Minute, "a shorter cadence an operator chose"},
		{3600, time.Hour, "a longer one"},
		// Not clamped up: zero means the operator asked for no periodic
		// reconciliation, and running it anyway would be the panel overriding
		// them.
		{0, 0, "off"},
		{-1, 0, "off, however it was spelled"},
		// Clamped down: a sweep lists every interface and reads every unit file.
		{1, MinSweepInterval, "below the floor"},
	} {
		settings.interval = tc.seconds
		if got := sweeper.Interval(); got != tc.want {
			t.Errorf("with the setting at %d (%s) the interval is %v, want %v",
				tc.seconds, tc.why, got, tc.want)
		}
	}

	// With no settings at all the schema's default stands rather than zero, so
	// a misconfigured panel still reconciles.
	if got := (&Sweeper{Service: &Service{}}).Interval(); got != DefaultSweepInterval {
		t.Errorf("with no settings the interval is %v, want the default %v", got, DefaultSweepInterval)
	}
}

// TestDriftIsOnlyReapPliedWhenTheOperatorAsked is the other half, and the part
// §12 is emphatic about: "Auto-reapply on drift only when
// system.auto_reapply_on_drift is explicitly enabled; default off."
//
// The setting had no consumer, so it was neither honoured nor disobeyed —
// nothing was watching for drift to respond to in the first place.
func TestDriftIsOnlyReappliedWhenTheOperatorAsked(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created := h.createTunnel(t)

	// Drift it the way §12 describes: change the MTU outside the panel.
	if err := h.links.SetMTU(ctx, created.InterfaceName, 1400); err != nil {
		t.Fatalf("changing the MTU outside the panel failed: %v", err)
	}
	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatalf("the report failed: %v", err)
	}
	var drifted bool
	for _, item := range report.Items {
		if item.InterfaceName == created.InterfaceName && item.Status == StatusDrifted {
			drifted = true
		}
	}
	if !drifted {
		t.Fatalf("the tunnel did not read as drifted after its MTU was changed: %+v", report.Items)
	}

	// Default off: the sweep reports and changes nothing.
	settings := &fakeSweepSettings{interval: 300, reapply: false}
	sweeper := &Sweeper{Service: h.service, Settings: settings}
	sweeper.Sweep(ctx)

	live, err := h.links.Get(ctx, created.InterfaceName)
	if err != nil {
		t.Fatalf("reading the interface back failed: %v", err)
	}
	if live.MTU != 1400 {
		t.Errorf("the sweep changed an interface with auto-reapply off: MTU is %d, want the "+
			"drifted 1400", live.MTU)
	}

	// Turned on, the same drift is repaired.
	settings.reapply = true
	sweeper.Sweep(ctx)

	live, err = h.links.Get(ctx, created.InterfaceName)
	if err != nil {
		t.Fatalf("reading the interface back failed: %v", err)
	}
	if live.MTU != int(created.Mtu) {
		t.Errorf("with auto-reapply on the drift was not repaired: MTU is %d, want %d",
			live.MTU, created.Mtu)
	}
}

// TestTheSweepNeverTouchesWhatItDoesNotManage holds §17.1 against the one code
// path that now runs without anybody asking it to. An unmanaged interface is
// somebody else's until a human says otherwise, and a sweep that adopted or
// removed one on a timer would be the worst possible reading of "reconcile".
func TestTheSweepNeverTouchesWhatItDoesNotManage(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.legacyTunnel(t, "gre-ir-15", 15, "172.17.15.1")
	before, err := h.links.Get(ctx, "gre-ir-15")
	if err != nil {
		t.Fatalf("reading the unmanaged interface failed: %v", err)
	}

	// Even with the most eager policy the operator can set.
	sweeper := &Sweeper{
		Service:  h.service,
		Settings: &fakeSweepSettings{interval: 300, reapply: true},
	}
	sweeper.Sweep(ctx)

	after, err := h.links.Get(ctx, "gre-ir-15")
	if err != nil {
		t.Fatalf("the sweep removed an interface the panel does not manage: %v", err)
	}
	if after.MTU != before.MTU || after.Index != before.Index {
		t.Errorf("the sweep altered an unmanaged interface: %+v -> %+v", before, after)
	}

	records, err := h.repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range records {
		if rec.InterfaceName == "gre-ir-15" {
			t.Error("the sweep adopted an unmanaged interface on a timer")
		}
	}
}

// TestStartAndStopAreQuietAndTerminate keeps the goroutine honest: §16 requires
// every goroutine to be owned by a context and to exit on shutdown.
func TestStartAndStopAreQuietAndTerminate(t *testing.T) {
	h := newHarness(t)
	sweeper := &Sweeper{
		Service:  h.service,
		Settings: &fakeSweepSettings{interval: 300},
	}

	sweeper.Start(context.Background())
	sweeper.Start(context.Background()) // a second start is a no-op, not a second goroutine

	done := make(chan struct{})
	go func() {
		sweeper.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep did not stop when it was asked to")
	}

	// Stopping twice must not panic on a closed channel.
	sweeper.Stop()
}
