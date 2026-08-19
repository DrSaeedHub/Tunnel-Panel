package route

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

// scriptedProber answers per address, so a test can have one backend stop
// listening while the other keeps answering.
type scriptedProber struct {
	mu   sync.Mutex
	down map[string]bool
}

func (p *scriptedProber) Probe(ctx context.Context, params ReachabilityParams) ReachabilityResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.down[params.Address] {
		return ReachabilityResult{
			Address: params.Address, Port: params.Port, Conclusive: true,
			Detail: "connection refused",
		}
	}
	return ReachabilityResult{
		Address: params.Address, Port: params.Port,
		Reachable: true, Conclusive: true, LatencyMs: 1.5, Detail: "connected",
	}
}

func (p *scriptedProber) set(address string, down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down[address] = down
}

// stubSettings answers the monitor's settings reads with nothing, so every
// value comes from the rule and the monitor's own fallbacks.
type stubSettings struct{}

func (stubSettings) Bool(string) bool     { return false }
func (stubSettings) Int(string) int64     { return 0 }
func (stubSettings) Float(string) float64 { return 0 }

type monitorHarness struct {
	ctx     context.Context
	repo    *Repo
	monitor *Monitor
	prober  *scriptedProber
	applies int
	clock   time.Time
}

// newMonitorHarness stores one rule across two destinations and returns a
// monitor over it, with the clock and the probe answers in the test's hands.
func newMonitorHarness(t *testing.T, mode int64) *monitorHarness {
	t.Helper()
	ctx, _, repo := openRepo(t)

	failures := int64(2)
	recoveries := int64(1)
	in := validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID:                model.NatModeMasquerade,
		LoadBalanceModeID:        model.LoadBalanceModeRoundRobin,
		IsEnabled:                true,
		IsMonitorEnabled:         boolPtr(true),
		MonitorModeID:            &mode,
		MonitorFailureThreshold:  &failures,
		MonitorRecoveryThreshold: &recoveries,
		Destinations: []validate.RouteDestinationInput{
			{Address: "198.51.100.20", Port: 2044, IsEnabled: true},
			{Address: "198.51.100.21", Port: 2044, IsEnabled: true},
		},
	}
	if _, err := repo.Insert(ctx, in); err != nil {
		t.Fatalf("storing the rule failed: %v", err)
	}

	h := &monitorHarness{
		ctx:    ctx,
		repo:   repo,
		prober: &scriptedProber{down: map[string]bool{}},
		clock:  time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC),
	}
	h.monitor = NewMonitor(MonitorDeps{
		Repo: repo, Prober: h.prober, Settings: stubSettings{}, Store: repo,
		Now:     func() time.Time { return h.clock },
		Reapply: func(context.Context) error { h.applies++; return nil },
	})
	return h
}

// probe advances the clock past any interval and takes one reading.
func (h *monitorHarness) probe() {
	h.clock = h.clock.Add(time.Minute)
	h.monitor.Sample(h.ctx)
}

// stateOf returns the monitor's verdict for one address.
func (h *monitorHarness) stateOf(t *testing.T, address string) DestinationHealth {
	t.Helper()
	for _, entry := range h.monitor.Health(1) {
		if entry.Address == address {
			return entry
		}
	}
	t.Fatalf("no monitoring state for %s", address)
	return DestinationHealth{}
}

// rotation returns the destinations the ruleset would actually be built from.
func (h *monitorHarness) rotation(t *testing.T) []string {
	t.Helper()
	rec, err := h.repo.ByID(h.ctx, 1)
	if err != nil {
		t.Fatalf("reading the rule failed: %v", err)
	}
	var out []string
	for _, d := range rec.Spec().Destinations {
		out = append(out, d.Address)
	}
	return out
}

func boolPtr(v bool) *bool { return &v }

// A single failed probe is a lost probe and not an outage, which is what the
// threshold is for.
func TestADestinationIsCalledDownOnlyAfterTheThreshold(t *testing.T) {
	h := newMonitorHarness(t, model.RouteMonitorModeReport)
	h.prober.set("198.51.100.21", true)

	h.probe()
	if got := h.stateOf(t, "198.51.100.21").State; got == DestinationStateDown {
		t.Errorf("one failed probe called the destination %s", got)
	}
	h.probe()
	if got := h.stateOf(t, "198.51.100.21").State; got != DestinationStateDown {
		t.Errorf("state after two failures = %q, want Down", got)
	}
	// The one still answering is not dragged down with it.
	if got := h.stateOf(t, "198.51.100.20").State; got != DestinationStateUp {
		t.Errorf("the healthy destination reads %q, want Up", got)
	}
}

// Reporting is the mode that changes nothing. The destination is named as down
// and keeps taking its share, because taking it out is a change to the
// installed ruleset and this rule did not ask for one.
func TestReportingNeverTakesADestinationOutOfTheRotation(t *testing.T) {
	h := newMonitorHarness(t, model.RouteMonitorModeReport)
	h.prober.set("198.51.100.21", true)

	h.probe()
	h.probe()
	h.probe()

	if got := h.stateOf(t, "198.51.100.21"); got.IsSuppressed {
		t.Errorf("a reporting rule suppressed a destination: %+v", got)
	}
	if got := h.rotation(t); len(got) != 2 {
		t.Errorf("rotation = %v, want both destinations", got)
	}
	if h.applies != 0 {
		t.Errorf("the ruleset was rebuilt %d times by a rule that only reports", h.applies)
	}
}

// Failover is the mode that does. The destination leaves the ruleset, the
// ruleset is rebuilt once rather than on every probe, and it comes back the
// moment the backend answers again.
func TestFailoverTakesADeadDestinationOutAndPutsItBack(t *testing.T) {
	h := newMonitorHarness(t, model.RouteMonitorModeFailover)
	h.prober.set("198.51.100.21", true)

	h.probe()
	h.probe()

	if !h.stateOf(t, "198.51.100.21").IsSuppressed {
		t.Fatal("a failed destination was left in the rotation by a failover rule")
	}
	if got := h.rotation(t); len(got) != 1 || got[0] != "198.51.100.20" {
		t.Errorf("rotation = %v, want only the destination that is answering", got)
	}
	if h.applies != 1 {
		t.Errorf("the ruleset was rebuilt %d times, want once", h.applies)
	}

	// A probe that confirms what is already true rebuilds nothing.
	h.probe()
	if h.applies != 1 {
		t.Errorf("a repeat of the same verdict rebuilt the ruleset again: %d", h.applies)
	}

	h.prober.set("198.51.100.21", false)
	h.probe()
	if h.stateOf(t, "198.51.100.21").IsSuppressed {
		t.Error("a recovered destination was left out of the rotation")
	}
	if got := h.rotation(t); len(got) != 2 {
		t.Errorf("rotation after recovery = %v, want both destinations", got)
	}
	if h.applies != 2 {
		t.Errorf("recovery rebuilt the ruleset %d times, want a second one", h.applies)
	}
}

// A rule with every destination down is a rule with nowhere to send traffic.
// Removing the last one turns a relay that is failing into a relay that does
// not exist, which is harder to diagnose and no better for the packets.
func TestFailoverNeverRemovesTheLastDestination(t *testing.T) {
	h := newMonitorHarness(t, model.RouteMonitorModeFailover)
	h.prober.set("198.51.100.20", true)
	h.prober.set("198.51.100.21", true)

	h.probe()
	h.probe()
	h.probe()

	// Both are reported down, which is the truth and is the point of reporting.
	for _, address := range []string{"198.51.100.20", "198.51.100.21"} {
		if got := h.stateOf(t, address).State; got != DestinationStateDown {
			t.Errorf("%s reads %q, want Down", address, got)
		}
	}
	// And nothing was taken out: emptying the rotation would have replaced a
	// failing relay with one that does not exist.
	if got := h.rotation(t); len(got) != 2 {
		t.Errorf("rotation = %v, want both left in when neither can be spared", got)
	}
	if h.applies != 0 {
		t.Errorf("the ruleset was rebuilt %d times to change nothing", h.applies)
	}
}

// Turning monitoring off must not leave a destination out of a rotation that
// nothing is watching any more.
func TestATurnedOffMonitorReturnsWhatItTookOut(t *testing.T) {
	h := newMonitorHarness(t, model.RouteMonitorModeFailover)
	h.prober.set("198.51.100.21", true)

	h.probe()
	h.probe()
	if got := h.rotation(t); len(got) != 1 {
		t.Fatalf("rotation = %v, want the failed destination removed first", got)
	}

	rec, err := h.repo.ByID(h.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	in := inputFrom(rec)
	in.IsMonitorEnabled = boolPtr(false)
	if err := h.repo.Update(h.ctx, 1, in); err != nil {
		t.Fatalf("turning monitoring off failed: %v", err)
	}

	h.probe()
	if got := h.rotation(t); len(got) != 2 {
		t.Errorf("rotation = %v, want both back once nothing is watching", got)
	}
	if got := h.stateOf(t, "198.51.100.21").State; got != DestinationStateDisabled {
		t.Errorf("an unmonitored destination reads %q, want Disabled", got)
	}
}

// inputFrom turns a stored rule back into the request that would recreate it,
// which is what an edit through the API amounts to.
func inputFrom(rec Record) validate.RouteInput {
	in := validate.RouteInput{
		RouteRuleID:              rec.RouteRuleID,
		RouteRuleTitle:           rec.RouteRuleTitle,
		RouteProtocolID:          rec.RouteProtocolID,
		AddressFamilyID:          rec.AddressFamilyID,
		BindAddress:              rec.BindAddress,
		BindPort:                 int(rec.BindPort),
		DestinationAddress:       rec.DestinationAddress,
		DestinationPort:          int(rec.DestinationPort),
		NatModeID:                rec.NatModeID,
		LoadBalanceModeID:        rec.LoadBalanceModeID,
		IsEnabled:                rec.IsEnabled,
		IsMonitorEnabled:         rec.IsMonitorEnabled,
		MonitorModeID:            rec.MonitorModeID,
		MonitorFailureThreshold:  rec.MonitorFailureThreshold,
		MonitorRecoveryThreshold: rec.MonitorRecoveryThreshold,
	}
	for _, d := range rec.Destinations {
		in.Destinations = append(in.Destinations, validate.RouteDestinationInput{
			Address: d.Address, Port: int(d.Port), Weight: int(d.Weight), IsEnabled: d.IsEnabled,
		})
	}
	return in
}
