package route

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// newAccounting returns accounting over a fresh database with one stored rule,
// backed by a fake netfilter backend whose counters a test drives directly.
func newAccounting(t *testing.T) (context.Context, *Accounting, *rules.Fake, *Repo) {
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

	backend := rules.NewFake()
	accounting := NewAccounting(AccountingDeps{
		Repo: NewCounterRepo(database), Routes: repo, Backend: backend,
		Conntrack: NewFakeConntrack(),
	})
	if err := accounting.Load(ctx); err != nil {
		t.Fatalf("loading the accounting failed: %v", err)
	}
	return ctx, accounting, backend, repo
}

func counter(id int64, rx, tx uint64) map[int64]rules.Counter {
	return map[int64]rules.Counter{id: {
		RouteRuleID: id, RxBytes: rx, TxBytes: tx,
		RxPackets: rx / 100, TxPackets: tx / 100,
	}}
}

// TestCumulativeTotalsSurviveACounterReset is the requirement of §5.2. Every
// edit, enable, disable and reboot rebuilds the ruleset and zeroes the kernel's
// counters; presenting the counter that has just restarted as a lifetime total
// is a correctness bug, and here it would happen constantly.
func TestCumulativeTotalsSurviveACounterReset(t *testing.T) {
	ctx, accounting, _, _ := newAccounting(t)
	now := time.Now()

	// Traffic accumulates in the kernel's counter.
	accounting.Observe(counter(1, 1_000, 4_000), now)
	accounting.Observe(counter(1, 5_000, 20_000), now.Add(time.Second))

	traffic, ok := accounting.Traffic(1)
	if !ok {
		t.Fatal("the rule has no traffic figures")
	}
	// The first sighting starts the total rather than being added to it, so the
	// panel's total is what moved after it: 4000 in, 16000 out.
	if traffic.RxBytesSinceCreation != 4_000 || traffic.TxBytesSinceCreation != 16_000 {
		t.Fatalf("before the reset the totals are rx=%d tx=%d, want 4000/16000",
			traffic.RxBytesSinceCreation, traffic.TxBytesSinceCreation)
	}
	if traffic.RxBytesSinceBoot != 5_000 || traffic.TxBytesSinceBoot != 20_000 {
		t.Errorf("the kernel's own counters are not reported: rx=%d tx=%d",
			traffic.RxBytesSinceBoot, traffic.TxBytesSinceBoot)
	}

	// The ruleset is rebuilt, which zeroes the counters, and traffic resumes.
	accounting.Observe(counter(1, 300, 900), now.Add(2*time.Second))

	traffic, _ = accounting.Traffic(1)
	if !traffic.ResetDetected {
		t.Error("the counter restart was not detected, so the total is now wrong")
	}
	// The whole of the new counter is added: after a rebuild every byte it
	// holds is new.
	if traffic.RxBytesSinceCreation != 4_300 || traffic.TxBytesSinceCreation != 16_900 {
		t.Errorf("after the reset the totals are rx=%d tx=%d, want 4300/16900",
			traffic.RxBytesSinceCreation, traffic.TxBytesSinceCreation)
	}
	// The two figures are never blended: since-boot went backwards while
	// since-creation did not.
	if traffic.RxBytesSinceBoot != 300 {
		t.Errorf("the since-boot figure is %d, want the kernel's own 300", traffic.RxBytesSinceBoot)
	}

	// And the totals survive a restart of the panel, because they are written
	// down rather than only held in memory.
	if err := accounting.Flush(ctx); err != nil {
		t.Fatalf("writing the totals down failed: %v", err)
	}
	reloaded := NewAccounting(AccountingDeps{Repo: accounting.repo, Routes: accounting.routes})
	if err := reloaded.Load(ctx); err != nil {
		t.Fatalf("reloading failed: %v", err)
	}
	reloaded.mu.RLock()
	stored := reloaded.state[1]
	reloaded.mu.RUnlock()
	if stored == nil || stored.RxBytesTotal != 4_300 || stored.TxBytesTotal != 16_900 {
		t.Errorf("the persisted totals are %+v, want 4300/16900", stored)
	}
}

// TestSnapshotFoldsTheCountersBeforeARebuild covers the other half of §5.2: the
// pipeline snapshots immediately before replacing the ruleset, so the traffic
// counted since the last sample is folded in rather than lost with the counter
// that held it.
func TestSnapshotFoldsTheCountersBeforeARebuild(t *testing.T) {
	ctx, accounting, backend, _ := newAccounting(t)

	backend.SetCounters(counter(1, 1_000, 1_000))
	accounting.Sample(ctx)

	// Traffic moves, and then the operator edits the rule.
	backend.SetCounters(counter(1, 9_000, 9_000))
	if err := accounting.Snapshot(ctx); err != nil {
		t.Fatalf("Snapshot returned an unexpected error: %v", err)
	}

	// The snapshot both folded and persisted, so a crash between here and the
	// next sample loses nothing.
	volumes, err := accounting.repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 1 || volumes[0].RxBytesTotal != 8_000 {
		t.Fatalf("the snapshot stored %+v, want 8000 folded in", volumes)
	}

	// Now the rebuild happens and the counters restart from nothing.
	backend.SetCounters(counter(1, 0, 0))
	accounting.Sample(ctx)

	traffic, _ := accounting.Traffic(1)
	if traffic.RxBytesSinceCreation != 8_000 {
		t.Errorf("after the rebuild the total is %d, want the 8000 the snapshot saved",
			traffic.RxBytesSinceCreation)
	}
}

// TestRatesAreComputedOverTheRealInterval: a rate is bytes divided by the gap
// the bytes were counted over, not by the interval that was configured.
func TestRatesAreComputedOverTheRealInterval(t *testing.T) {
	_, accounting, _, _ := newAccounting(t)
	now := time.Now()

	accounting.Observe(counter(1, 0, 0), now)
	accounting.Observe(counter(1, 500, 2_000), now.Add(2*time.Second))

	traffic, _ := accounting.Traffic(1)
	if traffic.RxBytesPerSecond != 250 || traffic.TxBytesPerSecond != 1_000 {
		t.Errorf("the rates are rx=%.0f tx=%.0f, want 250/1000",
			traffic.RxBytesPerSecond, traffic.TxBytesPerSecond)
	}
	if traffic.IntervalSeconds != 2 {
		t.Errorf("the interval is reported as %.1f, want the real 2 seconds", traffic.IntervalSeconds)
	}

	points := accounting.History(1, 0)
	if len(points) != 2 {
		t.Fatalf("the ring buffer holds %d points, want 2", len(points))
	}
	if points[1].RxBytes != 500 {
		t.Errorf("the last point holds %d bytes, want the 500 of that interval", points[1].RxBytes)
	}
}

// TestForgetDropsEverythingAboutADeletedRule.
func TestForgetDropsEverythingAboutADeletedRule(t *testing.T) {
	ctx, accounting, _, _ := newAccounting(t)
	accounting.Observe(counter(1, 100, 100), time.Now())
	if err := accounting.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	if err := accounting.Forget(ctx, 1); err != nil {
		t.Fatalf("Forget returned an unexpected error: %v", err)
	}
	if _, ok := accounting.Traffic(1); ok {
		t.Error("the deleted rule still has live figures")
	}
	volumes, err := accounting.repo.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 0 {
		t.Errorf("the stored counter survived the delete: %+v", volumes)
	}
}

// TestAggregateRowsAreWrittenAndPruned covers the history half of §5.4.
func TestAggregateRowsAreWrittenAndPruned(t *testing.T) {
	ctx, accounting, _, _ := newAccounting(t)
	now := time.Now()

	accounting.Observe(counter(1, 0, 0), now)
	accounting.Observe(counter(1, 4_000, 8_000), now.Add(time.Second))
	accounting.WriteAggregates(ctx)

	samples, err := accounting.StoredHistory(ctx, 1, now.Add(-time.Hour), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("stored %d history rows, want 1", len(samples))
	}
	if samples[0].RxBytes != 4_000 || samples[0].TxBytes != 8_000 {
		t.Errorf("the bucket holds rx=%d tx=%d, want 4000/8000", samples[0].RxBytes, samples[0].TxBytes)
	}

	// A quiet interval writes nothing rather than filling the table with zeroes.
	accounting.Observe(counter(1, 4_000, 8_000), now.Add(2*time.Second))
	accounting.WriteAggregates(ctx)
	samples, _ = accounting.StoredHistory(ctx, 1, now.Add(-time.Hour), 0)
	if len(samples) != 1 {
		t.Errorf("a quiet interval stored a row: %d rows", len(samples))
	}
}

// TestConnectionsAreAttributedToTheRuleThatCreatedThem covers §5.3: the flows
// are matched on what the client connected to, which is what survives every NAT
// mode.
func TestConnectionsAreAttributedToTheRuleThatCreatedThem(t *testing.T) {
	ctx, accounting, _, _ := newAccounting(t)

	fake := NewFakeConntrack(
		Flow{Protocol: "tcp", SourceAddress: "192.0.2.5", SourcePort: 51234,
			BindAddress: "203.0.113.10", BindPort: 2044,
			DestinationAddress: "198.51.100.20", DestinationPort: 2044, State: "ESTABLISHED"},
		Flow{Protocol: "tcp", SourceAddress: "192.0.2.6", SourcePort: 51235,
			BindAddress: "203.0.113.10", BindPort: 2044,
			DestinationAddress: "198.51.100.20", DestinationPort: 2044, State: "ESTABLISHED"},
		// Somebody else's connection to a different port on the same address.
		Flow{Protocol: "tcp", SourceAddress: "192.0.2.7", SourcePort: 51236,
			BindAddress: "203.0.113.10", BindPort: 22, State: "ESTABLISHED"},
	)
	accounting.conntrack = fake

	counts := accounting.SampleConnections(ctx)
	if counts[1].Active != 2 {
		t.Errorf("the rule was credited with %d connections, want its own 2", counts[1].Active)
	}
	// The first reading has nothing to compare against, so nothing is new.
	if counts[1].New != 0 {
		t.Errorf("the first reading reported %d new connections, want 0", counts[1].New)
	}

	// One goes away and two arrive.
	fake.List = []Flow{
		{Protocol: "tcp", SourceAddress: "192.0.2.5", SourcePort: 51234,
			BindAddress: "203.0.113.10", BindPort: 2044},
		{Protocol: "tcp", SourceAddress: "192.0.2.8", SourcePort: 51240,
			BindAddress: "203.0.113.10", BindPort: 2044},
		{Protocol: "tcp", SourceAddress: "192.0.2.9", SourcePort: 51241,
			BindAddress: "203.0.113.10", BindPort: 2044},
	}
	counts = accounting.SampleConnections(ctx)
	if counts[1].Active != 3 {
		t.Errorf("the rule has %d active connections, want 3", counts[1].Active)
	}
	if counts[1].New != 2 {
		t.Errorf("%d connections were counted as new, want the 2 that appeared", counts[1].New)
	}
}

// TestParseConntrackLineReadsBothTuples: the /proc fallback has to attribute a
// flow to the rule and name the destination that actually took it.
func TestParseConntrackLineReadsBothTuples(t *testing.T) {
	const line = "ipv4     2 tcp      6 431995 ESTABLISHED src=192.0.2.5 dst=203.0.113.10 " +
		"sport=51234 dport=2044 packets=12 bytes=1440 src=198.51.100.20 dst=203.0.113.10 " +
		"sport=2044 dport=51234 packets=10 bytes=1200 [ASSURED] mark=0 zone=0 use=2"

	flow, ok := ParseConntrackLine(line)
	if !ok {
		t.Fatal("the line was not parsed")
	}
	if flow.Protocol != "tcp" || flow.State != "ESTABLISHED" {
		t.Errorf("protocol %q state %q", flow.Protocol, flow.State)
	}
	if flow.SourceAddress != "192.0.2.5" || flow.SourcePort != 51234 {
		t.Errorf("the client is %s:%d", flow.SourceAddress, flow.SourcePort)
	}
	if flow.BindAddress != "203.0.113.10" || flow.BindPort != 2044 {
		t.Errorf("what the client connected to is %s:%d", flow.BindAddress, flow.BindPort)
	}
	if flow.DestinationAddress != "198.51.100.20" || flow.DestinationPort != 2044 {
		t.Errorf("where it went is %s:%d", flow.DestinationAddress, flow.DestinationPort)
	}
	if flow.TxBytes != 1440 || flow.RxBytes != 1200 {
		t.Errorf("the byte counters are tx=%d rx=%d, want 1440/1200", flow.TxBytes, flow.RxBytes)
	}
	if flow.TimeoutSeconds != 431995 {
		t.Errorf("the timeout is %d", flow.TimeoutSeconds)
	}

	// A UDP flow has no state, and inventing one would be worse than saying so.
	const udp = "ipv4     2 udp      17 29 src=192.0.2.5 dst=203.0.113.10 sport=5000 dport=5353 " +
		"packets=2 bytes=200 src=198.51.100.20 dst=203.0.113.10 sport=5353 dport=5000 " +
		"packets=1 bytes=100 mark=0 use=2"
	udpFlow, ok := ParseConntrackLine(udp)
	if !ok {
		t.Fatal("the UDP line was not parsed")
	}
	if udpFlow.State != "" {
		t.Errorf("a UDP flow was given the state %q", udpFlow.State)
	}
	if udpFlow.Protocol != "udp" || udpFlow.BindPort != 5353 {
		t.Errorf("the UDP flow was misread: %+v", udpFlow)
	}
}

// TestSinceBootMeaningIsCarriedWithTheFigures: the shorter label is not
// self-explanatory, so the explanation travels with the numbers.
func TestSinceBootMeaningIsCarriedWithTheFigures(t *testing.T) {
	if !strings.Contains(SinceBootMeaning, "never added together") {
		t.Error("the note does not say the two figures must not be blended")
	}
}

// What an operator watching a relay wants is not the bytes standing on the open
// connections but the ones moving. They are subtracted per flow, because a
// destination's total falls whenever one of its connections closes and a
// difference taken on the totals reports that fall as negative throughput.
func TestWhatMovedToEachDestinationIsSubtractedPerFlow(t *testing.T) {
	state := newConntrackState()
	spec := rules.RouteSpec{
		RouteRuleID: 1, Protocol: rules.ProtocolTCP,
		BindAddress: "203.0.113.10", BindPorts: rules.PortRange{Port: 2044},
	}
	at := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	flow := func(source string, destination string, rx, tx uint64) Flow {
		return Flow{
			Protocol: "tcp", SourceAddress: source, SourcePort: 51234,
			BindAddress: "203.0.113.10", BindPort: 2044,
			DestinationAddress: destination, DestinationPort: 2044,
			RxBytes: rx, TxBytes: tx,
		}
	}

	// The first reading has nothing to subtract from, so it is not a rate.
	first := []Flow{
		flow("192.0.2.5", "198.51.100.20", 1_000, 500),
		flow("192.0.2.6", "198.51.100.21", 2_000, 1_000),
	}
	counts := state.observe([]rules.RouteSpec{spec}, first, at)
	if counts[1].RateIntervalSeconds != 0 {
		t.Fatalf("the first reading produced a rate over %v", counts[1].RateIntervalSeconds)
	}
	if len(counts[1].ByDestination) != 2 {
		t.Fatalf("by destination = %+v, want both destinations", counts[1].ByDestination)
	}

	// Five seconds later: one flow moved, one has gone, and one is new. The
	// one that is new did not exist at the last reading, so everything on it
	// moved inside the gap and all of it counts.
	second := []Flow{
		flow("192.0.2.5", "198.51.100.20", 11_000, 5_500),
		flow("192.0.2.9", "198.51.100.21", 3_000, 1_500),
	}
	counts = state.observe([]rules.RouteSpec{spec}, second, at.Add(5*time.Second))
	if counts[1].RateIntervalSeconds != 5 {
		t.Fatalf("interval = %v, want the five seconds between the readings",
			counts[1].RateIntervalSeconds)
	}

	byAddress := map[string]DestinationLoad{}
	for _, entry := range counts[1].ByDestination {
		byAddress[entry.Address] = entry
	}
	// 10_000 bytes over five seconds on the flow that was there both times.
	if got := byAddress["198.51.100.20"]; got.RxBytesPerSecond != 2000 || got.TxBytesPerSecond != 1000 {
		t.Errorf("the continuing flow moved %+v, want 2000/1000 per second", got)
	}
	// The whole of the new flow, and nothing from the one that disappeared.
	if got := byAddress["198.51.100.21"]; got.RxBytesPerSecond != 600 || got.TxBytesPerSecond != 300 {
		t.Errorf("the new flow moved %+v, want 600/300 per second", got)
	}

	// A reading taken hours later is not a measurement of anything.
	counts = state.observe([]rules.RouteSpec{spec}, second, at.Add(6*time.Hour))
	if counts[1].RateIntervalSeconds != 0 {
		t.Error("two readings six hours apart were reported as a rate")
	}
}
