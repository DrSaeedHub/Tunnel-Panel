package monitor

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/tunnel"
)

// fakeTunnels is the set of tunnels the supervisor should monitor.
type fakeTunnels struct {
	mu      sync.Mutex
	records []tunnel.Record
}

func (f *fakeTunnels) List(ctx context.Context) ([]tunnel.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]tunnel.Record(nil), f.records...), nil
}

func (f *fakeTunnels) set(records ...tunnel.Record) {
	f.mu.Lock()
	f.records = records
	f.mu.Unlock()
}

// monitoredTunnel builds a tunnel record with an address and a peer, which is
// the minimum a prober needs.
func monitoredTunnel(id int64, name, source, target string) tunnel.Record {
	peer := target
	rec := tunnel.Record{}
	rec.TunnelID = id
	rec.InterfaceName = name
	rec.IsEnabled = true
	rec.Addresses = []model.TunnelAddress{{
		TunnelID: id, Address: source, PrefixLength: 30, PeerAddress: &peer, IsPrimary: true,
	}}
	return rec
}

type harness struct {
	supervisor *Supervisor
	tunnels    *fakeTunnels
	dialer     *fakeDialer
	settings   *settings.Store
	links      *link.Fake
	store      *Store
	database   *db.DB
}

// seedTunnelRow inserts the minimum Tunnel row the monitoring tables' foreign
// keys need. The supervisor reads tunnels through an interface, but the history
// it writes references the real table.
func (h *harness) seedTunnelRow(t *testing.T, id int64, name string) {
	t.Helper()
	now := model.NowUTC()
	_, err := h.database.Write.Exec(`
		INSERT INTO Tunnel (TunnelID, TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName,
			LocalEndpoint, RemoteEndpoint, Ttl, Tos, Mtu, ApplyStatusID, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, '203.0.113.10', '198.51.100.20', 255, 'inherit', 1472, ?, ?, ?, 0)`,
		id, model.TunnelTypeGRE, model.TunnelSideA, model.PersistenceTypeRuntime, name,
		model.ApplyStatusApplied, now, now)
	if err != nil {
		t.Fatalf("seeding tunnel row %d failed: %v", id, err)
	}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
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
	// Probe fast so the tests do not have to wait a second per sample.
	if _, err := store.Update(ctx, map[string]any{
		"monitor.interval_seconds":     0.2,
		"monitor.timeout_seconds":      0.2,
		"monitor.state_change_samples": 1,
		"monitor.window_size":          10,
	}, nil); err != nil {
		t.Fatalf("configuring the test settings failed: %v", err)
	}

	tunnels := &fakeTunnels{}
	dialer := newFakeDialer()
	links := link.NewFake()

	supervisor := New(Deps{
		Tunnels:  tunnels,
		Store:    NewStore(database),
		Settings: store,
		Links:    links,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dialer:   dialer,
	})
	return &harness{
		supervisor: supervisor, tunnels: tunnels, dialer: dialer,
		settings: store, links: links, store: NewStore(database), database: database,
	}
}

// answerEverything makes the fake network reply to every probe, which is what a
// reachable peer does.
func answerEverything(d *fakeDialer) {
	d.OnWrite = func(c *fakeConn, id, sequence int, payload []byte) {
		c.deliver(replyTo(id, sequence, payload), nil)
	}
}

// eventually polls until the condition holds or the deadline passes.
func eventually(t *testing.T, why string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", why)
}

// ---------------------------------------------------------------- the prober

func TestProberReachesUpWhenThePeerAnswers(t *testing.T) {
	h := newHarness(t)
	answerEverything(h.dialer)
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatalf("starting the supervisor failed: %v", err)
	}
	defer h.supervisor.Stop()

	eventually(t, "the tunnel to be reported up", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.MonitorStateID == model.MonitorStateUp
	})

	snapshot, _ := h.supervisor.Snapshot(1)
	if snapshot.Stats.Received == 0 {
		t.Fatalf("no replies were counted: %+v", snapshot.Stats)
	}
	if snapshot.Stats.RttAvgMs == nil {
		t.Fatal("a round-trip time must be measured from the packet's own timestamp")
	}
	if snapshot.Source != "172.17.1.1" || snapshot.Target != "172.17.1.2" {
		t.Fatalf("the snapshot names the wrong endpoints: %+v", snapshot)
	}
}

func TestProberReachesDownWhenNothingAnswers(t *testing.T) {
	h := newHarness(t)
	h.seedTunnelRow(t, 1, "gre-a-1")
	// The fake network swallows everything: no replies at all.
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	eventually(t, "the tunnel to be reported down", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.MonitorStateID == model.MonitorStateDown
	})

	// The transition is recorded, which is what the history view reads.
	eventually(t, "the transition to be written", func() bool {
		events, err := h.store.Events(context.Background(), 1, 10)
		return err == nil && len(events) > 0
	})
	events, _ := h.store.Events(context.Background(), 1, 10)
	if events[0].ToMonitorStateID != model.MonitorStateDown {
		t.Fatalf("the recorded transition is %+v", events[0])
	}
	if events[0].Reason == "" {
		t.Fatal("a recorded transition must say why")
	}
}

// ---------------------------------------------------------------- supervision

// Probers follow the tunnels without a restart: created, deleted, enabled and
// disabled all take effect immediately (§10.3).
func TestSupervisorFollowsTheTunnels(t *testing.T) {
	h := newHarness(t)
	answerEverything(h.dialer)

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	if h.supervisor.Running() != 0 {
		t.Fatal("nothing should be probed before there are tunnels")
	}

	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))
	h.supervisor.TunnelsChanged()
	eventually(t, "a prober to start", func() bool { return h.supervisor.Running() == 1 })

	// A second tunnel gets its own socket and its own identifier.
	h.tunnels.set(
		monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"),
		monitoredTunnel(2, "gre-a-2", "172.17.2.1", "172.17.2.2"),
	)
	h.supervisor.TunnelsChanged()
	eventually(t, "a second prober to start", func() bool { return h.supervisor.Running() == 2 })

	// Disabling a tunnel stops its prober and reports why, rather than making
	// the tunnel vanish from the display.
	disabled := monitoredTunnel(2, "gre-a-2", "172.17.2.1", "172.17.2.2")
	disabled.IsEnabled = false
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"), disabled)
	h.supervisor.TunnelsChanged()
	eventually(t, "the disabled tunnel's prober to stop", func() bool { return h.supervisor.Running() == 1 })

	snapshot, ok := h.supervisor.Snapshot(2)
	if !ok || snapshot.MonitorStateID != model.MonitorStateDisabled {
		t.Fatalf("a disabled tunnel must still be reported: %+v %v", snapshot, ok)
	}
	if snapshot.Reason == "" {
		t.Fatal("a disabled tunnel must say why it is not monitored")
	}

	// Deleting it removes it entirely.
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))
	h.supervisor.TunnelsChanged()
	eventually(t, "the deleted tunnel to disappear", func() bool {
		_, ok := h.supervisor.Snapshot(2)
		return !ok
	})
}

// Monitoring switched off per tunnel is honoured, and switching it back on
// starts the prober again without a restart.
func TestPerTunnelMonitorToggle(t *testing.T) {
	h := newHarness(t)
	answerEverything(h.dialer)

	off := false
	rec := monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2")
	rec.IsMonitorEnabled = &off
	h.tunnels.set(rec)

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	eventually(t, "the tunnel to be reported disabled", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.MonitorStateID == model.MonitorStateDisabled
	})

	on := true
	rec.IsMonitorEnabled = &on
	h.tunnels.set(rec)
	h.supervisor.TunnelsChanged()

	eventually(t, "the prober to start", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.MonitorStateID == model.MonitorStateUp
	})
}

// A settings change reconfigures live probers; nothing restarts the process
// (§5.3, §10.3).
func TestSettingsChangeTakesEffectWithoutARestart(t *testing.T) {
	h := newHarness(t)
	answerEverything(h.dialer)
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	eventually(t, "the prober to start", func() bool { return h.supervisor.Running() == 1 })
	before := h.dialer.listenCount()

	// A threshold change needs no new socket, so the prober is reconfigured in
	// place rather than torn down and rebuilt.
	if _, err := h.settings.Update(ctx, map[string]any{"monitor.degraded_loss_pct": 5.0}, nil); err != nil {
		t.Fatal(err)
	}
	h.supervisor.SettingsChanged([]string{"monitor.degraded_loss_pct"})

	eventually(t, "the new threshold to be picked up", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.Enabled
	})
	if h.dialer.listenCount() != before {
		t.Fatal("a threshold change must not re-open the socket")
	}

	// Switching monitoring off globally stops every prober.
	if _, err := h.settings.Update(ctx, map[string]any{"monitor.enabled": false}, nil); err != nil {
		t.Fatal(err)
	}
	h.supervisor.SettingsChanged([]string{"monitor.enabled"})
	eventually(t, "every prober to stop", func() bool { return h.supervisor.Running() == 0 })
}

// An interface that vanishes is Down at once with a specific reason, rather
// than being discovered one probe timeout at a time (§10.3).
func TestVanishedInterfaceIsReportedImmediately(t *testing.T) {
	h := newHarness(t)
	answerEverything(h.dialer)
	h.links.AddLink(link.Link{Name: "gre-a-1", Kind: link.KindGRE, Index: 3})
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	eventually(t, "the tunnel to be reported up", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.MonitorStateID == model.MonitorStateUp
	})

	if err := h.links.Delete(ctx, "gre-a-1"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the vanished interface to be reported down", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.MonitorStateID == model.MonitorStateDown &&
			snapshot.Reason == ReasonInterfaceMissing
	})

	// And the reason must not outlive the fact. A socket bound to an address
	// survives that address being removed — writes simply start failing — so
	// the prober need never restart, and without something clearing the reason
	// a recovered tunnel goes on reporting its interface as missing.
	h.links.AddLink(link.Link{
		Name: "gre-a-1", Kind: link.KindGRE, Index: 3, IsUp: true, IsLowerUp: true,
	})
	h.links.Publish(link.Event{
		Kind: link.EventAdded,
		Link: link.Link{Name: "gre-a-1", Kind: link.KindGRE, Index: 3, IsUp: true},
	})
	eventually(t, "the recovered interface to be explained by measurement again", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.Reason != ReasonInterfaceMissing && snapshot.Reason != ""
	})
}

// A prober whose socket cannot be opened is retried with backoff rather than
// abandoned (§10.3).
func TestFailedProberIsRetried(t *testing.T) {
	h := newHarness(t)
	h.dialer.Err = errDialFailed
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	eventually(t, "the failure to be reported", func() bool {
		snapshot, ok := h.supervisor.Snapshot(1)
		return ok && snapshot.Reason != "" && snapshot.MonitorStateID == model.MonitorStateUnknown
	})
	// The supervisor keeps the worker: it is retrying, not gone.
	if h.supervisor.Running() != 1 {
		t.Fatal("a failing prober must stay registered so it can be retried")
	}
}

// The interface coming back cuts the backoff short (§10.3).
//
// A prober cannot bind to an address that does not exist yet, which is exactly
// what happens while a tunnel is being rebuilt. The backoff doubles to two
// minutes, so without acting on the netlink event that says the interface is
// back, monitoring stays dark for up to that long after the cause is gone —
// even though the panel has already been told.
func TestAReturningInterfaceCutsTheBackoffShort(t *testing.T) {
	h := newHarness(t)
	h.dialer.Err = errDialFailed
	h.tunnels.set(monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"))

	ctx := context.Background()
	if err := h.supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer h.supervisor.Stop()

	// Let it fail enough times that the next retry is seconds away rather than
	// milliseconds: after waits of 1s and 2s, the third failure earns a 4s one.
	eventually(t, "the prober to have failed several times", func() bool {
		return h.dialer.attemptCount() >= 3
	})
	failed := h.dialer.attemptCount()

	// The socket works again and the interface is announced.
	h.dialer.setErr(nil)
	h.links.AddLink(link.Link{
		Name: "gre-a-1", Index: 5, MTU: 1472, Kind: link.KindGRE,
		OperState: "UNKNOWN", IsUp: true, IsLowerUp: true,
	})
	h.links.Publish(link.Event{Kind: link.EventAdded, Link: link.Link{Name: "gre-a-1", IsUp: true}})

	// Well inside the 4-second wait the prober would otherwise be serving.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.dialer.attemptCount() > failed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the prober did not retry after its interface came back: still %d attempts", failed)
}

// ---------------------------------------------------------------- the hub

// Every subscriber receives events and every goroutine exits on disconnect;
// with -race this also proves there is no data race in the fan-out (§10.5).
func TestHubFansOutAndCleansUp(t *testing.T) {
	hub := NewHub()

	const subscribers = 8
	var wg sync.WaitGroup
	received := make([]int, subscribers)
	ids := make([]int, subscribers)
	channels := make([]<-chan Snapshot, subscribers)

	for i := 0; i < subscribers; i++ {
		ids[i], channels[i] = hub.Subscribe()
	}
	if hub.Subscribers() != subscribers {
		t.Fatalf("hub has %d subscribers, want %d", hub.Subscribers(), subscribers)
	}

	for i := 0; i < subscribers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for range channels[i] {
				received[i]++
			}
		}(i)
	}

	for i := 0; i < 5; i++ {
		hub.Publish(Snapshot{TunnelID: 1, State: "Up"})
	}

	// Unsubscribing closes the channel, which is what ends the goroutine.
	for _, id := range ids {
		hub.Unsubscribe(id)
	}
	wg.Wait()

	if hub.Subscribers() != 0 {
		t.Fatalf("%d subscribers survived disconnect", hub.Subscribers())
	}
	for i, count := range received {
		if count == 0 {
			t.Fatalf("subscriber %d received nothing", i)
		}
	}

	// Publishing after everyone has gone is harmless, and a late subscriber to a
	// closed hub gets a closed channel rather than hanging.
	hub.Publish(Snapshot{TunnelID: 2})
	hub.Close()
	_, ch := hub.Subscribe()
	if _, open := <-ch; open {
		t.Fatal("subscribing to a closed hub must return a closed channel")
	}
}

// A subscriber that never reads must not stall the measurement loop.
func TestSlowSubscriberDoesNotBlockPublishing(t *testing.T) {
	hub := NewHub()
	id, _ := hub.Subscribe() // deliberately never read
	defer hub.Unsubscribe(id)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < subscriberBuffer*4; i++ {
			hub.Publish(Snapshot{TunnelID: int64(i)})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publishing blocked on a subscriber that was not reading")
	}
}

// ---------------------------------------------------------------- shutdown

// Stopping closes every socket and leaves no goroutine behind (§10.3).
func TestStopClosesEverySocket(t *testing.T) {
	h := newHarness(t)
	answerEverything(h.dialer)
	h.tunnels.set(
		monitoredTunnel(1, "gre-a-1", "172.17.1.1", "172.17.1.2"),
		monitoredTunnel(2, "gre-a-2", "172.17.2.1", "172.17.2.2"),
	)

	if err := h.supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "both probers to start", func() bool { return h.supervisor.Running() == 2 })

	h.supervisor.Stop()

	if h.supervisor.Running() != 0 {
		t.Fatalf("%d probers survived the shutdown", h.supervisor.Running())
	}
	for _, source := range []string{"172.17.1.1", "172.17.2.1"} {
		conn := h.dialer.conn(source)
		if conn == nil {
			continue
		}
		conn.mu.Lock()
		closed := conn.closed
		conn.mu.Unlock()
		if !closed {
			t.Fatalf("the socket bound to %s was left open", source)
		}
	}
}
