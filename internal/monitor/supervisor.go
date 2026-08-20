package monitor

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/tunnel"
)

// Backoff bounds for restarting a failed prober (§10.3).
const (
	minBackoff = 1 * time.Second
	maxBackoff = 2 * time.Minute
	// stableRun is how long a prober must have run for its failure to count as
	// a fresh problem rather than a continuation of the last one.
	stableRun = 30 * time.Second
)

// reconcileInterval is the backstop sweep. Changes normally arrive by
// notification; this catches anything that did not.
const reconcileInterval = 30 * time.Second

// TunnelSource is the set of tunnels to monitor.
type TunnelSource interface {
	List(ctx context.Context) ([]tunnel.Record, error)
}

// Supervisor owns every prober: it starts them, stops them, restarts the ones
// that fail, and keeps them in step with the tunnels and the settings (§10.3).
type Supervisor struct {
	tunnels  TunnelSource
	store    *Store
	settings Settings
	links    link.LinkManager
	hub      *Hub
	log      *slog.Logger
	dialer   Dialer
	traffic  TrafficReader
	peer     PeerChecker

	aggregator *aggregator

	mu      sync.Mutex
	running map[int64]*worker
	// disabled holds the last snapshot of tunnels that are known but not
	// probed, so the status endpoint can say why rather than returning nothing.
	disabled map[int64]Snapshot

	notify chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// started guards against a second Start.
	started bool
}

// worker is one running prober and the goroutine supervising it.
type worker struct {
	prober *prober
	cancel context.CancelFunc
	done   chan struct{}
	// wake cuts a backoff short when the reason the prober failed has demonstrably
	// gone away, such as the interface it binds to coming back (§10.3).
	wake chan struct{}
}

// nudge asks a worker to retry now rather than at the end of its backoff. It
// never blocks: one pending wake-up is as good as several.
func (w *worker) nudge() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Deps is what the supervisor needs.
type Deps struct {
	Tunnels  TunnelSource
	Store    *Store
	Settings Settings
	Links    link.LinkManager
	Log      *slog.Logger
	// Dialer opens probe sockets. Nil means real ones.
	Dialer Dialer
	// Traffic reads the interface counters that tell a filtered path from a
	// dead one. Nil means the kernel's own, under /sys.
	Traffic TrafficReader
	// Peer knocks on the far end over TCP when a tunnel is idle and its
	// probes are unanswered. Nil means a real connection.
	Peer PeerChecker
	// PanelPort is the port this panel serves on, which is what the knock
	// goes to: the far end of a tunnel this panel manages is usually running
	// it too, and a refusal answers the question just as well.
	PanelPort int
}

// New returns a supervisor. It does not start anything until Start is called.
func New(d Deps) *Supervisor {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	dialer := d.Dialer
	if dialer == nil {
		dialer = SystemDialer{}
	}
	traffic := d.Traffic
	if traffic == nil {
		traffic = SysfsTraffic{}
	}
	peer := d.Peer
	if peer == nil {
		peer = TCPPeerChecker{Port: d.PanelPort}
	}
	return &Supervisor{
		tunnels:    d.Tunnels,
		store:      d.Store,
		settings:   d.Settings,
		links:      d.Links,
		hub:        NewHub(),
		log:        log,
		dialer:     dialer,
		traffic:    traffic,
		peer:       peer,
		aggregator: newAggregator(d.Store, log),
		running:    map[int64]*worker{},
		disabled:   map[int64]Snapshot{},
		notify:     make(chan struct{}, 1),
	}
}

// Hub exposes the fan-out for the live stream endpoint.
func (s *Supervisor) Hub() *Hub { return s.hub }

// Store exposes the history store for the history endpoint.
func (s *Supervisor) Store() *Store { return s.store }

// Start brings the supervisor up and probes every monitor-enabled tunnel.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	runCtx := s.ctx
	s.mu.Unlock()

	s.wg.Add(1)
	go s.loop(runCtx)

	s.wg.Add(1)
	go s.watchLinks(runCtx)

	s.TunnelsChanged()
	return nil
}

// Stop shuts every prober down and closes every socket (§10.3).
func (s *Supervisor) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.wg.Wait()

	s.mu.Lock()
	workers := make([]*worker, 0, len(s.running))
	for id, w := range s.running {
		workers = append(workers, w)
		delete(s.running, id)
	}
	s.mu.Unlock()

	for _, w := range workers {
		w.cancel()
		<-w.done
	}
	s.hub.Close()
}

// TunnelsChanged asks the supervisor to bring its probers back in step. The
// tunnel service calls it after every successful change, so a tunnel starts or
// stops being monitored the moment it is created, deleted, enabled or disabled
// — never at the next restart (§10.3).
func (s *Supervisor) TunnelsChanged() {
	select {
	case s.notify <- struct{}{}:
	default:
		// A sweep is already pending; one is enough.
	}
}

// SettingsChanged is the same signal for a settings edit. Every threshold is
// re-resolved and any prober whose configuration actually changed is restarted.
func (s *Supervisor) SettingsChanged(changed []string) {
	for _, key := range changed {
		if len(key) >= 8 && key[:8] == "monitor." {
			s.TunnelsChanged()
			return
		}
	}
}

// loop runs the reconcile sweep, the history flush and the pruning.
func (s *Supervisor) loop(ctx context.Context) {
	defer s.wg.Done()

	sweep := time.NewTicker(reconcileInterval)
	defer sweep.Stop()

	flush := time.NewTicker(time.Second)
	defer flush.Stop()

	prune := time.NewTicker(time.Hour)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			// One last flush so the final partial bucket is not lost.
			s.flushHistory(context.WithoutCancel(ctx))
			return
		case <-s.notify:
			s.reconcile(ctx)
		case <-sweep.C:
			s.reconcile(ctx)
		case <-flush.C:
			s.flushHistory(ctx)
		case <-prune.C:
			if _, err := s.store.Prune(ctx, s.settings.Int("monitor.history_retention_days")); err != nil {
				s.log.Error("pruning monitoring history failed", "error", err)
			}
		}
	}
}

func (s *Supervisor) flushHistory(ctx context.Context) {
	interval := time.Duration(s.settings.Int("monitor.aggregate_interval_seconds")) * time.Second
	if interval <= 0 {
		interval = time.Minute
	}
	s.aggregator.flush(ctx, interval, time.Now())
}

// reconcile brings the set of running probers in line with the tunnels.
func (s *Supervisor) reconcile(ctx context.Context) {
	records, err := s.tunnels.List(ctx)
	if err != nil {
		s.log.Error("reading tunnels for monitoring failed", "error", err)
		return
	}

	wanted := map[int64]Config{}
	disabled := map[int64]Snapshot{}
	for _, rec := range records {
		cfg := ConfigFor(rec, s.settings)
		if cfg.Enabled {
			wanted[cfg.TunnelID] = cfg
			continue
		}
		disabled[cfg.TunnelID] = Snapshot{
			TunnelID:       cfg.TunnelID,
			InterfaceName:  cfg.InterfaceName,
			MonitorStateID: model.MonitorStateDisabled,
			State:          StateName(model.MonitorStateDisabled),
			Reason:         cfg.Reason,
			Source:         cfg.Source,
			Target:         cfg.Target,
			Enabled:        false,
			UpdatedAt:      time.Now(),
		}
	}

	s.mu.Lock()
	s.disabled = disabled
	var (
		toStop  []*worker
		toStart []Config
	)
	for id, w := range s.running {
		cfg, keep := wanted[id]
		if !keep {
			toStop = append(toStop, w)
			delete(s.running, id)
			continue
		}
		current := w.prober.Config()
		if current.Equal(cfg) {
			continue
		}
		// A change to what is probed, or how, needs a new socket; a change to
		// only the thresholds does not.
		if needsRestart(current, cfg) {
			toStop = append(toStop, w)
			delete(s.running, id)
			toStart = append(toStart, cfg)
			continue
		}
		w.prober.update(cfg)
	}
	for id, cfg := range wanted {
		if _, exists := s.running[id]; !exists {
			toStart = append(toStart, cfg)
		}
	}
	s.mu.Unlock()

	for _, w := range toStop {
		w.cancel()
		<-w.done
		s.aggregator.forget(w.prober.Config().TunnelID)
	}
	for _, cfg := range toStart {
		s.startProber(ctx, cfg)
	}

	// Publish the disabled tunnels too, so the live stream and the summary show
	// every tunnel rather than only the probed ones.
	for _, snapshot := range disabled {
		s.hub.Publish(snapshot)
	}
}

// needsRestart reports whether a configuration change means a new socket.
func needsRestart(current, next Config) bool {
	return current.Source != next.Source || current.Target != next.Target ||
		current.PacketSize != next.PacketSize
}

// startProber launches one prober with bounded exponential backoff on failure
// (§10.3).
func (s *Supervisor) startProber(ctx context.Context, cfg Config) {
	probeCtx, cancel := context.WithCancel(ctx)
	p := newProber(cfg, s.dialer, s.hub, s, s.aggregator, s.traffic, s.peer)
	w := &worker{prober: p, cancel: cancel, done: make(chan struct{}), wake: make(chan struct{}, 1)}

	s.mu.Lock()
	if existing, ok := s.running[cfg.TunnelID]; ok {
		// Another sweep won the race; leave its prober alone.
		s.mu.Unlock()
		cancel()
		close(w.done)
		_ = existing
		return
	}
	s.running[cfg.TunnelID] = w
	s.mu.Unlock()

	go func() {
		defer close(w.done)
		backoff := minBackoff

		for probeCtx.Err() == nil {
			started := time.Now()
			err := p.run(probeCtx)
			if probeCtx.Err() != nil {
				return
			}
			if err != nil {
				s.log.Warn("the monitoring prober stopped and will be restarted",
					"tunnel_id", cfg.TunnelID, "interface", p.Config().InterfaceName,
					"error", err, "retry_in", backoff.String())
				p.force(probeCtx, model.MonitorStateUnknown,
					"the prober could not run: "+err.Error())
			}
			// A prober that ran for a good while and then stopped has hit a new
			// problem, not the same one again, so it does not inherit the wait
			// that the last round of failures earned.
			if time.Since(started) >= stableRun {
				backoff = minBackoff
			}

			select {
			case <-probeCtx.Done():
				return
			case <-w.wake:
				// The reason it could not run has gone away, so there is
				// nothing to wait for.
				backoff = minBackoff
				continue
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}

// watchLinks turns netlink notifications into monitoring state.
//
// An interface that vanishes is moved to Down with a specific reason
// immediately, rather than being discovered a timeout at a time by a sender
// spinning on write errors (§10.3).
func (s *Supervisor) watchLinks(ctx context.Context) {
	defer s.wg.Done()

	if s.links == nil {
		return
	}
	events, err := s.links.Subscribe(ctx)
	if err != nil {
		s.log.Info("link events are unavailable, so a vanished interface is noticed by probe timeouts instead",
			"error", err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			s.handleLinkEvent(ctx, event)
		}
	}
}

func (s *Supervisor) handleLinkEvent(ctx context.Context, event link.Event) {
	s.mu.Lock()
	var target *worker
	for _, w := range s.running {
		if w.prober.Config().InterfaceName == event.Link.Name {
			target = w
			break
		}
	}
	s.mu.Unlock()

	if target == nil {
		// A tunnel appearing may mean a new interface to monitor.
		if event.Kind == link.EventAdded {
			s.TunnelsChanged()
		}
		return
	}

	switch {
	case event.Kind == link.EventRemoved:
		target.prober.force(ctx, model.MonitorStateDown, ReasonInterfaceMissing)
		s.TunnelsChanged()
	case event.Kind == link.EventAdded, event.Kind == link.EventChanged && event.Link.IsUp:
		// The interface is back. A prober that could not bind to its address is
		// otherwise left waiting out a backoff of up to two minutes for
		// something the panel has just been told is fixed, and one that never
		// stopped goes on reporting the interface as missing.
		target.prober.release()
		target.nudge()
	case event.Kind == link.EventChanged && !event.Link.IsUp:
		target.prober.force(ctx, model.MonitorStateDown, "the interface is administratively down")
	}
}

// ReasonInterfaceMissing is the exact reason recorded when the netlink
// subscription reports that a monitored interface has gone (§10.3).
const ReasonInterfaceMissing = "interface_missing"

// RecordTransition writes a MonitorEvent for a state change (§10.2).
func (s *Supervisor) RecordTransition(ctx context.Context, cfg Config, t Transition, stats Stats) {
	event := Event{
		TunnelID:           cfg.TunnelID,
		FromMonitorStateID: t.From,
		ToMonitorStateID:   t.To,
		Reason:             t.Reason,
	}
	if stats.Sent > 0 {
		loss := stats.LossPercent
		event.LossPercent = &loss
	}
	event.RttAvgMs = stats.RttAvgMs

	if err := s.store.WriteEvent(ctx, event); err != nil {
		s.log.Error("writing a monitoring event failed", "tunnel_id", cfg.TunnelID, "error", err)
	}
	s.log.Info("tunnel monitoring state changed",
		"tunnel_id", cfg.TunnelID, "interface", cfg.InterfaceName,
		"from", StateName(t.From), "to", StateName(t.To), "reason", t.Reason)
}

// Snapshot returns one tunnel's current picture.
func (s *Supervisor) Snapshot(tunnelID int64) (Snapshot, bool) {
	s.mu.Lock()
	w, running := s.running[tunnelID]
	disabled, known := s.disabled[tunnelID]
	s.mu.Unlock()

	if running {
		return w.prober.Snapshot(), true
	}
	if known {
		return disabled, true
	}
	return Snapshot{}, false
}

// Summary returns every tunnel's picture, monitored or not, ordered by tunnel
// identifier so the display is stable.
func (s *Supervisor) Summary() []Snapshot {
	s.mu.Lock()
	out := make([]Snapshot, 0, len(s.running)+len(s.disabled))
	for _, w := range s.running {
		out = append(out, w.prober.Snapshot())
	}
	for _, snapshot := range s.disabled {
		out = append(out, snapshot)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].TunnelID < out[j].TunnelID })
	return out
}

// Counts totals the tunnels in each state, which the dashboard header shows.
func (s *Supervisor) Counts() map[string]int {
	counts := map[string]int{}
	for _, snapshot := range s.Summary() {
		counts[snapshot.State]++
	}
	return counts
}

// Running reports how many probers are active, which the health endpoint shows.
func (s *Supervisor) Running() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.running)
}

// Probe answers a one-off reachability question using the same ICMP path as the
// continuous monitoring, which is what lets the tunnel service verify a peer
// after an apply without owning a second implementation (§9.3).
func (s *Supervisor) Probe(ctx context.Context, source, target string, count int,
	budget time.Duration) (tunnel.PeerProbeResult, error) {

	result, err := Ping(ctx, s.dialer, PingRequest{
		Source: source, Target: target, Count: count,
		Interval: budget / time.Duration(max(count, 1)), Timeout: budget,
	}, nil)
	if err != nil {
		return tunnel.PeerProbeResult{}, err
	}
	return tunnel.PeerProbeResult{
		Sent: result.Sent, Received: result.Received, RttMs: result.RttAvgMs,
	}, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
