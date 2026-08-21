package route

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/metrics"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// SinceBootMeaning is carried in every traffic response beside the two sets of
// figures, because the shorter label is not self-explanatory here.
//
// The kernel's counters are zeroed by every rebuild of the ruleset — every
// edit, enable, disable, reconcile repair and reboot — not only by a reboot. The
// panel's own totals are the ones that survive all of that. Presenting either
// as the other is the correctness bug §5.2 exists to prevent, so both are
// returned, labelled, and never added together.
const SinceBootMeaning = "The since-boot figures are the kernel's own counters, which are zeroed " +
	"every time the ruleset is rebuilt — on every edit, enable, disable and reboot. The " +
	"since-creation figures are the panel's, folded across every one of those resets. They are two " +
	"different measurements and are never added together."

// historyPoints is how many samples the in-memory ring buffer keeps per rule,
// which is what the sparklines are drawn from. At the default one-second
// interval this is five minutes.
const historyPoints = 300

// Traffic is one rule's live accounting.
type Traffic struct {
	RouteRuleID int64     `json:"route_rule_id"`
	Title       string    `json:"title"`
	At          time.Time `json:"at"`
	// IntervalSeconds is the gap the rates were computed over, so a stale
	// figure can be told from a fresh one.
	IntervalSeconds float64 `json:"interval_seconds"`

	RxBytesPerSecond   float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond   float64 `json:"tx_bytes_per_second"`
	RxPacketsPerSecond float64 `json:"rx_packets_per_second"`
	TxPacketsPerSecond float64 `json:"tx_packets_per_second"`

	// The kernel's own counters, zeroed by every rebuild of the ruleset.
	RxBytesSinceBoot   uint64 `json:"rx_bytes_since_boot"`
	TxBytesSinceBoot   uint64 `json:"tx_bytes_since_boot"`
	RxPacketsSinceBoot uint64 `json:"rx_packets_since_boot"`
	TxPacketsSinceBoot uint64 `json:"tx_packets_since_boot"`

	// The panel's totals, folded across every reset.
	RxBytesSinceCreation   uint64 `json:"rx_bytes_since_creation"`
	TxBytesSinceCreation   uint64 `json:"tx_bytes_since_creation"`
	RxPacketsSinceCreation uint64 `json:"rx_packets_since_creation"`
	TxPacketsSinceCreation uint64 `json:"tx_packets_since_creation"`

	ActiveConnections       int     `json:"active_connections"`
	NewConnectionsPerSecond float64 `json:"new_connections_per_second"`

	// ResetDetected reports that the last sample saw the counters restart.
	ResetDetected bool `json:"reset_detected"`
}

// Point is one entry of the in-memory ring buffer, for the sparklines.
type Point struct {
	At                time.Time `json:"at"`
	IntervalSeconds   float64   `json:"interval_seconds"`
	RxBytes           uint64    `json:"rx_bytes"`
	TxBytes           uint64    `json:"tx_bytes"`
	RxBytesPerSecond  float64   `json:"rx_bytes_per_second"`
	TxBytesPerSecond  float64   `json:"tx_bytes_per_second"`
	ActiveConnections int       `json:"active_connections"`
}

// delta is what moved between two samples, which is both what a rate is
// computed from and what an aggregate bucket accumulates.
type delta struct {
	rxBytes, txBytes     uint64
	rxPackets, txPackets uint64
}

// bucket accumulates the deltas of one aggregate interval.
//
// The connection figures are the interval's high-water mark rather than its
// mean: what an operator wants from a history row is how busy the relay got,
// and an average over a minute hides a burst that filled the table.
type bucket struct {
	start                       time.Time
	rxBytes, txBytes            uint64
	rxPackets, txPackets        uint64
	activeConnections, newConns int
	samples                     int
}

// AccountingDeps is what the accounting needs.
type AccountingDeps struct {
	Repo      *CounterRepo
	Routes    *Repo
	Backend   rules.Backend
	Conntrack ConntrackReader
	Settings  Settings
	Log       *slog.Logger
}

// Accounting samples the forward-hook counters, folds them across the resets
// every rebuild causes, keeps a ring buffer for the sparklines and writes the
// aggregate history rows (§5).
//
// It never reads a counter from a nat chain. NAT hooks see only the first
// packet of a connection; a counter there measures connections while claiming
// to measure bytes, and would under-report a busy relay by orders of magnitude.
// The rules the figures come from live in the filter forward hook and carry no
// verdict, which is why sampling them cannot affect what the ruleset does.
type Accounting struct {
	repo      *CounterRepo
	routes    *Repo
	backend   rules.Backend
	conntrack ConntrackReader
	settings  Settings
	log       *slog.Logger

	mu      sync.RWMutex
	state   map[int64]*Volume
	dirty   map[int64]bool
	live    map[int64]Traffic
	history map[int64][]Point
	pending map[int64]*bucket
	counts  map[int64]ConnectionCount
	titles  map[int64]string
	specs   []rules.RouteSpec

	destVolumes map[destVolumeKey]*DestVolume
	destDirty   map[destVolumeKey]bool

	conn         *conntrackState
	lastSampleAt time.Time
	lastConnAt   time.Time

	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

// NewAccounting returns the accounting.
func NewAccounting(d AccountingDeps) *Accounting {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	conntrack := d.Conntrack
	if conntrack == nil {
		conntrack = SelectConntrack()
	}
	return &Accounting{
		repo: d.Repo, routes: d.Routes, backend: d.Backend, conntrack: conntrack,
		settings: d.Settings, log: log,
		state: map[int64]*Volume{}, dirty: map[int64]bool{},
		live: map[int64]Traffic{}, history: map[int64][]Point{},
		pending: map[int64]*bucket{}, counts: map[int64]ConnectionCount{},
		titles: map[int64]string{}, conn: newConntrackState(),
		destVolumes: map[destVolumeKey]*DestVolume{}, destDirty: map[destVolumeKey]bool{},
	}
}

// Conntrack exposes the reader, which the diagnostics use for the live
// connection list.
func (a *Accounting) Conntrack() ConntrackReader { return a.conntrack }

// ---------------------------------------------------------------- lifecycle

// Load reads the persisted totals and the current set of rules.
func (a *Accounting) Load(ctx context.Context) error {
	if a.repo == nil {
		return nil
	}
	volumes, err := a.repo.Load(ctx)
	if err != nil {
		return err
	}

	destVolumes, err := a.repo.LoadDestinationVolumes(ctx)
	if err != nil {
		return err
	}

	a.mu.Lock()
	for _, v := range volumes {
		copied := v
		a.state[v.RouteRuleID] = &copied
	}
	for _, v := range destVolumes {
		copied := v
		a.destVolumes[destVolumeKey{routeRuleID: v.RouteRuleID, address: v.Address, port: v.Port}] = &copied
	}
	a.mu.Unlock()

	return a.RefreshRules(ctx)
}

// RefreshRules re-reads which rules are installed, which is what the service
// calls after every change: the accounting needs the new set to attribute
// counters and connections, and it must not go looking for a rule that has just
// been deleted.
func (a *Accounting) RefreshRules(ctx context.Context) error {
	if a.routes == nil {
		return nil
	}
	records, err := a.routes.List(ctx)
	if err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.specs = DesiredOf(records).Sorted()
	a.titles = make(map[int64]string, len(records))
	for _, rec := range records {
		a.titles[rec.RouteRuleID] = rec.RouteRuleTitle
	}
	return nil
}

// Start begins sampling.
func (a *Accounting) Start(ctx context.Context) error {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return nil
	}
	a.started = true
	loopCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.mu.Unlock()

	if err := a.Load(ctx); err != nil {
		a.log.Error("reading the persisted route traffic counters failed", "error", err)
	}

	// One reading immediately, so the first request after startup has figures
	// rather than zeroes.
	a.Sample(loopCtx)
	a.SampleConnections(loopCtx)

	a.wg.Add(1)
	go a.loop(loopCtx)
	return nil
}

// Stop ends sampling and writes the totals down (§5.2, §20).
func (a *Accounting) Stop() {
	a.mu.Lock()
	cancel := a.cancel
	a.started = false
	a.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	a.wg.Wait()

	flushCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := a.Flush(flushCtx); err != nil {
		a.log.Error("writing the route traffic counters down at shutdown failed", "error", err)
	}
}

func (a *Accounting) loop(ctx context.Context) {
	defer a.wg.Done()

	counterEvery := a.interval("routes.counter_interval_seconds", time.Second)
	counters := time.NewTicker(counterEvery)
	defer counters.Stop()

	connEvery := a.interval("routes.conntrack_interval_seconds", 5*time.Second)
	connections := time.NewTicker(connEvery)
	defer connections.Stop()

	// The in-memory totals are authoritative between writes; writing every
	// thirty seconds bounds what a crash can lose to that much traffic.
	flush := time.NewTicker(30 * time.Second)
	defer flush.Stop()

	aggregate := time.NewTicker(a.aggregateInterval())
	defer aggregate.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-counters.C:
			a.Sample(ctx)
			// A settings change takes effect without a process restart.
			if next := a.interval("routes.counter_interval_seconds", time.Second); next != counterEvery {
				counterEvery = next
				counters.Reset(next)
			}

		case <-connections.C:
			a.SampleConnections(ctx)
			if next := a.interval("routes.conntrack_interval_seconds", 5*time.Second); next != connEvery {
				connEvery = next
				connections.Reset(next)
			}

		case <-aggregate.C:
			a.WriteAggregates(ctx)
			aggregate.Reset(a.aggregateInterval())

		case <-flush.C:
			if err := a.Flush(ctx); err != nil {
				a.log.Error("persisting the route traffic counters failed", "error", err)
			}
		}
	}
}

func (a *Accounting) interval(key string, fallback time.Duration) time.Duration {
	if a.settings == nil {
		return fallback
	}
	seconds := a.settings.Float(key)
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds * float64(time.Second))
}

func (a *Accounting) aggregateInterval() time.Duration {
	if a.settings == nil {
		return time.Minute
	}
	seconds := a.settings.Int("routes.aggregate_interval_seconds")
	if seconds <= 0 {
		return time.Minute
	}
	return time.Duration(seconds) * time.Second
}

// ---------------------------------------------------------------- sampling

// Sample takes one reading of the byte counters and folds it in.
func (a *Accounting) Sample(ctx context.Context) []Traffic {
	if a.backend == nil {
		return nil
	}
	raw, err := a.backend.Counters(ctx)
	if err != nil {
		// A host whose counters cannot be read is not a host with no traffic,
		// so nothing is recorded and the previous figures stand.
		a.log.Debug("reading the route traffic counters failed", "error", err)
		return nil
	}
	return a.Observe(raw, time.Now())
}

// Observe folds a set of raw readings into the running totals and returns the
// live figures.
//
// This is the whole of §5.2. The totals always already include everything up to
// the LastRaw figures, so an ordinary sample adds the difference and a sample
// that went backwards — which is what every rebuild produces — adds the whole of
// the new value instead, because after a rebuild every byte the counter holds is
// new.
func (a *Accounting) Observe(raw map[int64]rules.Counter, now time.Time) []Traffic {
	a.mu.Lock()
	defer a.mu.Unlock()

	elapsed := 0.0
	if !a.lastSampleAt.IsZero() {
		elapsed = now.Sub(a.lastSampleAt).Seconds()
	}
	a.lastSampleAt = now

	out := make([]Traffic, 0, len(raw))
	for id, counter := range raw {
		volume, known := a.state[id]
		if !known {
			// First sighting. The counter already holds traffic this panel never
			// saw — it was installed before the panel started sampling, or the
			// rule was adopted — so it starts the total rather than being added
			// to it.
			volume = &Volume{
				RouteRuleID:      id,
				LastRawRxBytes:   counter.RxBytes,
				LastRawTxBytes:   counter.TxBytes,
				LastRawRxPackets: counter.RxPackets,
				LastRawTxPackets: counter.TxPackets,
			}
			a.state[id] = volume
			a.dirty[id] = true
			out = append(out, a.record(*volume, counter, delta{}, elapsed, now))
			continue
		}

		reset := counter.RxBytes < volume.LastRawRxBytes || counter.TxBytes < volume.LastRawTxBytes ||
			counter.RxPackets < volume.LastRawRxPackets || counter.TxPackets < volume.LastRawTxPackets

		var moved delta
		if reset {
			moved = delta{
				rxBytes: counter.RxBytes, txBytes: counter.TxBytes,
				rxPackets: counter.RxPackets, txPackets: counter.TxPackets,
			}
		} else {
			moved = delta{
				rxBytes:   counter.RxBytes - volume.LastRawRxBytes,
				txBytes:   counter.TxBytes - volume.LastRawTxBytes,
				rxPackets: counter.RxPackets - volume.LastRawRxPackets,
				txPackets: counter.TxPackets - volume.LastRawTxPackets,
			}
		}
		volume.RxBytesTotal += moved.rxBytes
		volume.TxBytesTotal += moved.txBytes
		volume.RxPacketsTotal += moved.rxPackets
		volume.TxPacketsTotal += moved.txPackets

		volume.ResetDetected = reset
		volume.LastRawRxBytes = counter.RxBytes
		volume.LastRawTxBytes = counter.TxBytes
		volume.LastRawRxPackets = counter.RxPackets
		volume.LastRawTxPackets = counter.TxPackets
		a.dirty[id] = true

		out = append(out, a.record(*volume, counter, moved, elapsed, now))
	}

	sort.Slice(out, func(i, j int) bool { return out[i].RouteRuleID < out[j].RouteRuleID })
	return out
}

// record builds one rule's live figures and files them in the ring buffer and
// the pending aggregate bucket. The caller holds the lock.
func (a *Accounting) record(volume Volume, counter rules.Counter,
	moved delta, elapsed float64, now time.Time) Traffic {

	traffic := Traffic{
		RouteRuleID: volume.RouteRuleID, Title: a.titles[volume.RouteRuleID],
		At: now, IntervalSeconds: elapsed,

		RxBytesSinceBoot:   counter.RxBytes,
		TxBytesSinceBoot:   counter.TxBytes,
		RxPacketsSinceBoot: counter.RxPackets,
		TxPacketsSinceBoot: counter.TxPackets,

		RxBytesSinceCreation:   volume.RxBytesTotal,
		TxBytesSinceCreation:   volume.TxBytesTotal,
		RxPacketsSinceCreation: volume.RxPacketsTotal,
		TxPacketsSinceCreation: volume.TxPacketsTotal,

		ResetDetected: volume.ResetDetected,
	}
	if elapsed > 0 {
		traffic.RxBytesPerSecond = float64(moved.rxBytes) / elapsed
		traffic.TxBytesPerSecond = float64(moved.txBytes) / elapsed
		traffic.RxPacketsPerSecond = float64(moved.rxPackets) / elapsed
		traffic.TxPacketsPerSecond = float64(moved.txPackets) / elapsed
	}
	if count, ok := a.counts[volume.RouteRuleID]; ok {
		traffic.ActiveConnections = count.Active
		if gap := now.Sub(a.lastConnAt).Seconds(); gap > 0 && !a.lastConnAt.IsZero() {
			traffic.NewConnectionsPerSecond = float64(count.New) / gap
		}
	}
	a.live[volume.RouteRuleID] = traffic

	points := append(a.history[volume.RouteRuleID], Point{
		At: now, IntervalSeconds: elapsed,
		RxBytes: moved.rxBytes, TxBytes: moved.txBytes,
		RxBytesPerSecond: traffic.RxBytesPerSecond, TxBytesPerSecond: traffic.TxBytesPerSecond,
		ActiveConnections: traffic.ActiveConnections,
	})
	if len(points) > historyPoints {
		points = points[len(points)-historyPoints:]
	}
	a.history[volume.RouteRuleID] = points

	pending, ok := a.pending[volume.RouteRuleID]
	if !ok {
		pending = &bucket{start: now}
		a.pending[volume.RouteRuleID] = pending
	}
	pending.rxBytes += moved.rxBytes
	pending.txBytes += moved.txBytes
	pending.rxPackets += moved.rxPackets
	pending.txPackets += moved.txPackets
	pending.samples++
	if traffic.ActiveConnections > pending.activeConnections {
		pending.activeConnections = traffic.ActiveConnections
	}
	return traffic
}

// SampleConnections reads the connection tracking table on its own slower
// interval and attributes each flow to the rule that created it (§5.3).
func (a *Accounting) SampleConnections(ctx context.Context) map[int64]ConnectionCount {
	if a.conntrack == nil {
		return nil
	}
	a.mu.RLock()
	specs := append([]rules.RouteSpec(nil), a.specs...)
	a.mu.RUnlock()
	if len(specs) == 0 {
		return nil
	}

	flows, err := a.conntrack.Flows(ctx)
	if err != nil {
		a.log.Debug("reading connection tracking failed", "error", err,
			"reader", a.conntrack.Name())
		return nil
	}

	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	counts := a.conn.observe(specs, flows, now)
	gap := 0.0
	if !a.lastConnAt.IsZero() {
		gap = now.Sub(a.lastConnAt).Seconds()
	}
	a.lastConnAt = now
	a.counts = counts

	a.foldDestinationMovement(counts)

	for id, count := range counts {
		traffic := a.live[id]
		traffic.ActiveConnections = count.Active
		if gap > 0 {
			traffic.NewConnectionsPerSecond = float64(count.New) / gap
		}
		a.live[id] = traffic

		if pending, ok := a.pending[id]; ok {
			pending.newConns += count.New
			if count.Active > pending.activeConnections {
				pending.activeConnections = count.Active
			}
		}
	}
	return counts
}

// ---------------------------------------------------------------- persistence

// Snapshot folds the live counters into the persisted totals and writes them
// down. It is the CounterStore the service calls immediately before every
// rebuild, because the rebuild zeroes the counters and a snapshot that is
// skipped is traffic that is lost (§5.2).
func (a *Accounting) Snapshot(ctx context.Context) error {
	a.Sample(ctx)
	return a.Flush(ctx)
}

// Flush writes down every total that has moved.
func (a *Accounting) Flush(ctx context.Context) error {
	if a.repo == nil {
		return nil
	}
	a.mu.Lock()
	pending := make([]Volume, 0, len(a.dirty))
	for id := range a.dirty {
		if v, ok := a.state[id]; ok {
			pending = append(pending, *v)
		}
	}
	a.dirty = map[int64]bool{}
	pendingDest := make([]DestVolume, 0, len(a.destDirty))
	for key := range a.destDirty {
		if v, ok := a.destVolumes[key]; ok {
			pendingDest = append(pendingDest, *v)
		}
	}
	a.destDirty = map[destVolumeKey]bool{}
	a.mu.Unlock()

	if err := a.repo.Save(ctx, pending); err != nil {
		// The figures stay dirty so the next flush tries again rather than
		// losing them.
		a.mu.Lock()
		for _, v := range pending {
			a.dirty[v.RouteRuleID] = true
		}
		a.mu.Unlock()
		return err
	}
	if err := a.repo.SaveDestinationVolumes(ctx, pendingDest); err != nil {
		a.mu.Lock()
		for _, v := range pendingDest {
			a.destDirty[destVolumeKey{routeRuleID: v.RouteRuleID, address: v.Address, port: v.Port}] = true
		}
		a.mu.Unlock()
		return err
	}
	return nil
}

// WriteAggregates closes the pending buckets and stores them as history rows.
func (a *Accounting) WriteAggregates(ctx context.Context) {
	if a.repo == nil {
		return
	}
	a.mu.Lock()
	samples := make([]Sample, 0, len(a.pending))
	for id, pending := range a.pending {
		if pending == nil || pending.samples == 0 {
			continue
		}
		// A bucket with no traffic and no connections is not worth a row: a
		// quiet relay would otherwise fill the table with zeroes.
		if pending.rxBytes == 0 && pending.txBytes == 0 &&
			pending.activeConnections == 0 && pending.newConns == 0 {
			delete(a.pending, id)
			continue
		}
		samples = append(samples, Sample{
			RouteRuleID:     id,
			BucketStartDate: model.FormatTime(pending.start.UTC()),
			RxBytes:         pending.rxBytes, TxBytes: pending.txBytes,
			RxPackets: pending.rxPackets, TxPackets: pending.txPackets,
			ActiveConnections: pending.activeConnections,
			NewConnections:    pending.newConns,
		})
		delete(a.pending, id)
	}
	a.mu.Unlock()

	if len(samples) == 0 {
		return
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].RouteRuleID < samples[j].RouteRuleID })
	if err := a.repo.WriteSamples(ctx, samples); err != nil {
		a.log.Error("storing the route traffic history failed", "error", err, "rows", len(samples))
	}
}

// Prune drops history past the retention window.
func (a *Accounting) Prune(ctx context.Context) (int64, error) {
	if a.repo == nil {
		return 0, nil
	}
	days := int64(30)
	if a.settings != nil {
		if configured := a.settings.Int("routes.history_retention_days"); configured > 0 {
			days = configured
		}
	}
	return a.repo.PruneSamples(ctx, days)
}

// Forget drops the accounting for a deleted rule, in memory and on disk.
func (a *Accounting) Forget(ctx context.Context, routeRuleID int64) error {
	a.mu.Lock()
	delete(a.state, routeRuleID)
	delete(a.dirty, routeRuleID)
	delete(a.live, routeRuleID)
	delete(a.history, routeRuleID)
	delete(a.pending, routeRuleID)
	delete(a.counts, routeRuleID)
	delete(a.titles, routeRuleID)
	a.conn.forget(routeRuleID)
	a.mu.Unlock()

	if a.repo == nil {
		return nil
	}
	return a.repo.Forget(ctx, routeRuleID)
}

// ---------------------------------------------------------------- reading

// Traffic returns one rule's live figures.
func (a *Accounting) Traffic(routeRuleID int64) (Traffic, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	traffic, ok := a.live[routeRuleID]
	return traffic, ok
}

// All returns every rule's live figures, in identifier order.
func (a *Accounting) All() []Traffic {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]Traffic, 0, len(a.live))
	for _, traffic := range a.live {
		out = append(out, traffic)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RouteRuleID < out[j].RouteRuleID })
	return out
}

// History returns the in-memory ring buffer for one rule, oldest first.
func (a *Accounting) History(routeRuleID int64, limit int) []Point {
	a.mu.RLock()
	defer a.mu.RUnlock()

	points := a.history[routeRuleID]
	if limit <= 0 || limit > len(points) {
		limit = len(points)
	}
	out := make([]Point, limit)
	copy(out, points[len(points)-limit:])
	return out
}

// Connections returns the last connection counts read for one rule.
func (a *Accounting) Connections(routeRuleID int64) (ConnectionCount, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	count, ok := a.counts[routeRuleID]
	return count, ok
}

// Summary is the aggregate across every rule, which the dashboard shows.
type Summary struct {
	Routes            int       `json:"routes"`
	RxBytesPerSecond  float64   `json:"rx_bytes_per_second"`
	TxBytesPerSecond  float64   `json:"tx_bytes_per_second"`
	RxBytesTotal      uint64    `json:"rx_bytes_since_creation"`
	TxBytesTotal      uint64    `json:"tx_bytes_since_creation"`
	ActiveConnections int       `json:"active_connections"`
	At                time.Time `json:"at"`
}

// Summary totals the live figures.
func (a *Accounting) Summary() Summary {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := Summary{Routes: len(a.live), At: a.lastSampleAt}
	for _, traffic := range a.live {
		out.RxBytesPerSecond += traffic.RxBytesPerSecond
		out.TxBytesPerSecond += traffic.TxBytesPerSecond
		out.RxBytesTotal += traffic.RxBytesSinceCreation
		out.TxBytesTotal += traffic.TxBytesSinceCreation
		out.ActiveConnections += traffic.ActiveConnections
	}
	return out
}

// StoredHistory returns the persisted aggregate rows for one rule.
func (a *Accounting) StoredHistory(ctx context.Context, routeRuleID int64, since time.Time, limit int) ([]Sample, error) {
	if a.repo == nil {
		return []Sample{}, nil
	}
	return a.repo.Samples(ctx, routeRuleID, model.FormatTime(since.UTC()), limit)
}

// RouteTraffic satisfies metrics.RouteSource, which is what multiplexes relay
// traffic into the existing metrics stream rather than adding a second one
// (§5.4).
func (a *Accounting) RouteTraffic() []metrics.RouteTraffic {
	a.mu.RLock()
	defer a.mu.RUnlock()

	out := make([]metrics.RouteTraffic, 0, len(a.live))
	for _, traffic := range a.live {
		out = append(out, metrics.RouteTraffic{
			RouteRuleID:             traffic.RouteRuleID,
			Title:                   traffic.Title,
			RxBytesPerSecond:        traffic.RxBytesPerSecond,
			TxBytesPerSecond:        traffic.TxBytesPerSecond,
			RxBytesSinceBoot:        traffic.RxBytesSinceBoot,
			TxBytesSinceBoot:        traffic.TxBytesSinceBoot,
			RxBytesSinceCreation:    traffic.RxBytesSinceCreation,
			TxBytesSinceCreation:    traffic.TxBytesSinceCreation,
			ActiveConnections:       traffic.ActiveConnections,
			NewConnectionsPerSecond: traffic.NewConnectionsPerSecond,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RouteRuleID < out[j].RouteRuleID })
	return out
}
