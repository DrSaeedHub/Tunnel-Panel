package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/link"
)

// Settings is the slice of the settings store this package reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	Float(key string) float64
}

// RouteTraffic is one forwarding rule's live relay traffic.
//
// It is carried in this package's snapshot rather than in one of its own so
// that route traffic is multiplexed into the metrics stream the frontend
// already subscribes to, instead of a second stream and a second connection
// (§5.4 of the port forwarding specification). The two byte figures are kept
// apart deliberately: the since-boot one is the kernel's counter, which every
// rebuild of the ruleset zeroes, and the since-creation one is the panel's own,
// folded across those resets.
type RouteTraffic struct {
	RouteRuleID int64  `json:"route_rule_id"`
	Title       string `json:"title"`

	RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64 `json:"tx_bytes_per_second"`

	RxBytesSinceBoot     uint64 `json:"rx_bytes_since_boot"`
	TxBytesSinceBoot     uint64 `json:"tx_bytes_since_boot"`
	RxBytesSinceCreation uint64 `json:"rx_bytes_since_creation"`
	TxBytesSinceCreation uint64 `json:"tx_bytes_since_creation"`

	ActiveConnections       int     `json:"active_connections"`
	NewConnectionsPerSecond float64 `json:"new_connections_per_second"`
}

// RouteTotals is the relay throughput across every rule, which the dashboard's
// traffic card uses to account for relayed bytes rather than leaving them
// unexplained (§12.4).
type RouteTotals struct {
	Routes            int     `json:"routes"`
	RxBytesPerSecond  float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond  float64 `json:"tx_bytes_per_second"`
	ActiveConnections int     `json:"active_connections"`
}

// RouteSource supplies the relay traffic to multiplex into each reading. It is
// satisfied by the port forwarding accounting, and is an interface here so this
// package does not depend on that one.
type RouteSource interface {
	RouteTraffic() []RouteTraffic
}

// Snapshot is one complete reading of the machine's health.
type Snapshot struct {
	At time.Time `json:"at"`

	Cpu     []CPUUsage  `json:"cpu"`
	Load    LoadAverage `json:"load"`
	Memory  Memory      `json:"memory"`
	Swap    Swap        `json:"swap"`
	Disks   []Disk      `json:"disks"`
	Network struct {
		Interfaces []Interface   `json:"interfaces"`
		Totals     NetworkTotals `json:"totals"`
	} `json:"network"`

	// Routes is the port forwarding traffic, absent on an instance with no
	// forwarding rules rather than present and empty.
	Routes      []RouteTraffic `json:"routes,omitempty"`
	RouteTotals RouteTotals    `json:"route_totals"`

	// IntervalSeconds is the gap this reading's rates were computed over, so a
	// consumer can tell a fresh figure from a stale one.
	IntervalSeconds float64 `json:"interval_seconds"`
	// Errors lists what could not be read, so a partial reading says so rather
	// than reporting zeroes as measurements.
	Errors []string `json:"errors,omitempty"`
}

// Sampler reads the machine on a ticker, keeps a ring buffer for sparklines,
// and fans each reading out to the live stream (§11).
type Sampler struct {
	reader   *Reader
	links    link.LinkManager
	counters *Counters
	settings Settings
	log      *slog.Logger
	hub      *Hub

	// routes is wired after construction, because the forwarding accounting is
	// built after the sampler and reads the same settings store.
	routesMu sync.RWMutex
	routes   RouteSource

	mu       sync.RWMutex
	latest   Snapshot
	history  []Snapshot
	previous struct {
		cpu        []CPUTimes
		interfaces map[string]InterfaceCounters
		at         time.Time
	}

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

// Deps is what the sampler needs.
type Deps struct {
	Reader   *Reader
	Links    link.LinkManager
	Counters *Counters
	Settings Settings
	Log      *slog.Logger
}

// New returns a sampler.
func New(d Deps) *Sampler {
	reader := d.Reader
	if reader == nil {
		reader = NewReader()
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	return &Sampler{
		reader: reader, links: d.Links, counters: d.Counters,
		settings: d.Settings, log: log, hub: NewHub(),
	}
}

// Hub exposes the fan-out for the live stream endpoint.
func (s *Sampler) Hub() *Hub { return s.hub }

// Counters exposes the traffic accounting, which shutdown flushes.
func (s *Sampler) Counters() *Counters { return s.counters }

// SetRoutes wires the port forwarding accounting, so relay traffic rides the
// metrics stream the frontend is already subscribed to.
func (s *Sampler) SetRoutes(source RouteSource) {
	s.routesMu.Lock()
	s.routes = source
	s.routesMu.Unlock()
}

// routeTraffic reads the relay figures for one snapshot.
func (s *Sampler) routeTraffic() ([]RouteTraffic, RouteTotals) {
	s.routesMu.RLock()
	source := s.routes
	s.routesMu.RUnlock()
	if source == nil {
		return nil, RouteTotals{}
	}

	list := source.RouteTraffic()
	totals := RouteTotals{Routes: len(list)}
	for _, route := range list {
		totals.RxBytesPerSecond += route.RxBytesPerSecond
		totals.TxBytesPerSecond += route.TxBytesPerSecond
		totals.ActiveConnections += route.ActiveConnections
	}
	return list, totals
}

// Start begins sampling.
func (s *Sampler) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	if s.counters != nil {
		if err := s.counters.Load(ctx); err != nil {
			s.log.Error("reading persisted traffic counters failed", "error", err)
		}
	}

	// One reading immediately, so the first request after startup has data
	// rather than an empty snapshot.
	s.Sample(s.ctx)

	s.wg.Add(1)
	go s.loop(s.ctx)
	return nil
}

// Stop ends sampling and flushes the traffic counters (§20).
func (s *Sampler) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
	s.hub.Close()
}

func (s *Sampler) loop(ctx context.Context) {
	defer s.wg.Done()

	interval := s.interval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// The totals are written far less often than they are updated: the in-memory
	// figures are authoritative between writes, and a flush every thirty seconds
	// bounds what a crash can lose to that much traffic.
	flush := time.NewTicker(30 * time.Second)
	defer flush.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.Sample(ctx)
			// A settings change to the interval takes effect without a restart.
			if next := s.interval(); next != interval {
				interval = next
				ticker.Reset(next)
			}
		case <-flush.C:
			s.flush(ctx)
		}
	}
}

func (s *Sampler) interval() time.Duration {
	if s.settings == nil {
		return time.Second
	}
	seconds := s.settings.Float("metrics.sample_interval_seconds")
	if seconds <= 0 {
		seconds = 1
	}
	return time.Duration(seconds * float64(time.Second))
}

func (s *Sampler) historyPoints() int {
	if s.settings == nil {
		return 300
	}
	points := int(s.settings.Int("metrics.history_points"))
	if points < 1 {
		points = 300
	}
	return points
}

func (s *Sampler) flush(ctx context.Context) {
	if s.counters == nil {
		return
	}
	if err := s.counters.Flush(ctx); err != nil {
		s.log.Error("persisting traffic counters failed", "error", err)
	}
}

// Flush persists the traffic counters now, which graceful shutdown calls.
func (s *Sampler) Flush(ctx context.Context) error {
	if s.counters == nil {
		return nil
	}
	return s.counters.Flush(ctx)
}

// Sample takes one reading, stores it and publishes it.
func (s *Sampler) Sample(ctx context.Context) Snapshot {
	now := time.Now()
	snapshot := Snapshot{At: now}

	s.mu.RLock()
	previousCpu := s.previous.cpu
	previousInterfaces := s.previous.interfaces
	previousAt := s.previous.at
	s.mu.RUnlock()

	elapsed := 0.0
	if !previousAt.IsZero() {
		elapsed = now.Sub(previousAt).Seconds()
	}
	snapshot.IntervalSeconds = elapsed

	currentCpu, err := s.reader.CPU()
	if err != nil {
		snapshot.Errors = append(snapshot.Errors, err.Error())
	} else if previousCpu != nil {
		snapshot.Cpu = CPUDelta(previousCpu, currentCpu)
	}

	if load, err := s.reader.Load(); err != nil {
		snapshot.Errors = append(snapshot.Errors, err.Error())
	} else {
		snapshot.Load = load
	}

	if memory, swap, err := s.reader.MemoryInfo(); err != nil {
		snapshot.Errors = append(snapshot.Errors, err.Error())
	} else {
		snapshot.Memory = memory
		snapshot.Swap = swap
	}

	if disks, err := s.reader.Disks(); err != nil {
		snapshot.Errors = append(snapshot.Errors, err.Error())
	} else {
		hide := s.settings != nil && s.settings.Bool("metrics.hide_pseudo_filesystems")
		snapshot.Disks = FilterDisks(disks, hide)
	}

	interfaces := s.readInterfaces(ctx, &snapshot)
	ApplyThroughput(interfaces, previousInterfaces, elapsed)

	// The volume accounting runs on every sample, because a reset between two
	// samples is only detectable by comparing them (§11.3).
	if s.counters != nil {
		observations := make([]Observation, 0, len(interfaces))
		for _, iface := range interfaces {
			observations = append(observations, Observation{
				Name: iface.Name, Index: iface.Index,
				RxBytes: iface.Counters.RxBytes, TxBytes: iface.Counters.TxBytes,
			})
		}
		volumes := s.counters.Observe(observations)
		byName := make(map[string]Volume, len(volumes))
		for _, v := range volumes {
			byName[v.InterfaceName] = v
		}
		for i := range interfaces {
			interfaces[i].RxBytesSinceBoot = interfaces[i].Counters.RxBytes
			interfaces[i].TxBytesSinceBoot = interfaces[i].Counters.TxBytes
			if v, ok := byName[interfaces[i].Name]; ok {
				interfaces[i].RxBytesSinceInstall = v.RxBytesTotal
				interfaces[i].TxBytesSinceInstall = v.TxBytesTotal
			}
		}
	} else {
		for i := range interfaces {
			interfaces[i].RxBytesSinceBoot = interfaces[i].Counters.RxBytes
			interfaces[i].TxBytesSinceBoot = interfaces[i].Counters.TxBytes
		}
	}

	snapshot.Network.Interfaces = interfaces
	snapshot.Network.Totals = Totals(interfaces)
	snapshot.Routes, snapshot.RouteTotals = s.routeTraffic()
	snapshot.normaliseLists()

	s.mu.Lock()
	s.latest = snapshot
	s.previous.cpu = currentCpu
	s.previous.interfaces = CountersOf(interfaces)
	s.previous.at = now
	s.history = append(s.history, snapshot)
	if limit := s.historyPoints(); len(s.history) > limit {
		s.history = s.history[len(s.history)-limit:]
	}
	s.mu.Unlock()

	s.hub.Publish(snapshot)
	return snapshot
}

// normaliseLists makes every list in a snapshot an empty list rather than a
// nil one, so the JSON carries [] instead of null.
//
// A nil Go slice marshalling to null is an accident of encoding/json, not a
// statement anyone meant to make, and the difference is invisible from this
// side. It was very visible from the browser: the first sample after every
// start has no CPU utilisation, because utilisation is a delta and there is
// nothing yet to subtract from, so `cpu` arrived as null. The dashboard reads
// `point.cpu[0]` and threw, which took the whole resource grid down with it —
// the Disk and Traffic cards simply did not render for the first sampling
// interval after each restart, which is exactly when somebody is looking at
// the panel because they have just upgraded it.
//
// An empty list says what is true — no per-core figures for this reading — and
// says it in a shape every consumer already handles. Routes is deliberately
// left alone: it is `omitempty` and its absence means "this host has no
// forwarding rules", which is a different statement from "none right now".
func (s *Snapshot) normaliseLists() {
	if s.Cpu == nil {
		s.Cpu = []CPUUsage{}
	}
	if s.Disks == nil {
		s.Disks = []Disk{}
	}
	if s.Network.Interfaces == nil {
		s.Network.Interfaces = []Interface{}
	}
}

// readInterfaces prefers netlink and falls back to /proc/net/dev.
func (s *Sampler) readInterfaces(ctx context.Context, snapshot *Snapshot) []Interface {
	if s.links != nil {
		links, err := s.links.List(ctx)
		if err == nil {
			return InterfacesFromLinks(links)
		}
		snapshot.Errors = append(snapshot.Errors,
			"interface details came from /proc because netlink could not be read: "+err.Error())
	}
	counters, err := s.reader.ProcNetDev()
	if err != nil {
		snapshot.Errors = append(snapshot.Errors, err.Error())
		return nil
	}
	return InterfacesFromProc(counters)
}

// Latest returns the most recent reading.
func (s *Sampler) Latest() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	latest := s.latest
	// Also normalised here, because this is reachable before the first sample
	// has run at all — a request that lands in the gap between the panel
	// answering and the sampler ticking gets the zero value, whose lists are
	// nil for a different reason than the first sample's are.
	latest.normaliseLists()
	return latest
}

// History returns the ring buffer, oldest first, capped at limit when given.
func (s *Sampler) History(limit int) []Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > len(s.history) {
		limit = len(s.history)
	}
	out := make([]Snapshot, limit)
	copy(out, s.history[len(s.history)-limit:])
	return out
}

// AllDisks returns every mount including the kernel's own, which the filtered
// snapshot leaves out but which stays retrievable (§11.1).
func (s *Sampler) AllDisks() ([]Disk, error) { return s.reader.Disks() }

// Healthy reports whether the sampler has produced a reading, which the health
// endpoint shows.
func (s *Sampler) Healthy() (bool, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.latest.At.IsZero(), s.latest.At
}
