package route

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/model"
)

// Monitoring a forwarding rule's destinations (§10).
//
// A relay across two backends is the case this exists for. Every figure the
// panel can show about such a rule is an observation of traffic, and traffic
// only tells you a destination is dead once something has already tried it and
// failed. A probe asks the question directly and on a schedule, so a backend
// that stopped listening is named before an operator has to work it out from a
// share that went to zero.
//
// What it does about the answer is the operator's choice, per rule. Reporting
// changes nothing: the destination is marked down and stays in the rotation.
// Failover takes it out, which is a change to the installed ruleset that the
// panel makes without being asked — so it is never the default, it never
// removes the last destination a rule has, and it is undone the moment the
// destination answers again.

// Monitor state names, which are the MonitorState lookup's own.
const (
	DestinationStateUnknown  = "Unknown"
	DestinationStateUp       = "Up"
	DestinationStateDown     = "Down"
	DestinationStateDisabled = "Disabled"
)

// DestinationHealth is one destination's monitoring, as the API reports it.
type DestinationHealth struct {
	RouteDestinationID int64  `json:"route_destination_id"`
	RouteRuleID        int64  `json:"route_rule_id"`
	Address            string `json:"address"`
	Port               int    `json:"port"`
	// MonitorPort is what is actually knocked on, which is the traffic port
	// unless the destination names another.
	MonitorPort int `json:"monitor_port"`

	State          string `json:"state"`
	MonitorStateID int64  `json:"monitor_state_id"`
	// Since is when the state last changed, so "down" carries how long for.
	Since string `json:"since,omitempty"`
	// Detail is the probe's own words when it failed, which is the difference
	// between a refused connection and a timeout.
	Detail string `json:"detail,omitempty"`

	LastProbeAt string   `json:"last_probe_at,omitempty"`
	LatencyMs   *float64 `json:"latency_ms,omitempty"`

	ConsecutiveFailures  int `json:"consecutive_failures"`
	ConsecutiveSuccesses int `json:"consecutive_successes"`

	// IsSuppressed is the failover state: the monitor has taken this
	// destination out of the rotation and the ruleset no longer names it.
	IsSuppressed bool `json:"is_suppressed"`
	// Mode is what this rule does about a failure, in the operator's terms.
	Mode string `json:"mode"`
	// IntervalSeconds is the resolved probe interval, after the destination's
	// own setting, the rule's, and the panel's have been laid over each other.
	IntervalSeconds float64 `json:"interval_seconds"`
}

// MonitorSettings is the slice of the settings store the monitor reads.
type MonitorSettings interface {
	Bool(key string) bool
	Int(key string) int64
	Float(key string) float64
}

// SuppressionStore is how the monitor records that a destination is out of the
// rotation. *Repo satisfies it.
type SuppressionStore interface {
	SetDestinationSuppressed(ctx context.Context, destinationID int64, suppressed bool) error
}

// MonitorDeps is everything the monitor needs. Every one is an interface or a
// function, so the whole loop runs against fakes without a network.
type MonitorDeps struct {
	Repo     *Repo
	Prober   Prober
	Settings MonitorSettings
	Store    SuppressionStore
	// Reapply rebuilds the installed ruleset. It is called only when a
	// suppression actually changed, because rebuilding a ruleset is not free
	// and a probe that confirms what is already true has changed nothing.
	Reapply func(ctx context.Context) error
	Log     *slog.Logger
	Now     func() time.Time
}

// Monitor probes the destinations of every rule that asks for it.
type Monitor struct {
	repo     *Repo
	prober   Prober
	settings MonitorSettings
	store    SuppressionStore
	reapply  func(ctx context.Context) error
	log      *slog.Logger
	now      func() time.Time

	mu    sync.RWMutex
	state map[int64]*destinationState
}

// destinationState is what the monitor remembers between probes.
type destinationState struct {
	health DestinationHealth
	dueAt  time.Time
	since  time.Time
	lastAt time.Time
	// failover is the mode the last probe ran under, so the rotation decision
	// does not have to read the rule again to know what it is allowed to do.
	failover bool
}

// NewMonitor builds the monitor. A nil prober gets the real one, which is the
// same probe the create form runs before a rule exists.
func NewMonitor(d MonitorDeps) *Monitor {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	prober := d.Prober
	if prober == nil {
		prober = NetProber{}
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	return &Monitor{
		repo: d.Repo, prober: prober, settings: d.Settings, store: d.Store,
		reapply: d.Reapply, log: log, now: now,
		state: map[int64]*destinationState{},
	}
}

// tick is how often the monitor looks for work. The probes themselves run on
// each destination's own interval; this only decides the resolution with which
// those intervals are honoured.
const monitorTick = time.Second

// Run probes until the context is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	ticker := time.NewTicker(monitorTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Sample(ctx)
		}
	}
}

// Sample probes every destination that is due and acts on what comes back. It
// is separated from Run so a test drives it a tick at a time.
func (m *Monitor) Sample(ctx context.Context) {
	if m.repo == nil {
		return
	}
	records, err := m.repo.List(ctx)
	if err != nil {
		m.log.Debug("reading the forwarding rules for monitoring failed", "error", err)
		return
	}

	now := m.now()
	live := map[int64]bool{}
	type job struct {
		record      Record
		destination model.RouteDestination
		config      monitorConfig
	}
	var due []job

	for _, rec := range records {
		for _, d := range rec.Destinations {
			live[d.RouteDestinationID] = true
			config := m.configFor(rec, d)
			state := m.stateFor(rec, d, config, now)

			if !config.enabled {
				// A destination that is no longer monitored must not be left out
				// of the rotation by a monitor that is no longer watching it.
				m.markDisabled(ctx, state)
				continue
			}
			if now.Before(state.dueAt) {
				continue
			}
			due = append(due, job{record: rec, destination: d, config: config})
		}
	}
	m.forgetAllBut(live)
	if len(due) == 0 {
		return
	}

	// Probes are independent and mostly waiting, so they go together. The
	// results are folded in afterwards, in a fixed order, so two destinations
	// answering at the same moment cannot interleave into the state map.
	type answer struct {
		id     int64
		result ReachabilityResult
	}
	results := make([]answer, len(due))
	var wg sync.WaitGroup
	for i, item := range due {
		wg.Add(1)
		go func(i int, item job) {
			defer wg.Done()
			results[i] = answer{
				id: item.destination.RouteDestinationID,
				result: m.prober.Probe(ctx, ReachabilityParams{
					Address:        item.destination.Address,
					Port:           item.config.port,
					Protocol:       item.config.protocol,
					TimeoutSeconds: item.config.timeout.Seconds(),
				}),
			}
		}(i, item)
	}
	wg.Wait()

	after := m.now()
	touched := map[int64]Record{}
	for i, item := range due {
		m.record(item.record, item.destination, item.config, results[i].result, after)
		touched[item.record.RouteRuleID] = item.record
	}

	changed := false
	for _, rec := range touched {
		if m.reconcileRotation(ctx, rec) {
			changed = true
		}
	}
	if changed && m.reapply != nil {
		if err := m.reapply(ctx); err != nil {
			m.log.Error("rebuilding the ruleset after a destination changed state failed",
				"error", err)
		}
	}
}

// monitorConfig is the resolved policy for one destination: the destination's
// own settings laid over the rule's, laid over the panel's.
type monitorConfig struct {
	enabled   bool
	failover  bool
	port      int
	protocol  string
	interval  time.Duration
	timeout   time.Duration
	failures  int
	successes int
}

func (m *Monitor) configFor(rec Record, d model.RouteDestination) monitorConfig {
	config := monitorConfig{
		enabled:   m.settingBool("routes.monitor_enabled", false),
		interval:  seconds(m.settingFloat("routes.monitor_interval_seconds", 15), 15*time.Second),
		timeout:   seconds(m.settingFloat("routes.monitor_timeout_seconds", 3), 3*time.Second),
		failures:  int(m.settingInt("routes.monitor_failure_threshold", 3)),
		successes: int(m.settingInt("routes.monitor_recovery_threshold", 2)),
	}

	if rec.IsMonitorEnabled != nil {
		config.enabled = *rec.IsMonitorEnabled
	}
	if rec.MonitorIntervalSeconds != nil {
		config.interval = seconds(*rec.MonitorIntervalSeconds, config.interval)
	}
	if rec.MonitorTimeoutSeconds != nil {
		config.timeout = seconds(*rec.MonitorTimeoutSeconds, config.timeout)
	}
	if rec.MonitorFailureThreshold != nil {
		config.failures = int(*rec.MonitorFailureThreshold)
	}
	if rec.MonitorRecoveryThreshold != nil {
		config.successes = int(*rec.MonitorRecoveryThreshold)
	}
	config.failover = rec.MonitorModeID != nil && *rec.MonitorModeID == model.RouteMonitorModeFailover

	if d.IsMonitorEnabled != nil {
		config.enabled = *d.IsMonitorEnabled
	}
	if d.MonitorIntervalSeconds != nil {
		config.interval = seconds(*d.MonitorIntervalSeconds, config.interval)
	}
	if d.MonitorTimeoutSeconds != nil {
		config.timeout = seconds(*d.MonitorTimeoutSeconds, config.timeout)
	}
	if d.MonitorFailureThreshold != nil {
		config.failures = int(*d.MonitorFailureThreshold)
	}
	if d.MonitorRecoveryThreshold != nil {
		config.successes = int(*d.MonitorRecoveryThreshold)
	}

	// A destination an operator has switched off is not probed: it is carrying
	// nothing, and reporting it down would be reporting the operator's own
	// decision back to them as a fault.
	if !d.IsEnabled || !rec.IsEnabled {
		config.enabled = false
	}

	config.port = int(d.Port)
	if d.MonitorPort != nil && *d.MonitorPort > 0 {
		config.port = int(*d.MonitorPort)
	}
	// The probe is a TCP connect wherever one is meaningful. Silence from a UDP
	// port proves nothing either way, so a UDP relay is probed over TCP on
	// whatever port the destination names — which is why MonitorPort exists.
	config.protocol = "tcp"

	if config.failures < 1 {
		config.failures = 1
	}
	if config.successes < 1 {
		config.successes = 1
	}
	return config
}

// record folds one probe result into a destination's state. It decides nothing
// about the rotation: that is a question about the rule as a whole and is
// answered once every probe in the round has landed.
func (m *Monitor) record(rec Record, d model.RouteDestination,
	config monitorConfig, result ReachabilityResult, at time.Time) {

	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.state[d.RouteDestinationID]
	if !ok {
		return
	}

	state.lastAt = at
	state.dueAt = at.Add(config.interval)
	state.health.LastProbeAt = at.UTC().Format(time.RFC3339)
	state.health.Detail = result.Detail
	state.health.MonitorPort = config.port
	state.health.IntervalSeconds = config.interval.Seconds()
	state.health.Mode = model.RouteMonitorModeName(modeOf(rec))
	if result.Reachable {
		latency := result.LatencyMs
		state.health.LatencyMs = &latency
		state.health.ConsecutiveFailures = 0
		state.health.ConsecutiveSuccesses++
	} else {
		state.health.LatencyMs = nil
		state.health.ConsecutiveSuccesses = 0
		state.health.ConsecutiveFailures++
	}

	previous := state.health.State
	switch {
	case result.Reachable && state.health.ConsecutiveSuccesses >= config.successes:
		state.health.State = DestinationStateUp
	case !result.Reachable && state.health.ConsecutiveFailures >= config.failures:
		state.health.State = DestinationStateDown
	}
	if state.health.State != previous {
		state.since = at
		state.health.Since = at.UTC().Format(time.RFC3339)
		m.log.Info("a forwarding destination changed state",
			"rule", rec.RouteRuleTitle, "destination", fmt.Sprintf("%s:%d", d.Address, d.Port),
			"from", previous, "to", state.health.State, "detail", result.Detail)
	}
	state.health.MonitorStateID = monitorStateID(state.health.State)
	state.failover = config.failover
}

// reconcileRotation decides which of a rule's destinations belong in the
// ruleset and writes the difference. It reports whether anything moved, which
// is what decides if the ruleset is rebuilt.
//
// The decision is made for the rule as a whole and never one destination at a
// time, because the guard below is about the set: taking one out is only
// allowed while another is still there to take the traffic.
func (m *Monitor) reconcileRotation(ctx context.Context, rec Record) bool {
	m.mu.Lock()
	wanted := map[int64]bool{}
	eligible := 0
	failing := 0
	for _, d := range rec.Destinations {
		if !d.IsEnabled {
			continue
		}
		eligible++
		state, ok := m.state[d.RouteDestinationID]
		if !ok {
			continue
		}
		if state.failover && state.health.State == DestinationStateDown {
			wanted[d.RouteDestinationID] = true
			failing++
		}
	}
	// Never all of them. A rule with every destination down is a rule with
	// nowhere to send traffic, and emptying the rotation would turn a relay
	// that is failing into a relay that does not exist -- harder to diagnose,
	// and no better for the packets. Nothing is taken out in that round.
	if eligible > 0 && failing >= eligible {
		wanted = map[int64]bool{}
	}
	m.mu.Unlock()

	changed := false
	for _, d := range rec.Destinations {
		if !d.IsEnabled {
			continue
		}
		if wanted[d.RouteDestinationID] == m.suppressedNow(d) {
			continue
		}
		if m.store == nil {
			continue
		}
		out := wanted[d.RouteDestinationID]
		if err := m.store.SetDestinationSuppressed(ctx, d.RouteDestinationID, out); err != nil {
			m.log.Error("recording that a destination left the rotation failed",
				"destination", fmt.Sprintf("%s:%d", d.Address, d.Port), "error", err)
			continue
		}
		m.setSuppressed(d.RouteDestinationID, out)
		changed = true
		if out {
			m.log.Warn("a forwarding destination was taken out of the rotation",
				"rule", rec.RouteRuleTitle,
				"destination", fmt.Sprintf("%s:%d", d.Address, d.Port))
		} else {
			m.log.Info("a forwarding destination is back in the rotation",
				"rule", rec.RouteRuleTitle,
				"destination", fmt.Sprintf("%s:%d", d.Address, d.Port))
		}
	}
	return changed
}

// suppressedNow is what the monitor believes about a destination, which is the
// stored value until the monitor has changed it within this round.
func (m *Monitor) suppressedNow(d model.RouteDestination) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if state, ok := m.state[d.RouteDestinationID]; ok {
		return state.health.IsSuppressed
	}
	return d.IsSuppressed
}

func (m *Monitor) setSuppressed(destinationID int64, suppressed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state, ok := m.state[destinationID]; ok {
		state.health.IsSuppressed = suppressed
	}
}

// markDisabled records that a destination is not being monitored, and puts it
// back in the rotation if a monitor that is no longer running took it out.
func (m *Monitor) markDisabled(ctx context.Context, state *destinationState) {
	m.mu.Lock()
	was := state.health.IsSuppressed
	state.health.State = DestinationStateDisabled
	state.health.MonitorStateID = model.MonitorStateDisabled
	state.health.ConsecutiveFailures = 0
	state.health.ConsecutiveSuccesses = 0
	state.health.LatencyMs = nil
	id := state.health.RouteDestinationID
	m.mu.Unlock()

	if !was || m.store == nil {
		return
	}
	if err := m.store.SetDestinationSuppressed(ctx, id, false); err != nil {
		m.log.Error("returning an unmonitored destination to the rotation failed", "error", err)
		return
	}
	m.setSuppressed(id, false)
	if m.reapply != nil {
		if err := m.reapply(ctx); err != nil {
			m.log.Error("rebuilding the ruleset after monitoring was turned off failed", "error", err)
		}
	}
}

func (m *Monitor) stateFor(rec Record, d model.RouteDestination,
	config monitorConfig, now time.Time) *destinationState {

	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.state[d.RouteDestinationID]
	if !ok {
		state = &destinationState{
			health: DestinationHealth{
				RouteDestinationID: d.RouteDestinationID,
				RouteRuleID:        rec.RouteRuleID,
				State:              DestinationStateUnknown,
				MonitorStateID:     model.MonitorStateUnknown,
			},
			since: now,
		}
		m.state[d.RouteDestinationID] = state
	}
	state.health.RouteRuleID = rec.RouteRuleID
	state.health.Address = d.Address
	state.health.Port = int(d.Port)
	state.health.MonitorPort = config.port
	state.health.IsSuppressed = d.IsSuppressed
	state.health.Mode = model.RouteMonitorModeName(modeOf(rec))
	state.health.IntervalSeconds = config.interval.Seconds()
	if state.health.Since == "" {
		state.health.Since = state.since.UTC().Format(time.RFC3339)
	}
	if config.enabled && state.health.State == DestinationStateDisabled {
		state.health.State = DestinationStateUnknown
		state.health.MonitorStateID = model.MonitorStateUnknown
	}
	return state
}

// forgetAllBut drops the state of destinations that no longer exist. A rule's
// destination rows are replaced whenever it is saved, so this runs constantly
// rather than only on delete.
func (m *Monitor) forgetAllBut(live map[int64]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id := range m.state {
		if !live[id] {
			delete(m.state, id)
		}
	}
}

// Health returns what is known about one rule's destinations, in the order the
// rule lists them.
func (m *Monitor) Health(routeRuleID int64) []DestinationHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DestinationHealth, 0, 4)
	for _, state := range m.state {
		if state.health.RouteRuleID == routeRuleID {
			out = append(out, state.health)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RouteDestinationID < out[j].RouteDestinationID
	})
	return out
}

// Down returns every destination that is down right now, across every rule. It
// is what the dashboard needs to say "something is wrong over there".
func (m *Monitor) Down() []DestinationHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DestinationHealth, 0, 2)
	for _, state := range m.state {
		if state.health.State == DestinationStateDown {
			out = append(out, state.health)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RouteDestinationID < out[j].RouteDestinationID
	})
	return out
}

func modeOf(rec Record) int64 {
	if rec.MonitorModeID != nil {
		return *rec.MonitorModeID
	}
	return model.RouteMonitorModeReport
}

func monitorStateID(state string) int64 {
	switch state {
	case DestinationStateUp:
		return model.MonitorStateUp
	case DestinationStateDown:
		return model.MonitorStateDown
	case DestinationStateDisabled:
		return model.MonitorStateDisabled
	}
	return model.MonitorStateUnknown
}

func seconds(value float64, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return time.Duration(value * float64(time.Second))
}

func (m *Monitor) settingBool(key string, fallback bool) bool {
	if m.settings == nil {
		return fallback
	}
	return m.settings.Bool(key)
}

func (m *Monitor) settingFloat(key string, fallback float64) float64 {
	if m.settings == nil {
		return fallback
	}
	if v := m.settings.Float(key); v > 0 {
		return v
	}
	return fallback
}

func (m *Monitor) settingInt(key string, fallback int64) int64 {
	if m.settings == nil {
		return fallback
	}
	if v := m.settings.Int(key); v > 0 {
		return v
	}
	return fallback
}
