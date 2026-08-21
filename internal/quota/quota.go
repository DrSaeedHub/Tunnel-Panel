// Package quota is traffic limits: how much a tunnel, a forwarding rule or one
// of a rule's destinations may carry over a window, and what happens when it
// has carried that much.
//
// There are two answers, and they are the two modes. Warning changes nothing —
// the limit is a line on a gauge, and crossing it is reported and left alone.
// Enforcing stops the thing that crossed it: the tunnel is brought down, the
// rule is disabled, the destination is taken out of service. What was stopped
// by the panel is started again by the panel when the window rolls over, when
// the usage is reset, or when the limit is removed — an operator who bought
// another month of traffic should not also have to remember what to turn back
// on.
//
// Usage is a subtraction, never a reset: every subject already has a
// cumulative counter that survives reboots and rebuilds, and a window is a
// baseline recorded against it. Rolling over rebases the baseline and touches
// no counter, so the lifetime figures stay whole.
package quota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Subject names one limited thing. Exactly one of the three shapes is filled:
// a tunnel id, a rule id, or a rule id with an address and port.
type Subject struct {
	ScopeID     int64
	TunnelID    int64
	RouteRuleID int64
	Address     string
	Port        int64
}

// DestinationKey is how destination statuses are keyed in responses: the
// address and port joined the way the interface displays them.
func DestinationKey(address string, port int64) string {
	return fmt.Sprintf("%s:%d", address, port)
}

// Limit is one limit's configuration.
type Limit struct {
	LimitBytes int64
	ModeID     int64
	PeriodID   int64
	// DirectionID says which direction counts against the limit: both
	// together, received only, or sent only. A relay whose plan meters only
	// what it serves out can say so instead of halving its allowance.
	DirectionID int64
}

// row is one quota as stored, config and window state together.
type row struct {
	id      int64
	subject Subject
	limit   Limit

	baselineRx, baselineTx int64
	periodStart            string
	quotaDisabled          string
}

// Deps is everything the checker needs, as functions rather than packages so
// that this package depends on none of the ones it acts on.
type Deps struct {
	DB *db.DB

	// The cumulative counters. ok=false means the subject has no reading yet,
	// which is treated as zero for display and as unknown for enforcement:
	// nothing is ever stopped on a counter that could not be read.
	TunnelVolume      func(interfaceName string) (rx, tx uint64, ok bool)
	RuleVolume        func(routeRuleID int64) (rx, tx uint64, ok bool)
	DestinationVolume func(routeRuleID int64, address string, port int64) (rx, tx uint64, ok bool)

	// The enforcement arms. Stop and start act through the same services an
	// operator's own click would, so the interface is torn down or the
	// ruleset rebuilt exactly as if the switch had been flipped by hand.
	StopTunnel            func(ctx context.Context, tunnelID int64) error
	StartTunnel           func(ctx context.Context, tunnelID int64) error
	StopRule              func(ctx context.Context, routeRuleID int64) error
	StartRule             func(ctx context.Context, routeRuleID int64) error
	SetDestinationEnabled func(ctx context.Context, destinationID int64, enabled bool) error

	Log *slog.Logger
	Now func() time.Time
}

// Checker computes usage against every limit, acts on the enforcing ones, and
// keeps the statuses the interface reads.
type Checker struct {
	deps Deps

	mu           sync.RWMutex
	tunnels      map[int64]model.QuotaStatus
	rules        map[int64]model.QuotaStatus
	destinations map[int64]map[string]model.QuotaStatus
}

// New returns a checker over the given dependencies.
func New(deps Deps) *Checker {
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Checker{
		deps:         deps,
		tunnels:      map[int64]model.QuotaStatus{},
		rules:        map[int64]model.QuotaStatus{},
		destinations: map[int64]map[string]model.QuotaStatus{},
	}
}

// Run sweeps on the given interval until the context ends.
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	c.Sweep(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.Sweep(ctx)
		}
	}
}

// ---------------------------------------------------------------- statuses

// TunnelStatus returns one tunnel's limit as of the last sweep.
func (c *Checker) TunnelStatus(tunnelID int64) *model.QuotaStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if status, ok := c.tunnels[tunnelID]; ok {
		copied := status
		return &copied
	}
	return nil
}

// RuleStatus returns one rule's limit as of the last sweep.
func (c *Checker) RuleStatus(routeRuleID int64) *model.QuotaStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if status, ok := c.rules[routeRuleID]; ok {
		copied := status
		return &copied
	}
	return nil
}

// All returns every status, for the one endpoint the interface polls.
func (c *Checker) All() (tunnels, rules map[int64]model.QuotaStatus,
	destinations map[int64]map[string]model.QuotaStatus) {

	c.mu.RLock()
	defer c.mu.RUnlock()
	tunnels = make(map[int64]model.QuotaStatus, len(c.tunnels))
	for id, status := range c.tunnels {
		tunnels[id] = status
	}
	rules = make(map[int64]model.QuotaStatus, len(c.rules))
	for id, status := range c.rules {
		rules[id] = status
	}
	destinations = make(map[int64]map[string]model.QuotaStatus, len(c.destinations))
	for id, byDest := range c.destinations {
		copied := make(map[string]model.QuotaStatus, len(byDest))
		for key, status := range byDest {
			copied[key] = status
		}
		destinations[id] = copied
	}
	return tunnels, rules, destinations
}

// ---------------------------------------------------------------- writing

// Set creates or replaces a subject's limit. A limit of zero or less removes
// it; removing one the panel had enforced starts the subject again, because an
// operator deleting a limit means the stopping should stop.
func (c *Checker) Set(ctx context.Context, subject Subject, limit Limit) error {
	stored, err := c.load(ctx, subject)
	if err != nil {
		return err
	}

	if limit.LimitBytes <= 0 {
		if stored == nil {
			return nil
		}
		if stored.quotaDisabled != "" {
			if err := c.start(ctx, *stored); err != nil {
				c.deps.Log.Error("a subject whose traffic limit was removed could not be started again",
					"error", err)
			}
		}
		if err := c.remove(ctx, stored.id); err != nil {
			return err
		}
		c.forgetStatus(subject)
		return nil
	}

	if limit.ModeID != model.TrafficLimitModeEnforce {
		limit.ModeID = model.TrafficLimitModeWarn
	}
	switch limit.PeriodID {
	case model.TrafficPeriodTotal, model.TrafficPeriodDaily, model.TrafficPeriodWeekly, model.TrafficPeriodMonthly:
	default:
		limit.PeriodID = model.TrafficPeriodMonthly
	}
	switch limit.DirectionID {
	case model.TrafficDirectionRx, model.TrafficDirectionTx:
	default:
		limit.DirectionID = model.TrafficDirectionBoth
	}

	now := c.deps.Now().UTC()
	rx, tx, _ := c.volume(ctx, subject)
	if stored == nil {
		// A new limit starts counting now, not from the beginning of the
		// counters: traffic carried before anybody asked for a limit was
		// never against one.
		return c.insert(ctx, subject, limit, int64(rx), int64(tx), model.FormatTime(windowStart(now, limit.PeriodID)))
	}

	// Changing the window changes what "so far" means, so the count restarts.
	// Changing only the amount or the mode keeps the window as it is: raising
	// a limit mid-month must not forgive the month's usage.
	baselineRx, baselineTx := stored.baselineRx, stored.baselineTx
	periodStart := stored.periodStart
	if limit.PeriodID != stored.limit.PeriodID {
		baselineRx, baselineTx = int64(rx), int64(tx)
		periodStart = model.FormatTime(windowStart(now, limit.PeriodID))
	}
	return c.update(ctx, stored.id, limit, baselineRx, baselineTx, periodStart, stored.quotaDisabled)
}

// Reset rebases a subject's usage to zero and starts it again if the panel had
// stopped it. This is the "I bought more traffic" button.
func (c *Checker) Reset(ctx context.Context, subject Subject) error {
	stored, err := c.load(ctx, subject)
	if err != nil {
		return err
	}
	if stored == nil {
		return fmt.Errorf("no traffic limit is set here")
	}
	if stored.quotaDisabled != "" {
		if err := c.start(ctx, *stored); err != nil {
			return fmt.Errorf("starting it again: %w", err)
		}
	}
	now := c.deps.Now().UTC()
	rx, tx, _ := c.volume(ctx, subject)
	if err := c.update(ctx, stored.id, stored.limit, int64(rx), int64(tx),
		model.FormatTime(windowStart(now, stored.limit.PeriodID)), ""); err != nil {
		return err
	}
	c.Sweep(ctx)
	return nil
}

// ---------------------------------------------------------------- the sweep

// Sweep reads every limit, rolls the windows that have ended, updates the
// statuses, and acts on the enforcing limits that have been reached.
func (c *Checker) Sweep(ctx context.Context) {
	rows, err := c.loadAll(ctx)
	if err != nil {
		c.deps.Log.Error("reading the traffic limits failed", "error", err)
		return
	}

	tunnels := map[int64]model.QuotaStatus{}
	rules := map[int64]model.QuotaStatus{}
	destinations := map[int64]map[string]model.QuotaStatus{}

	now := c.deps.Now().UTC()
	for _, stored := range rows {
		status, ok := c.check(ctx, stored, now)
		if !ok {
			continue
		}
		switch stored.subject.ScopeID {
		case model.QuotaScopeTunnel:
			tunnels[stored.subject.TunnelID] = status
		case model.QuotaScopeRule:
			rules[stored.subject.RouteRuleID] = status
		case model.QuotaScopeDestination:
			byDest := destinations[stored.subject.RouteRuleID]
			if byDest == nil {
				byDest = map[string]model.QuotaStatus{}
				destinations[stored.subject.RouteRuleID] = byDest
			}
			byDest[DestinationKey(stored.subject.Address, stored.subject.Port)] = status
		}
	}

	c.mu.Lock()
	c.tunnels, c.rules, c.destinations = tunnels, rules, destinations
	c.mu.Unlock()
}

// check handles one limit: window rollover, usage, and enforcement.
func (c *Checker) check(ctx context.Context, stored row, now time.Time) (model.QuotaStatus, bool) {
	subject := stored.subject

	// A limit whose subject is gone is a leftover, not an error.
	alive, enabled, err := c.subjectState(ctx, subject)
	if err != nil {
		c.deps.Log.Error("reading a limited subject failed", "error", err)
		return model.QuotaStatus{}, false
	}
	if !alive {
		if err := c.remove(ctx, stored.id); err != nil {
			c.deps.Log.Error("removing an orphaned traffic limit failed", "error", err)
		}
		return model.QuotaStatus{}, false
	}

	rx, tx, readable := c.volume(ctx, subject)

	// The window rolls over: rebase, and start again what this limit stopped.
	start := windowStart(now, stored.limit.PeriodID)
	if stored.limit.PeriodID != model.TrafficPeriodTotal && !start.IsZero() {
		storedStart, parseErr := model.ParseTime(stored.periodStart)
		if stored.periodStart == "" || (parseErr == nil && storedStart.Before(start)) {
			if stored.quotaDisabled != "" {
				if err := c.start(ctx, stored); err != nil {
					// Not rolled over: the retry is the next sweep.
					c.deps.Log.Error("starting a subject again at its window's end failed", "error", err)
					return c.status(stored, rx, tx), true
				}
				stored.quotaDisabled = ""
			}
			stored.baselineRx, stored.baselineTx = int64(rx), int64(tx)
			stored.periodStart = model.FormatTime(start)
			if err := c.update(ctx, stored.id, stored.limit,
				stored.baselineRx, stored.baselineTx, stored.periodStart, ""); err != nil {
				c.deps.Log.Error("recording a rolled-over traffic window failed", "error", err)
			}
		}
	}
	if stored.periodStart == "" {
		// First sight of a limit written before the checker ran: the window
		// starts now.
		stored.baselineRx, stored.baselineTx = int64(rx), int64(tx)
		stored.periodStart = model.FormatTime(windowStart(now, stored.limit.PeriodID))
		if err := c.update(ctx, stored.id, stored.limit,
			stored.baselineRx, stored.baselineTx, stored.periodStart, stored.quotaDisabled); err != nil {
			c.deps.Log.Error("recording a traffic window's start failed", "error", err)
		}
	}

	status := c.status(stored, rx, tx)

	// Enforcement. Only on a counter that was actually read, only once, and
	// only while the subject is still running.
	if status.Exhausted && stored.limit.ModeID == model.TrafficLimitModeEnforce &&
		stored.quotaDisabled == "" && readable && enabled {
		if err := c.stop(ctx, stored); err != nil {
			c.deps.Log.Error("stopping a subject at its traffic limit failed", "error", err)
			return status, true
		}
		stamp := model.FormatTime(c.deps.Now().UTC())
		if err := c.update(ctx, stored.id, stored.limit,
			stored.baselineRx, stored.baselineTx, stored.periodStart, stamp); err != nil {
			c.deps.Log.Error("recording an enforced traffic limit failed", "error", err)
		}
		status.Stopped = true
		c.deps.Log.Warn("a traffic limit was reached and the panel stopped the subject",
			"scope", subject.ScopeID, "tunnel", subject.TunnelID,
			"rule", subject.RouteRuleID, "destination", subject.Address,
			"used_bytes", status.UsedBytes, "limit_bytes", status.LimitBytes)
	}
	return status, true
}

func (c *Checker) status(stored row, rx, tx uint64) model.QuotaStatus {
	// A counter below its baseline means the counter itself was lost and
	// began again. Zero is the only honest reading.
	usedRx := max64(int64(rx)-stored.baselineRx, 0)
	usedTx := max64(int64(tx)-stored.baselineTx, 0)

	used := usedRx + usedTx
	switch stored.limit.DirectionID {
	case model.TrafficDirectionRx:
		used = usedRx
	case model.TrafficDirectionTx:
		used = usedTx
	}
	return model.QuotaStatus{
		LimitBytes:  stored.limit.LimitBytes,
		ModeID:      stored.limit.ModeID,
		PeriodID:    stored.limit.PeriodID,
		DirectionID: stored.limit.DirectionID,
		UsedBytes:   used,
		UsedRxBytes: usedRx,
		UsedTxBytes: usedTx,
		PeriodStart: stored.periodStart,
		Exhausted:   used >= stored.limit.LimitBytes,
		Stopped:     stored.quotaDisabled != "",
	}
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// windowStart is when the current window began, in UTC. Days end at midnight,
// weeks on Monday, months on the first; the total window never begins again.
func windowStart(now time.Time, periodID int64) time.Time {
	now = now.UTC()
	switch periodID {
	case model.TrafficPeriodDaily:
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	case model.TrafficPeriodWeekly:
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		back := (int(day.Weekday()) + 6) % 7 // Monday = 0
		return day.AddDate(0, 0, -back)
	case model.TrafficPeriodMonthly:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return now // total: records when counting began, and never moves back
}

// ---------------------------------------------------------------- acting

func (c *Checker) volume(ctx context.Context, subject Subject) (rx, tx uint64, ok bool) {
	switch subject.ScopeID {
	case model.QuotaScopeTunnel:
		name, err := c.tunnelInterface(ctx, subject.TunnelID)
		if err != nil || name == "" {
			return 0, 0, false
		}
		return c.deps.TunnelVolume(name)
	case model.QuotaScopeRule:
		return c.deps.RuleVolume(subject.RouteRuleID)
	case model.QuotaScopeDestination:
		return c.deps.DestinationVolume(subject.RouteRuleID, subject.Address, subject.Port)
	}
	return 0, 0, false
}

func (c *Checker) stop(ctx context.Context, stored row) error {
	switch stored.subject.ScopeID {
	case model.QuotaScopeTunnel:
		return c.deps.StopTunnel(ctx, stored.subject.TunnelID)
	case model.QuotaScopeRule:
		return c.deps.StopRule(ctx, stored.subject.RouteRuleID)
	case model.QuotaScopeDestination:
		id, err := c.destinationID(ctx, stored.subject)
		if err != nil {
			return err
		}
		return c.deps.SetDestinationEnabled(ctx, id, false)
	}
	return fmt.Errorf("unknown scope %d", stored.subject.ScopeID)
}

func (c *Checker) start(ctx context.Context, stored row) error {
	switch stored.subject.ScopeID {
	case model.QuotaScopeTunnel:
		return c.deps.StartTunnel(ctx, stored.subject.TunnelID)
	case model.QuotaScopeRule:
		return c.deps.StartRule(ctx, stored.subject.RouteRuleID)
	case model.QuotaScopeDestination:
		id, err := c.destinationID(ctx, stored.subject)
		if err != nil {
			return err
		}
		return c.deps.SetDestinationEnabled(ctx, id, true)
	}
	return fmt.Errorf("unknown scope %d", stored.subject.ScopeID)
}

// ---------------------------------------------------------------- storage

func (c *Checker) loadAll(ctx context.Context) ([]row, error) {
	rows, err := c.deps.DB.Read.QueryContext(ctx, `
		SELECT TrafficQuotaID, ScopeTypeID, TunnelID, RouteRuleID, Address, Port,
		       LimitBytes, ModeID, PeriodID, DirectionID,
		       BaselineRxBytes, BaselineTxBytes, PeriodStartDate, QuotaDisabledDate
		FROM TrafficQuota WHERE IsDeleted = 0`)
	if err != nil {
		return nil, fmt.Errorf("reading traffic limits: %w", err)
	}
	defer rows.Close()

	var out []row
	for rows.Next() {
		stored, err := scanRow(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, stored)
	}
	return out, rows.Err()
}

func (c *Checker) load(ctx context.Context, subject Subject) (*row, error) {
	where, args := subjectWhere(subject)
	stored, err := scanRow(c.deps.DB.Read.QueryRowContext(ctx, `
		SELECT TrafficQuotaID, ScopeTypeID, TunnelID, RouteRuleID, Address, Port,
		       LimitBytes, ModeID, PeriodID, DirectionID,
		       BaselineRxBytes, BaselineTxBytes, PeriodStartDate, QuotaDisabledDate
		FROM TrafficQuota WHERE IsDeleted = 0 AND `+where, args...).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

func scanRow(scan func(...any) error) (row, error) {
	var stored row
	var tunnelID, ruleID, port sql.NullInt64
	var address, periodStart, quotaDisabled sql.NullString
	if err := scan(&stored.id, &stored.subject.ScopeID, &tunnelID, &ruleID, &address, &port,
		&stored.limit.LimitBytes, &stored.limit.ModeID, &stored.limit.PeriodID,
		&stored.limit.DirectionID,
		&stored.baselineRx, &stored.baselineTx, &periodStart, &quotaDisabled); err != nil {
		return stored, fmt.Errorf("reading a traffic limit: %w", err)
	}
	stored.subject.TunnelID = tunnelID.Int64
	stored.subject.RouteRuleID = ruleID.Int64
	stored.subject.Address = address.String
	stored.subject.Port = port.Int64
	stored.periodStart = periodStart.String
	stored.quotaDisabled = quotaDisabled.String
	return stored, nil
}

func subjectWhere(subject Subject) (string, []any) {
	switch subject.ScopeID {
	case model.QuotaScopeTunnel:
		return "ScopeTypeID = 10 AND TunnelID = ?", []any{subject.TunnelID}
	case model.QuotaScopeRule:
		return "ScopeTypeID = 20 AND RouteRuleID = ?", []any{subject.RouteRuleID}
	default:
		return "ScopeTypeID = 30 AND RouteRuleID = ? AND Address = ? AND Port = ?",
			[]any{subject.RouteRuleID, subject.Address, subject.Port}
	}
}

func (c *Checker) insert(ctx context.Context, subject Subject, limit Limit,
	baselineRx, baselineTx int64, periodStart string) error {

	now := model.NowUTC()
	var tunnelID, ruleID, port any
	var address any
	if subject.ScopeID == model.QuotaScopeTunnel {
		tunnelID = subject.TunnelID
	} else {
		ruleID = subject.RouteRuleID
	}
	if subject.ScopeID == model.QuotaScopeDestination {
		address, port = subject.Address, subject.Port
	}
	_, err := c.deps.DB.Write.ExecContext(ctx, `
		INSERT INTO TrafficQuota
			(ScopeTypeID, TunnelID, RouteRuleID, Address, Port,
			 LimitBytes, ModeID, PeriodID, DirectionID,
			 BaselineRxBytes, BaselineTxBytes, PeriodStartDate,
			 CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		subject.ScopeID, tunnelID, ruleID, address, port,
		limit.LimitBytes, limit.ModeID, limit.PeriodID, limit.DirectionID,
		baselineRx, baselineTx, periodStart, now, now)
	if err != nil {
		return fmt.Errorf("storing a traffic limit: %w", err)
	}
	return nil
}

func (c *Checker) update(ctx context.Context, id int64, limit Limit,
	baselineRx, baselineTx int64, periodStart, quotaDisabled string) error {

	var disabled any
	if quotaDisabled != "" {
		disabled = quotaDisabled
	}
	_, err := c.deps.DB.Write.ExecContext(ctx, `
		UPDATE TrafficQuota
		SET LimitBytes = ?, ModeID = ?, PeriodID = ?, DirectionID = ?,
		    BaselineRxBytes = ?, BaselineTxBytes = ?, PeriodStartDate = ?,
		    QuotaDisabledDate = ?, UpdatedDate = ?
		WHERE TrafficQuotaID = ? AND IsDeleted = 0`,
		limit.LimitBytes, limit.ModeID, limit.PeriodID, limit.DirectionID,
		baselineRx, baselineTx, periodStart, disabled, model.NowUTC(), id)
	if err != nil {
		return fmt.Errorf("updating a traffic limit: %w", err)
	}
	return nil
}

func (c *Checker) remove(ctx context.Context, id int64) error {
	_, err := c.deps.DB.Write.ExecContext(ctx, `
		UPDATE TrafficQuota SET IsDeleted = 1, UpdatedDate = ? WHERE TrafficQuotaID = ?`,
		model.NowUTC(), id)
	if err != nil {
		return fmt.Errorf("removing a traffic limit: %w", err)
	}
	return nil
}

func (c *Checker) forgetStatus(subject Subject) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch subject.ScopeID {
	case model.QuotaScopeTunnel:
		delete(c.tunnels, subject.TunnelID)
	case model.QuotaScopeRule:
		delete(c.rules, subject.RouteRuleID)
	case model.QuotaScopeDestination:
		if byDest, ok := c.destinations[subject.RouteRuleID]; ok {
			delete(byDest, DestinationKey(subject.Address, subject.Port))
		}
	}
}

// ---------------------------------------------------------------- subjects

// subjectState reports whether the limited thing still exists and whether it
// is currently enabled.
func (c *Checker) subjectState(ctx context.Context, subject Subject) (alive, enabled bool, err error) {
	var isEnabled int64
	switch subject.ScopeID {
	case model.QuotaScopeTunnel:
		err = c.deps.DB.Read.QueryRowContext(ctx,
			`SELECT IsEnabled FROM Tunnel WHERE TunnelID = ? AND IsDeleted = 0`,
			subject.TunnelID).Scan(&isEnabled)
	case model.QuotaScopeRule:
		err = c.deps.DB.Read.QueryRowContext(ctx,
			`SELECT IsEnabled FROM RouteRule WHERE RouteRuleID = ? AND IsDeleted = 0`,
			subject.RouteRuleID).Scan(&isEnabled)
	case model.QuotaScopeDestination:
		err = c.deps.DB.Read.QueryRowContext(ctx, `
			SELECT d.IsEnabled FROM RouteDestination d
			JOIN RouteRule r ON r.RouteRuleID = d.RouteRuleID AND r.IsDeleted = 0
			WHERE d.RouteRuleID = ? AND d.Address = ? AND d.Port = ? AND d.IsDeleted = 0`,
			subject.RouteRuleID, subject.Address, subject.Port).Scan(&isEnabled)
	default:
		return false, false, fmt.Errorf("unknown scope %d", subject.ScopeID)
	}
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, isEnabled != 0, nil
}

func (c *Checker) tunnelInterface(ctx context.Context, tunnelID int64) (string, error) {
	var name string
	err := c.deps.DB.Read.QueryRowContext(ctx,
		`SELECT InterfaceName FROM Tunnel WHERE TunnelID = ? AND IsDeleted = 0`,
		tunnelID).Scan(&name)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return name, err
}

func (c *Checker) destinationID(ctx context.Context, subject Subject) (int64, error) {
	var id int64
	err := c.deps.DB.Read.QueryRowContext(ctx, `
		SELECT RouteDestinationID FROM RouteDestination
		WHERE RouteRuleID = ? AND Address = ? AND Port = ? AND IsDeleted = 0`,
		subject.RouteRuleID, subject.Address, subject.Port).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("the destination %s no longer exists on rule %d",
			DestinationKey(subject.Address, subject.Port), subject.RouteRuleID)
	}
	return id, err
}

// ParseScope maps the API's scope word to its identifier.
func ParseScope(scope string) (int64, error) {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "tunnel":
		return model.QuotaScopeTunnel, nil
	case "rule":
		return model.QuotaScopeRule, nil
	case "destination":
		return model.QuotaScopeDestination, nil
	}
	return 0, fmt.Errorf("scope has to be tunnel, rule or destination")
}
