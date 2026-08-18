package route

import (
	"context"
	"fmt"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Volume is one forwarding rule's cumulative traffic as the panel accounts for
// it (§5.2).
//
// The invariant that makes this correct is that the totals always already
// include everything up to the LastRaw figures. An ordinary sample adds the
// difference; a sample whose raw value went backwards is a counter that was
// rebuilt, and the whole of the new value is added instead. What moved between
// the last sample and the rebuild is genuinely unknowable — the counter holding
// it no longer exists — which is why the snapshot before every rebuild matters.
type Volume struct {
	RouteRuleID int64 `json:"route_rule_id"`

	RxBytesTotal   uint64 `json:"rx_bytes_total"`
	TxBytesTotal   uint64 `json:"tx_bytes_total"`
	RxPacketsTotal uint64 `json:"rx_packets_total"`
	TxPacketsTotal uint64 `json:"tx_packets_total"`

	// The kernel's counters at the last sample, already folded into the totals.
	LastRawRxBytes   uint64 `json:"last_raw_rx_bytes"`
	LastRawTxBytes   uint64 `json:"last_raw_tx_bytes"`
	LastRawRxPackets uint64 `json:"last_raw_rx_packets"`
	LastRawTxPackets uint64 `json:"last_raw_tx_packets"`

	// ResetDetected reports that this sample saw the counters restart, which
	// happens on every rebuild of the ruleset.
	ResetDetected bool `json:"reset_detected"`
}

// Sample is one aggregated bucket of a rule's traffic, as stored.
type Sample struct {
	RouteRuleID       int64  `json:"route_rule_id"`
	BucketStartDate   string `json:"bucket_start_date"`
	RxBytes           uint64 `json:"rx_bytes"`
	TxBytes           uint64 `json:"tx_bytes"`
	RxPackets         uint64 `json:"rx_packets"`
	TxPackets         uint64 `json:"tx_packets"`
	ActiveConnections int    `json:"active_connections"`
	NewConnections    int    `json:"new_connections"`
}

// CounterRepo is the database view of the accounting tables. It is separate
// from Repo because the read paths of one and the write paths of the other run
// on different schedules: rules change when an operator changes them, counters
// change every second.
type CounterRepo struct {
	db *db.DB
}

// NewCounterRepo returns a repository over the given database.
func NewCounterRepo(database *db.DB) *CounterRepo { return &CounterRepo{db: database} }

// Load reads the persisted totals.
func (r *CounterRepo) Load(ctx context.Context) ([]Volume, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT RouteRuleID, RxBytesTotal, TxBytesTotal, RxPacketsTotal, TxPacketsTotal,
		       LastRawRxBytes, LastRawTxBytes, LastRawRxPackets, LastRawTxPackets
		FROM RouteTrafficCounter WHERE IsDeleted = 0`)
	if err != nil {
		return nil, fmt.Errorf("reading route traffic counters: %w", err)
	}
	defer rows.Close()

	var out []Volume
	for rows.Next() {
		var v Volume
		var rxTotal, txTotal, rxPackets, txPackets int64
		var rawRx, rawTx, rawRxPackets, rawTxPackets int64
		if err := rows.Scan(&v.RouteRuleID, &rxTotal, &txTotal, &rxPackets, &txPackets,
			&rawRx, &rawTx, &rawRxPackets, &rawTxPackets); err != nil {
			return nil, fmt.Errorf("reading a route traffic counter: %w", err)
		}
		v.RxBytesTotal, v.TxBytesTotal = uint64(rxTotal), uint64(txTotal)
		v.RxPacketsTotal, v.TxPacketsTotal = uint64(rxPackets), uint64(txPackets)
		v.LastRawRxBytes, v.LastRawTxBytes = uint64(rawRx), uint64(rawTx)
		v.LastRawRxPackets, v.LastRawTxPackets = uint64(rawRxPackets), uint64(rawTxPackets)
		out = append(out, v)
	}
	return out, rows.Err()
}

// Save writes the totals that have moved, in one transaction.
func (r *CounterRepo) Save(ctx context.Context, volumes []Volume) error {
	if len(volumes) == 0 {
		return nil
	}
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the route counter transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	// The unique index on the rule is partial, filtered on IsDeleted = 0, so
	// the conflict target has to repeat that filter to match it.
	const stmt = `
		INSERT INTO RouteTrafficCounter
			(RouteRuleID, RxBytesTotal, TxBytesTotal, RxPacketsTotal, TxPacketsTotal,
			 LastRawRxBytes, LastRawTxBytes, LastRawRxPackets, LastRawTxPackets,
			 LastSeenDate, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT (RouteRuleID) WHERE IsDeleted = 0 DO UPDATE SET
			RxBytesTotal     = excluded.RxBytesTotal,
			TxBytesTotal     = excluded.TxBytesTotal,
			RxPacketsTotal   = excluded.RxPacketsTotal,
			TxPacketsTotal   = excluded.TxPacketsTotal,
			LastRawRxBytes   = excluded.LastRawRxBytes,
			LastRawTxBytes   = excluded.LastRawTxBytes,
			LastRawRxPackets = excluded.LastRawRxPackets,
			LastRawTxPackets = excluded.LastRawTxPackets,
			LastSeenDate     = excluded.LastSeenDate,
			UpdatedDate      = excluded.UpdatedDate`

	for _, v := range volumes {
		if _, err := tx.ExecContext(ctx, stmt, v.RouteRuleID,
			int64(v.RxBytesTotal), int64(v.TxBytesTotal),
			int64(v.RxPacketsTotal), int64(v.TxPacketsTotal),
			int64(v.LastRawRxBytes), int64(v.LastRawTxBytes),
			int64(v.LastRawRxPackets), int64(v.LastRawTxPackets),
			now, now, now); err != nil {
			return fmt.Errorf("storing the traffic counter of rule %d: %w", v.RouteRuleID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing route traffic counters: %w", err)
	}
	return nil
}

// Forget removes a rule's accounting, which the delete path calls once the rule
// itself is gone.
func (r *CounterRepo) Forget(ctx context.Context, routeRuleID int64) error {
	if _, err := r.db.Write.ExecContext(ctx,
		`UPDATE RouteTrafficCounter SET IsDeleted = 1, UpdatedDate = ? WHERE RouteRuleID = ?`,
		model.NowUTC(), routeRuleID); err != nil {
		return fmt.Errorf("forgetting the traffic counter of rule %d: %w", routeRuleID, err)
	}
	return nil
}

// WriteSamples appends aggregate buckets.
func (r *CounterRepo) WriteSamples(ctx context.Context, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the route sample transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for _, s := range samples {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO RouteTrafficSample
				(RouteRuleID, BucketStartDate, RxBytes, TxBytes, RxPackets, TxPackets,
				 ActiveConnections, NewConnections, CreatedDate, UpdatedDate, IsDeleted)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
			s.RouteRuleID, s.BucketStartDate,
			int64(s.RxBytes), int64(s.TxBytes), int64(s.RxPackets), int64(s.TxPackets),
			s.ActiveConnections, s.NewConnections, now, now); err != nil {
			return fmt.Errorf("storing a traffic sample for rule %d: %w", s.RouteRuleID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing route traffic samples: %w", err)
	}
	return nil
}

// Samples returns the stored buckets for one rule in a window, oldest first.
func (r *CounterRepo) Samples(ctx context.Context, routeRuleID int64, since string, limit int) ([]Sample, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT RouteRuleID, BucketStartDate, RxBytes, TxBytes, RxPackets, TxPackets,
		       ActiveConnections, NewConnections
		FROM RouteTrafficSample
		WHERE RouteRuleID = ? AND IsDeleted = 0 AND BucketStartDate >= ?
		ORDER BY BucketStartDate
		LIMIT ?`, routeRuleID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("reading the traffic history of rule %d: %w", routeRuleID, err)
	}
	defer rows.Close()

	out := []Sample{}
	for rows.Next() {
		var s Sample
		var rxBytes, txBytes, rxPackets, txPackets int64
		if err := rows.Scan(&s.RouteRuleID, &s.BucketStartDate, &rxBytes, &txBytes,
			&rxPackets, &txPackets, &s.ActiveConnections, &s.NewConnections); err != nil {
			return nil, fmt.Errorf("reading a traffic sample: %w", err)
		}
		s.RxBytes, s.TxBytes = uint64(rxBytes), uint64(txBytes)
		s.RxPackets, s.TxPackets = uint64(rxPackets), uint64(txPackets)
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneSamples drops buckets past the retention window and returns how many
// rows went. Zero or fewer days keeps everything, which is what an operator who
// blanked the setting meant.
func (r *CounterRepo) PruneSamples(ctx context.Context, days int64) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := model.FormatTime(time.Now().UTC().AddDate(0, 0, -int(days)))
	res, err := r.db.Write.ExecContext(ctx,
		`DELETE FROM RouteTrafficSample WHERE BucketStartDate < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning route traffic samples: %w", err)
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return removed, nil
}
