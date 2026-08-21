package route

import (
	"context"
	"fmt"

	"github.com/drs/gre-panel/internal/model"
)

// Cumulative per-destination traffic.
//
// The rule's own counters cannot be split by destination after the fact, so
// the split is made where it is visible: every connection tracking reading
// already says what moved to each backend since the last one, and folding
// those movements up gives each destination a lifetime total the same way the
// rule gets one. The figure is a floor rather than an estimate above the
// truth — a connection that closes between two readings takes its last bytes
// with it — which is the honest direction for a number a traffic limit is
// compared against.
//
// The totals are keyed by rule, address and port rather than by
// RouteDestinationID, because saving a rule rewrites its destination rows and
// a lifetime total has to survive that.

// DestVolume is one destination's cumulative traffic as the panel accounts it.
type DestVolume struct {
	RouteRuleID int64
	Address     string
	Port        int
	RxBytes     uint64
	TxBytes     uint64
}

type destVolumeKey struct {
	routeRuleID int64
	address     string
	port        int
}

// foldDestinationMovement adds one reading's movements to the totals.
// Callers hold a.mu.
func (a *Accounting) foldDestinationMovement(counts map[int64]ConnectionCount) {
	for ruleID, count := range counts {
		for _, moved := range count.MovedByDestination {
			key := destVolumeKey{routeRuleID: ruleID, address: moved.Address, port: moved.Port}
			volume, ok := a.destVolumes[key]
			if !ok {
				volume = &DestVolume{RouteRuleID: ruleID, Address: moved.Address, Port: moved.Port}
				a.destVolumes[key] = volume
			}
			volume.RxBytes += moved.RxBytes
			volume.TxBytes += moved.TxBytes
			a.destDirty[key] = true
		}
	}
}

// DestinationVolume returns one destination's cumulative traffic. The second
// result reports whether the destination has ever been seen carrying anything;
// a destination that has not is honestly at zero.
func (a *Accounting) DestinationVolume(routeRuleID int64, address string, port int) (rx, tx uint64) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if volume, ok := a.destVolumes[destVolumeKey{routeRuleID: routeRuleID, address: address, port: port}]; ok {
		return volume.RxBytes, volume.TxBytes
	}
	return 0, 0
}

// LoadDestinationVolumes reads the persisted totals into memory.
func (r *CounterRepo) LoadDestinationVolumes(ctx context.Context) ([]DestVolume, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT RouteRuleID, Address, Port, RxBytesTotal, TxBytesTotal
		FROM RouteDestinationTrafficCounter WHERE IsDeleted = 0`)
	if err != nil {
		return nil, fmt.Errorf("reading destination traffic counters: %w", err)
	}
	defer rows.Close()

	var out []DestVolume
	for rows.Next() {
		var v DestVolume
		var rx, tx int64
		if err := rows.Scan(&v.RouteRuleID, &v.Address, &v.Port, &rx, &tx); err != nil {
			return nil, fmt.Errorf("reading a destination traffic counter: %w", err)
		}
		v.RxBytes, v.TxBytes = uint64(rx), uint64(tx)
		out = append(out, v)
	}
	return out, rows.Err()
}

// SaveDestinationVolumes writes the totals that have moved, in one transaction.
func (r *CounterRepo) SaveDestinationVolumes(ctx context.Context, volumes []DestVolume) error {
	if len(volumes) == 0 {
		return nil
	}
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the destination counter transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for _, v := range volumes {
		result, err := tx.ExecContext(ctx, `
			UPDATE RouteDestinationTrafficCounter
			SET RxBytesTotal = ?, TxBytesTotal = ?, LastSeenDate = ?, UpdatedDate = ?
			WHERE RouteRuleID = ? AND Address = ? AND Port = ? AND IsDeleted = 0`,
			int64(v.RxBytes), int64(v.TxBytes), now, now, v.RouteRuleID, v.Address, v.Port)
		if err != nil {
			return fmt.Errorf("saving a destination traffic counter: %w", err)
		}
		if affected, _ := result.RowsAffected(); affected > 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO RouteDestinationTrafficCounter
				(RouteRuleID, Address, Port, RxBytesTotal, TxBytesTotal,
				 LastSeenDate, CreatedDate, UpdatedDate, IsDeleted)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
			v.RouteRuleID, v.Address, v.Port, int64(v.RxBytes), int64(v.TxBytes),
			now, now, now); err != nil {
			return fmt.Errorf("storing a destination traffic counter: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing the destination counters: %w", err)
	}
	return nil
}
