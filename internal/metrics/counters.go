package metrics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Volume is one interface's cumulative traffic as the panel accounts for it.
type Volume struct {
	InterfaceName  string `json:"interface_name"`
	InterfaceIndex int    `json:"interface_index"`
	// RxBytesTotal and TxBytesTotal survive reboots and interface recreation.
	RxBytesTotal uint64 `json:"rx_bytes_total"`
	TxBytesTotal uint64 `json:"tx_bytes_total"`
	// LastRawRxBytes and LastRawTxBytes are the kernel counters at the last
	// sample, already folded into the totals above.
	LastRawRxBytes uint64 `json:"last_raw_rx_bytes"`
	LastRawTxBytes uint64 `json:"last_raw_tx_bytes"`
	// ResetDetected reports that this sample saw the counter restart.
	ResetDetected bool `json:"reset_detected"`
}

// Counters accounts for cumulative traffic across reboots and across interface
// recreation (§11.3).
//
// Both happen routinely here: restarting a tunnel deletes and recreates its
// link, which zeroes the kernel's counters. Presenting a counter that has just
// restarted as a lifetime total is a correctness bug, so the panel keeps its
// own total and rebases whenever the kernel's counter goes backwards or the
// interface index changes.
type Counters struct {
	db *db.DB

	mu    sync.Mutex
	state map[string]*Volume
	// dirty marks the interfaces whose totals have moved since the last write.
	dirty map[string]bool
}

// NewCounters returns a traffic accounter backed by the given database.
func NewCounters(database *db.DB) *Counters {
	return &Counters{db: database, state: map[string]*Volume{}, dirty: map[string]bool{}}
}

// Load reads the persisted totals into memory.
func (c *Counters) Load(ctx context.Context) error {
	rows, err := c.db.Read.QueryContext(ctx, `
		SELECT InterfaceName, InterfaceIndex, RxBytesTotal, TxBytesTotal, LastRawRxBytes, LastRawTxBytes
		FROM InterfaceTrafficCounter WHERE IsDeleted = 0`)
	if err != nil {
		return fmt.Errorf("reading traffic counters: %w", err)
	}
	defer rows.Close()

	c.mu.Lock()
	defer c.mu.Unlock()
	for rows.Next() {
		var v Volume
		var index, rxTotal, txTotal, rxRaw, txRaw int64
		if err := rows.Scan(&v.InterfaceName, &index, &rxTotal, &txTotal, &rxRaw, &txRaw); err != nil {
			return fmt.Errorf("reading a traffic counter: %w", err)
		}
		v.InterfaceIndex = int(index)
		v.RxBytesTotal = uint64(rxTotal)
		v.TxBytesTotal = uint64(txTotal)
		v.LastRawRxBytes = uint64(rxRaw)
		v.LastRawTxBytes = uint64(txRaw)
		copied := v
		c.state[v.InterfaceName] = &copied
	}
	return rows.Err()
}

// Observation is one interface's raw counters at one moment.
type Observation struct {
	Name    string
	Index   int
	RxBytes uint64
	TxBytes uint64
}

// Observe folds a set of readings into the running totals and returns them.
//
// The accounting invariant is that RxBytesTotal always already includes
// everything up to LastRawRxBytes. So an ordinary sample adds the difference,
// and a reset — a counter that went backwards, or an interface index that
// changed — adds the whole of the new counter, because the new interface's
// bytes are all new. Anything transferred between the last sample and the reset
// is genuinely unknowable: the counter that held it is gone.
func (c *Counters) Observe(observations []Observation) []Volume {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]Volume, 0, len(observations))
	for _, observation := range observations {
		v, known := c.state[observation.Name]
		if !known {
			// First sighting: the counter it already carries is traffic this
			// panel never saw, so it starts the total rather than being added
			// to it. Otherwise installing the panel would credit the interface
			// with everything since the machine booted.
			v = &Volume{
				InterfaceName:  observation.Name,
				InterfaceIndex: observation.Index,
				LastRawRxBytes: observation.RxBytes,
				LastRawTxBytes: observation.TxBytes,
			}
			c.state[observation.Name] = v
			c.dirty[observation.Name] = true
			out = append(out, *v)
			continue
		}

		reset := observation.RxBytes < v.LastRawRxBytes ||
			observation.TxBytes < v.LastRawTxBytes ||
			(observation.Index != 0 && v.InterfaceIndex != 0 && observation.Index != v.InterfaceIndex)

		if reset {
			v.RxBytesTotal += observation.RxBytes
			v.TxBytesTotal += observation.TxBytes
		} else {
			v.RxBytesTotal += observation.RxBytes - v.LastRawRxBytes
			v.TxBytesTotal += observation.TxBytes - v.LastRawTxBytes
		}

		v.ResetDetected = reset
		v.LastRawRxBytes = observation.RxBytes
		v.LastRawTxBytes = observation.TxBytes
		if observation.Index != 0 {
			v.InterfaceIndex = observation.Index
		}
		c.dirty[observation.Name] = true
		out = append(out, *v)
	}
	return out
}

// Volumes returns the current totals.
func (c *Counters) Volumes() map[string]Volume {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Volume, len(c.state))
	for name, v := range c.state {
		out[name] = *v
	}
	return out
}

// Flush persists everything that has moved. It is called periodically and on
// graceful shutdown, so at most one interval's traffic is ever lost (§11.3,
// §20).
func (c *Counters) Flush(ctx context.Context) error {
	c.mu.Lock()
	pending := make([]Volume, 0, len(c.dirty))
	for name := range c.dirty {
		if v, ok := c.state[name]; ok {
			pending = append(pending, *v)
		}
	}
	c.dirty = map[string]bool{}
	c.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}

	now := model.NowUTC()
	tx, err := c.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the traffic counter transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	const stmt = `
		INSERT INTO InterfaceTrafficCounter
			(InterfaceName, InterfaceIndex, RxBytesTotal, TxBytesTotal,
			 LastRawRxBytes, LastRawTxBytes, LastSeenDate, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		-- The unique index on the name is partial, filtered on IsDeleted = 0,
		-- so the conflict target has to repeat that filter to match it.
		ON CONFLICT (InterfaceName) WHERE IsDeleted = 0 DO UPDATE SET
			InterfaceIndex = excluded.InterfaceIndex,
			RxBytesTotal   = excluded.RxBytesTotal,
			TxBytesTotal   = excluded.TxBytesTotal,
			LastRawRxBytes = excluded.LastRawRxBytes,
			LastRawTxBytes = excluded.LastRawTxBytes,
			LastSeenDate   = excluded.LastSeenDate,
			UpdatedDate    = excluded.UpdatedDate`

	for _, v := range pending {
		if _, err := tx.ExecContext(ctx, stmt, v.InterfaceName, v.InterfaceIndex,
			int64(v.RxBytesTotal), int64(v.TxBytesTotal),
			int64(v.LastRawRxBytes), int64(v.LastRawTxBytes), now, now, now); err != nil {
			return fmt.Errorf("storing the traffic counter for %s: %w", v.InterfaceName, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing traffic counters: %w", err)
	}
	return nil
}

// Forget removes an interface's accounting, which the delete path uses when a
// tunnel is removed for good.
func (c *Counters) Forget(ctx context.Context, name string) error {
	c.mu.Lock()
	delete(c.state, name)
	delete(c.dirty, name)
	c.mu.Unlock()

	_, err := c.db.Write.ExecContext(ctx,
		`UPDATE InterfaceTrafficCounter SET IsDeleted = 1, UpdatedDate = ? WHERE InterfaceName = ?`,
		model.NowUTC(), name)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("forgetting the traffic counter for %s: %w", name, err)
	}
	return nil
}
