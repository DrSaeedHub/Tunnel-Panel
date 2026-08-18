package diag

import (
	"context"
	"fmt"
	"time"

	"github.com/drs/gre-panel/internal/link"
)

// CounterSnapshot is the raw interface statistics plus how fast they are
// moving (§13.3).
type CounterSnapshot struct {
	InterfaceName string `json:"interface_name"`
	// Counters are the kernel's own cumulative figures.
	Counters link.Statistics `json:"counters"`
	// Deltas are what changed over the sampling interval, and Rates the same
	// per second. Both are raw numbers: formatting belongs to the frontend.
	Deltas           link.Statistics `json:"deltas"`
	RxBytesPerSecond float64         `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64         `json:"tx_bytes_per_second"`
	IntervalSeconds  float64         `json:"interval_seconds"`
	SampledAt        time.Time       `json:"sampled_at"`
}

// Counters reads an interface's statistics twice and reports both the totals
// and the movement between them (§13.3).
func (s *Service) Counters(ctx context.Context, tunnelID int64, sampleSeconds float64) (CounterSnapshot, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return CounterSnapshot{}, err
	}
	if sampleSeconds <= 0 {
		sampleSeconds = 1
	}
	if sampleSeconds > 30 {
		sampleSeconds = 30
	}

	before, err := s.links.Statistics(ctx, rec.InterfaceName)
	if err != nil {
		return CounterSnapshot{}, fmt.Errorf("reading the counters of %s: %w", rec.InterfaceName, err)
	}
	started := time.Now()

	timer := time.NewTimer(time.Duration(sampleSeconds * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return CounterSnapshot{}, ctx.Err()
	case <-timer.C:
	}

	after, err := s.links.Statistics(ctx, rec.InterfaceName)
	if err != nil {
		return CounterSnapshot{}, fmt.Errorf("reading the counters of %s: %w", rec.InterfaceName, err)
	}
	elapsed := time.Since(started).Seconds()

	snapshot := CounterSnapshot{
		InterfaceName:   rec.InterfaceName,
		Counters:        after,
		IntervalSeconds: elapsed,
		SampledAt:       time.Now(),
	}
	// A counter that went backwards means the interface was rebuilt between the
	// two readings, so the difference is reported as zero rather than as a
	// wildly wrong number.
	snapshot.Deltas = link.Statistics{
		RxBytes:   saturating(after.RxBytes, before.RxBytes),
		TxBytes:   saturating(after.TxBytes, before.TxBytes),
		RxPackets: saturating(after.RxPackets, before.RxPackets),
		TxPackets: saturating(after.TxPackets, before.TxPackets),
		RxErrors:  saturating(after.RxErrors, before.RxErrors),
		TxErrors:  saturating(after.TxErrors, before.TxErrors),
		RxDropped: saturating(after.RxDropped, before.RxDropped),
		TxDropped: saturating(after.TxDropped, before.TxDropped),
	}
	if elapsed > 0 {
		snapshot.RxBytesPerSecond = float64(snapshot.Deltas.RxBytes) / elapsed
		snapshot.TxBytesPerSecond = float64(snapshot.Deltas.TxBytes) / elapsed
	}
	return snapshot, nil
}
