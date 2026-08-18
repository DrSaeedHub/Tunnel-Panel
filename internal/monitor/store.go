package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Store persists monitoring history and state changes.
type Store struct {
	db *db.DB
}

// NewStore returns a store over the given database.
func NewStore(database *db.DB) *Store { return &Store{db: database} }

// Sample is one aggregated bucket, written once per
// monitor.aggregate_interval_seconds per tunnel (§10.4).
type Sample struct {
	TunnelID        int64      `json:"tunnel_id"`
	BucketStartDate string     `json:"bucket_start_date"`
	SentCount       int64      `json:"sent_count"`
	ReceivedCount   int64      `json:"received_count"`
	LossPercent     float64    `json:"loss_percent"`
	RttMinMs        *float64   `json:"rtt_min_ms"`
	RttAvgMs        *float64   `json:"rtt_avg_ms"`
	RttMaxMs        *float64   `json:"rtt_max_ms"`
	RttMdevMs       *float64   `json:"rtt_mdev_ms"`
	JitterMs        *float64   `json:"jitter_ms"`
	MonitorStateID  int64      `json:"monitor_state_id"`
	State           string     `json:"state"`
	BucketStart     *time.Time `json:"-"`
}

// WriteSample stores one bucket.
func (s *Store) WriteSample(ctx context.Context, sample Sample) error {
	now := model.NowUTC()
	_, err := s.db.Write.ExecContext(ctx, `
		INSERT INTO MonitorSample
			(TunnelID, BucketStartDate, SentCount, ReceivedCount, LossPercent,
			 RttMinMs, RttAvgMs, RttMaxMs, RttMdevMs, JitterMs, MonitorStateID,
			 CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		sample.TunnelID, sample.BucketStartDate, sample.SentCount, sample.ReceivedCount,
		sample.LossPercent, sample.RttMinMs, sample.RttAvgMs, sample.RttMaxMs,
		sample.RttMdevMs, sample.JitterMs, sample.MonitorStateID, now, now)
	if err != nil {
		return fmt.Errorf("storing a monitoring sample for tunnel %d: %w", sample.TunnelID, err)
	}
	return nil
}

// Event is one state transition.
type Event struct {
	MonitorEventID     int64    `json:"monitor_event_id"`
	TunnelID           int64    `json:"tunnel_id"`
	FromMonitorStateID int64    `json:"from_monitor_state_id"`
	ToMonitorStateID   int64    `json:"to_monitor_state_id"`
	FromState          string   `json:"from_state"`
	ToState            string   `json:"to_state"`
	Reason             string   `json:"reason"`
	LossPercent        *float64 `json:"loss_percent"`
	RttAvgMs           *float64 `json:"rtt_avg_ms"`
	CreatedDate        string   `json:"created_date"`
}

// WriteEvent stores one transition.
func (s *Store) WriteEvent(ctx context.Context, event Event) error {
	_, err := s.db.Write.ExecContext(ctx, `
		INSERT INTO MonitorEvent
			(TunnelID, FromMonitorStateID, ToMonitorStateID, Reason, LossPercent, RttAvgMs, CreatedDate)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.TunnelID, event.FromMonitorStateID, event.ToMonitorStateID, event.Reason,
		event.LossPercent, event.RttAvgMs, model.NowUTC())
	if err != nil {
		return fmt.Errorf("storing a monitoring event for tunnel %d: %w", event.TunnelID, err)
	}
	return nil
}

// Events returns the most recent transitions for one tunnel, newest first.
func (s *Store) Events(ctx context.Context, tunnelID int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT MonitorEventID, TunnelID, FromMonitorStateID, ToMonitorStateID, Reason,
		       LossPercent, RttAvgMs, CreatedDate
		FROM MonitorEvent WHERE TunnelID = ?
		ORDER BY CreatedDate DESC, MonitorEventID DESC LIMIT ?`, tunnelID, limit)
	if err != nil {
		return nil, fmt.Errorf("reading monitoring events: %w", err)
	}
	defer rows.Close()

	out := []Event{}
	for rows.Next() {
		var e Event
		var loss, rtt sql.NullFloat64
		if err := rows.Scan(&e.MonitorEventID, &e.TunnelID, &e.FromMonitorStateID, &e.ToMonitorStateID,
			&e.Reason, &loss, &rtt, &e.CreatedDate); err != nil {
			return nil, fmt.Errorf("reading a monitoring event: %w", err)
		}
		if loss.Valid {
			v := loss.Float64
			e.LossPercent = &v
		}
		if rtt.Valid {
			v := rtt.Float64
			e.RttAvgMs = &v
		}
		e.FromState = StateName(e.FromMonitorStateID)
		e.ToState = StateName(e.ToMonitorStateID)
		out = append(out, e)
	}
	return out, rows.Err()
}

// HistoryQuery selects and downsamples stored history (§10.4).
type HistoryQuery struct {
	TunnelID int64
	From     time.Time
	To       time.Time
	// ResolutionSeconds groups stored buckets into coarser ones for charting.
	// Zero returns the stored buckets unchanged.
	ResolutionSeconds int
	Limit             int
}

// HistoryPoint is one point of a chart.
type HistoryPoint struct {
	BucketStart   string   `json:"bucket_start"`
	SentCount     int64    `json:"sent_count"`
	ReceivedCount int64    `json:"received_count"`
	LossPercent   float64  `json:"loss_percent"`
	RttMinMs      *float64 `json:"rtt_min_ms"`
	RttAvgMs      *float64 `json:"rtt_avg_ms"`
	RttMaxMs      *float64 `json:"rtt_max_ms"`
	JitterMs      *float64 `json:"jitter_ms"`
	// WorstStateID is the worst state seen inside this point's range, so
	// downsampling can never hide an outage between two healthy buckets.
	WorstStateID int64  `json:"worst_monitor_state_id"`
	WorstState   string `json:"worst_state"`
	// Samples counts the stored buckets folded into this point.
	Samples int `json:"samples"`
}

// History reads stored buckets and folds them to the requested resolution.
func (s *Store) History(ctx context.Context, q HistoryQuery) ([]HistoryPoint, error) {
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-24 * time.Hour)
	}
	limit := q.Limit
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}

	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT BucketStartDate, SentCount, ReceivedCount, LossPercent,
		       RttMinMs, RttAvgMs, RttMaxMs, RttMdevMs, JitterMs, MonitorStateID
		FROM MonitorSample
		WHERE TunnelID = ? AND IsDeleted = 0 AND BucketStartDate >= ? AND BucketStartDate <= ?
		ORDER BY BucketStartDate LIMIT ?`,
		q.TunnelID, model.FormatTime(q.From), model.FormatTime(q.To), limit)
	if err != nil {
		return nil, fmt.Errorf("reading monitoring history: %w", err)
	}
	defer rows.Close()

	var stored []Sample
	for rows.Next() {
		var sample Sample
		var min, avg, max, mdev, jitter sql.NullFloat64
		if err := rows.Scan(&sample.BucketStartDate, &sample.SentCount, &sample.ReceivedCount,
			&sample.LossPercent, &min, &avg, &max, &mdev, &jitter, &sample.MonitorStateID); err != nil {
			return nil, fmt.Errorf("reading a monitoring sample: %w", err)
		}
		sample.RttMinMs = nullFloat(min)
		sample.RttAvgMs = nullFloat(avg)
		sample.RttMaxMs = nullFloat(max)
		sample.RttMdevMs = nullFloat(mdev)
		sample.JitterMs = nullFloat(jitter)
		if parsed, err := model.ParseTime(sample.BucketStartDate); err == nil {
			sample.BucketStart = &parsed
		}
		stored = append(stored, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading monitoring history: %w", err)
	}
	return downsample(stored, q.ResolutionSeconds), nil
}

// downsample folds stored buckets into coarser points.
//
// Loss is recomputed from the summed counts rather than averaged, because the
// mean of percentages over unequal sample counts is not the percentage; and the
// worst state in each range is carried through, so a brief outage cannot be
// smoothed out of existence by zooming out.
func downsample(stored []Sample, resolutionSeconds int) []HistoryPoint {
	out := []HistoryPoint{}
	if len(stored) == 0 {
		return out
	}
	if resolutionSeconds <= 0 {
		for _, sample := range stored {
			out = append(out, HistoryPoint{
				BucketStart: sample.BucketStartDate,
				SentCount:   sample.SentCount, ReceivedCount: sample.ReceivedCount,
				LossPercent: sample.LossPercent,
				RttMinMs:    sample.RttMinMs, RttAvgMs: sample.RttAvgMs, RttMaxMs: sample.RttMaxMs,
				JitterMs:     sample.JitterMs,
				WorstStateID: sample.MonitorStateID, WorstState: StateName(sample.MonitorStateID),
				Samples: 1,
			})
		}
		return out
	}

	resolution := time.Duration(resolutionSeconds) * time.Second
	var (
		current     *HistoryPoint
		bucketStart time.Time
		rttAvgTotal float64
		rttAvgCount int
		jitterTotal float64
		jitterCount int
	)

	flush := func() {
		if current == nil {
			return
		}
		if current.SentCount > 0 {
			current.LossPercent = float64(current.SentCount-current.ReceivedCount) /
				float64(current.SentCount) * 100
		}
		if rttAvgCount > 0 {
			avg := rttAvgTotal / float64(rttAvgCount)
			current.RttAvgMs = &avg
		}
		if jitterCount > 0 {
			jitter := jitterTotal / float64(jitterCount)
			current.JitterMs = &jitter
		}
		current.WorstState = StateName(current.WorstStateID)
		out = append(out, *current)
		current = nil
		rttAvgTotal, rttAvgCount, jitterTotal, jitterCount = 0, 0, 0, 0
	}

	for _, sample := range stored {
		at := time.Time{}
		if sample.BucketStart != nil {
			at = *sample.BucketStart
		}
		start := at.Truncate(resolution)

		if current == nil || !start.Equal(bucketStart) {
			flush()
			bucketStart = start
			current = &HistoryPoint{BucketStart: model.FormatTime(start)}
		}

		current.Samples++
		current.SentCount += sample.SentCount
		current.ReceivedCount += sample.ReceivedCount
		if sample.RttMinMs != nil && (current.RttMinMs == nil || *sample.RttMinMs < *current.RttMinMs) {
			v := *sample.RttMinMs
			current.RttMinMs = &v
		}
		if sample.RttMaxMs != nil && (current.RttMaxMs == nil || *sample.RttMaxMs > *current.RttMaxMs) {
			v := *sample.RttMaxMs
			current.RttMaxMs = &v
		}
		if sample.RttAvgMs != nil {
			rttAvgTotal += *sample.RttAvgMs
			rttAvgCount++
		}
		if sample.JitterMs != nil {
			jitterTotal += *sample.JitterMs
			jitterCount++
		}
		if worseState(sample.MonitorStateID, current.WorstStateID) {
			current.WorstStateID = sample.MonitorStateID
		}
	}
	flush()
	return out
}

// worseState orders the states so the worst one survives downsampling.
func worseState(candidate, incumbent int64) bool {
	rank := map[int64]int{
		model.MonitorStateDisabled: 0,
		model.MonitorStateUnknown:  1,
		model.MonitorStateUp:       2,
		model.MonitorStateDegraded: 3,
		model.MonitorStateDown:     4,
	}
	return rank[candidate] > rank[incumbent]
}

// Prune deletes history older than the retention window (§10.4).
func (s *Store) Prune(ctx context.Context, retentionDays int64) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := model.FormatTime(time.Now().AddDate(0, 0, -int(retentionDays)))

	samples, err := s.db.Write.ExecContext(ctx,
		`DELETE FROM MonitorSample WHERE BucketStartDate < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning monitoring samples: %w", err)
	}
	removed, _ := samples.RowsAffected()

	events, err := s.db.Write.ExecContext(ctx,
		`DELETE FROM MonitorEvent WHERE CreatedDate < ?`, cutoff)
	if err != nil {
		return removed, fmt.Errorf("pruning monitoring events: %w", err)
	}
	eventRows, _ := events.RowsAffected()
	return removed + eventRows, nil
}

func nullFloat(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

// ---------------------------------------------------------------- aggregation

// aggregator accumulates per-probe figures into the one row per tunnel per
// aggregate interval that history is made of (§10.4).
//
// It accumulates rather than sampling the last window, because the window
// overlaps between ticks: summing counts across ticks would double-count. What
// it stores is the window's own view at the end of each bucket, plus the worst
// state seen during it.
type aggregator struct {
	store *Store
	log   logger

	mu      sync.Mutex
	buckets map[int64]*bucket
}

type bucket struct {
	start    time.Time
	cfg      Config
	last     Stats
	worst    int64
	haveData bool
}

type logger interface {
	Error(msg string, args ...any)
}

func newAggregator(store *Store, log logger) *aggregator {
	return &aggregator{store: store, log: log, buckets: map[int64]*bucket{}}
}

// add folds one evaluation into the open bucket for its tunnel.
func (a *aggregator) add(cfg Config, stats Stats, state int64, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	b := a.buckets[cfg.TunnelID]
	if b == nil {
		b = &bucket{start: now, cfg: cfg, worst: state}
		a.buckets[cfg.TunnelID] = b
	}
	b.cfg = cfg
	b.last = stats
	b.haveData = true
	if worseState(state, b.worst) {
		b.worst = state
	}
}

// flush writes and clears every bucket older than the interval.
func (a *aggregator) flush(ctx context.Context, interval time.Duration, now time.Time) {
	a.mu.Lock()
	var due []*bucket
	for id, b := range a.buckets {
		if !b.haveData || now.Sub(b.start) < interval {
			continue
		}
		due = append(due, b)
		delete(a.buckets, id)
	}
	a.mu.Unlock()

	for _, b := range due {
		sample := Sample{
			TunnelID:        b.cfg.TunnelID,
			BucketStartDate: model.FormatTime(b.start),
			SentCount:       int64(b.last.Sent),
			ReceivedCount:   int64(b.last.Received),
			LossPercent:     b.last.LossPercent,
			RttMinMs:        b.last.RttMinMs,
			RttAvgMs:        b.last.RttAvgMs,
			RttMaxMs:        b.last.RttMaxMs,
			RttMdevMs:       b.last.RttMdevMs,
			JitterMs:        b.last.JitterMs,
			MonitorStateID:  b.worst,
		}
		if err := a.store.WriteSample(ctx, sample); err != nil && a.log != nil {
			a.log.Error("writing a monitoring sample failed",
				"tunnel_id", b.cfg.TunnelID, "error", err)
		}
	}
}

// forget drops a tunnel's open bucket, which happens when it stops being
// monitored.
func (a *aggregator) forget(tunnelID int64) {
	a.mu.Lock()
	delete(a.buckets, tunnelID)
	a.mu.Unlock()
}
