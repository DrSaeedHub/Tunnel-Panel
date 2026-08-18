package reconcile

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/tunnel"
)

// DefaultSweepInterval is used when the setting is unreadable. It matches the
// schema's default for system.reconcile_interval_seconds.
const DefaultSweepInterval = 300 * time.Second

// MinSweepInterval bounds how often the sweep can be asked to run. A reconcile
// lists every interface and reads every unit file, so a very small interval
// would spend the host's time discovering nothing.
const MinSweepInterval = 10 * time.Second

// Sweeper runs the reconciliation the specification asks for periodically as
// well as on demand (§12).
//
// It existed only on demand: the report was built when somebody asked the API
// for it, and nothing ever ran it on a schedule. That left two settings with no
// consumer at all — system.reconcile_interval_seconds, which named a cadence
// nothing kept, and system.auto_reapply_on_drift, which named a response to
// drift nothing was watching for. Both were stored, validated, and described on
// the Settings page, and neither did anything.
//
// What it does on finding drift is deliberately narrow. It reapplies a drifted
// tunnel only when the operator has explicitly asked for that, and it never
// adopts, never forgets, and never removes an interface — an unmanaged
// interface belongs to somebody else until a human says otherwise (§12, §17.1).
type Sweeper struct {
	Service  *Service
	Settings SweepSettings
	Log      *slog.Logger

	mu      sync.Mutex
	stop    context.CancelFunc
	stopped chan struct{}
}

// SweepSettings is the settings the sweep reads. It re-reads them every cycle,
// so changing the cadence or turning auto-reapply on takes effect without a
// restart.
type SweepSettings interface {
	Bool(key string) bool
	Int(key string) int64
}

// Start begins sweeping. It returns immediately; Stop waits for the sweep to
// finish the cycle it is in.
func (s *Sweeper) Start(ctx context.Context) {
	if s == nil || s.Service == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.stop = cancel
	s.stopped = make(chan struct{})
	go s.run(runCtx, s.stopped)
}

// Stop ends the sweep and waits for it.
func (s *Sweeper) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	stop, stopped := s.stop, s.stopped
	s.stop, s.stopped = nil, nil
	s.mu.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-stopped
}

// Interval is the configured cadence, bounded, and zero when sweeping is off.
//
// Zero or a negative value turns the sweep off entirely rather than being
// clamped up to the minimum: an operator who sets it to zero is asking for no
// periodic reconciliation, and quietly running it anyway would be the panel
// deciding policy for them.
func (s *Sweeper) Interval() time.Duration {
	if s.Settings == nil {
		return DefaultSweepInterval
	}
	seconds := s.Settings.Int("system.reconcile_interval_seconds")
	if seconds <= 0 {
		return 0
	}
	interval := time.Duration(seconds) * time.Second
	if interval < MinSweepInterval {
		return MinSweepInterval
	}
	return interval
}

func (s *Sweeper) run(ctx context.Context, done chan struct{}) {
	defer close(done)

	for {
		interval := s.Interval()
		if interval == 0 {
			// Off, but not forgotten: wake occasionally so turning it back on in
			// the interface takes effect without restarting the panel.
			interval = DefaultSweepInterval
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				continue
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		s.Sweep(ctx)
	}
}

// Sweep runs one reconciliation and acts on it. It is exported so a test can
// drive a single cycle rather than waiting on a ticker.
func (s *Sweeper) Sweep(ctx context.Context) {
	report, err := s.Service.Report(ctx)
	if err != nil {
		s.log().Error("the periodic reconcile could not read this host's state", "error", err)
		return
	}

	drifted := make([]Item, 0)
	for _, item := range report.Items {
		if item.Status == StatusDrifted && item.TunnelID != nil {
			drifted = append(drifted, item)
		}
	}
	if len(drifted) == 0 {
		return
	}

	if !s.autoReapply() {
		// Reported and left alone. An operator who changed something outside the
		// panel may have meant it, so the default is to say so rather than to
		// undo it.
		for _, item := range drifted {
			s.log().Warn("a tunnel has drifted from its stored configuration",
				"interface", item.InterfaceName, "detail", item.Detail,
				"auto_reapply", false)
		}
		return
	}

	for _, item := range drifted {
		if ctx.Err() != nil {
			return
		}
		// No client address is attached: this is the panel acting on its own
		// schedule rather than on a request, so there is no session for the
		// change to cut off, and the safety check that guards that has nothing
		// to compare against.
		if _, err := s.Service.Tunnels.Reapply(ctx, *item.TunnelID, tunnel.Request{}); err != nil {
			s.log().Error("reapplying a drifted tunnel failed",
				"interface", item.InterfaceName, "error", err)
			continue
		}
		s.log().Info("reapplied a drifted tunnel because system.auto_reapply_on_drift is on",
			"interface", item.InterfaceName, "detail", item.Detail)
	}
}

func (s *Sweeper) autoReapply() bool {
	return s.Settings != nil && s.Settings.Bool("system.auto_reapply_on_drift")
}

func (s *Sweeper) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}
