package monitor

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drs/gre-panel/internal/model"
)

// readSlice is how long a receive waits before checking for cancellation. It
// bounds shutdown latency without busy-waiting.
const readSlice = 250 * time.Millisecond

// maxSequence is where the 16-bit ICMP sequence number wraps.
const maxSequence = 1 << 16

// Snapshot is one tunnel's current monitoring picture, as the status endpoint
// and the live stream report it.
type Snapshot struct {
	TunnelID       int64     `json:"tunnel_id"`
	InterfaceName  string    `json:"interface_name"`
	MonitorStateID int64     `json:"monitor_state_id"`
	State          string    `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	Stats          Stats     `json:"stats"`
	Source         string    `json:"source,omitempty"`
	Target         string    `json:"target,omitempty"`
	Enabled        bool      `json:"enabled"`
	Since          time.Time `json:"since"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Publisher receives every snapshot a prober produces. The supervisor uses it
// to fan out to the live stream and to the history writer.
type Publisher interface {
	Publish(Snapshot)
}

// TransitionSink records a state change. Every transition writes a
// MonitorEvent row (§10.2).
type TransitionSink interface {
	RecordTransition(ctx context.Context, cfg Config, t Transition, stats Stats)
}

// prober monitors one tunnel: one socket, one sender, one receiver, one
// evaluator.
type prober struct {
	cfg     atomic.Pointer[Config]
	dialer  Dialer
	window  *Window
	machine *Machine

	publisher   Publisher
	transitions TransitionSink
	aggregator  *aggregator

	identifier int
	isIPv6     bool
	// traffic answers whether the interface moved anything since the last
	// sample, which is what keeps a filtered path from reading as a dead one.
	traffic *trafficWatch

	mu        sync.Mutex
	since     time.Time
	updatedAt time.Time
	lastState int64
	lastStats Stats
	lastError string
}

// newProber builds a prober for one tunnel. The echo identifier is derived from
// the tunnel identifier so that replies can never be miscounted across tunnels
// sharing a raw socket's view of the network (§10.1).
func newProber(cfg Config, dialer Dialer, publisher Publisher, transitions TransitionSink,
	agg *aggregator, traffic TrafficReader) *prober {
	p := &prober{
		dialer:      dialer,
		window:      NewWindow(cfg.WindowSize),
		machine:     NewMachine(cfg.StateChangeSamples),
		publisher:   publisher,
		transitions: transitions,
		aggregator:  agg,
		identifier:  identifierFor(cfg.TunnelID),
		since:       time.Now(),
		lastState:   model.MonitorStateUnknown,
		traffic:     &trafficWatch{reader: traffic},
	}
	p.cfg.Store(&cfg)
	return p
}

// identifierFor derives a stable, non-zero 16-bit echo identifier.
//
// It is mixed with the process identifier so two panels on one host — which
// should not happen, and which the data directory lock prevents — still could
// not read each other's replies.
func identifierFor(tunnelID int64) int {
	id := (int(tunnelID)*2654435761 + os.Getpid()) & 0xffff
	if id == 0 {
		id = 1
	}
	return id
}

// Config returns the configuration in force.
func (p *prober) Config() Config { return *p.cfg.Load() }

// Snapshot returns the current picture.
func (p *prober) Snapshot() Snapshot {
	cfg := p.Config()
	p.mu.Lock()
	defer p.mu.Unlock()

	state, reason := p.machine.Current()
	return Snapshot{
		TunnelID:       cfg.TunnelID,
		InterfaceName:  cfg.InterfaceName,
		MonitorStateID: state,
		State:          StateName(state),
		Reason:         reason,
		Stats:          p.lastStats,
		Source:         cfg.Source,
		Target:         cfg.Target,
		Enabled:        cfg.Enabled,
		Since:          p.since,
		UpdatedAt:      p.updatedAt,
	}
}

// run probes until the context is cancelled. It returns the error that stopped
// it, so the supervisor can back off and retry (§10.3).
func (p *prober) run(ctx context.Context) error {
	cfg := p.Config()

	if err := sameFamily(cfg.Source, cfg.Target); err != nil {
		return err
	}
	target, isIPv6, err := targetAddr(cfg.Target)
	if err != nil {
		return err
	}
	p.isIPv6 = isIPv6

	conn, err := p.dialer.Listen(cfg.Source)
	if err != nil {
		return err
	}
	// Closing the socket is what unblocks a receive that is parked in the
	// kernel, so it happens on every exit path.
	defer conn.Close()

	p.window.Reset()

	// The socket is open, so whatever fact stopped the last run — a missing
	// interface, an address that could not be bound — has stopped being true,
	// and measurements may explain the state again.
	p.release()

	// The three goroutines run under a context of our own so that one of them
	// failing tears the other two down. Closing the socket is not enough on its
	// own: the evaluator never touches it and would otherwise keep ticking
	// while the wait below blocked on it forever.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)
	errs := make(chan error, 3)

	go func() {
		defer wg.Done()
		errs <- p.send(runCtx, conn, target)
	}()
	go func() {
		defer wg.Done()
		errs <- p.receive(runCtx, conn)
	}()
	go func() {
		defer wg.Done()
		errs <- p.evaluate(runCtx)
	}()

	// The first error stops the prober; the cancellation and the socket close
	// then unwind the rest.
	var first error
	select {
	case <-ctx.Done():
	case first = <-errs:
	}
	cancel()
	conn.Close()
	wg.Wait()
	close(errs)

	if first != nil {
		return first
	}
	return ctx.Err()
}

// send transmits one probe per tick.
func (p *prober) send(ctx context.Context, conn PacketConn, target net.Addr) error {
	cfg := p.Config()
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	sequence := 0
	for {
		// Send immediately, then on every tick: waiting a whole interval before
		// the first probe would leave a fresh tunnel Unknown for no reason.
		now := time.Now()
		current := p.Config()

		packet, err := Encode(p.isIPv6, p.identifier, sequence, current.TunnelID, now, current.PacketSize)
		if err != nil {
			return err
		}
		p.window.Sent(sequence, now, current.Timeout)
		if _, err := conn.WriteTo(packet, target); err != nil {
			if isClosed(err) || ctx.Err() != nil {
				return nil
			}
			// A send failure is recorded against the probe rather than killing
			// the prober: a transient ENETUNREACH while an interface is being
			// rebuilt is a loss, not a fault.
			p.window.Error(sequence, "the probe could not be sent: "+err.Error())
		}

		sequence = (sequence + 1) % maxSequence

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		// An interval change from a settings edit takes effect without a
		// restart (§10.3).
		if next := p.Config().Interval; next != cfg.Interval {
			cfg.Interval = next
			ticker.Reset(next)
		}
	}
}

// receive matches inbound messages to probes.
func (p *prober) receive(ctx context.Context, conn PacketConn) error {
	buffer := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return nil
		}
		if err := conn.SetReadDeadline(time.Now().Add(readSlice)); err != nil {
			if isClosed(err) || ctx.Err() != nil {
				return nil
			}
			return err
		}

		n, from, err := conn.ReadFrom(buffer)
		if err != nil {
			if isTimeout(err) {
				continue // the slice expired, which is how cancellation is noticed
			}
			if isClosed(err) || ctx.Err() != nil {
				return nil
			}
			return err
		}

		cfg := p.Config()
		reply, err := Decode(p.isIPv6, p.identifier, cfg.TunnelID, buffer[:n], from)
		if err != nil {
			// Not ours. On a raw socket most inbound traffic is somebody else's,
			// and silently discarding it is the whole point of the identifier
			// and the payload marker.
			continue
		}

		now := time.Now()
		switch reply.Kind {
		case ReplyEcho:
			rtt := now.Sub(reply.SentAt)
			if rtt < 0 {
				// The echoed timestamp cannot be in the future; if it is, the
				// payload was not one of ours after all.
				continue
			}
			p.window.Reply(reply.Sequence, rtt, now)
		default:
			p.window.Error(reply.Sequence, reply.Detail)
		}
	}
}

// evaluate turns the window into a state on every tick.
func (p *prober) evaluate(ctx context.Context) error {
	cfg := p.Config()
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		current := p.Config()
		if current.Interval != cfg.Interval {
			cfg.Interval = current.Interval
			ticker.Reset(current.Interval)
		}
		p.window.Resize(current.WindowSize)
		// The machine is only ever touched under the lock: a netlink event can
		// be forcing a state through it at this moment.
		p.mu.Lock()
		p.machine.SetRequired(current.StateChangeSamples)
		p.mu.Unlock()

		p.sample(ctx, time.Now())
	}
}

// sample computes one verdict and publishes it.
//
// Everything that touches the state machine or the recorded figures happens
// under the lock, because the evaluator is not the only goroutine that moves
// them: a netlink event forcing the state runs concurrently with this.
func (p *prober) sample(ctx context.Context, now time.Time) {
	cfg := p.Config()
	stats := p.window.Stats(now)
	stats.CarryingTraffic = p.traffic.moved(cfg.InterfaceName)
	state, reason := Classify(stats, cfg)

	p.mu.Lock()
	transition, changed := p.machine.Observe(state, reason)
	if changed {
		p.since = now
		p.lastState = transition.To
	}
	p.lastStats = stats
	p.lastError = stats.LastError
	p.updatedAt = now
	current, _ := p.machine.Current()
	p.mu.Unlock()

	if changed && p.transitions != nil {
		p.transitions.RecordTransition(ctx, cfg, transition, stats)
	}
	if p.aggregator != nil {
		p.aggregator.add(cfg, stats, current, now)
	}
	if p.publisher != nil {
		p.publisher.Publish(p.Snapshot())
	}
}

// force sets a state that is a fact rather than a measurement, such as the
// interface having vanished (§10.3).
func (p *prober) force(ctx context.Context, state int64, reason string) {
	cfg := p.Config()

	p.mu.Lock()
	transition, changed := p.machine.Force(state, reason)
	if changed {
		p.since = time.Now()
		p.lastState = state
	}
	p.updatedAt = time.Now()
	// Copied inside the lock: the evaluator writes these from another goroutine.
	stats := p.lastStats
	p.mu.Unlock()

	if changed && p.transitions != nil {
		p.transitions.RecordTransition(ctx, cfg, transition, stats)
	}
	if p.publisher != nil {
		p.publisher.Publish(p.Snapshot())
	}
}

// release lets measurements explain the state again, once whatever fact was
// forced has stopped being true.
//
// A socket bound to an address survives that address being removed — writes
// simply start failing — so a prober whose interface vanished and came back
// need never restart, and nothing else would clear the reason it was given.
func (p *prober) release() {
	p.mu.Lock()
	p.machine.Release()
	p.mu.Unlock()
}

// update swaps in a new configuration. The prober picks it up on its next tick,
// which is what lets a settings change take effect without a restart (§10.3).
func (p *prober) update(cfg Config) {
	p.cfg.Store(&cfg)
}

// isTimeout reports whether an error is nothing worse than an expired read
// deadline.
//
// It deliberately does not insist on a full net.Error: anything that says it
// timed out is taken at its word, because mistaking a deadline for a fault
// stops the prober, and a deadline expiring is the normal case — it is how the
// receiver notices cancellation.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}
