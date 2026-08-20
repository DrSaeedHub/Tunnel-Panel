package monitor

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
)

// probeConfig is a workable configuration for a prober under test: fast enough
// that a test does not wait on it, strict enough that it still exercises the
// real code paths.
func probeConfig() Config {
	return Config{
		TunnelID:            1,
		InterfaceName:       "gre-test",
		Source:              "10.0.0.1",
		Target:              "10.0.0.2",
		Interval:            10 * time.Millisecond,
		Timeout:             20 * time.Millisecond,
		PacketSize:          56,
		WindowSize:          20,
		DegradedLossPercent: 5,
		DownLossPercent:     50,
		StateChangeSamples:  3,
		Enabled:             true,
	}
}

// faultyConn is a socket whose reads fail with something that is neither a
// timeout nor a close: a genuine fault, of the kind that must stop the prober
// so the supervisor can back off and restart it.
type faultyConn struct {
	fakeConn
	err error
}

func (c *faultyConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, c.err }

type faultyDialer struct{ err error }

func (d faultyDialer) Listen(string) (PacketConn, error) {
	conn := &faultyConn{err: d.err}
	conn.inbound = make(chan inboundPacket, 1)
	return conn, nil
}

// A read fault must stop the prober and be reported, not hang it.
//
// The three goroutines a prober runs are not independent: the evaluator exits
// only on cancellation and never touches the socket, so a run that reacted to
// a failed receive by closing the socket alone would wait on that evaluator for
// ever. Nothing would be logged, nothing would be restarted, and the tunnel
// would sit on its last reading looking merely quiet rather than broken.
func TestAReadFaultStopsTheProberInsteadOfHangingIt(t *testing.T) {
	t.Parallel()

	fault := errors.New("the socket broke")
	p := newProber(probeConfig(), faultyDialer{err: fault}, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- p.run(ctx) }()

	select {
	case err := <-done:
		if !errors.Is(err, fault) {
			t.Fatalf("run returned %v, want the read fault %v", err, fault)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after a read fault; it is deadlocked waiting on its own goroutines")
	}
}

// The same must hold when the context is cancelled: every goroutine exits.
func TestCancellingAProberStopsEveryGoroutine(t *testing.T) {
	t.Parallel()

	dialer := newFakeDialer()
	dialer.OnWrite = func(c *fakeConn, id, sequence int, payload []byte) {
		c.deliver(replyTo(id, sequence, payload), &net.IPAddr{IP: net.ParseIP("10.0.0.2")})
	}
	p := newProber(probeConfig(), dialer, nil, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
}

// An expired read deadline is the normal case, not a fault: it is how the
// receiver notices cancellation between packets. Treating it as a fault stops
// the prober a quarter of a second into its first run, which leaves the tunnel
// frozen on whatever it had measured by then.
func TestAnExpiredReadDeadlineIsNotAFault(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{"the loopback socket's timeout", loopbackTimeout{}},
		{"a real socket's deadline", os.ErrDeadlineExceeded},
		{"a wrapped net.OpError", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !isTimeout(c.err) {
				t.Fatalf("isTimeout(%v) = false, want true", c.err)
			}
		})
	}

	if isTimeout(errors.New("the socket broke")) {
		t.Fatal("a plain error must not be mistaken for a timeout")
	}
	if isTimeout(net.ErrClosed) {
		t.Fatal("a closed socket must not be mistaken for a timeout")
	}

	// It must also be a net.Error in full, deprecated Temporary included, so
	// that it is indistinguishable from what a real socket returns.
	var netErr net.Error = loopbackTimeout{}
	if !netErr.Timeout() {
		t.Fatal("the loopback timeout must report itself as a timeout")
	}
}

// The development-mode dialer has to keep a prober running: it is what the
// monitoring subsystem is demonstrated with when the panel runs unprivileged
// and cannot open a raw socket at all. A prober that stalls on it is not
// answering probes, whatever the counters last said.
func TestTheLoopbackDialerKeepsAProberProbing(t *testing.T) {
	t.Parallel()

	cfg := probeConfig()
	cfg.Interval = 20 * time.Millisecond
	cfg.Timeout = 100 * time.Millisecond

	recorder := &snapshotRecorder{}
	p := newProber(cfg, LoopbackDialer{Latency: time.Millisecond}, recorder, nil, nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.run(ctx) }()

	// Long enough to cover several read slices, which is where a receiver that
	// mistook a deadline for a fault used to stop.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := p.Snapshot()
		if snapshot.Stats.Sent > 10 && snapshot.MonitorStateID == model.MonitorStateUp {
			cancel()
			if snapshot.Stats.Received == 0 {
				t.Fatalf("the loopback dialer answered nothing: %+v", snapshot.Stats)
			}
			if snapshot.Stats.LossPercent > 0 {
				t.Fatalf("the loopback dialer answers everything, so loss must be zero: %+v", snapshot.Stats)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	final := p.Snapshot()
	cancel()
	t.Fatalf("the prober stalled: state %s after sending %d and receiving %d",
		final.State, final.Stats.Sent, final.Stats.Received)
}

// snapshotRecorder keeps the snapshots a prober publishes.
type snapshotRecorder struct {
	mu   sync.Mutex
	seen []Snapshot
}

func (r *snapshotRecorder) Publish(s Snapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, s)
}
