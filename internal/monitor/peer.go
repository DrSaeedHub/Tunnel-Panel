package monitor

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PeerChecker knocks on the far end of a tunnel over TCP.
//
// It is the second opinion on the one case a probe cannot settle: a path that
// filters ICMP, where a working tunnel answers nothing at all. Opening a
// connection asks the far end's IP stack directly, and it answers whether or
// not anything is listening.
type PeerChecker interface {
	// Answered reports that something at that address replied. A refusal counts:
	// a reset could only have come back if the tunnel carried the packet there
	// and carried the answer back, which is the whole question.
	Answered(ctx context.Context, source, target string, timeout time.Duration) bool
}

// TCPPeerChecker opens a real connection.
type TCPPeerChecker struct {
	// Port is what to knock on. The panel's own port is the default because the
	// far end of a tunnel this panel manages is usually running it too; when it
	// is not, the refusal is just as good an answer.
	Port int
}

// Answered opens a connection and reports whether the far end's stack replied.
func (c TCPPeerChecker) Answered(ctx context.Context, source, target string, timeout time.Duration) bool {
	if strings.TrimSpace(target) == "" || c.Port <= 0 {
		return false
	}
	dialer := net.Dialer{Timeout: timeout}
	// Bound to the tunnel's own address, so this tests the tunnel rather than
	// whatever route the kernel would otherwise prefer.
	if source != "" {
		if addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(source, "0")); err == nil {
			dialer.LocalAddr = addr
		}
	}
	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(attempt, "tcp", net.JoinHostPort(target, strconv.Itoa(c.Port)))
	if err == nil {
		conn.Close()
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused")
}

// peerWatch rate-limits the knock.
//
// The check costs a round trip and a socket, and the answer does not change
// between one probe interval and the next. Asking once a minute is enough to
// keep a filtered tunnel reading as up without turning the monitor into a
// connection generator.
type peerWatch struct {
	checker PeerChecker
	last    time.Time
	result  bool
}

const peerCheckEvery = time.Minute

func (w *peerWatch) answered(ctx context.Context, cfg Config) bool {
	if w == nil || w.checker == nil {
		return false
	}
	if !w.last.IsZero() && time.Since(w.last) < peerCheckEvery {
		return w.result
	}
	w.last = time.Now()
	w.result = w.checker.Answered(ctx, cfg.Source, cfg.Target, cfg.Timeout)
	return w.result
}
