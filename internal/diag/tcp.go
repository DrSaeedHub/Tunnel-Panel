package diag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/drs/gre-panel/internal/model"
)

// A TCP check across the tunnel.
//
// The ping is the better measurement when it works: it gives loss, round-trip
// time and jitter, and it is what the continuous monitor is built on. But on a
// great many of the paths this panel is used across, something between the two
// ends drops ICMP outright while carrying TCP perfectly well, and there a ping
// measures the filter rather than the tunnel.
//
// This measures the tunnel. It is deliberately the weakest possible test —
// open a connection to the peer's address across the tunnel and see what the
// other end's IP stack says — because the weakest test is the one that needs
// nothing to be running at the far end.

// TCPParams describes one check.
type TCPParams struct {
	// Target is the address to knock on. Empty means the tunnel's peer, which
	// is what an operator means when they ask whether the tunnel is up.
	Target string `json:"target,omitempty"`
	// Port is what to knock on there. Zero means the port this panel serves,
	// because the far end of a tunnel this panel manages is usually running it
	// too — and when it is not, a refusal is just as good an answer.
	Port int `json:"port,omitempty"`
	// TimeoutSeconds bounds the attempt.
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty"`
}

// TCPResult is what the check found.
type TCPResult struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Port   int    `json:"port"`

	// Answered reports that the far end's IP stack replied, which is the whole
	// question. A connection that was refused answers it as well as one that
	// was accepted: something at that address processed the packet and sent a
	// reset, and it could only do that if the tunnel carried both directions.
	Answered bool `json:"answered"`
	// Accepted reports that something was actually listening on the port. It is
	// a stronger statement than Answered and a less important one.
	Accepted bool `json:"accepted"`
	// Refused reports the reset. It is called out separately because it is the
	// result that reads like a failure and is not one.
	Refused bool `json:"refused"`

	LatencyMs float64 `json:"latency_ms,omitempty"`
	// Detail is the sentence an operator reads.
	Detail string `json:"detail"`
	Error  string `json:"error,omitempty"`

	CheckedAt string `json:"checked_at"`
}

// TCPCheck opens a connection to the far end of a tunnel and reports what
// answered.
func (s *Service) TCPCheck(ctx context.Context, tunnelID int64, params TCPParams) (TCPResult, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return TCPResult{}, err
	}
	source, peer := probeEndpoints(rec)

	target := strings.TrimSpace(params.Target)
	if target == "" {
		target = peer
	}
	if target == "" {
		return TCPResult{}, fmt.Errorf(
			"no peer address is recorded for this tunnel; give an explicit target")
	}

	port := params.Port
	if port <= 0 {
		port = s.panelPort()
	}
	if port <= 0 || port > 65535 {
		return TCPResult{}, fmt.Errorf("%d is not a port to knock on", port)
	}

	timeout := time.Duration(params.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	return tcpProbe(ctx, source, target, port, timeout), nil
}

// tcpProbe is the check itself, separated so the monitor can use it without
// going through the repository.
func tcpProbe(ctx context.Context, source, target string, port int, timeout time.Duration) TCPResult {
	result := TCPResult{
		Source: source, Target: target, Port: port,
		CheckedAt: model.NowUTC(),
	}

	dialer := net.Dialer{Timeout: timeout}
	// Binding to the tunnel's own address is what makes this a test of the
	// tunnel rather than of whatever route the kernel would otherwise prefer.
	// A source that cannot be bound is not worth failing over: the check still
	// means something without it.
	if source != "" {
		if addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(source, "0")); err == nil {
			dialer.LocalAddr = addr
		}
	}

	attempt, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	started := time.Now()
	conn, err := dialer.DialContext(attempt, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	elapsed := time.Since(started)

	if err == nil {
		conn.Close()
		result.Answered, result.Accepted = true, true
		result.LatencyMs = float64(elapsed.Microseconds()) / 1000
		result.Detail = fmt.Sprintf("%s answered on port %d in %.1f ms: the tunnel carries traffic "+
			"in both directions.", target, port, result.LatencyMs)
		return result
	}

	result.Error = err.Error()
	// A refusal is an answer. Something at that address received the packet and
	// sent a reset, which it could only do if the tunnel carried the packet
	// there and the reply back. For deciding whether a tunnel is up, that is
	// the same news as a connection being accepted.
	if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused") {
		result.Answered, result.Refused = true, true
		result.LatencyMs = float64(elapsed.Microseconds()) / 1000
		result.Detail = fmt.Sprintf("%s refused the connection on port %d in %.1f ms. Nothing is "+
			"listening there, which is not a fault: the refusal itself proves the tunnel carried the "+
			"packet and carried the answer back.", target, port, result.LatencyMs)
		return result
	}

	if errors.Is(err, context.DeadlineExceeded) || isTimeoutError(err) {
		result.Detail = fmt.Sprintf("%s did not answer on port %d within %s. Nothing came back at "+
			"all, which is what a tunnel that is not carrying traffic looks like.", target, port, timeout)
		return result
	}
	result.Detail = fmt.Sprintf("the connection to %s on port %d could not be made: %s",
		target, port, err.Error())
	return result
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// panelPort is the port this panel serves on, which is the most likely thing
// to be listening at the far end of a tunnel this panel manages. Zero means
// it was not given one, and the caller has to name a port.
func (s *Service) panelPort() int { return s.panelPortNumber }
