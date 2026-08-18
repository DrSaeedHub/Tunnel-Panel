package monitor

import (
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// LoopbackDialer answers every probe itself without touching the network.
//
// Opening a raw ICMP socket needs root, so in development mode — where the
// panel runs unprivileged against the fake link manager — real probing is not
// available at all. This stands in for it the same way the fake link manager
// stands in for the kernel, so the monitoring subsystem can be run and
// demonstrated end to end. It is never selected when the panel runs for real.
type LoopbackDialer struct {
	// Latency is the delay before each reply, so a demonstration shows a
	// plausible round-trip time rather than zero.
	Latency time.Duration
	// LossRatio drops one reply in every N, where N is this value. Zero answers
	// everything.
	LossRatio int
}

// Listen returns a socket that answers its own probes.
func (d LoopbackDialer) Listen(source string) (PacketConn, error) {
	latency := d.Latency
	if latency <= 0 {
		latency = 2 * time.Millisecond
	}
	return &loopbackConn{
		inbound:   make(chan []byte, 64),
		latency:   latency,
		lossRatio: d.LossRatio,
		from:      &net.IPAddr{IP: net.ParseIP(source)},
	}, nil
}

type loopbackConn struct {
	mu       sync.Mutex
	closed   bool
	inbound  chan []byte
	deadline time.Time
	sent     int

	latency   time.Duration
	lossRatio int
	from      net.Addr
	wg        sync.WaitGroup
}

func (c *loopbackConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.sent++
	drop := c.lossRatio > 0 && c.sent%c.lossRatio == 0
	latency := c.latency
	c.wg.Add(1)
	c.mu.Unlock()

	if drop {
		c.wg.Done()
		return len(b), nil
	}

	reply, err := buildEchoReply(b)
	if err != nil {
		c.wg.Done()
		return len(b), nil
	}

	// The reply arrives after a delay, the way a real one would, so the
	// measured round-trip time is a real measurement of a simulated path
	// rather than a hardcoded number.
	go func() {
		defer c.wg.Done()
		timer := time.NewTimer(latency)
		defer timer.Stop()
		<-timer.C

		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return
		}
		defer func() { _ = recover() }() // the socket may close as we deliver
		select {
		case c.inbound <- reply:
		default:
		}
	}()
	return len(b), nil
}

// buildEchoReply turns an echo request into the reply a reachable peer would
// send: the same identifier, sequence and payload, so every validation the
// receiver does still applies.
func buildEchoReply(request []byte) ([]byte, error) {
	message, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), request)
	if err != nil {
		message, err = icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), request)
		if err != nil {
			return nil, err
		}
	}
	echo, ok := message.Body.(*icmp.Echo)
	if !ok {
		return nil, net.ErrClosed
	}

	replyType := icmp.Type(ipv4.ICMPTypeEchoReply)
	if message.Type == ipv6.ICMPTypeEchoRequest {
		replyType = ipv6.ICMPTypeEchoReply
	}
	reply := icmp.Message{
		Type: replyType,
		Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: append([]byte(nil), echo.Data...)},
	}
	return reply.Marshal(nil)
}

func (c *loopbackConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	closed, deadline := c.closed, c.deadline
	c.mu.Unlock()
	if closed {
		return 0, nil, net.ErrClosed
	}

	var timer <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, nil, loopbackTimeout{}
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}

	select {
	case packet, open := <-c.inbound:
		if !open {
			return 0, nil, net.ErrClosed
		}
		return copy(b, packet), c.from, nil
	case <-timer:
		return 0, nil, loopbackTimeout{}
	}
}

func (c *loopbackConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

// SetDontFragment and SetTTL are accepted and ignored: there is no path to
// have an MTU or a hop limit on.
func (c *loopbackConn) SetDontFragment(bool) error { return nil }
func (c *loopbackConn) SetTTL(int) error           { return nil }

func (c *loopbackConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	// Wait for the in-flight replies before closing the channel they write to,
	// so shutting down cannot panic on a send to a closed channel.
	c.wg.Wait()
	close(c.inbound)
	return nil
}

// loopbackTimeout is what an expired read deadline looks like. It implements
// the whole of net.Error, deprecated Temporary included, so that it is
// indistinguishable from what a real socket returns.
type loopbackTimeout struct{}

func (loopbackTimeout) Error() string   { return "i/o timeout" }
func (loopbackTimeout) Timeout() bool   { return true }
func (loopbackTimeout) Temporary() bool { return true }
