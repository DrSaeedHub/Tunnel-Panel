package monitor

import (
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// fakeConn is an in-memory ICMP socket. It lets a test decide, packet by
// packet, what comes back: a reply, an error, silence, or a late answer.
type fakeConn struct {
	mu       sync.Mutex
	closed   bool
	written  [][]byte
	inbound  chan inboundPacket
	deadline time.Time

	dontFragment bool
	ttl          int

	// OnWrite is called for every outgoing packet, with the decoded echo
	// request, so a test can answer it however it likes.
	OnWrite func(c *fakeConn, id, sequence int, payload []byte)
}

type inboundPacket struct {
	data []byte
	from net.Addr
}

func newFakeConn() *fakeConn {
	return &fakeConn{inbound: make(chan inboundPacket, 256)}
}

func (c *fakeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.written = append(c.written, append([]byte(nil), b...))
	handler := c.OnWrite
	c.mu.Unlock()

	if handler != nil {
		if message, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b); err == nil {
			if echo, ok := message.Body.(*icmp.Echo); ok {
				handler(c, echo.ID, echo.Seq, echo.Data)
			}
		}
	}
	return len(b), nil
}

func (c *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
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
				return 0, nil, timeoutError{}
			}
			t := time.NewTimer(wait)
			defer t.Stop()
			timer = t.C
		}

		select {
		case packet, ok := <-c.inbound:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			n := copy(b, packet.data)
			return n, packet.from, nil
		case <-timer:
			return 0, nil, timeoutError{}
		}
	}
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *fakeConn) SetDontFragment(on bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dontFragment = on
	return nil
}

func (c *fakeConn) SetTTL(ttl int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.inbound)
	}
	return nil
}

// deliver queues an inbound packet, which is how a test answers a probe.
//
// The send happens under the lock that Close also takes. The queue is buffered
// and the send is non-blocking, so nothing can wait here — and checking the
// flag and then sending without the lock would race the close of the very
// channel being sent on.
func (c *fakeConn) deliver(data []byte, from net.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.inbound <- inboundPacket{data: data, from: from}:
	default:
	}
}

// replyTo builds the echo reply for a request, which is what a reachable peer
// would send back: the same identifier, sequence and payload.
func replyTo(id, sequence int, payload []byte) []byte {
	message := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: id, Seq: sequence, Data: append([]byte(nil), payload...)},
	}
	raw, _ := message.Marshal(nil)
	return raw
}

// quotedRequest builds the part of an ICMP error that identifies the datagram
// that provoked it: an IPv4 header followed by the first eight bytes of the
// original, which for an echo request carries the identifier and sequence.
func quotedRequest(id, sequence int) []byte {
	quoted := make([]byte, 20+8)
	quoted[0] = 0x45 // version 4, header length 5 words
	quoted[20] = 8   // the original was an echo request
	quoted[24] = byte(id >> 8)
	quoted[25] = byte(id)
	quoted[26] = byte(sequence >> 8)
	quoted[27] = byte(sequence)
	return quoted
}

// errorReply builds an ICMP error for a request.
func errorReply(messageType icmp.Type, code, id, sequence int) []byte {
	quoted := quotedRequest(id, sequence)

	var body icmp.MessageBody
	switch messageType {
	case ipv4.ICMPTypeTimeExceeded:
		body = &icmp.TimeExceeded{Data: quoted}
	default:
		body = &icmp.DstUnreach{Data: quoted}
	}
	message := icmp.Message{Type: messageType, Code: code, Body: body}
	raw, _ := message.Marshal(nil)
	return raw
}

// fragmentationNeeded builds the IPv4 message a router sends when a packet is
// too big and the Don't-Fragment bit forbids splitting it. The next-hop MTU
// lives in the two header bytes that other unreachable codes leave unused, so
// this message is assembled by hand rather than through the library's body
// types, which zero them.
func fragmentationNeeded(id, sequence, mtu int) []byte {
	quoted := quotedRequest(id, sequence)
	raw := make([]byte, 8+len(quoted))
	raw[0] = 3 // destination unreachable
	raw[1] = 4 // fragmentation needed and Don't-Fragment set
	raw[6] = byte(mtu >> 8)
	raw[7] = byte(mtu)
	copy(raw[8:], quoted)
	return raw
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// fakeDialer hands out fake sockets and remembers them by source address.
type fakeDialer struct {
	mu    sync.Mutex
	conns map[string]*fakeConn
	// OnWrite is installed on every socket this dialer creates.
	OnWrite func(c *fakeConn, id, sequence int, payload []byte)
	// Err, when set, makes Listen fail, which exercises the backoff path.
	Err error
	// listens counts how many sockets were opened.
	listens int
	// attempts counts every call, including the ones Err turned away, which is
	// what a test watching the retry schedule needs.
	attempts int
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{conns: map[string]*fakeConn{}}
}

func (d *fakeDialer) Listen(source string) (PacketConn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.attempts++
	if d.Err != nil {
		return nil, d.Err
	}
	d.listens++
	conn := newFakeConn()
	conn.OnWrite = d.OnWrite
	d.conns[source] = conn
	return conn, nil
}

func (d *fakeDialer) conn(source string) *fakeConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns[source]
}

// setErr changes what Listen does while the supervisor is running, which is
// how a test makes a broken socket start working again.
func (d *fakeDialer) setErr(err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Err = err
}

// attemptCount is how many times a socket was asked for, successfully or not.
func (d *fakeDialer) attemptCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.attempts
}

func (d *fakeDialer) listenCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.listens
}

var errDialFailed = errors.New("the socket could not be opened")
