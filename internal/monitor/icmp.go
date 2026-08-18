// Package monitor is the always-on liveness monitoring subsystem (§10).
//
// It probes with raw ICMP sockets and never spawns a `ping` process. A socket
// is not a process: a hundred monitored tunnels cost a hundred file
// descriptors rather than a hundred processes, the round-trip time is measured
// from the packet rather than scraped out of another program's output, and
// there is no dependency on the locale or version of iputils.
package monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Magic is the payload marker every probe carries. A reply whose payload does
// not start with it is not ours, whatever its identifier says (§10.1).
var Magic = [4]byte{'G', 'R', 'E', 'P'}

// PayloadHeader is the fixed part of a probe payload: the marker, the tunnel
// identifier, and the send timestamp.
//
// Carrying the timestamp in the packet is what makes the round-trip time exact
// without a lookup table: the reply echoes it back, so the measurement is
// end-to-end and cannot be skewed by the receiver being busy.
const PayloadHeader = 4 + 8 + 8 // magic + tunnel id + nanosecond timestamp

// MinPacketSize is the smallest payload that still carries the header.
const MinPacketSize = PayloadHeader

// PacketConn is the part of an ICMP socket the prober uses. It is an interface
// so the whole probing loop can be tested against an in-memory network.
type PacketConn interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
	ReadFrom(b []byte) (int, net.Addr, error)
	SetReadDeadline(t time.Time) error
	// SetDontFragment sets the Don't-Fragment bit, which the path MTU probe
	// needs (§13.2).
	SetDontFragment(on bool) error
	// SetTTL sets the outgoing hop limit, which traceroute needs.
	SetTTL(ttl int) error
	Close() error
}

// Dialer opens an ICMP socket bound to a source address.
type Dialer interface {
	// Listen binds a socket to source. Binding matters: it is what makes the
	// probe egress through the tunnel rather than through the default route
	// (§10.1).
	Listen(source string) (PacketConn, error)
}

// SystemDialer opens real sockets.
type SystemDialer struct{}

// Listen binds a raw ICMP socket to the given source address.
func (SystemDialer) Listen(source string) (PacketConn, error) {
	addr, err := netip.ParseAddr(source)
	if err != nil {
		return nil, fmt.Errorf("probe source %q is not an IP address: %w", source, err)
	}
	addr = addr.Unmap()

	network := "ip4:icmp"
	if addr.Is6() {
		network = "ip6:ipv6-icmp"
	}
	// net.ListenPacket rather than icmp.ListenPacket, because the concrete
	// *net.IPConn it returns exposes the file descriptor, and the Don't-Fragment
	// bit and the hop limit are socket options the diagnostics need.
	conn, err := net.ListenPacket(network, addr.String())
	if err != nil {
		return nil, fmt.Errorf("opening an ICMP socket bound to %s: %w", addr, err)
	}
	ipConn, ok := conn.(*net.IPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("the ICMP socket for %s is not an IP connection", addr)
	}
	return &systemConn{conn: ipConn, isIPv6: addr.Is6()}, nil
}

type systemConn struct {
	conn   *net.IPConn
	isIPv6 bool
}

func (c *systemConn) WriteTo(b []byte, addr net.Addr) (int, error) { return c.conn.WriteTo(b, addr) }

func (c *systemConn) ReadFrom(b []byte) (int, net.Addr, error) { return c.conn.ReadFrom(b) }

func (c *systemConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

func (c *systemConn) Close() error { return c.conn.Close() }

// SetDontFragment turns on path MTU discovery for outgoing probes, so an
// oversized packet is rejected rather than fragmented (§13.2).
func (c *systemConn) SetDontFragment(on bool) error {
	if c.isIPv6 {
		// IPv6 never fragments in transit, so the bit does not exist there and
		// an oversized packet already fails the way the probe needs.
		return nil
	}
	return c.control(func(fd int) error { return setDontFragment(fd, on) })
}

// SetTTL sets the outgoing hop limit, which is how traceroute walks the path.
func (c *systemConn) SetTTL(ttl int) error {
	if c.isIPv6 {
		return ipv6.NewConn(c.conn).SetHopLimit(ttl)
	}
	return ipv4.NewConn(c.conn).SetTTL(ttl)
}

func (c *systemConn) control(fn func(fd int) error) error {
	raw, err := c.conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

// Probe is one outgoing packet.
type Probe struct {
	Sequence int
	SentAt   time.Time
	Size     int
}

// ReplyKind classifies what came back.
type ReplyKind string

const (
	// ReplyEcho is the answer we wanted.
	ReplyEcho ReplyKind = "echo_reply"
	// ReplyUnreachable and ReplyTimeExceeded are ICMP errors attributed to the
	// probe that caused them (§10.1).
	ReplyUnreachable  ReplyKind = "destination_unreachable"
	ReplyTimeExceeded ReplyKind = "time_exceeded"
	// ReplyTooBig is the path MTU signal: the packet needed fragmenting and the
	// Don't-Fragment bit forbade it.
	ReplyTooBig ReplyKind = "packet_too_big"
)

// Reply is one decoded, matched inbound message.
type Reply struct {
	Kind ReplyKind
	// Sequence is the probe this reply belongs to.
	Sequence int
	// SentAt is the timestamp the probe carried, echoed back. For an ICMP error
	// it is zero, because the error quotes only the first eight bytes of the
	// original datagram and the payload is not among them.
	SentAt time.Time
	// From is the address the message came from, which for an ICMP error is a
	// router on the path rather than the target.
	From string
	// Detail describes an error reply for display.
	Detail string
	// Mtu is the next-hop MTU reported by a packet-too-big message, when there
	// is one.
	Mtu int
}

// ErrNotOurs is returned when a message is well-formed but belongs to another
// socket: a different identifier, or a payload without our marker. On a raw
// ICMP socket every process's replies arrive on every socket, so discarding
// them precisely is what keeps one tunnel's loss figure from counting
// another's traffic (§10.1).
var ErrNotOurs = errors.New("monitor: this ICMP message is not ours")

// buildPayload lays out a probe payload of the requested total size.
func buildPayload(tunnelID int64, sentAt time.Time, size int) []byte {
	if size < PayloadHeader {
		size = PayloadHeader
	}
	payload := make([]byte, size)
	copy(payload[0:4], Magic[:])
	binary.BigEndian.PutUint64(payload[4:12], uint64(tunnelID))
	binary.BigEndian.PutUint64(payload[12:20], uint64(sentAt.UnixNano()))
	// The remainder is a repeating pattern rather than zeroes, so a link that
	// mangles payloads is visible in a capture.
	for i := PayloadHeader; i < size; i++ {
		payload[i] = byte(i)
	}
	return payload
}

// parsePayload validates a payload and returns the timestamp it carried.
func parsePayload(tunnelID int64, payload []byte) (time.Time, error) {
	if len(payload) < PayloadHeader {
		return time.Time{}, ErrNotOurs
	}
	if !equalMagic(payload[0:4]) {
		return time.Time{}, ErrNotOurs
	}
	if int64(binary.BigEndian.Uint64(payload[4:12])) != tunnelID {
		return time.Time{}, ErrNotOurs
	}
	nanos := int64(binary.BigEndian.Uint64(payload[12:20]))
	sentAt := time.Unix(0, nanos)
	// A timestamp from the future, or from implausibly far in the past, means
	// the payload was not one of ours however well it matched.
	if nanos <= 0 {
		return time.Time{}, ErrNotOurs
	}
	return sentAt, nil
}

func equalMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == Magic[0] && b[1] == Magic[1] && b[2] == Magic[2] && b[3] == Magic[3]
}

// Encode builds an echo request packet.
func Encode(isIPv6 bool, identifier, sequence int, tunnelID int64, sentAt time.Time, size int) ([]byte, error) {
	messageType := icmp.Type(ipv4.ICMPTypeEcho)
	if isIPv6 {
		messageType = ipv6.ICMPTypeEchoRequest
	}
	message := icmp.Message{
		Type: messageType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   identifier,
			Seq:  sequence,
			Data: buildPayload(tunnelID, sentAt, size),
		},
	}
	return message.Marshal(nil)
}

// Decode parses an inbound message and matches it to this prober.
//
// It returns ErrNotOurs for anything belonging to another socket, which the
// caller discards silently: on a raw socket that is most of the traffic.
func Decode(isIPv6 bool, identifier int, tunnelID int64, raw []byte, from net.Addr) (Reply, error) {
	protocol := ipv4.ICMPTypeEchoReply.Protocol()
	if isIPv6 {
		protocol = ipv6.ICMPTypeEchoReply.Protocol()
	}
	message, err := icmp.ParseMessage(protocol, raw)
	if err != nil {
		return Reply{}, ErrNotOurs
	}

	source := ""
	if from != nil {
		source = from.String()
	}

	switch body := message.Body.(type) {
	case *icmp.Echo:
		// An echo request seen on our own socket is our own outgoing packet
		// looped back, not an answer.
		if message.Type == ipv4.ICMPTypeEcho || message.Type == ipv6.ICMPTypeEchoRequest {
			return Reply{}, ErrNotOurs
		}
		if body.ID != identifier {
			return Reply{}, ErrNotOurs
		}
		sentAt, err := parsePayload(tunnelID, body.Data)
		if err != nil {
			return Reply{}, err
		}
		return Reply{Kind: ReplyEcho, Sequence: body.Seq, SentAt: sentAt, From: source}, nil

	case *icmp.DstUnreach:
		// IPv4 carries "fragmentation needed" as an unreachable with code 4, and
		// puts the next-hop MTU in the two bytes the message header otherwise
		// leaves unused. That number is the direct answer the path MTU search
		// wants, so it is read here rather than inferred from the search
		// (§13.2).
		if !isIPv6 && message.Code == 4 {
			mtu := 0
			if len(raw) >= 8 {
				mtu = int(binary.BigEndian.Uint16(raw[6:8]))
			}
			return decodeError(isIPv6, identifier, ReplyTooBig, source,
				describeUnreachable(isIPv6, message.Code), body.Data, mtu)
		}
		return decodeError(isIPv6, identifier, ReplyUnreachable, source,
			describeUnreachable(isIPv6, message.Code), body.Data, 0)

	case *icmp.TimeExceeded:
		return decodeError(isIPv6, identifier, ReplyTimeExceeded, source,
			"the packet's hop limit ran out before it reached the target", body.Data, 0)

	case *icmp.PacketTooBig:
		return decodeError(isIPv6, identifier, ReplyTooBig, source,
			fmt.Sprintf("the packet was too big for a link on the path, which reported an MTU of %d", body.MTU),
			body.Data, body.MTU)
	}
	return Reply{}, ErrNotOurs
}

// decodeError attributes an ICMP error to the probe that caused it.
//
// The error quotes the original IP header plus the first eight bytes of the
// datagram that provoked it, and for an echo request those eight bytes are the
// ICMP header — which carries the identifier and the sequence number. That is
// exactly enough to say which probe died, and it is why an error is counted
// against the right sequence rather than as an unexplained loss (§10.1).
func decodeError(isIPv6 bool, identifier int, kind ReplyKind, from, detail string, quoted []byte, mtu int) (Reply, error) {
	innerHeaderLen := 40 // the fixed IPv6 header
	if !isIPv6 {
		if len(quoted) < 1 {
			return Reply{}, ErrNotOurs
		}
		innerHeaderLen = int(quoted[0]&0x0f) * 4
		if innerHeaderLen < 20 {
			return Reply{}, ErrNotOurs
		}
	}
	if len(quoted) < innerHeaderLen+8 {
		return Reply{}, ErrNotOurs
	}

	inner := quoted[innerHeaderLen:]
	innerID := int(binary.BigEndian.Uint16(inner[4:6]))
	innerSeq := int(binary.BigEndian.Uint16(inner[6:8]))
	if innerID != identifier {
		return Reply{}, ErrNotOurs
	}
	return Reply{Kind: kind, Sequence: innerSeq, From: from, Detail: detail, Mtu: mtu}, nil
}

func describeUnreachable(isIPv6 bool, code int) string {
	if isIPv6 {
		switch code {
		case 0:
			return "no route to the target"
		case 1:
			return "the target is administratively unreachable, which usually means a firewall"
		case 3:
			return "the target address is unreachable"
		case 4:
			return "the target port is unreachable"
		}
		return "the target is unreachable"
	}
	switch code {
	case 0:
		return "no route to the target network"
	case 1:
		return "no route to the target host"
	case 2:
		return "the protocol is unreachable at the target"
	case 3:
		return "the port is unreachable at the target"
	case 4:
		return "the packet needed fragmenting but the Don't-Fragment bit was set"
	case 9, 10, 13:
		return "the target is administratively unreachable, which usually means a firewall"
	}
	return "the target is unreachable"
}

// targetAddr builds the destination address for a raw ICMP write.
func targetAddr(target string) (net.Addr, bool, error) {
	addr, err := netip.ParseAddr(target)
	if err != nil {
		return nil, false, fmt.Errorf("probe target %q is not an IP address: %w", target, err)
	}
	addr = addr.Unmap()
	return &net.IPAddr{IP: net.IP(addr.AsSlice())}, addr.Is6(), nil
}

// sameFamily reports whether two addresses can talk to each other.
func sameFamily(source, target string) error {
	a, err := netip.ParseAddr(source)
	if err != nil {
		return fmt.Errorf("probe source %q is not an IP address", source)
	}
	b, err := netip.ParseAddr(target)
	if err != nil {
		return fmt.Errorf("probe target %q is not an IP address", target)
	}
	if a.Unmap().Is4() != b.Unmap().Is4() {
		return fmt.Errorf("the probe source %s and target %s are different address families", source, target)
	}
	return nil
}

// contextDeadline returns the earlier of a context deadline and a fallback.
func contextDeadline(ctx context.Context, fallback time.Time) time.Time {
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(fallback) {
		return deadline
	}
	return fallback
}
