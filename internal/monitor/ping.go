package monitor

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"syscall"
	"time"
)

// PingRequest is one on-demand measurement (§13.1).
type PingRequest struct {
	TunnelID int64
	Source   string
	Target   string
	Count    int
	Interval time.Duration
	Timeout  time.Duration
	// PacketSize is the ICMP payload size in bytes.
	PacketSize int
	// DontFragment sets the Don't-Fragment bit, which is what turns this into a
	// path MTU probe (§13.2).
	DontFragment bool
	// Ttl limits the hop count, which is what turns this into a traceroute hop.
	Ttl int
}

// PingPacket is the fate of one probe, streamed as it is decided.
type PingPacket struct {
	Sequence int       `json:"sequence"`
	Success  bool      `json:"success"`
	RttMs    *float64  `json:"rtt_ms,omitempty"`
	Size     int       `json:"size"`
	From     string    `json:"from,omitempty"`
	Error    string    `json:"error,omitempty"`
	Kind     string    `json:"kind,omitempty"`
	At       time.Time `json:"at"`
}

// PingResult is the summary.
type PingResult struct {
	Sent        int     `json:"sent"`
	Received    int     `json:"received"`
	LossPercent float64 `json:"loss_percent"`

	RttMinMs  *float64 `json:"rtt_min_ms"`
	RttAvgMs  *float64 `json:"rtt_avg_ms"`
	RttMaxMs  *float64 `json:"rtt_max_ms"`
	RttMdevMs *float64 `json:"rtt_mdev_ms"`
	JitterMs  *float64 `json:"jitter_ms"`

	// ReportedMtu is the next-hop MTU an oversized packet provoked, which is
	// the direct answer the path MTU search is looking for.
	ReportedMtu int `json:"reported_mtu,omitempty"`
	// TooLargeToSend records that the kernel refused to send the probe at all
	// because it exceeded the outgoing interface's MTU and the Don't-Fragment
	// bit forbade splitting it. It is a definite answer rather than the absence
	// of one: the packet never left the host, so waiting for a reply that was
	// never provoked proves nothing (§13.2).
	TooLargeToSend bool `json:"too_large_to_send,omitempty"`
	// Answered lists the addresses that replied, which traceroute needs and
	// which also reveals a reply arriving from an unexpected host.
	Answered []string `json:"answered_by,omitempty"`

	Packets []PingPacket `json:"packets,omitempty"`
	// Duration is how long the whole run took.
	Duration time.Duration `json:"-"`
}

// pending is one probe awaiting its fate.
type pending struct {
	sequence int
	sentAt   time.Time
	deadline time.Time
	size     int
}

// Ping sends a bounded number of probes and reports what happened to each.
//
// It is the same ICMP path the continuous monitoring uses — same socket, same
// identifier and payload validation, same timestamp-in-the-packet timing — so
// the on-demand measurement and the background one cannot disagree about what
// the link is doing (§13.1).
//
// onPacket, when set, is called as each probe is decided, which is what the
// streaming endpoint sends over server-sent events.
func Ping(ctx context.Context, dialer Dialer, req PingRequest, onPacket func(PingPacket)) (PingResult, error) {
	if req.Count < 1 {
		req.Count = 1
	}
	if req.Interval <= 0 {
		req.Interval = 100 * time.Millisecond
	}
	if req.Timeout <= 0 {
		req.Timeout = time.Second
	}
	if req.PacketSize < MinPacketSize {
		req.PacketSize = MinPacketSize
	}
	if err := sameFamily(req.Source, req.Target); err != nil {
		return PingResult{}, err
	}

	target, isIPv6, err := targetAddr(req.Target)
	if err != nil {
		return PingResult{}, err
	}

	conn, err := dialer.Listen(req.Source)
	if err != nil {
		return PingResult{}, err
	}
	defer conn.Close()

	if req.DontFragment {
		if err := conn.SetDontFragment(true); err != nil {
			return PingResult{}, fmt.Errorf("setting the Don't-Fragment bit: %w", err)
		}
	}
	if req.Ttl > 0 {
		if err := conn.SetTTL(req.Ttl); err != nil {
			return PingResult{}, fmt.Errorf("setting the hop limit: %w", err)
		}
	}

	identifier := identifierFor(req.TunnelID)
	replies := make(chan Reply, req.Count*2+8)

	// The receiver runs until the socket is closed, which the deferred Close
	// above guarantees on every exit path.
	receiverDone := make(chan struct{})
	go func() {
		defer close(receiverDone)
		buffer := make([]byte, 65535)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(readSlice)); err != nil {
				return
			}
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				if isTimeout(err) {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				return
			}
			reply, err := Decode(isIPv6, identifier, req.TunnelID, buffer[:n], from)
			if err != nil {
				continue // somebody else's traffic
			}
			select {
			case replies <- reply:
			default:
			}
		}
	}()

	started := time.Now()
	result := PingResult{Packets: []PingPacket{}}
	outstanding := map[int]*pending{}
	answered := map[string]bool{}
	var rtts []float64

	emit := func(packet PingPacket) {
		result.Packets = append(result.Packets, packet)
		if onPacket != nil {
			onPacket(packet)
		}
	}

	sent := 0
	sequence := 0
	nextSend := time.Now()

	// One loop drives everything: it sends when the interval says to, records
	// replies as they arrive, and gives up on probes whose timeout has passed.
	// Sending is gated on the clock rather than on the previous reply, so a
	// fast peer cannot make the run go faster than the requested interval.
	for {
		if sent >= req.Count && len(outstanding) == 0 {
			break
		}

		now := time.Now()
		if sent < req.Count && !now.Before(nextSend) {
			packet, err := Encode(isIPv6, identifier, sequence, req.TunnelID, now, req.PacketSize)
			if err != nil {
				return finish(result, rtts, answered, started), err
			}
			entry := &pending{sequence: sequence, sentAt: now, deadline: now.Add(req.Timeout), size: len(packet)}

			if _, err := conn.WriteTo(packet, target); err != nil {
				// A send that fails is a decided probe: it never left.
				kind, detail := "send_failed", "the probe could not be sent: "+err.Error()
				if errors.Is(err, syscall.EMSGSIZE) {
					// The kernel itself refused the packet for being larger than
					// the outgoing interface allows without fragmenting. That is
					// the answer the MTU search wants, not a lost packet.
					result.TooLargeToSend = true
					kind = "too_large"
					detail = fmt.Sprintf("the kernel refused to send a %d-byte packet without fragmenting it", len(packet))
				}
				emit(PingPacket{
					Sequence: sequence, Success: false, Size: len(packet), At: now,
					Error: detail, Kind: kind,
				})
			} else {
				outstanding[sequence] = entry
			}
			result.Sent++
			sent++
			sequence = (sequence + 1) % maxSequence
			nextSend = now.Add(req.Interval)
			continue
		}

		// Wait for whichever comes first: the next send, the earliest timeout,
		// or a reply.
		wait := time.Duration(0)
		if sent < req.Count {
			wait = time.Until(nextSend)
		}
		if deadline, ok := earliestDeadline(outstanding); ok {
			until := time.Until(deadline)
			if wait <= 0 || until < wait {
				wait = until
			}
		}
		if wait < 0 {
			wait = 0
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			expireAll(outstanding, &result, emit)
			return finish(result, rtts, answered, started), ctx.Err()
		case reply := <-replies:
			timer.Stop()
			handleReply(reply, outstanding, answered, &rtts, &result, emit)
		case <-timer.C:
			expire(outstanding, &result, emit, time.Now())
		}
	}

	// Drain anything that arrived in the last instant, so a reply that beat the
	// loop's exit is still counted.
	for {
		select {
		case reply := <-replies:
			handleReply(reply, outstanding, answered, &rtts, &result, emit)
			continue
		default:
		}
		break
	}

	out := finish(result, rtts, answered, started)
	return out, nil
}

// handleReply records one inbound message against its probe.
func handleReply(reply Reply, outstanding map[int]*pending, answered map[string]bool,
	rtts *[]float64, result *PingResult, emit func(PingPacket)) {

	entry, ok := outstanding[reply.Sequence]
	if !ok {
		// Either a duplicate, or a reply to a probe already given up on. A
		// duplicate is not a second success, and a probe already reported lost
		// keeps its verdict here because the packet list has already been
		// streamed; the rolling window in the background monitor is where a
		// late reply overrides a loss.
		return
	}
	delete(outstanding, reply.Sequence)

	if reply.From != "" {
		answered[reply.From] = true
	}
	now := time.Now()

	if reply.Kind == ReplyEcho {
		rtt := now.Sub(entry.sentAt)
		if !reply.SentAt.IsZero() {
			rtt = now.Sub(reply.SentAt)
		}
		ms := float64(rtt) / float64(time.Millisecond)
		*rtts = append(*rtts, ms)
		result.Received++
		emit(PingPacket{
			Sequence: reply.Sequence, Success: true, RttMs: &ms, Size: entry.size,
			From: reply.From, Kind: string(ReplyEcho), At: now,
		})
		return
	}

	if reply.Mtu > 0 && (result.ReportedMtu == 0 || reply.Mtu < result.ReportedMtu) {
		result.ReportedMtu = reply.Mtu
	}
	emit(PingPacket{
		Sequence: reply.Sequence, Success: false, Size: entry.size, From: reply.From,
		Error: reply.Detail, Kind: string(reply.Kind), At: now,
	})
}

// expire gives up on probes whose timeout has passed.
func expire(outstanding map[int]*pending, result *PingResult, emit func(PingPacket), now time.Time) {
	for sequence, entry := range outstanding {
		if now.Before(entry.deadline) {
			continue
		}
		delete(outstanding, sequence)
		emit(PingPacket{
			Sequence: sequence, Success: false, Size: entry.size, At: now,
			Error: "no reply within the timeout", Kind: "timeout",
		})
	}
}

// earliestDeadline returns when the first outstanding probe gives up.
func earliestDeadline(outstanding map[int]*pending) (time.Time, bool) {
	earliest := time.Time{}
	for _, entry := range outstanding {
		if earliest.IsZero() || entry.deadline.Before(earliest) {
			earliest = entry.deadline
		}
	}
	return earliest, !earliest.IsZero()
}

// expireAll gives up on every outstanding probe, which is what cancelling does:
// the packets that were in flight are reported rather than silently dropped.
func expireAll(outstanding map[int]*pending, result *PingResult, emit func(PingPacket)) {
	now := time.Now()
	for sequence, entry := range outstanding {
		delete(outstanding, sequence)
		emit(PingPacket{
			Sequence: sequence, Success: false, Size: entry.size, At: now,
			Error: "the run was stopped before this probe was answered", Kind: "cancelled",
		})
	}
}

// finish computes the summary statistics.
func finish(result PingResult, rtts []float64, answered map[string]bool, started time.Time) PingResult {
	result.Duration = time.Since(started)
	if result.Sent > 0 {
		result.LossPercent = float64(result.Sent-result.Received) / float64(result.Sent) * 100
	}

	for address := range answered {
		result.Answered = append(result.Answered, address)
	}
	sort.Strings(result.Answered)

	if len(rtts) == 0 {
		return result
	}

	ordered := append([]float64(nil), rtts...)
	sorted := append([]float64(nil), rtts...)
	sort.Float64s(sorted)

	var sum, sumSquares float64
	for _, v := range sorted {
		sum += v
		sumSquares += v * v
	}
	mean := sum / float64(len(sorted))
	variance := sumSquares/float64(len(sorted)) - mean*mean
	if variance < 0 {
		variance = 0
	}
	mdev := math.Sqrt(variance)

	min, max := sorted[0], sorted[len(sorted)-1]
	result.RttMinMs = &min
	result.RttMaxMs = &max
	result.RttAvgMs = &mean
	result.RttMdevMs = &mdev

	if len(ordered) > 1 {
		var total float64
		for i := 1; i < len(ordered); i++ {
			total += math.Abs(ordered[i] - ordered[i-1])
		}
		jitter := total / float64(len(ordered)-1)
		result.JitterMs = &jitter
	}
	return result
}
