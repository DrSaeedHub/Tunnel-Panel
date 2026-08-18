package monitor

import (
	"math"
	"sort"
	"sync"
	"time"
)

// entry is one probe and what became of it.
type entry struct {
	sequence int
	sentAt   time.Time
	deadline time.Time

	replied bool
	rtt     time.Duration
	// reason describes an ICMP error that ended this probe.
	reason string
}

// decided reports whether this probe's fate is known: it was answered, or its
// timeout has passed.
//
// The distinction is the whole point of §10.1. A probe still within its timeout
// is not a loss, it is unfinished, and counting it as a loss would make every
// window report a phantom loss rate equal to one packet's worth.
func (e *entry) decided(now time.Time) bool {
	return e.replied || !now.Before(e.deadline)
}

func (e *entry) lost(now time.Time) bool { return !e.replied && !now.Before(e.deadline) }

// Stats is the rolling picture of one tunnel's reachability.
type Stats struct {
	// Sent counts probes whose fate is decided; Pending are still in flight.
	Sent     int `json:"sent"`
	Received int `json:"received"`
	Lost     int `json:"lost"`
	Pending  int `json:"pending"`

	LossPercent float64 `json:"loss_percent"`

	RttMinMs  *float64 `json:"rtt_min_ms"`
	RttAvgMs  *float64 `json:"rtt_avg_ms"`
	RttMaxMs  *float64 `json:"rtt_max_ms"`
	RttMdevMs *float64 `json:"rtt_mdev_ms"`
	// JitterMs is the mean absolute difference between successive round-trip
	// times, which is what an operator means by jitter (§10.1).
	JitterMs *float64 `json:"jitter_ms"`

	// LastRttMs is the most recent measurement, which the live stream shows.
	LastRttMs *float64 `json:"last_rtt_ms"`
	// LastReplyAt is when the last answer arrived.
	LastReplyAt *time.Time `json:"last_reply_at"`
	// LastError describes the most recent ICMP error, if there was one.
	LastError string `json:"last_error,omitempty"`
}

// Window is the rolling record of the last N probes for one tunnel.
//
// It is safe for concurrent use: the sender, the receiver and the evaluator all
// touch it.
type Window struct {
	mu      sync.Mutex
	size    int
	order   []int
	entries map[int]*entry

	lastError   string
	lastReplyAt time.Time
	lastRtt     time.Duration
	haveLastRtt bool
}

// NewWindow returns a window keeping the last size probes.
func NewWindow(size int) *Window {
	if size < 1 {
		size = 1
	}
	return &Window{size: size, entries: make(map[int]*entry, size)}
}

// Resize changes how many probes the window keeps, dropping the oldest when it
// shrinks. Settings can change at runtime, so this happens without a restart.
func (w *Window) Resize(size int) {
	if size < 1 {
		size = 1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.size = size
	w.trim()
}

// Sent records an outgoing probe.
func (w *Window) Sent(sequence int, sentAt time.Time, timeout time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// A sequence number wraps eventually; reusing one replaces the old record
	// rather than corrupting it.
	if _, exists := w.entries[sequence]; exists {
		w.remove(sequence)
	}
	w.entries[sequence] = &entry{
		sequence: sequence,
		sentAt:   sentAt,
		deadline: sentAt.Add(timeout),
	}
	w.order = append(w.order, sequence)
	w.trim()
}

// Reply records an answer.
//
// A reply that arrives after its timeout still counts: it overrides the loss
// verdict for that sequence. Getting this wrong inflates the reported loss rate
// on any link whose latency occasionally exceeds the timeout, which is exactly
// the link an operator is trying to diagnose (§10.1).
func (w *Window) Reply(sequence int, rtt time.Duration, at time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	e, ok := w.entries[sequence]
	if !ok {
		// The probe has already aged out of the window entirely, so there is
		// nothing left to correct.
		return false
	}
	if e.replied {
		return false // a duplicate reply is not a second success
	}
	e.replied = true
	e.rtt = rtt
	e.reason = ""

	w.lastReplyAt = at
	w.lastRtt = rtt
	w.haveLastRtt = true
	return true
}

// Error records an ICMP error against the probe that caused it.
func (w *Window) Error(sequence int, reason string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.lastError = reason
	e, ok := w.entries[sequence]
	if !ok || e.replied {
		return
	}
	e.reason = reason
	// An error is a definitive answer that the probe failed, so its deadline is
	// brought forward rather than waiting out a timeout that cannot now succeed.
	e.deadline = time.Now()
}

// Stats computes the current figures as of now.
func (w *Window) Stats(now time.Time) Stats {
	w.mu.Lock()
	defer w.mu.Unlock()

	var (
		out      Stats
		rtts     []float64
		ordered  []float64
		sumRtt   float64
		sumRtt2  float64
		received int
	)

	for _, sequence := range w.order {
		e := w.entries[sequence]
		if e == nil {
			continue
		}
		switch {
		case e.replied:
			out.Sent++
			received++
			ms := float64(e.rtt) / float64(time.Millisecond)
			rtts = append(rtts, ms)
			ordered = append(ordered, ms)
			sumRtt += ms
			sumRtt2 += ms * ms
		case e.lost(now):
			out.Sent++
		default:
			out.Pending++
		}
	}

	out.Received = received
	out.Lost = out.Sent - received
	if out.Sent > 0 {
		out.LossPercent = float64(out.Lost) / float64(out.Sent) * 100
	}

	if len(rtts) > 0 {
		sort.Float64s(rtts)
		min, max := rtts[0], rtts[len(rtts)-1]
		mean := sumRtt / float64(len(rtts))
		// The same definition iputils uses for mdev: the population standard
		// deviation of the round-trip times.
		variance := sumRtt2/float64(len(rtts)) - mean*mean
		if variance < 0 {
			variance = 0
		}
		mdev := math.Sqrt(variance)

		out.RttMinMs = &min
		out.RttMaxMs = &max
		out.RttAvgMs = &mean
		out.RttMdevMs = &mdev
	}

	// Jitter is computed over the replies in the order they were sent, not in
	// sorted order: it is about how much consecutive packets differ.
	if len(ordered) > 1 {
		var total float64
		for i := 1; i < len(ordered); i++ {
			total += math.Abs(ordered[i] - ordered[i-1])
		}
		jitter := total / float64(len(ordered)-1)
		out.JitterMs = &jitter
	}

	if w.haveLastRtt {
		last := float64(w.lastRtt) / float64(time.Millisecond)
		out.LastRttMs = &last
	}
	if !w.lastReplyAt.IsZero() {
		at := w.lastReplyAt
		out.LastReplyAt = &at
	}
	out.LastError = w.lastError
	return out
}

// Reset forgets every probe, which is what happens when a prober restarts.
func (w *Window) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.order = nil
	w.entries = make(map[int]*entry, w.size)
	w.lastError = ""
	w.lastReplyAt = time.Time{}
	w.haveLastRtt = false
}

// trim drops the oldest probes once the window is full. The caller holds the
// lock.
func (w *Window) trim() {
	for len(w.order) > w.size {
		oldest := w.order[0]
		w.order = w.order[1:]
		delete(w.entries, oldest)
	}
}

// remove deletes one sequence. The caller holds the lock.
func (w *Window) remove(sequence int) {
	delete(w.entries, sequence)
	for i, s := range w.order {
		if s == sequence {
			w.order = append(w.order[:i], w.order[i+1:]...)
			return
		}
	}
}
