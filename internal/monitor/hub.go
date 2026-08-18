package monitor

import "sync"

// subscriberBuffer is how many events a slow subscriber may fall behind by
// before events start being dropped for it. Dropping is deliberate: a browser
// tab that has been backgrounded must never be able to stall the prober that
// feeds it.
const subscriberBuffer = 64

// Hub fans monitoring snapshots out to every live-stream subscriber (§10.5).
//
// Publishing never blocks. A subscriber that cannot keep up loses events rather
// than applying back-pressure to the measurement loop, because a monitoring
// system that stops measuring when someone opens a slow connection is worse
// than one that shows a gap.
type Hub struct {
	mu     sync.Mutex
	next   int
	subs   map[int]chan Snapshot
	closed bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[int]chan Snapshot{}} }

// Subscribe registers a subscriber and returns its identifier and channel. The
// caller must Unsubscribe, which closes the channel.
func (h *Hub) Subscribe() (int, <-chan Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		ch := make(chan Snapshot)
		close(ch)
		return 0, ch
	}
	h.next++
	id := h.next
	ch := make(chan Snapshot, subscriberBuffer)
	h.subs[id] = ch
	return id, ch
}

// Unsubscribe removes a subscriber and closes its channel, which is what ends
// the goroutine reading from it (§10.5).
func (h *Hub) Unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if ch, ok := h.subs[id]; ok {
		delete(h.subs, id)
		close(ch)
	}
}

// Publish delivers a snapshot to every subscriber that has room for it.
func (h *Hub) Publish(snapshot Snapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, ch := range h.subs {
		select {
		case ch <- snapshot:
		default:
		}
	}
}

// Subscribers reports how many live subscribers there are, which the health
// endpoint shows.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Close ends every subscription. After it, Subscribe returns a closed channel
// so a late subscriber sees the shutdown rather than hanging.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return
	}
	h.closed = true
	for id, ch := range h.subs {
		delete(h.subs, id)
		close(ch)
	}
}
