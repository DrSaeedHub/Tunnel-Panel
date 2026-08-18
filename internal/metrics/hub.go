package metrics

import "sync"

// subscriberBuffer is how far a slow subscriber may fall behind before events
// are dropped for it. Sampling must never stall because somebody's browser tab
// stopped reading.
const subscriberBuffer = 16

// Hub fans metric readings out to the live stream subscribers (§11.4).
type Hub struct {
	mu     sync.Mutex
	next   int
	subs   map[int]chan Snapshot
	closed bool
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[int]chan Snapshot{}} }

// Subscribe registers a subscriber. The caller must Unsubscribe, which closes
// the channel and so ends the goroutine reading from it.
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

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(id int) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if ch, ok := h.subs[id]; ok {
		delete(h.subs, id)
		close(ch)
	}
}

// Publish delivers a reading to every subscriber with room for it.
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

// Subscribers reports the live subscriber count.
func (h *Hub) Subscribers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Close ends every subscription.
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
