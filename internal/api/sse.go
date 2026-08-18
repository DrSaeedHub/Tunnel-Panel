package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// heartbeatInterval is how often an idle stream sends a comment line.
//
// A proxy or a load balancer will close a connection that has said nothing for
// a while, and a monitoring stream is idle precisely when everything is fine.
// The heartbeat is what stops "nothing is wrong" from looking like "the
// connection died" (§10.5).
const heartbeatInterval = 20 * time.Second

// sseStream writes server-sent events to one client.
type sseStream struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

// newSSE prepares a response for streaming. It reports false when the
// connection cannot stream, which the caller answers as an error rather than
// by writing a body nobody will receive.
func newSSE(w http.ResponseWriter) (*sseStream, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Nginx buffers proxied responses by default, which would hold every event
	// until the buffer filled. This asks it not to.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	return &sseStream{w: w, flusher: flusher}, true
}

// Send writes one named event with a JSON payload.
func (s *sseStream) Send(event string, payload any) error {
	// The same normalisation writeJSON applies. A live update is a response
	// body too, and it reaches the same components: the dashboard's resource
	// cards are fed from here, and a nil list arriving as null takes them down
	// exactly as it did when the metrics snapshot sent "cpu": null.
	encoded, err := json.Marshal(normaliseNilLists(payload))
	if err != nil {
		return fmt.Errorf("encoding a stream event: %w", err)
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, encoded); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// Comment writes a comment line, which keeps the connection alive without
// meaning anything to the client.
func (s *sseStream) Comment(text string) error {
	if _, err := fmt.Fprintf(s.w, ": %s\n\n", text); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

// streamNotSupported answers a client whose connection cannot stream.
func streamNotSupported(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, CodeInternal,
		"This connection cannot carry a live stream.", "", nil)
}
