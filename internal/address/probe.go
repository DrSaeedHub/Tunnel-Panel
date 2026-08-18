package address

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// HTTPDoer is the slice of *http.Client the health poll needs, so a test can
// answer without a socket.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// maxHealthBody bounds what is read from a URL that may not be the panel at
// all. Nothing legitimate here is anywhere near it.
const maxHealthBody = 64 << 10

func get(ctx context.Context, client HTTPDoer, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHealthBody))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// isPanelHealthBody reports whether a response body is this panel's health
// envelope.
//
// The fields checked are the ones only that endpoint produces together. A bare
// 404 from outside the web path has an empty body and fails here, which is the
// case this exists to separate: after a web path change, the old panel is still
// answering on the same port, and "something replied" is not evidence that the
// new path works.
func isPanelHealthBody(body []byte) bool {
	if len(bytes.TrimSpace(body)) == 0 {
		return false
	}
	var envelope struct {
		Status         *string `json:"status"`
		SetupRequired  *bool   `json:"setup_required"`
		UptimeSeconds  *int64  `json:"uptime_seconds"`
		ComponentCount []struct {
			Name string `json:"name"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false
	}
	return envelope.Status != nil && envelope.SetupRequired != nil && envelope.UptimeSeconds != nil
}
