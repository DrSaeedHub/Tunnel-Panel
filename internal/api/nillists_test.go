package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Three defects in this panel were one sentence: a nil Go slice marshals to
// JSON null, the interface calls .map or .length on it, and the page dies.
// "cpu": null took out the dashboard's resource cards; "allowed_sources": null
// made every forwarding rule impossible to edit. The remaining ones are in the
// diagnostics results — evidence, steps, hops — where an empty list is not an
// edge case but the ordinary outcome: a clean analyze has nothing to report.
//
// The assertion is on the serialised bytes rather than the Go value, because
// the wire format is what the browser parses. A Go-value check passes while the
// response still says null.

func TestANilListIsSerialisedAsAnEmptyList(t *testing.T) {
	type inner struct {
		Deep []string `json:"deep"`
	}
	type payload struct {
		Plain    []string         `json:"plain"`
		Omitted  []string         `json:"omitted,omitempty"`
		Renamed  []int            `json:"renamed"`
		Nested   inner            `json:"nested"`
		Pointer  *inner           `json:"pointer"`
		Children []inner          `json:"children"`
		Mapped   map[string]inner `json:"mapped"`
		Ignored  []string         `json:"-"`
		Present  []string         `json:"present"`
	}

	encoded := marshalThroughWriter(t, payload{
		Present: []string{"kept"},
		Pointer: &inner{},
		Mapped:  map[string]inner{"a": {}},
	})

	for _, field := range []string{`"plain":[]`, `"renamed":[]`, `"children":[]`,
		`"deep":[]`, `"present":["kept"]`} {
		if !strings.Contains(encoded, field) {
			t.Errorf("expected %s in the response, got:\n  %s", field, encoded)
		}
	}
	if strings.Contains(encoded, `:null`) {
		t.Errorf("a list was serialised as null, which the interface cannot map over:\n  %s", encoded)
	}
	// omitempty says the absence of the field is meaningful. Normalising it
	// would turn "there is no such thing" into "here is an empty thing".
	if strings.Contains(encoded, `"omitted"`) {
		t.Errorf("an omitempty list was materialised, changing what its absence means:\n  %s", encoded)
	}
}

func TestNormalisingLeavesEverythingElseAlone(t *testing.T) {
	type payload struct {
		Name   string            `json:"name"`
		Count  int               `json:"count"`
		Ratio  float64           `json:"ratio"`
		Flag   bool              `json:"flag"`
		Maybe  *int              `json:"maybe"`
		Lookup map[string]string `json:"lookup"`
	}

	original := payload{Name: "relay", Count: 3, Ratio: 1.5, Flag: true}
	direct, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	throughWriter := marshalThroughWriter(t, original)
	if string(direct) != throughWriter {
		t.Errorf("normalising changed a payload with no nil lists in it:\n  before %s\n  after  %s",
			direct, throughWriter)
	}
}

func TestATopLevelNilListIsAnEmptyList(t *testing.T) {
	var rows []string
	if got := marshalThroughWriter(t, rows); got != "[]" {
		t.Errorf("a nil slice response serialised as %s, want []", got)
	}
}

func TestNormalisingSurvivesAValueThatPointsAtItself(t *testing.T) {
	// A cycle here would hang the response path, which is worse than the defect
	// being fixed. Response payloads are trees today; this keeps it that way by
	// construction rather than by convention.
	type node struct {
		Next  *node    `json:"next,omitempty"`
		Items []string `json:"items"`
	}
	first := &node{}
	first.Next = first

	done := make(chan struct{})
	go func() {
		defer close(done)
		normaliseNilLists(first)
	}()
	select {
	case <-done:
	case <-timeoutAfterASecond():
		t.Fatal("normalising a self-referential value did not terminate")
	}
	if first.Items == nil {
		t.Error("the list on a self-referential value was not normalised")
	}
}

// marshalThroughWriter runs a value through the same normalisation the response
// writer applies, and returns the bytes a client would receive.
func marshalThroughWriter(t *testing.T, v any) string {
	t.Helper()
	body, err := json.Marshal(normaliseNilLists(v))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	return string(body)
}

func timeoutAfterASecond() <-chan time.Time { return time.After(time.Second) }

// The live stream is a response body too, and it was not going through the same
// normalisation: writeJSON's own comment calls itself "the only place a response
// body is written", and sseStream.Send marshals directly. The dashboard's
// resource cards are fed from this path, and they are the ones a nil list took
// down in the first place.
func TestTheLiveStreamNormalisesItsListsToo(t *testing.T) {
	type update struct {
		Cpu   []string `json:"cpu"`
		Disks []string `json:"disks"`
	}

	recorder := httptest.NewRecorder()
	stream, ok := newSSE(recorder)
	if !ok {
		t.Fatal("the recorder does not support streaming, so this proves nothing")
	}
	if err := stream.Send("metrics", update{}); err != nil {
		t.Fatalf("sending: %v", err)
	}

	body := recorder.Body.String()
	if strings.Contains(body, `:null`) {
		t.Errorf("the stream sent a list as null, which the dashboard calls .map on:\n  %s", body)
	}
	for _, want := range []string{`"cpu":[]`, `"disks":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %s in the stream payload, got:\n  %s", want, body)
		}
	}
}
