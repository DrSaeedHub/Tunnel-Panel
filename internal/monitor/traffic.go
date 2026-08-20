package monitor

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TrafficReader reports how many bytes an interface has carried in total.
//
// It exists because a probe that gets no answer is not the same thing as a link
// that is not working. On a path where ICMP is filtered — which is the normal
// condition on a good many of the routes this panel is used across — a tunnel
// carrying traffic at full speed answers no probes at all. Reading the
// interface's own counters is what tells those two apart, and it costs one
// small file read per interval.
type TrafficReader interface {
	// Bytes returns the total carried in both directions. The second result is
	// false when the interface has no counters to read, which is the honest
	// answer for one that does not exist.
	Bytes(name string) (uint64, bool)
}

// SysfsTraffic reads the counters the kernel publishes for every interface.
type SysfsTraffic struct {
	// Root is "/" in production and a fixture directory in tests, the same
	// arrangement the forwarding manager uses.
	Root string
}

// Bytes returns the interface's total, or false when it cannot be read.
func (s SysfsTraffic) Bytes(name string) (uint64, bool) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\\") {
		return 0, false
	}
	root := s.Root
	if root == "" {
		root = "/"
	}
	rx, okRx := readCounter(filepath.Join(root, "sys/class/net", name, "statistics/rx_bytes"))
	tx, okTx := readCounter(filepath.Join(root, "sys/class/net", name, "statistics/tx_bytes"))
	if !okRx && !okTx {
		return 0, false
	}
	return rx + tx, true
}

func readCounter(path string) (uint64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// trafficWatch remembers an interface's counter between samples so the next one
// can say whether anything moved.
//
// A counter that goes backwards is an interface that was recreated, which is
// itself a sign of life rather than of silence: the total is lower than last
// time because the interface is new, and packets have crossed the new one.
type trafficWatch struct {
	reader TrafficReader
	last   uint64
	seen   bool
}

// moved reports whether the interface has carried anything since the previous
// call. The first call establishes the baseline and reports nothing, because
// one reading is not a measurement.
func (w *trafficWatch) moved(name string) bool {
	if w == nil || w.reader == nil {
		return false
	}
	total, ok := w.reader.Bytes(name)
	if !ok {
		w.seen = false
		return false
	}
	previous, had := w.last, w.seen
	w.last, w.seen = total, true
	if !had {
		return false
	}
	return total != previous
}
