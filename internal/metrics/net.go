package metrics

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/link"
)

// Interface classes (§11.2).
const (
	ClassPhysical = "physical"
	ClassTunnel   = "tunnel"
	ClassLoopback = "loopback"
	ClassOther    = "other"
)

// InterfaceCounters are the raw kernel counters for one interface.
type InterfaceCounters struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxDropped uint64 `json:"tx_dropped"`
}

// Interface is one interface as the metrics endpoint reports it.
type Interface struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	// Class is physical, tunnel, loopback or other, so the interface can group
	// and filter without guessing from the name.
	Class      string   `json:"class"`
	IsLoopback bool     `json:"is_loopback"`
	Kind       string   `json:"kind,omitempty"`
	Mtu        int      `json:"mtu,omitempty"`
	OperState  string   `json:"oper_state,omitempty"`
	IsUp       bool     `json:"is_up"`
	Flags      []string `json:"flags,omitempty"`
	// PrimaryAddress is the first global address, which is what an operator
	// recognises the interface by.
	PrimaryAddress string   `json:"primary_address,omitempty"`
	Addresses      []string `json:"addresses,omitempty"`

	Counters InterfaceCounters `json:"counters"`

	// Throughput is the current rate in bytes per second, from the difference
	// between consecutive samples (§11.2).
	RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64 `json:"tx_bytes_per_second"`

	// Volume since boot is the kernel's own counter, which resets when the
	// machine reboots or the interface is recreated. Volume since install is
	// the panel's persisted total, which survives both. They are separate
	// fields on purpose: blending them would produce a number that is neither
	// (§11.3).
	RxBytesSinceBoot    uint64 `json:"rx_bytes_since_boot"`
	TxBytesSinceBoot    uint64 `json:"tx_bytes_since_boot"`
	RxBytesSinceInstall uint64 `json:"rx_bytes_since_install"`
	TxBytesSinceInstall uint64 `json:"tx_bytes_since_install"`
}

// ClassifyInterface decides which class an interface belongs to.
//
// A tunnel is anything the kernel calls a tunnel kind, plus anything named the
// way the install script this panel replaces named its tunnels, so an adopted
// one is grouped correctly even before it is adopted (§11.2).
func ClassifyInterface(name, kind string, isLoopback bool) string {
	switch {
	case isLoopback || name == "lo" || kind == "loopback":
		return ClassLoopback
	case link.IsTunnelKind(kind):
		return ClassTunnel
	case strings.HasPrefix(name, "gre"):
		return ClassTunnel
	case kind == "device" || kind == "" || kind == "ether":
		return ClassPhysical
	}
	return ClassOther
}

// ProcNetDev parses /proc/net/dev.
//
// It is the fallback source: netlink statistics are preferred because they come
// with the interface's index, flags and addresses in the same read. This parser
// exists because /proc/net/dev is always there, even when netlink is not.
func (r *Reader) ProcNetDev() (map[string]InterfaceCounters, error) {
	file, err := os.Open(r.path("proc", "net", "dev"))
	if err != nil {
		return nil, fmt.Errorf("reading interface counters: %w", err)
	}
	defer file.Close()

	out := map[string]InterfaceCounters{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		name, rest, found := strings.Cut(line, ":")
		if !found {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}

		fields := strings.Fields(rest)
		if len(fields) < 16 {
			continue
		}
		value := func(i int) uint64 {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return 0
			}
			return v
		}
		// The column order is fixed: receive bytes, packets, errs, drop, fifo,
		// frame, compressed, multicast, then the same eight for transmit.
		out[name] = InterfaceCounters{
			RxBytes: value(0), RxPackets: value(1), RxErrors: value(2), RxDropped: value(3),
			TxBytes: value(8), TxPackets: value(9), TxErrors: value(10), TxDropped: value(11),
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading interface counters: %w", err)
	}
	return out, nil
}

// InterfacesFromLinks builds the interface list from netlink's view, which is
// the preferred source because one read gives the counters, the flags, the
// addresses and the index together (§11.2).
func InterfacesFromLinks(links []link.Link) []Interface {
	out := make([]Interface, 0, len(links))
	for _, l := range links {
		iface := Interface{
			Name:       l.Name,
			Index:      l.Index,
			Kind:       l.Kind,
			Mtu:        l.MTU,
			OperState:  l.OperState,
			IsUp:       l.IsUp,
			Flags:      l.Flags,
			IsLoopback: l.IsLoopback(),
		}
		iface.Class = ClassifyInterface(l.Name, l.Kind, l.IsLoopback())

		for _, addr := range l.Addresses {
			iface.Addresses = append(iface.Addresses, addr.String())
			if iface.PrimaryAddress == "" && addr.Scope != "link" && addr.Scope != "host" {
				iface.PrimaryAddress = addr.Address
			}
		}
		if iface.PrimaryAddress == "" && len(iface.Addresses) > 0 {
			iface.PrimaryAddress = l.Addresses[0].Address
		}

		if l.Statistics != nil {
			iface.Counters = InterfaceCounters{
				RxBytes: l.Statistics.RxBytes, TxBytes: l.Statistics.TxBytes,
				RxPackets: l.Statistics.RxPackets, TxPackets: l.Statistics.TxPackets,
				RxErrors: l.Statistics.RxErrors, TxErrors: l.Statistics.TxErrors,
				RxDropped: l.Statistics.RxDropped, TxDropped: l.Statistics.TxDropped,
			}
		}
		out = append(out, iface)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// InterfacesFromProc builds the interface list from /proc/net/dev alone, which
// is all that is available when netlink is not.
func InterfacesFromProc(counters map[string]InterfaceCounters) []Interface {
	out := make([]Interface, 0, len(counters))
	for name, c := range counters {
		isLoopback := name == "lo"
		out = append(out, Interface{
			Name: name, Counters: c, IsLoopback: isLoopback,
			Class: ClassifyInterface(name, "", isLoopback),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ApplyThroughput fills in the per-second rates from the difference between two
// readings.
//
// A counter that went backwards means the interface was recreated, so the rate
// for that interval is reported as zero rather than as a nonsensical negative
// or an enormous positive number.
func ApplyThroughput(current []Interface, previous map[string]InterfaceCounters, elapsedSeconds float64) {
	if elapsedSeconds <= 0 {
		return
	}
	for i := range current {
		before, ok := previous[current[i].Name]
		if !ok {
			continue
		}
		if current[i].Counters.RxBytes >= before.RxBytes {
			current[i].RxBytesPerSecond = float64(current[i].Counters.RxBytes-before.RxBytes) / elapsedSeconds
		}
		if current[i].Counters.TxBytes >= before.TxBytes {
			current[i].TxBytesPerSecond = float64(current[i].Counters.TxBytes-before.TxBytes) / elapsedSeconds
		}
	}
}

// CountersOf reduces an interface list to its raw counters, for the next
// interval's difference.
func CountersOf(interfaces []Interface) map[string]InterfaceCounters {
	out := make(map[string]InterfaceCounters, len(interfaces))
	for _, iface := range interfaces {
		out[iface.Name] = iface.Counters
	}
	return out
}

// NetworkTotals is the aggregate across every interface, which is what the
// dashboard headline shows.
type NetworkTotals struct {
	RxBytesPerSecond float64 `json:"rx_bytes_per_second"`
	TxBytesPerSecond float64 `json:"tx_bytes_per_second"`

	RxBytesSinceBoot    uint64 `json:"rx_bytes_since_boot"`
	TxBytesSinceBoot    uint64 `json:"tx_bytes_since_boot"`
	RxBytesSinceInstall uint64 `json:"rx_bytes_since_install"`
	TxBytesSinceInstall uint64 `json:"tx_bytes_since_install"`
}

// Totals aggregates the interfaces, excluding the loopback, whose traffic is
// this machine talking to itself and would double every figure it appears in.
func Totals(interfaces []Interface) NetworkTotals {
	var out NetworkTotals
	for _, iface := range interfaces {
		if iface.IsLoopback {
			continue
		}
		out.RxBytesPerSecond += iface.RxBytesPerSecond
		out.TxBytesPerSecond += iface.TxBytesPerSecond
		out.RxBytesSinceBoot += iface.RxBytesSinceBoot
		out.TxBytesSinceBoot += iface.TxBytesSinceBoot
		out.RxBytesSinceInstall += iface.RxBytesSinceInstall
		out.TxBytesSinceInstall += iface.TxBytesSinceInstall
	}
	return out
}
