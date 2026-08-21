package route

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/rules"
)

// Flow is one live connection crossing a relay, as connection tracking sees it
// (§5.3, §8).
//
// The two directions are named from the relay's point of view, the same way the
// byte counters are: Tx is what the client sent towards the destination and Rx
// is what came back.
type Flow struct {
	Protocol string `json:"protocol"`

	// SourceAddress and SourcePort are the client.
	SourceAddress string `json:"source_address"`
	SourcePort    int    `json:"source_port"`
	// BindAddress and BindPort are what the client connected to, which is what
	// attributes a flow to a forwarding rule.
	BindAddress string `json:"bind_address"`
	BindPort    int    `json:"bind_port"`
	// DestinationAddress and DestinationPort are where the traffic was actually
	// sent, read from the reply tuple rather than from the rule, so a flow shows
	// which destination of a load-balanced set took it.
	DestinationAddress string `json:"destination_address"`
	DestinationPort    int    `json:"destination_port"`

	// State is the transport's own state where there is one. UDP has none, and
	// reporting an empty string is honest where inventing "ESTABLISHED" is not.
	State string `json:"state,omitempty"`
	// AgeSeconds is how long the flow has existed, when the source of the
	// reading knows. The /proc fallback does not.
	AgeSeconds float64 `json:"age_seconds,omitempty"`
	// TimeoutSeconds is how long conntrack will keep it without traffic.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	TxBytes   uint64 `json:"tx_bytes"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	RxPackets uint64 `json:"rx_packets"`

	Mark uint32 `json:"mark,omitempty"`
}

// Key identifies a flow across samples, which is what makes counting the new
// ones possible without the reader having to report a start time.
func (f Flow) Key() string {
	return fmt.Sprintf("%s|%s:%d|%s:%d", f.Protocol, f.SourceAddress, f.SourcePort,
		f.BindAddress, f.BindPort)
}

// Belongs reports whether this flow is one a forwarding rule created.
//
// The match is on the original destination — what the client connected to —
// because that is what survives every NAT mode: the reply tuple's source is the
// real destination under masquerade and the client's own address under None.
func (f Flow) Belongs(spec rules.RouteSpec) bool {
	if !protocolMatches(f.Protocol, spec.Protocol) {
		return false
	}
	if !portInRange(f.BindPort, spec.BindPorts) {
		return false
	}
	if spec.BindsAnyAddress() {
		return true
	}
	return sameAddress(f.BindAddress, spec.BindAddress)
}

func protocolMatches(protocol string, want rules.Protocol) bool {
	if want == rules.ProtocolBoth {
		return protocol == string(rules.ProtocolTCP) || protocol == string(rules.ProtocolUDP)
	}
	return strings.EqualFold(protocol, string(want))
}

func portInRange(port int, r rules.PortRange) bool {
	if r.IsRange() {
		return port >= r.Port && port <= r.End
	}
	return port == r.Port
}

func sameAddress(a, b string) bool {
	left, err := netip.ParseAddr(strings.TrimSpace(a))
	if err != nil {
		return false
	}
	right, err := netip.ParseAddr(strings.TrimSpace(b))
	if err != nil {
		return false
	}
	return left.Unmap() == right.Unmap()
}

// ConntrackReader reads the kernel's connection tracking table.
//
// Reading it is expensive on a busy host — the table can hold hundreds of
// thousands of entries — which is why this has its own slower interval
// (routes.conntrack_interval_seconds) rather than being folded into the
// per-second byte sampling (§5.3).
type ConntrackReader interface {
	// Name identifies the implementation, which the diagnostics report so an
	// operator knows whether the figures came from netlink or from /proc.
	Name() string
	// Available reports whether connection tracking can be read here, and why
	// not when it cannot. A host with no conntrack module loaded is reported as
	// such rather than as a host with no connections.
	Available() (bool, string)
	// Flows returns every tracked connection.
	Flows(ctx context.Context) ([]Flow, error)
}

// procConntrackPath is the kernel's text listing of the table, which is the
// fallback when netlink is unavailable.
const procConntrackPath = "proc/net/nf_conntrack"

// ProcConntrack reads /proc/net/nf_conntrack.
//
// It is the fallback: parsing a text table is slower than a netlink dump and
// the file does not carry a start time, so flow ages are not reported from it.
// Root is "/" in production and a fixture directory in tests.
type ProcConntrack struct {
	Root string
}

// NewProcConntrack returns a reader over the real filesystem.
func NewProcConntrack() *ProcConntrack { return &ProcConntrack{Root: "/"} }

// Name identifies the implementation.
func (p *ProcConntrack) Name() string { return "proc" }

func (p *ProcConntrack) path() string {
	root := p.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, procConntrackPath)
}

// Available reports whether the table can be read here.
func (p *ProcConntrack) Available() (bool, string) {
	f, err := os.Open(p.path())
	if err != nil {
		return false, "connection tracking could not be read from " + p.path() + ": " + err.Error()
	}
	_ = f.Close()
	return true, ""
}

// Flows parses the table.
func (p *ProcConntrack) Flows(ctx context.Context) ([]Flow, error) {
	f, err := os.Open(p.path())
	if err != nil {
		return nil, fmt.Errorf("reading connection tracking: %w", err)
	}
	defer f.Close()

	var out []Flow
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		if flow, ok := ParseConntrackLine(scanner.Text()); ok {
			out = append(out, flow)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading connection tracking: %w", err)
	}
	return out, nil
}

// ParseConntrackLine reads one line of /proc/net/nf_conntrack.
//
// The line holds the original tuple and then the reply tuple, each spelled as
// src=/dst=/sport=/dport=, with the packet and byte counters between them when
// accounting is on. The reply tuple's destination is where the traffic actually
// went, which is what makes a load-balanced rule's flows attributable to the
// destination that took them.
func ParseConntrackLine(line string) (Flow, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return Flow{}, false
	}

	flow := Flow{}
	// The transport protocol is the third field on an ipv4/ipv6 line and the
	// first on the shorter form some kernels print.
	for _, field := range fields[:4] {
		if field == "tcp" || field == "udp" {
			flow.Protocol = field
			break
		}
	}
	if flow.Protocol == "" {
		return Flow{}, false
	}

	// The state is an uppercase word before the first src=, present for TCP and
	// absent for UDP.
	for _, field := range fields {
		if strings.Contains(field, "=") {
			break
		}
		if field == strings.ToUpper(field) && strings.ContainsAny(field, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			flow.State = field
		}
	}
	if len(fields) > 4 {
		if timeout, err := strconv.Atoi(fields[4]); err == nil {
			flow.TimeoutSeconds = timeout
		}
	}

	// Two tuples: the first src=/dst= group is the original direction, the
	// second is the reply.
	tuple := 0
	seen := map[string]bool{}
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		if key == "src" && seen["src"] {
			tuple++
			seen = map[string]bool{}
		}
		seen[key] = true

		switch {
		case tuple == 0 && key == "src":
			flow.SourceAddress = value
		case tuple == 0 && key == "dst":
			flow.BindAddress = value
		case tuple == 0 && key == "sport":
			flow.SourcePort = atoiOrZero(value)
		case tuple == 0 && key == "dport":
			flow.BindPort = atoiOrZero(value)
		case tuple == 0 && key == "packets":
			flow.TxPackets = atouOrZero(value)
		case tuple == 0 && key == "bytes":
			flow.TxBytes = atouOrZero(value)

		case tuple == 1 && key == "src":
			flow.DestinationAddress = value
		case tuple == 1 && key == "sport":
			flow.DestinationPort = atoiOrZero(value)
		case tuple == 1 && key == "packets":
			flow.RxPackets = atouOrZero(value)
		case tuple == 1 && key == "bytes":
			flow.RxBytes = atouOrZero(value)

		case key == "mark":
			flow.Mark = uint32(atouOrZero(value))
		}
	}
	if flow.SourceAddress == "" || flow.BindPort == 0 {
		return Flow{}, false
	}
	return flow, true
}

func atoiOrZero(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func atouOrZero(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// FakeConntrack is a seeded reader, which is what makes the connection list and
// the analysis testable without traffic.
type FakeConntrack struct {
	List  []Flow
	Err   error
	Ready bool
	Note  string
}

// NewFakeConntrack returns a reader that reports the given flows.
func NewFakeConntrack(flows ...Flow) *FakeConntrack {
	return &FakeConntrack{List: flows, Ready: true}
}

// Name identifies the implementation.
func (f *FakeConntrack) Name() string { return "fake" }

// Available reports what the fake was told to report.
func (f *FakeConntrack) Available() (bool, string) { return f.Ready, f.Note }

// Flows returns the seeded flows.
func (f *FakeConntrack) Flows(ctx context.Context) ([]Flow, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return append([]Flow(nil), f.List...), nil
}

// ---------------------------------------------------------------- attribution

// ConnectionCount is one rule's share of the connection tracking table.
type ConnectionCount struct {
	RouteRuleID int64 `json:"route_rule_id"`
	// Active is how many connections are tracked for this rule right now.
	Active int `json:"active"`
	// New is how many appeared since the previous reading, which divided by the
	// gap gives the new-connections-per-second figure.
	New int `json:"new"`
	// BySource counts connections per client address, which is what a
	// per-source connection limit is actually enforcing.
	BySource map[string]int `json:"by_source,omitempty"`
	// ByDestination is where the connections actually went, with what moved
	// to each since the previous reading.
	ByDestination []DestinationLoad `json:"by_destination,omitempty"`
	// MovedByDestination is the same movement as raw byte counts, which is
	// what the cumulative per-destination accounting folds up. Internal: the
	// response already carries the movement as rates.
	MovedByDestination []DestinationMoved `json:"-"`
	// RateIntervalSeconds is the gap those rates were measured over. Zero
	// means there was no usable previous reading and they are not rates.
	RateIntervalSeconds float64 `json:"rate_interval_seconds,omitempty"`
}

// FlowsFor returns the flows belonging to one rule, newest first where the
// reader knows the age.
func FlowsFor(flows []Flow, spec rules.RouteSpec) []Flow {
	out := make([]Flow, 0, 8)
	for _, flow := range flows {
		if flow.Belongs(spec) {
			out = append(out, flow)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AgeSeconds < out[j].AgeSeconds })
	return out
}

// conntrackState remembers the flows seen last time and the bytes on them, so
// the number of new connections is counted rather than estimated from an age
// the /proc listing does not carry, and so what moved to each destination can
// be subtracted rather than guessed.
type conntrackState struct {
	seen map[int64]map[string]flowBytes
	at   time.Time
}

// maxTrackedFlows caps what one rule's flow set costs to remember. A relay busy
// enough to exceed it gets a new-connection rate derived from a truncated set,
// which is reported as an approximation rather than silently wrong: the active
// count itself is never truncated.
const maxTrackedFlows = 50000

func newConntrackState() *conntrackState {
	return &conntrackState{seen: map[int64]map[string]flowBytes{}}
}

// observe folds one conntrack reading into the counts.
func (c *conntrackState) observe(specs []rules.RouteSpec, flows []Flow, now time.Time) map[int64]ConnectionCount {
	out := make(map[int64]ConnectionCount, len(specs))
	next := make(map[int64]map[string]flowBytes, len(specs))

	// A gap outside the window is not a measurement: below the floor the
	// counters have barely moved and the division amplifies the noise, and
	// above the ceiling the sampler was stopped and the two readings have
	// nothing to do with each other.
	gap := 0.0
	if !c.at.IsZero() {
		if elapsed := now.Sub(c.at); elapsed >= minRateGap && elapsed <= maxRateGap {
			gap = elapsed.Seconds()
		}
	}

	for _, spec := range specs {
		count := ConnectionCount{RouteRuleID: spec.RouteRuleID, BySource: map[string]int{}}
		previous := c.seen[spec.RouteRuleID]
		keys := make(map[string]flowBytes, len(previous))
		load := newDestinationTally()

		for _, flow := range flows {
			if !flow.Belongs(spec) {
				continue
			}
			count.Active++
			count.BySource[flow.SourceAddress]++
			key := flow.Key()
			if len(keys) < maxTrackedFlows {
				keys[key] = flowBytes{rx: flow.RxBytes, tx: flow.TxBytes}
			}
			was, seen := previous[key]
			if previous != nil && !seen {
				count.New++
			}
			load.add(flow, was, seen, previous != nil)
		}
		// The first reading has nothing to compare against, so every flow would
		// look new. Reporting zero is right: they are not new, they are the
		// first thing that was seen.
		if previous == nil {
			count.New = 0
		}
		if previous != nil && gap > 0 {
			count.RateIntervalSeconds = gap
		}
		count.ByDestination, count.MovedByDestination = load.result(count.RateIntervalSeconds)
		next[spec.RouteRuleID] = keys
		out[spec.RouteRuleID] = count
	}

	c.seen = next
	c.at = now
	return out
}

// forget drops a rule's remembered flows.
func (c *conntrackState) forget(routeRuleID int64) { delete(c.seen, routeRuleID) }

// destinationTally folds a rule's flows into one entry per destination: what is
// open there now, and what moved to it since the previous reading.
//
// The subtraction is per flow and never per destination. A destination's total
// falls whenever one of its connections closes, and a difference taken on the
// totals reports that fall as negative throughput. A flow the previous reading
// did not have did not exist then, so every byte on it moved inside the gap and
// all of it counts; a flow that has gone takes whatever it carried after the
// last reading with it, which is why the figure is a floor on the throughput
// and not an estimate above it.
type destinationTally struct {
	index map[destinationKey]int
	rows  []DestinationLoad
	moved []movement
}

func newDestinationTally() *destinationTally {
	return &destinationTally{index: map[destinationKey]int{}}
}

func (d *destinationTally) add(flow Flow, was flowBytes, seen, comparable bool) {
	key := destinationKey{address: flow.DestinationAddress, port: flow.DestinationPort}
	at, ok := d.index[key]
	if !ok {
		at = len(d.rows)
		d.index[key] = at
		d.rows = append(d.rows, DestinationLoad{Address: key.address, Port: key.port})
		d.moved = append(d.moved, movement{})
	}
	d.rows[at].Connections++
	d.rows[at].RxBytes += flow.RxBytes
	d.rows[at].TxBytes += flow.TxBytes

	if !comparable {
		return
	}
	if !seen {
		d.moved[at].rx += float64(flow.RxBytes)
		d.moved[at].tx += float64(flow.TxBytes)
		return
	}
	// A counter that went backwards is a new connection reusing the tuple of
	// one that closed. It contributes nothing rather than a negative.
	if flow.RxBytes > was.rx {
		d.moved[at].rx += float64(flow.RxBytes - was.rx)
	}
	if flow.TxBytes > was.tx {
		d.moved[at].tx += float64(flow.TxBytes - was.tx)
	}
}

// DestinationMoved is what one reading saw move to one destination, in bytes.
type DestinationMoved struct {
	Address string
	Port    int
	RxBytes uint64
	TxBytes uint64
}

// result returns the destinations busiest first, with the movement divided by
// the gap when there was a usable one, and the raw movement beside it for the
// cumulative accounting.
func (d *destinationTally) result(seconds float64) ([]DestinationLoad, []DestinationMoved) {
	var moved []DestinationMoved
	for i := range d.rows {
		if d.moved[i].rx > 0 || d.moved[i].tx > 0 {
			moved = append(moved, DestinationMoved{
				Address: d.rows[i].Address, Port: d.rows[i].Port,
				RxBytes: uint64(d.moved[i].rx), TxBytes: uint64(d.moved[i].tx),
			})
		}
		if seconds > 0 {
			d.rows[i].RxBytesPerSecond = d.moved[i].rx / seconds
			d.rows[i].TxBytesPerSecond = d.moved[i].tx / seconds
		}
	}
	sort.SliceStable(d.rows, func(i, j int) bool {
		if d.rows[i].Connections != d.rows[j].Connections {
			return d.rows[i].Connections > d.rows[j].Connections
		}
		if d.rows[i].Address != d.rows[j].Address {
			return d.rows[i].Address < d.rows[j].Address
		}
		return d.rows[i].Port < d.rows[j].Port
	})
	return d.rows, moved
}
