// Package tuning is the kernel parameters a relay's throughput and stability
// depend on, and what this host should be setting them to.
//
// The panel already had one of these — it turns forwarding on, records what the
// parameter was before, and can put it back. This is the same idea applied to
// the rest of what a busy relay needs, because a stock kernel is sized for a
// machine that serves a handful of connections and a relay is not that machine.
//
// The parameters are split by what going wrong costs. The conntrack pair is
// under Safety because filling that table does not slow the host down, it takes
// it off the network: every new connection is refused, SSH included, and
// nothing in any log says why. The panel's own rules are what fill it, so the
// panel keeps it sized. Everything else is under Throughput, and is offered
// rather than applied: those are machine-wide choices that affect every other
// service on the host, and changing them unasked is not the panel's to do.
package tuning

import (
	"fmt"
	"math"
	"strings"
)

// Group decides whether the panel keeps a parameter set by itself or offers it.
type Group string

const (
	// GroupSafety is what the panel maintains because its own workload is what
	// breaks it. Filling the connection tracking table is not slow, it is down.
	GroupSafety Group = "safety"
	// GroupThroughput is what a relay wants for bandwidth and connection rate.
	// It is offered and never applied without being asked.
	GroupThroughput Group = "throughput"
)

// Facts are the things about this host that the recommendations are computed
// from. A recommendation that ignores them is a number from someone else's
// machine.
type Facts struct {
	// MemoryMB is total RAM. Buffers and table sizes are bounded by it: a
	// recommendation that does not fit is worse than no recommendation.
	MemoryMB int
	// Cores decides how much work can be in flight at once, which is what the
	// backlogs are sized from.
	Cores int
	// LiveConnections is what the relays on this host are actually carrying,
	// which is the only honest input to how big the tracking table has to be.
	LiveConnections int
}

// Parameter is one kernel setting the panel understands.
type Parameter struct {
	// Key is the sysctl name, which is also how it is written to the panel's
	// own file.
	Key string
	// Proc is the path under /proc it is read from, relative to the root.
	Proc string
	// Group decides whether the panel maintains it or merely offers it.
	Group Group
	// Title is the short name an operator reads.
	Title string
	// Explain says what the parameter does and what going wrong looks like, in
	// the words an operator would use rather than the kernel's.
	Explain string
	// Recommend returns what this host should be setting it to. An empty
	// string means the panel has no opinion for this host.
	Recommend func(Facts) string
	// Restart reports that a change needs services restarted to take effect.
	Restart bool
}

// Catalogue is every parameter the panel understands, in the order the
// interface shows them: the two that decide whether the host stays reachable,
// then the ones that decide how fast it is.
func Catalogue() []Parameter {
	return []Parameter{
		{
			Key: "net.netfilter.nf_conntrack_max", Proc: "proc/sys/net/netfilter/nf_conntrack_max",
			Group: GroupSafety,
			Title: "Connection tracking table size",
			Explain: "How many connections this server can track at once. The kernel sizes it from " +
				"how much memory the machine has, which has nothing to do with how many connections a " +
				"relay carries. When it fills, every new connection is refused — including SSH — and " +
				"nothing in any log says why. Rebooting appears to fix it, because rebooting empties " +
				"the table.",
			Recommend: func(f Facts) string { return fmt.Sprint(RecommendedConntrackMax(f)) },
		},
		{
			Key:   "net.netfilter.nf_conntrack_tcp_timeout_established",
			Proc:  "proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
			Group: GroupSafety,
			Title: "How long a finished connection keeps its slot",
			Explain: "A connection that ends without saying goodbye — a phone changing network, an app " +
				"killed, a laptop closed — holds its place in the table until this expires. The kernel " +
				"ships with five days, so on a relay the dead connections pile up until the table is " +
				"full. Six hours is longer than anything genuinely still open and short enough that " +
				"the dead ones leave.",
			Recommend: func(Facts) string { return "21600" },
		},
		{
			Key: "net.ipv4.tcp_congestion_control", Proc: "proc/sys/net/ipv4/tcp_congestion_control",
			Group: GroupThroughput,
			Title: "How fast the server is willing to send",
			Explain: "The algorithm that decides how quickly to speed up and how hard to back off when " +
				"the network is busy. The default backs off whenever a packet is lost, which on a long " +
				"path treats ordinary loss as congestion and never reaches the speed the link can " +
				"actually carry. BBR measures the path instead of guessing from loss, and is usually " +
				"the single largest difference on an intercontinental relay.",
			Recommend: func(Facts) string { return "bbr" },
		},
		{
			Key: "net.core.default_qdisc", Proc: "proc/sys/net/core/default_qdisc",
			Group: GroupThroughput,
			Title: "How outgoing packets are queued",
			Explain: "What the kernel does with packets waiting to go out. The default lets one busy " +
				"connection fill the queue and delay everything behind it. `fq` gives each connection " +
				"its own turn, which keeps one large transfer from making everything else feel slow, " +
				"and is what the congestion control above expects to be paired with.",
			Recommend: func(Facts) string { return "fq" },
		},
		{
			Key: "net.core.somaxconn", Proc: "proc/sys/net/core/somaxconn",
			Group: GroupThroughput,
			Title: "Connections waiting to be accepted",
			Explain: "How many finished connections may queue up waiting for a program to pick them up. " +
				"Too small and a burst of clients is refused rather than queued, which looks to them " +
				"like the server is down.",
			Recommend: func(f Facts) string { return fmt.Sprint(clamp(f.Cores*32768, 65535, 262144)) },
		},
		{
			Key: "net.ipv4.tcp_max_syn_backlog", Proc: "proc/sys/net/ipv4/tcp_max_syn_backlog",
			Group: GroupThroughput,
			Title: "Connections part-way through opening",
			Explain: "How many half-open connections the kernel will hold while they finish their " +
				"handshake. A relay opens a great many at once, and when this is too small the extra " +
				"ones are dropped silently and the client simply waits.",
			Recommend: func(f Facts) string { return fmt.Sprint(clamp(f.Cores*32768, 65535, 262144)) },
		},
		{
			Key: "net.core.netdev_max_backlog", Proc: "proc/sys/net/core/netdev_max_backlog",
			Group: GroupThroughput,
			Title: "Packets waiting to be processed",
			Explain: "How many arriving packets may queue while the processor catches up. On a fast " +
				"link the card can hand over packets faster than one core can take them, and anything " +
				"past this is dropped before any program has seen it.",
			Recommend: func(f Facts) string { return fmt.Sprint(clamp(f.Cores*32768, 65535, 250000)) },
		},
		{
			Key: "net.core.rmem_max", Proc: "proc/sys/net/core/rmem_max",
			Group: GroupThroughput,
			Title: "Largest receive buffer",
			Explain: "The most memory one connection may use for data that has arrived but not yet " +
				"been read. On a long path a lot of data is in flight at any moment, and a buffer too " +
				"small to hold it caps the speed no matter how fast the link is.",
			Recommend: func(f Facts) string { return fmt.Sprint(bufferBytes(f)) },
		},
		{
			Key: "net.core.wmem_max", Proc: "proc/sys/net/core/wmem_max",
			Group: GroupThroughput,
			Title: "Largest send buffer",
			Explain: "The same in the other direction: how much may be waiting to go out on one " +
				"connection. Too small and the sender stalls waiting for acknowledgements that are " +
				"still crossing the ocean.",
			Recommend: func(f Facts) string { return fmt.Sprint(bufferBytes(f)) },
		},
		{
			Key: "net.ipv4.tcp_rmem", Proc: "proc/sys/net/ipv4/tcp_rmem",
			Group: GroupThroughput,
			Title: "Receive buffer range",
			Explain: "The smallest, starting and largest receive buffer the kernel will pick for a " +
				"connection by itself. Raising the top of the range is what lets a fast connection on " +
				"a long path grow into it.",
			Recommend: func(f Facts) string { return fmt.Sprintf("4096 87380 %d", bufferBytes(f)) },
		},
		{
			Key: "net.ipv4.tcp_wmem", Proc: "proc/sys/net/ipv4/tcp_wmem",
			Group:     GroupThroughput,
			Title:     "Send buffer range",
			Explain:   "The same for sending.",
			Recommend: func(f Facts) string { return fmt.Sprintf("4096 65536 %d", bufferBytes(f)) },
		},
		{
			Key: "net.ipv4.tcp_fastopen", Proc: "proc/sys/net/ipv4/tcp_fastopen",
			Group: GroupThroughput,
			Title: "Send data with the handshake",
			Explain: "Lets a client that has connected before send its first request together with the " +
				"handshake instead of waiting for it to finish. It saves one round trip on every " +
				"reconnection, which on a long path is the difference a user actually notices.",
			Recommend: func(Facts) string { return "3" },
		},
		{
			Key: "net.ipv4.tcp_tw_reuse", Proc: "proc/sys/net/ipv4/tcp_tw_reuse",
			Group: GroupThroughput,
			Title: "Reuse recently closed ports",
			Explain: "Lets the kernel reuse a local port whose last connection has closed but is still " +
				"in its cooling-off period. A relay opens and closes so many connections that without " +
				"this it can run out of ports entirely while most of them sit idle.",
			Recommend: func(Facts) string { return "1" },
		},
		{
			Key: "net.ipv4.tcp_fin_timeout", Proc: "proc/sys/net/ipv4/tcp_fin_timeout",
			Group: GroupThroughput,
			Title: "How long to wait for the other side to finish closing",
			Explain: "After this server has closed its half of a connection, how long it waits for the " +
				"far end to close theirs. The default is generous; a relay with many short " +
				"connections is better off reclaiming them sooner.",
			Recommend: func(Facts) string { return "15" },
		},
		{
			Key: "net.ipv4.tcp_keepalive_time", Proc: "proc/sys/net/ipv4/tcp_keepalive_time",
			Group: GroupThroughput,
			Title: "How long an idle connection waits before being checked",
			Explain: "How long a connection may sit silent before the kernel asks the far end whether " +
				"it is still there. The default is over two hours, which is long enough for a relay to " +
				"hold thousands of connections to clients that vanished.",
			Recommend: func(Facts) string { return "300" },
		},
		{
			Key: "net.ipv4.ip_local_port_range", Proc: "proc/sys/net/ipv4/ip_local_port_range",
			Group: GroupThroughput,
			Title: "Ports available for outgoing connections",
			Explain: "The range of local port numbers this server may use when it opens a connection " +
				"of its own — which a relay does for every connection it carries. The default range " +
				"is about half of what is available, and running out of it stops the relay dead.",
			Recommend: func(Facts) string { return "1024 65535" },
		},
		{
			Key: "fs.file-max", Proc: "proc/sys/fs/file-max",
			Group: GroupThroughput,
			Title: "Open files allowed on the whole machine",
			Explain: "Every connection is an open file as far as the kernel is concerned, so a relay " +
				"carrying tens of thousands of them needs a limit that allows for it. Running out " +
				"produces errors that name files rather than connections, which is why it is confusing " +
				"the first time.",
			Recommend: func(f Facts) string { return fmt.Sprint(clamp(f.MemoryMB*512, 1048576, 8388608)) },
		},
	}
}

// RecommendedConntrackMax is how big the tracking table should be on this host.
//
// It is the larger of what the machine's memory can comfortably hold and what
// the relays are actually carrying, because either one alone gets it wrong: a
// big machine with no traffic does not need a huge table, and a small machine
// carrying forty thousand connections needs one whatever its memory says.
// Entries cost roughly 300 bytes, so even the ceiling here is a fraction of a
// small VPS's memory.
func RecommendedConntrackMax(f Facts) int {
	byMemory := f.MemoryMB * 64
	// Room for four times what is open now: a relay's peak is not its average,
	// and the table has to survive the peak rather than the average.
	byLoad := f.LiveConnections * 4
	want := byMemory
	if byLoad > want {
		want = byLoad
	}
	return powerOfTwoFloor(clamp(want, 262144, 2097152))
}

// bufferBytes is the largest socket buffer worth offering on this host: enough
// for a long fat path, never so much that a few connections could exhaust the
// machine.
func bufferBytes(f Facts) int {
	return clamp(f.MemoryMB*1024, 16777216, 134217728)
}

func clamp(value, low, high int) int {
	if value < low {
		return low
	}
	if value > high {
		return high
	}
	return value
}

// powerOfTwoFloor rounds down to a power of two, which is the shape the
// connection tracking table's own hashing prefers.
func powerOfTwoFloor(value int) int {
	if value < 2 {
		return value
	}
	return 1 << int(math.Floor(math.Log2(float64(value))))
}

// Matches reports whether a live value is already what was recommended.
//
// The comparison is on fields rather than on the string, because the kernel
// prints the multi-value parameters with tabs where a file writes spaces, and
// an operator should not be told a parameter needs changing because of
// whitespace.
func Matches(current, recommended string) bool {
	return strings.Join(strings.Fields(current), " ") == strings.Join(strings.Fields(recommended), " ")
}
