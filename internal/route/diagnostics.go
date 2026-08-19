package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// Verdicts (§8). They are stable strings: the frontend renders a different
// explanation and a different suggested fix for each.
const (
	VerdictRuleMissing            = "RULE_MISSING"
	VerdictForwardingDisabled     = "FORWARDING_DISABLED"
	VerdictNoInboundTraffic       = "NO_INBOUND_TRAFFIC"
	VerdictForwardBlocked         = "FORWARD_BLOCKED"
	VerdictDestinationUnreachable = "DESTINATION_UNREACHABLE"
	VerdictMtuProblem             = "MTU_PROBLEM"
	VerdictRuleShadowed           = "RULE_SHADOWED"
	VerdictTunnelDown             = "TUNNEL_DOWN"
	VerdictDisabled               = "RULE_DISABLED"
	VerdictHealthy                = "HEALTHY"
)

// Confidence qualifies a verdict, the same way the tunnel diagnostics do.
const (
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

// Evidence is one thing the analysis observed. Every verdict carries the
// evidence it rests on, because a bare status word tells an operator nothing.
type Evidence struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Data   any    `json:"data,omitempty"`
}

// ReachabilityParams describes a destination probe.
//
// It takes an address and a port rather than a rule identifier, because §8
// requires this to run as a pre-flight *before* the rule exists — which is the
// moment it is most useful, since it turns "create it and see" into an answer.
type ReachabilityParams struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	// TimeoutSeconds bounds one attempt.
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty"`
	// SourceAddress binds the probe to one local address, so a destination
	// reached through a tunnel is tested over the path the relay will use
	// rather than over whatever the routing table prefers.
	SourceAddress string `json:"source_address,omitempty"`
}

// ReachabilityResult is what the probe found.
type ReachabilityResult struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`

	// Reachable is true only when something answered. A UDP probe that got no
	// answer is neither reachable nor unreachable, which is what Conclusive
	// exists to say rather than leaving a guess to be read as a measurement.
	Reachable  bool    `json:"reachable"`
	Conclusive bool    `json:"conclusive"`
	LatencyMs  float64 `json:"latency_ms,omitempty"`

	// Detail is the sentence an operator reads; Error is the transport's own
	// message, kept separate so one can be translated and the other quoted.
	Detail    string `json:"detail"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checked_at"`
}

// Prober runs the destination probe. It is an interface so the analysis is
// testable without a network.
type Prober interface {
	Probe(ctx context.Context, params ReachabilityParams) ReachabilityResult
}

// NetProber probes with the host's own network stack.
type NetProber struct{}

// Probe connects to the destination, or sends a datagram and watches for the
// refusal that proves the host is there.
func (NetProber) Probe(ctx context.Context, params ReachabilityParams) ReachabilityResult {
	protocol := strings.ToLower(strings.TrimSpace(params.Protocol))
	if protocol == "" || protocol == string(rules.ProtocolBoth) {
		// "Both" is not a protocol to probe with; TCP is the one that can give
		// a definite answer, so that is what is used and what is reported.
		protocol = string(rules.ProtocolTCP)
	}
	timeout := time.Duration(params.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	result := ReachabilityResult{
		Address: params.Address, Port: params.Port, Protocol: protocol,
		CheckedAt: model.NowUTC(),
	}
	target := net.JoinHostPort(strings.TrimSpace(params.Address), strconv.Itoa(params.Port))

	dialer := &net.Dialer{Timeout: timeout}
	if source := strings.TrimSpace(params.SourceAddress); source != "" {
		if addr, err := net.ResolveIPAddr("ip", source); err == nil {
			dialer.LocalAddr = localAddrFor(protocol, addr.IP)
		}
	}

	started := time.Now()
	conn, err := dialer.DialContext(ctx, protocol, target)
	elapsed := time.Since(started)

	if protocol == string(rules.ProtocolUDP) {
		return probeUdp(ctx, conn, err, elapsed, timeout, result)
	}

	if err != nil {
		result.Conclusive = true
		result.Error = err.Error()
		result.Detail = describeDialError(target, err)
		return result
	}
	_ = conn.Close()

	result.Reachable = true
	result.Conclusive = true
	result.LatencyMs = float64(elapsed.Microseconds()) / 1000
	result.Detail = fmt.Sprintf("connected to %s in %.1f ms", target, result.LatencyMs)
	return result
}

// localAddrFor builds the source address a dial should bind to.
func localAddrFor(protocol string, ip net.IP) net.Addr {
	if protocol == string(rules.ProtocolUDP) {
		return &net.UDPAddr{IP: ip}
	}
	return &net.TCPAddr{IP: ip}
}

// probeUdp interprets a UDP probe.
//
// UDP has no handshake, so silence means nothing: a service that does not reply
// to an empty datagram looks exactly like a filtered port. What does prove
// something is a refusal — an ICMP port-unreachable comes back as
// ECONNREFUSED on the connected socket, which says the host is reachable and
// that nothing is listening there.
func probeUdp(ctx context.Context, conn net.Conn, dialErr error, elapsed, timeout time.Duration,
	result ReachabilityResult) ReachabilityResult {

	target := net.JoinHostPort(result.Address, strconv.Itoa(result.Port))
	if dialErr != nil {
		result.Conclusive = true
		result.Error = dialErr.Error()
		result.Detail = describeDialError(target, dialErr)
		return result
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if configured, ok := ctx.Deadline(); ok && configured.Before(deadline) {
		deadline = configured
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte{}); err != nil {
		result.Conclusive = true
		result.Error = err.Error()
		result.Detail = fmt.Sprintf("the probe to %s/udp could not be sent: %s", target, err.Error())
		return result
	}

	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	switch {
	case err == nil:
		result.Reachable, result.Conclusive = true, true
		result.LatencyMs = float64(elapsed.Microseconds()) / 1000
		result.Detail = fmt.Sprintf("%s/udp answered the probe", target)
	case errors.Is(err, syscall.ECONNREFUSED):
		result.Conclusive = true
		result.Error = err.Error()
		result.Detail = fmt.Sprintf("%s is reachable but nothing is listening on %d/udp: the host "+
			"refused the datagram", result.Address, result.Port)
	default:
		// Neither reachable nor unreachable, and saying so is the only honest
		// answer available.
		result.Detail = fmt.Sprintf("%s/udp did not answer within %s. UDP has no handshake, so a "+
			"service that does not reply to an empty datagram is indistinguishable from a filtered "+
			"port: this proves nothing either way.", target, timeout)
	}
	return result
}

// describeDialError turns a transport failure into the sentence that says what
// to do about it.
func describeDialError(target string, err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("%s refused the connection: the host is reachable and nothing is "+
			"listening on that port", target)
	case errors.Is(err, syscall.EHOSTUNREACH):
		return fmt.Sprintf("%s has no route from this server", target)
	case errors.Is(err, syscall.ENETUNREACH):
		return fmt.Sprintf("the network holding %s is not reachable from this server", target)
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return fmt.Sprintf("%s did not answer before the probe timed out, which is what a firewall "+
			"dropping the packets looks like", target)
	}
	return fmt.Sprintf("%s could not be reached: %s", target, err.Error())
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// ---------------------------------------------------------------- service

// DiagnosticsDeps is what the diagnostics need. Every one is an interface or a
// value the caller constructs, so the whole decision tree runs hermetically.
type DiagnosticsDeps struct {
	Repo       *Repo
	Backend    rules.Backend
	Forwarding *Forwarding
	Accounting *Accounting
	Conntrack  ConntrackReader
	Tunnels    TunnelSource
	Prober     Prober
	Log        *slog.Logger
}

// Diagnostics answers "is this rule working, and if not, why" (§8).
type Diagnostics struct {
	repo       *Repo
	backend    rules.Backend
	forwarding *Forwarding
	accounting *Accounting
	conntrack  ConntrackReader
	tunnels    TunnelSource
	prober     Prober
	log        *slog.Logger
}

// NewDiagnostics builds the diagnostics.
func NewDiagnostics(d DiagnosticsDeps) *Diagnostics {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	prober := d.Prober
	if prober == nil {
		prober = NetProber{}
	}
	conntrack := d.Conntrack
	if conntrack == nil && d.Accounting != nil {
		conntrack = d.Accounting.Conntrack()
	}
	if conntrack == nil {
		conntrack = SelectConntrack()
	}
	return &Diagnostics{
		repo: d.Repo, backend: d.Backend, forwarding: d.Forwarding, accounting: d.Accounting,
		conntrack: conntrack, tunnels: d.Tunnels, prober: prober, log: log,
	}
}

// SetTunnels wires the tunnel health source, which is built after this.
func (d *Diagnostics) SetTunnels(source TunnelSource) { d.tunnels = source }

// Test probes a destination. Params carrying no address are filled in from the
// stored rule, so the same endpoint serves the pre-flight and the on-demand
// check.
func (d *Diagnostics) Test(ctx context.Context, routeRuleID int64, params ReachabilityParams) (ReachabilityResult, error) {
	if routeRuleID != 0 && strings.TrimSpace(params.Address) == "" {
		rec, err := d.repo.ByID(ctx, routeRuleID)
		if err != nil {
			return ReachabilityResult{}, err
		}
		spec := rec.Spec()
		if len(spec.Destinations) == 0 {
			return ReachabilityResult{}, fmt.Errorf("%w: rule %d has no destination to test",
				rules.ErrNoDestination, routeRuleID)
		}
		params.Address = spec.Destinations[0].Address
		params.Port = spec.Destinations[0].Ports.Port
		if params.Protocol == "" {
			params.Protocol = string(spec.Protocol)
		}
	}
	if strings.TrimSpace(params.Address) == "" || params.Port <= 0 {
		return ReachabilityResult{}, errors.New("route: a reachability test needs an address and a port")
	}
	return d.prober.Probe(ctx, params), nil
}

// ConnectionList is the live conntrack view of one rule.
type ConnectionList struct {
	RouteRuleID int64  `json:"route_rule_id"`
	Reader      string `json:"reader"`
	// Available reports whether connection tracking could be read at all, so an
	// empty list is not mistaken for "nobody is using it".
	Available bool   `json:"available"`
	Detail    string `json:"detail,omitempty"`

	Connections []Flow `json:"connections"`
	Total       int    `json:"total"`
	// BySource counts connections per client, which is what a per-source limit
	// is actually enforcing.
	BySource map[string]int `json:"by_source,omitempty"`
	// ByDestination is the same reading taken the other way round, and is what
	// answers the question a load-balanced rule raises: where is the traffic
	// actually going. It is read from the reply tuple, so it is where packets
	// went and not where the rule says they should go.
	ByDestination []DestinationLoad `json:"by_destination,omitempty"`
	// NewPerSecond is the rate from the last two conntrack readings.
	NewPerSecond float64 `json:"new_per_second"`
	CheckedAt    string  `json:"checked_at"`
}

// DestinationLoad is what connection tracking shows at one destination.
//
// It is counted over every flow the rule has and not over the page of them the
// list returns, because the questions it answers are questions about all of
// them: is the traffic being spread at all, and is one destination of the set
// taking none of it.
type DestinationLoad struct {
	Address     string `json:"address"`
	Port        int    `json:"port"`
	Connections int    `json:"connections"`
	// RxBytes and TxBytes are the bytes on the flows that are live now, which
	// is a snapshot and not a total: a connection that has closed took its
	// counters out of the table with it. The rule's own counters are the
	// cumulative figure, and they are not attributable per destination.
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

// Connections lists the tracked connections belonging to one rule (§8).
func (d *Diagnostics) Connections(ctx context.Context, routeRuleID int64, limit int) (ConnectionList, error) {
	rec, err := d.repo.ByID(ctx, routeRuleID)
	if err != nil {
		return ConnectionList{}, err
	}
	out := ConnectionList{
		RouteRuleID: routeRuleID, Reader: d.conntrack.Name(),
		Connections: []Flow{}, BySource: map[string]int{}, CheckedAt: model.NowUTC(),
	}
	if ok, detail := d.conntrack.Available(); !ok {
		out.Detail = detail
		return out, nil
	}
	out.Available = true

	flows, err := d.conntrack.Flows(ctx)
	if err != nil {
		out.Available = false
		out.Detail = err.Error()
		return out, nil
	}

	mine := FlowsFor(flows, rec.Spec())
	out.Total = len(mine)
	for _, flow := range mine {
		out.BySource[flow.SourceAddress]++
	}
	out.ByDestination = loadByDestination(mine)
	if limit > 0 && limit < len(mine) {
		mine = mine[:limit]
	}
	out.Connections = mine

	if d.accounting != nil {
		if traffic, ok := d.accounting.Traffic(routeRuleID); ok {
			out.NewPerSecond = traffic.NewConnectionsPerSecond
		}
	}
	if out.Total == 0 {
		out.Detail = "connection tracking holds nothing for this rule, so nothing is using it right now"
	}
	return out, nil
}

// loadByDestination folds a rule's flows into one entry per destination, worst
// first: the destination taking the most connections leads, and a tie is broken
// on the address so the order does not shuffle between readings.
func loadByDestination(flows []Flow) []DestinationLoad {
	type key struct {
		address string
		port    int
	}
	index := map[key]int{}
	out := make([]DestinationLoad, 0, 4)
	for _, flow := range flows {
		k := key{address: flow.DestinationAddress, port: flow.DestinationPort}
		at, ok := index[k]
		if !ok {
			at = len(out)
			index[k] = at
			out = append(out, DestinationLoad{Address: k.address, Port: k.port})
		}
		out[at].Connections++
		out[at].RxBytes += flow.RxBytes
		out[at].TxBytes += flow.TxBytes
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Connections != out[j].Connections {
			return out[i].Connections > out[j].Connections
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// CounterReport is what §8 calls the rule hit counters: the packets and bytes
// the rule has actually matched.
type CounterReport struct {
	RouteRuleID int64 `json:"route_rule_id"`
	// The kernel's own figures, zeroed by every rebuild of the ruleset.
	RxBytesSinceBoot   uint64 `json:"rx_bytes_since_boot"`
	TxBytesSinceBoot   uint64 `json:"tx_bytes_since_boot"`
	RxPacketsSinceBoot uint64 `json:"rx_packets_since_boot"`
	TxPacketsSinceBoot uint64 `json:"tx_packets_since_boot"`
	// The panel's totals, folded across those resets.
	RxBytesSinceCreation uint64 `json:"rx_bytes_since_creation"`
	TxBytesSinceCreation uint64 `json:"tx_bytes_since_creation"`

	// Hit reports whether the rule has matched anything at all since the
	// ruleset was last built, which is the question "is this rule being
	// reached" reduces to.
	Hit bool `json:"hit"`
	// Source names where the figures came from, because the answer to "why is
	// this zero" depends on it.
	Source string `json:"source"`
	Note   string `json:"note"`

	CheckedAt string `json:"checked_at"`
}

// Counters reads the rule's own hit counters straight from the kernel rather
// than from the sampler's memory, so an operator asking the question gets the
// answer as of now.
func (d *Diagnostics) Counters(ctx context.Context, routeRuleID int64) (CounterReport, error) {
	if _, err := d.repo.ByID(ctx, routeRuleID); err != nil {
		return CounterReport{}, err
	}
	out := CounterReport{
		RouteRuleID: routeRuleID, CheckedAt: model.NowUTC(),
		Source: "the accounting rules in the filter hooks — forward, and for a rule " +
			"that also relays this server's own traffic, output and input as well",
		Note: SinceBootMeaning,
	}

	raw, err := d.backend.Counters(ctx)
	if err != nil {
		return out, fmt.Errorf("reading the rule's counters: %w", err)
	}
	counter := raw[routeRuleID]
	out.RxBytesSinceBoot, out.TxBytesSinceBoot = counter.RxBytes, counter.TxBytes
	out.RxPacketsSinceBoot, out.TxPacketsSinceBoot = counter.RxPackets, counter.TxPackets
	out.Hit = counter.RxPackets > 0 || counter.TxPackets > 0

	if d.accounting != nil {
		if traffic, ok := d.accounting.Traffic(routeRuleID); ok {
			out.RxBytesSinceCreation = traffic.RxBytesSinceCreation
			out.TxBytesSinceCreation = traffic.TxBytesSinceCreation
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- analysis

// AnalyzeParams tunes the analysis.
type AnalyzeParams struct {
	// Probe runs the destination reachability test as part of the analysis. It
	// is on by default, and can be turned off for a rule whose destination
	// deliberately refuses probes.
	Probe *bool `json:"probe,omitempty"`
	// TimeoutSeconds bounds that probe.
	TimeoutSeconds float64 `json:"timeout_seconds,omitempty"`
}

func (p AnalyzeParams) probeWanted() bool { return p.Probe == nil || *p.Probe }

// AnalyzeResult is a specific verdict with its evidence and a suggested fix.
type AnalyzeResult struct {
	RouteRuleID int64  `json:"route_rule_id"`
	Title       string `json:"title"`

	Verdict      string     `json:"verdict"`
	Confidence   string     `json:"confidence"`
	Summary      string     `json:"summary"`
	SuggestedFix []string   `json:"suggested_fix,omitempty"`
	Evidence     []Evidence `json:"evidence"`
	CheckedAt    string     `json:"checked_at"`
}

func (r *AnalyzeResult) add(name, detail string, data any) {
	r.Evidence = append(r.Evidence, Evidence{Name: name, Detail: detail, Data: data})
}

// stallPackets is how many packets a flow must have sent before a lopsided
// reply count is worth calling a stall. Below it, an ordinary short request
// would look like one.
const stallPackets = 8

// Analyze runs the decision tree of §8 and returns a specific verdict.
//
// One deliberate choice runs through it. The tree is written in terms of "hits
// on the DNAT rule", but the panel must not put a counter in a nat chain: a nat
// hook only ever sees the first packet of a connection, so a counter there
// measures connections while appearing to measure bytes (§5.1). The signal used
// instead is connection tracking — a flow whose original destination is this
// rule's bind address exists precisely because the DNAT matched and translated
// it — which answers the same question exactly, and from the kernel rather than
// from a counter the panel would have had to install in the wrong place.
func (d *Diagnostics) Analyze(ctx context.Context, routeRuleID int64, params AnalyzeParams) (AnalyzeResult, error) {
	rec, err := d.repo.ByID(ctx, routeRuleID)
	if err != nil {
		return AnalyzeResult{}, err
	}
	spec := rec.Spec()
	result := AnalyzeResult{
		RouteRuleID: routeRuleID, Title: rec.RouteRuleTitle,
		Confidence: ConfidenceHigh, Evidence: []Evidence{}, CheckedAt: model.NowUTC(),
	}

	// 0. A disabled rule installs nothing, and reporting it as missing would
	// send an operator looking for a fault that is a setting.
	if !rec.IsEnabled {
		result.Verdict = VerdictDisabled
		result.Summary = fmt.Sprintf("%s is disabled, so it installs no rules and carries no traffic.",
			rec.RouteRuleTitle)
		result.add("enabled", "the rule is stored but switched off", nil)
		result.SuggestedFix = []string{"Enable the rule to install it."}
		return result, nil
	}

	// 1. The rules have to be in the kernel.
	live, readErr := d.backend.ReadBack(ctx)
	if readErr != nil {
		result.Verdict = VerdictRuleMissing
		result.Confidence = ConfidenceLow
		result.Summary = "The panel's ruleset could not be read back from the kernel."
		result.add("ruleset", "reading the panel's namespace failed: "+readErr.Error(), nil)
		result.SuggestedFix = []string{
			"Check that the netfilter tools are installed and that the panel is running as root.",
		}
		return result, nil
	}
	installed := live.IDs()[routeRuleID]
	present := 0
	for _, rule := range live.Rules {
		if rule.RouteRuleID == routeRuleID {
			present++
		}
	}
	result.add("ruleset", fmt.Sprintf("the panel's %s namespace holds %d rule(s) for this "+
		"forwarding rule, out of %d in total", d.backend.Name(), present, len(live.Rules)),
		map[string]any{"installed": installed, "rules": present, "total": len(live.Rules)})

	if !installed {
		result.Verdict = VerdictRuleMissing
		result.Summary = fmt.Sprintf("%s is enabled but none of its rules are in the kernel.",
			rec.RouteRuleTitle)
		result.SuggestedFix = []string{
			"Reapply this rule, which installs the stored ruleset over whatever is there now.",
			"Check the reconcile report: something outside the panel may have flushed its namespace.",
		}
		return result, nil
	}
	if len(live.MissingJumps) > 0 {
		result.add("jump_rules", "the panel's chains are not reached from: "+
			strings.Join(live.MissingJumps, ", "), map[string]any{"missing": live.MissingJumps})
	}

	// 2. Forwarding has to be on, or the rules carry nothing.
	if d.forwarding != nil {
		status := d.forwarding.Status(ctx, spec.IsIPv6(), 1, 0)
		result.add("ip_forwarding", fmt.Sprintf("net.ipv4.ip_forward is %s and "+
			"net.ipv6.conf.all.forwarding is %s", onOff(status.IPv4Forwarding), onOff(status.IPv6Forwarding)),
			map[string]any{"ipv4": status.IPv4Forwarding, "ipv6": status.IPv6Forwarding})

		if !status.IPv4Forwarding || (spec.IsIPv6() && !status.IPv6Forwarding) {
			result.Verdict = VerdictForwardingDisabled
			result.Summary = "The rules are installed correctly, but this kernel is not forwarding " +
				"packets, so none of them can carry traffic."
			result.SuggestedFix = []string{
				"Turn forwarding on from the forwarding page, which writes the panel's own sysctl file.",
				"Check whether another package turned it off: the panel never does so by itself.",
			}
			return result, nil
		}
	}

	// 3. A foreign rule that takes the packet first explains everything below
	// it, so it is checked before the traffic-shape verdicts.
	shadows := d.shadowEvidence(ctx, spec, &result)

	// 4. What is actually moving. Connection tracking says whether the DNAT is
	// matching; the forward-hook counters say whether anything is being
	// forwarded once it has.
	flows, tracked := d.flowEvidence(ctx, spec, &result)
	counter, countersRead := d.counterEvidence(ctx, routeRuleID, &result)

	// 5. The destination has to be reachable, and a rule bound to a tunnel is
	// reported against that tunnel's state rather than as a generic failure.
	tunnel := d.tunnelEvidence(ctx, rec, &result)
	reach := d.probeEvidence(ctx, spec, params, &result)

	forwarded := countersRead && (counter.RxPackets > 0 || counter.TxPackets > 0)
	translated := tracked && len(flows) > 0

	switch {
	// §8.7 — something else is claiming the same listener.
	case len(shadows) > 0 && !forwarded:
		result.Verdict = VerdictRuleShadowed
		result.Summary = fmt.Sprintf("%s is installed but %s claims the same traffic, and a rule in a "+
			"built-in chain is reached before the panel's own table.",
			rec.RouteRuleTitle, shadows[0].Describe())
		result.SuggestedFix = []string{
			"Remove or narrow the rule the evidence quotes. The panel never deletes a rule it does not own.",
			"Bind this rule to a different address or port so the two no longer overlap.",
		}
		return result, nil

	// §8.5 — traffic is being forwarded, but the far end is not answering. The
	// tunnel a rule depends on is named explicitly rather than left implicit.
	case tunnel != nil && !tunnel.Healthy():
		result.Verdict = VerdictTunnelDown
		result.Summary = fmt.Sprintf("%s sends its traffic through %s, and that tunnel is not up. "+
			"The forwarding rules are installed correctly; the path they use is what is broken.",
			rec.RouteRuleTitle, tunnel.InterfaceName)
		result.SuggestedFix = []string{
			fmt.Sprintf("Bring %s up, or run the tunnel's own diagnostics.", tunnel.InterfaceName),
			"The rule needs no change: it works again as soon as the tunnel does.",
		}
		return result, nil

	case reach != nil && reach.Conclusive && !reach.Reachable:
		result.Verdict = VerdictDestinationUnreachable
		result.Summary = fmt.Sprintf("%s cannot reach its destination: %s",
			rec.RouteRuleTitle, reach.Detail)
		result.SuggestedFix = []string{
			"Check that the service on the destination is running and listening on that port.",
			"Check the route to the destination from this server.",
		}
		if tunnel != nil {
			result.SuggestedFix = append(result.SuggestedFix,
				fmt.Sprintf("The destination is reached through %s; run that tunnel's diagnostics too.",
					tunnel.InterfaceName))
		}
		return result, nil

	// §8.3 — nothing is arriving at all.
	case !translated && !forwarded:
		result.Verdict = VerdictNoInboundTraffic
		result.Confidence = ConfidenceLow
		result.Summary = fmt.Sprintf("%s is installed and working, and nothing has reached this server "+
			"on %s yet.", rec.RouteRuleTitle, bindDescription(spec))
		result.SuggestedFix = []string{
			"Check that clients are connecting to the right address and port.",
			fmt.Sprintf("Check that a firewall upstream of this server allows %s to %s.",
				spec.Protocol, bindDescription(spec)),
			"Check the bind address: a rule bound to one address does not receive traffic sent to another.",
		}
		return result, nil

	// §8.4 — the DNAT matched and created a flow, and nothing came out the
	// other side.
	case translated && !forwarded:
		result.Verdict = VerdictForwardBlocked
		result.Summary = fmt.Sprintf("Connections are reaching %s and being translated, but nothing is "+
			"being forwarded: another filter is dropping the packets.", rec.RouteRuleTitle)
		result.SuggestedFix = []string{
			"Check the FORWARD policy and any other filter rules on this host: the panel's own accept " +
				"is in its own chain and something ahead of it may be dropping first.",
			"Docker sets the FORWARD policy to DROP; a rule of its own may be taking these packets.",
		}
		if len(live.MissingJumps) > 0 {
			result.SuggestedFix = append(result.SuggestedFix,
				"The panel's chains are not reached from "+strings.Join(live.MissingJumps, ", ")+
					": reapply the rule to put the jump rules back.")
		}
		return result, nil
	}

	// §8.6 — connections establish and then stall, which is what a missing MSS
	// clamp does across a tunnel.
	if stalled := stalledFlows(flows); len(stalled) > 0 {
		result.add("stalled_flows", fmt.Sprintf("%d connection(s) are established with packets going out "+
			"and almost nothing coming back, which is the shape of a path MTU problem rather than a "+
			"reachability one", len(stalled)),
			map[string]any{"stalled": len(stalled), "clamping": spec.ClampMssToPmtu})

		if !spec.ClampMssToPmtu {
			result.Verdict = VerdictMtuProblem
			result.Summary = fmt.Sprintf("Connections through %s establish and then stall on the first "+
				"large transfer, and MSS clamping is off.", rec.RouteRuleTitle)
			result.SuggestedFix = []string{
				"Turn on MSS clamping for this rule. It rewrites the segment size of forwarded " +
					"connections to fit the path, which is exactly this symptom's cause.",
			}
			if tunnel != nil {
				result.SuggestedFix = append(result.SuggestedFix,
					fmt.Sprintf("Run the path MTU probe on %s and apply the MTU it recommends.",
						tunnel.InterfaceName))
			}
			return result, nil
		}
		result.Confidence = ConfidenceLow
		result.Verdict = VerdictMtuProblem
		result.Summary = fmt.Sprintf("Connections through %s establish and then stall, even though MSS "+
			"clamping is on.", rec.RouteRuleTitle)
		result.SuggestedFix = []string{
			"Run the path MTU probe on the tunnel and set the MTU it recommends on both ends.",
			"Check that the destination itself is not the one stalling.",
		}
		return result, nil
	}

	// §8.8 — nothing above matched.
	result.Verdict = VerdictHealthy
	result.Summary = fmt.Sprintf("%s is installed, forwarding traffic, and its destination answers.",
		rec.RouteRuleTitle)
	if len(shadows) > 0 {
		result.Confidence = ConfidenceLow
		result.Summary += " Another rule on this host claims overlapping traffic; it is not stopping " +
			"this one today, but the two are competing."
	}
	return result, nil
}

// shadowEvidence looks for a foreign rule claiming the same traffic.
func (d *Diagnostics) shadowEvidence(ctx context.Context, spec rules.RouteSpec, result *AnalyzeResult) []rules.ForeignRule {
	view, err := d.backend.Foreign(ctx)
	if err != nil || !view.Readable {
		detail := "the host's other netfilter rules could not be read, so a rule shadowing this one " +
			"would not have been seen"
		if err != nil {
			detail += ": " + err.Error()
		}
		result.add("foreign_rules", detail, nil)
		return nil
	}
	shadows := view.ShadowsOf(spec)
	if len(shadows) == 0 {
		result.add("foreign_rules", fmt.Sprintf("%d redirecting rule(s) belong to other software on "+
			"this host, none of them claiming this rule's traffic", len(view.Rules)),
			map[string]any{"managers": view.Managers, "total": len(view.Rules)})
		return nil
	}
	quoted := make([]string, 0, len(shadows))
	for _, rule := range shadows {
		quoted = append(quoted, rule.Describe())
	}
	result.add("foreign_rules", fmt.Sprintf("%d rule(s) the panel does not own claim this traffic: %s",
		len(shadows), strings.Join(quoted, "; ")),
		map[string]any{"rules": shadows, "managers": view.Managers})
	return shadows
}

// flowEvidence reads connection tracking for this rule.
func (d *Diagnostics) flowEvidence(ctx context.Context, spec rules.RouteSpec, result *AnalyzeResult) ([]Flow, bool) {
	if ok, detail := d.conntrack.Available(); !ok {
		result.add("connections", "connection tracking could not be read, so whether traffic is "+
			"arriving was not determined: "+detail, nil)
		return nil, false
	}
	all, err := d.conntrack.Flows(ctx)
	if err != nil {
		result.add("connections", "connection tracking could not be read: "+err.Error(), nil)
		return nil, false
	}
	mine := FlowsFor(all, spec)
	result.add("connections", fmt.Sprintf("connection tracking holds %d flow(s) whose original "+
		"destination is this rule's, which is the kernel's own record that the destination NAT "+
		"matched and translated them", len(mine)),
		map[string]any{"flows": len(mine), "reader": d.conntrack.Name()})
	return mine, true
}

// counterEvidence reads the forward-hook counters for this rule.
func (d *Diagnostics) counterEvidence(ctx context.Context, routeRuleID int64, result *AnalyzeResult) (rules.Counter, bool) {
	raw, err := d.backend.Counters(ctx)
	if err != nil {
		result.add("counters", "the rule's counters could not be read: "+err.Error(), nil)
		return rules.Counter{}, false
	}
	counter := raw[routeRuleID]
	result.add("counters", fmt.Sprintf("since the ruleset was last built this rule has forwarded "+
		"%d packet(s) and %d byte(s) towards its destination, and %d packet(s) and %d byte(s) back",
		counter.TxPackets, counter.TxBytes, counter.RxPackets, counter.RxBytes), counter)
	return counter, true
}

// tunnelEvidence reports the state of the tunnel a rule depends on (§10).
func (d *Diagnostics) tunnelEvidence(ctx context.Context, rec Record, result *AnalyzeResult) *TunnelHealth {
	if rec.TunnelID == nil || d.tunnels == nil {
		return nil
	}
	health, ok := d.tunnels.TunnelHealth(ctx, *rec.TunnelID)
	if !ok {
		result.add("tunnel", fmt.Sprintf("this rule names tunnel %d, which the panel no longer has",
			*rec.TunnelID), map[string]any{"tunnel_id": *rec.TunnelID})
		return nil
	}
	state := "up"
	if !health.Healthy() {
		state = "not up"
	}
	result.add("tunnel", fmt.Sprintf("the destination is reached through %s, which is %s",
		health.InterfaceName, state), health)
	return &health
}

// probeEvidence tests the destination.
func (d *Diagnostics) probeEvidence(ctx context.Context, spec rules.RouteSpec,
	params AnalyzeParams, result *AnalyzeResult) *ReachabilityResult {

	if !params.probeWanted() || len(spec.Destinations) == 0 {
		return nil
	}
	destination := spec.Destinations[0]
	probe := d.prober.Probe(ctx, ReachabilityParams{
		Address: destination.Address, Port: destination.Ports.Port,
		Protocol: string(spec.Protocol), TimeoutSeconds: params.TimeoutSeconds,
	})
	result.add("destination_probe", probe.Detail, probe)
	return &probe
}

// stalledFlows returns the connections that established and then stopped
// getting answers, which is the shape of a path MTU problem: the handshake is
// small enough to get through and the first full-size segment is not.
func stalledFlows(flows []Flow) []Flow {
	var out []Flow
	for _, flow := range flows {
		if !strings.EqualFold(flow.State, "ESTABLISHED") {
			continue
		}
		if flow.TxPackets < stallPackets {
			continue
		}
		if flow.RxPackets*4 <= flow.TxPackets {
			out = append(out, flow)
		}
	}
	return out
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// bindDescription names what a rule listens on, the way an error message does.
func bindDescription(spec rules.RouteSpec) string {
	if spec.BindsAnyAddress() {
		return fmt.Sprintf("every local address on port %s", spec.BindPorts.String())
	}
	return spec.BindAddress + ":" + spec.BindPorts.String()
}
