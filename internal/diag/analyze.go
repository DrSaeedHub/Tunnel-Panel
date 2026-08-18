package diag

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

// Verdicts (§13.4). They are stable strings: the frontend renders a different
// explanation and a different suggested fix for each.
const (
	VerdictInterfaceMissing    = "INTERFACE_MISSING"
	VerdictInterfaceDown       = "INTERFACE_DOWN"
	VerdictUnderlayUnreachable = "UNDERLAY_UNREACHABLE"
	VerdictNoReturnTraffic     = "NO_RETURN_TRAFFIC"
	VerdictKeyOrAddressing     = "KEY_OR_ADDRESSING_MISMATCH"
	VerdictMtuProblem          = "MTU_PROBLEM"
	VerdictLocalFirewall       = "LOCAL_FIREWALL_BLOCK"
	VerdictHealthy             = "HEALTHY"
)

// Confidence qualifies a verdict.
const (
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

// Evidence is one thing the analysis observed. Every verdict carries the
// evidence it rests on: a bare status word is what the script this panel
// replaces offered, and it told an operator nothing (§13.4).
type Evidence struct {
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Data   any    `json:"data,omitempty"`
}

// AnalyzeParams tunes the analysis.
type AnalyzeParams struct {
	// SampleSeconds is how long the counters are watched for movement.
	SampleSeconds float64 `json:"sample_seconds,omitempty"`
	// Capture allows a brief tcpdump when the setting permits it.
	Capture bool `json:"capture,omitempty"`
}

// AnalyzeResult is a specific verdict with its evidence and a suggested fix.
type AnalyzeResult struct {
	Verdict    string `json:"verdict"`
	Confidence string `json:"confidence"`
	Summary    string `json:"summary"`
	// SuggestedFix is what to do about it, in the order worth trying.
	SuggestedFix []string   `json:"suggested_fix,omitempty"`
	Evidence     []Evidence `json:"evidence"`
	CheckedAt    string     `json:"checked_at"`
}

func (r *AnalyzeResult) add(name, detail string, data any) {
	r.Evidence = append(r.Evidence, Evidence{Name: name, Detail: detail, Data: data})
}

// Analyze runs the decision tree and returns a specific verdict (§13.4).
func (s *Service) Analyze(ctx context.Context, tunnelID int64, params AnalyzeParams) (Run, AnalyzeResult, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return Run{}, AnalyzeResult{}, err
	}

	runID, err := s.begin(ctx, &tunnelID, model.DiagnosticTypeAnalyze, params)
	if err != nil {
		return Run{}, AnalyzeResult{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	release := s.track(runID, cancel)
	defer cancel()

	result := s.analyze(runCtx, rec, params)
	result.CheckedAt = model.NowUTC()

	if err := s.finish(ctx, runID, result, true); err != nil {
		s.log.Error("recording an analysis result failed", "run_id", runID, "error", err)
	}
	release()
	run := s.finalRun(ctx, runID, Run{
		TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypeAnalyze,
		Type: TypeName(model.DiagnosticTypeAnalyze), Params: params, Result: result, IsSuccess: true,
	})
	return run, result, nil
}

// analyze is the decision tree itself, in the order of §13.4.
func (s *Service) analyze(ctx context.Context, rec tunnel.Record, params AnalyzeParams) AnalyzeResult {
	result := AnalyzeResult{Confidence: ConfidenceHigh, Evidence: []Evidence{}}
	name := rec.InterfaceName

	// 1. The interface has to exist.
	observed, err := s.links.Get(ctx, name)
	if err != nil {
		result.Verdict = VerdictInterfaceMissing
		result.Summary = fmt.Sprintf("There is no interface called %s on this host.", name)
		result.add("interface", "the interface was not found", map[string]any{"interface_name": name})
		result.SuggestedFix = []string{
			"Reapply this tunnel, which rebuilds it from the stored configuration.",
			"Check whether something outside the panel removed it.",
		}
		return result
	}
	result.add("interface", fmt.Sprintf("%s exists as a %s interface with an MTU of %d",
		name, observed.Kind, observed.MTU),
		map[string]any{"kind": observed.Kind, "mtu": observed.MTU, "oper_state": observed.OperState})

	// 2. It has to be up. Health comes from the flags: a working GRE tunnel
	// reports operational state UNKNOWN, so that field is reported and never
	// used to decide (§2).
	if !observed.IsUp || !observed.IsLowerUp {
		result.Verdict = VerdictInterfaceDown
		result.Summary = fmt.Sprintf("%s exists but is not up: its flags are %s.",
			name, strings.Join(observed.Flags, ","))
		result.add("flags", "the interface is missing UP or LOWER_UP",
			map[string]any{"flags": observed.Flags, "oper_state": observed.OperState})
		result.SuggestedFix = []string{
			"Bring the tunnel up from the panel.",
			"Reapply it if bringing it up does not work.",
		}
		return result
	}
	result.add("flags", fmt.Sprintf("the flags are %s and the operational state is %s, which is normal "+
		"for a point-to-point tunnel", strings.Join(observed.Flags, ","), observed.OperState), nil)

	source, target := probeEndpoints(rec)

	// 3. The underlay has to carry packets, though ICMP being filtered while
	// GRE works is common enough that this is never a confident verdict.
	underlayReachable := false
	if rec.RemoteEndpoint != "" && rec.LocalEndpoint != "" {
		reply, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
			TunnelID: rec.TunnelID, Source: rec.LocalEndpoint, Target: rec.RemoteEndpoint,
			Count: 3, Interval: 200 * time.Millisecond, Timeout: time.Second,
		}, nil)
		switch {
		case err != nil:
			result.add("underlay", "the underlay could not be probed: "+err.Error(), nil)
		case reply.Received > 0:
			underlayReachable = true
			result.add("underlay", fmt.Sprintf("%d of %d probes to the remote endpoint %s were answered",
				reply.Received, reply.Sent, rec.RemoteEndpoint), reply)
		default:
			result.add("underlay", fmt.Sprintf("none of the %d probes to the remote endpoint %s were answered",
				reply.Sent, rec.RemoteEndpoint), reply)
		}
	}

	// 4 and 5. Which way traffic is moving is what separates "nothing is coming
	// back" from "something is coming back but it is not usable".
	before, after, elapsed := s.watchCounters(ctx, name, params.SampleSeconds)
	txMoved := after.TxBytes > before.TxBytes
	rxMoved := after.RxBytes > before.RxBytes
	result.add("counters", fmt.Sprintf(
		"over %.1f s the interface sent %d bytes and received %d bytes",
		elapsed, after.TxBytes-before.TxBytes, saturating(after.RxBytes, before.RxBytes)),
		map[string]any{
			"tx_bytes_delta": after.TxBytes - before.TxBytes,
			"rx_bytes_delta": saturating(after.RxBytes, before.RxBytes),
			"seconds":        elapsed,
		})

	// The probe through the tunnel is what says whether it actually works.
	tunnelReachable := false
	var tunnelLoss float64 = 100
	if source != "" && target != "" {
		reply, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
			TunnelID: rec.TunnelID, Source: source, Target: target,
			Count: 5, Interval: 200 * time.Millisecond, Timeout: time.Second,
		}, nil)
		if err != nil {
			result.add("tunnel_probe", "the tunnel could not be probed: "+err.Error(), nil)
		} else {
			tunnelReachable = reply.Received > 0
			tunnelLoss = reply.LossPercent
			result.add("tunnel_probe", fmt.Sprintf("%d of %d probes through the tunnel were answered",
				reply.Received, reply.Sent), reply)
		}
	} else {
		result.add("tunnel_probe", "this tunnel has no address pair, so it cannot be probed end to end", nil)
	}

	firewall := s.inspectFirewall(ctx)
	if firewall != nil {
		result.Evidence = append(result.Evidence, *firewall)
	}
	if capture := s.capture(ctx, params, observed, rec); capture != nil {
		result.Evidence = append(result.Evidence, *capture)
	}

	// The tunnel works.
	if tunnelReachable && tunnelLoss == 0 {
		result.Verdict = VerdictHealthy
		result.Summary = fmt.Sprintf("%s is up and carrying traffic: every probe through it was answered.", name)
		return result
	}

	// 7. A local rule that blocks protocol 47 explains everything above it, so
	// it is checked before the traffic-shape verdicts.
	if firewall != nil && firewall.Data != nil {
		if blocked, ok := firewall.Data.(map[string]any)["blocks_gre"].(bool); ok && blocked {
			result.Verdict = VerdictLocalFirewall
			result.Summary = "A firewall rule on this host affects protocol 47, which is what GRE uses."
			result.SuggestedFix = []string{
				"Review the rule the evidence quotes and allow protocol 47 to and from the remote endpoint.",
			}
			return result
		}
	}

	switch {
	// 4. Sending but nothing coming back.
	case txMoved && !rxMoved:
		result.Verdict = VerdictNoReturnTraffic
		result.Summary = fmt.Sprintf("%s is sending but nothing is coming back.", name)
		result.SuggestedFix = []string{
			"Protocol 47 may be filtered by a provider or a firewall between the two servers.",
			"The other end may not be configured yet; check that its tunnel exists and is up.",
			fmt.Sprintf("The remote endpoint may be wrong: this tunnel points at %s.", rec.RemoteEndpoint),
		}
		return result

	// 5. Traffic arriving but the probes still failing means the packets are
	// getting here and being rejected or misdirected.
	case rxMoved && !tunnelReachable:
		result.Verdict = VerdictKeyOrAddressing
		result.Summary = fmt.Sprintf(
			"%s is receiving traffic, but probes through it are not being answered.", name)
		result.SuggestedFix = []string{
			"Check that the GRE keys match exactly on both servers; a mismatch makes the kernel drop the packets.",
			fmt.Sprintf("Check that the peer address %s is inside this tunnel's own subnet.", target),
			"Check that the MTU, the checksum flags and the sequence flags match on both ends.",
		}
		return result

	// 6. Small packets get through and large ones do not.
	case tunnelReachable:
		if mtu := s.probeMtuShape(ctx, rec, source, target); mtu != nil {
			result.Evidence = append(result.Evidence, *mtu)
			if broken, ok := mtu.Data.(map[string]any)["large_packets_fail"].(bool); ok && broken {
				result.Verdict = VerdictMtuProblem
				result.Summary = fmt.Sprintf(
					"%s answers small packets but not large ones, which is an MTU problem.", name)
				result.SuggestedFix = []string{
					"Run the path MTU probe and apply the tunnel MTU it recommends.",
					"Set the same MTU on both ends: they have to agree.",
				}
				return result
			}
		}
		result.Verdict = VerdictHealthy
		result.Summary = fmt.Sprintf("%s is up and answering, with %.0f%% of probes lost.", name, tunnelLoss)
		if tunnelLoss > 0 {
			result.Confidence = ConfidenceLow
			result.Summary = fmt.Sprintf("%s is answering but losing %.0f%% of probes.", name, tunnelLoss)
			result.SuggestedFix = []string{
				"Watch the monitoring history: intermittent loss is usually the path rather than the tunnel.",
			}
		}
		return result
	}

	// Nothing is moving in either direction.
	if !underlayReachable {
		result.Verdict = VerdictUnderlayUnreachable
		result.Confidence = ConfidenceLow
		result.Summary = fmt.Sprintf(
			"The remote endpoint %s did not answer, so the two servers may not be able to reach each other at all.",
			rec.RemoteEndpoint)
		result.SuggestedFix = []string{
			"Check that the remote endpoint address is right.",
			"ICMP is often filtered while GRE still works, so confirm this before acting on it.",
			"Check that the other end is up and reachable by some other means.",
		}
		return result
	}

	result.Verdict = VerdictNoReturnTraffic
	result.Summary = fmt.Sprintf(
		"The remote endpoint answers, but %s is not carrying traffic in either direction.", name)
	result.SuggestedFix = []string{
		"Protocol 47 may be filtered even though ICMP is not.",
		"Check that the other end's tunnel exists, is up, and points back at this server.",
	}
	return result
}

// watchCounters reads the interface counters twice, so which way traffic is
// moving can be told from whether they moved at all.
func (s *Service) watchCounters(ctx context.Context, name string, sampleSeconds float64) (before, after link.Statistics, elapsed float64) {
	if sampleSeconds <= 0 {
		sampleSeconds = 2
	}
	if sampleSeconds > 30 {
		sampleSeconds = 30
	}

	before, _ = s.links.Statistics(ctx, name)
	started := time.Now()

	timer := time.NewTimer(time.Duration(sampleSeconds * float64(time.Second)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}

	after, _ = s.links.Statistics(ctx, name)
	return before, after, time.Since(started).Seconds()
}

// probeMtuShape checks whether large packets fail while small ones succeed,
// which is the shape of an MTU problem rather than a reachability one.
func (s *Service) probeMtuShape(ctx context.Context, rec tunnel.Record, source, target string) *Evidence {
	if source == "" || target == "" {
		return nil
	}
	large := int(rec.Mtu) - icmpEchoOverhead
	if large < monitor.MinPacketSize+64 {
		return nil
	}

	small, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
		TunnelID: rec.TunnelID, Source: source, Target: target,
		Count: 2, Interval: 100 * time.Millisecond, Timeout: time.Second, PacketSize: monitor.MinPacketSize,
	}, nil)
	if err != nil {
		return nil
	}
	big, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
		TunnelID: rec.TunnelID, Source: source, Target: target,
		Count: 2, Interval: 100 * time.Millisecond, Timeout: time.Second, PacketSize: large,
	}, nil)
	if err != nil {
		return nil
	}

	broken := small.Received > 0 && big.Received == 0
	return &Evidence{
		Name: "packet_size",
		Detail: fmt.Sprintf("small packets: %d of %d answered; packets filling the %d-byte MTU: %d of %d answered",
			small.Received, small.Sent, rec.Mtu, big.Received, big.Sent),
		Data: map[string]any{
			"large_packets_fail": broken,
			"small_received":     small.Received,
			"large_received":     big.Received,
			"large_payload":      large,
		},
	}
}

// inspectFirewall looks for a local rule affecting protocol 47 (§13.4).
func (s *Service) inspectFirewall(ctx context.Context) *Evidence {
	type attempt struct {
		bin  string
		argv []string
	}
	attempts := []attempt{}
	if s.nftBin != "" {
		attempts = append(attempts, attempt{s.nftBin, []string{s.nftBin, "list", "ruleset"}})
	}
	if s.iptablesBin != "" {
		attempts = append(attempts, attempt{s.iptablesBin, []string{s.iptablesBin, "-S"}})
	}
	if len(attempts) == 0 || s.runner == nil {
		return &Evidence{
			Name:   "firewall",
			Detail: "neither nft nor iptables is available here, so local firewall rules were not inspected",
		}
	}

	for _, a := range attempts {
		result, err := s.runner.Run(ctx, a.argv)
		if err != nil {
			continue
		}
		matches := greRules(result.Stdout)
		return &Evidence{
			Name: "firewall",
			Detail: fmt.Sprintf("%s reported %d rule(s) mentioning protocol 47",
				a.bin, len(matches)),
			Data: map[string]any{
				"tool":       a.bin,
				"blocks_gre": blocksGre(matches),
				"rules":      matches,
			},
		}
	}
	return &Evidence{Name: "firewall", Detail: "the firewall rules could not be read"}
}

// greRules picks out the rules that mention protocol 47 by any of its names.
func greRules(ruleset string) []string {
	var out []string
	for _, line := range strings.Split(ruleset, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "gre") || strings.Contains(lower, "proto 47") ||
			strings.Contains(lower, "protocol 47") || strings.Contains(lower, "-p 47") ||
			strings.Contains(lower, "ip protocol 47") {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

// blocksGre reports whether any matching rule drops or rejects.
func blocksGre(rules []string) bool {
	for _, rule := range rules {
		lower := strings.ToLower(rule)
		if strings.Contains(lower, "drop") || strings.Contains(lower, "reject") ||
			strings.Contains(lower, "deny") {
			return true
		}
	}
	return false
}

// capture takes a brief packet capture to prove whether GRE packets are
// actually leaving or arriving, which is strong evidence for the two
// traffic-shape verdicts (§13.4).
func (s *Service) capture(ctx context.Context, params AnalyzeParams, observed link.Link, rec tunnel.Record) *Evidence {
	allowed := s.settings == nil || s.settings.Bool("diagnostics.allow_tcpdump")
	if !allowed {
		return &Evidence{Name: "capture", Detail: "packet capture is switched off in the settings"}
	}
	if !params.Capture {
		return nil
	}
	if s.tcpdumpBin == "" || s.runner == nil {
		return &Evidence{Name: "capture", Detail: "tcpdump is not installed here, so nothing was captured"}
	}

	device := observed.Name
	if rec.BindDevice != nil && *rec.BindDevice != "" {
		device = *rec.BindDevice
	} else if underlay := s.underlayDevice(ctx, rec.LocalEndpoint); underlay != "" {
		device = underlay
	}

	captureCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	// A bounded capture: a handful of packets or a few seconds, whichever comes
	// first. It is evidence, not monitoring.
	result, err := s.runner.Run(captureCtx, []string{
		s.tcpdumpBin, "-ni", device, "-c", "5", "proto", "gre",
	})
	detail := fmt.Sprintf("captured on %s", device)
	if err != nil {
		detail = fmt.Sprintf("the capture on %s ended without seeing five GRE packets", device)
	}
	return &Evidence{
		Name:   "capture",
		Detail: detail,
		Data:   map[string]any{"device": device, "output": strings.TrimSpace(result.Stderr + "\n" + result.Stdout)},
	}
}

// underlayDevice finds the interface holding the local endpoint, which is where
// the encapsulated packets actually leave from.
func (s *Service) underlayDevice(ctx context.Context, localEndpoint string) string {
	if localEndpoint == "" {
		return ""
	}
	links, err := s.links.List(ctx)
	if err != nil {
		return ""
	}
	for _, l := range links {
		for _, addr := range l.Addresses {
			if addr.Address == localEndpoint {
				return l.Name
			}
		}
	}
	return ""
}

func saturating(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
