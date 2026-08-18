package diag

import (
	"context"
	"fmt"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// icmpEchoOverhead is the IPv4 header plus the ICMP echo header, which sit in
// front of the payload. A path MTU is an IP packet size, so the search converts
// between the two rather than reporting a payload size as an MTU.
const icmpEchoOverhead = 20 + 8

// icmpEchoOverheadIPv6 is the same for IPv6.
const icmpEchoOverheadIPv6 = 40 + 8

// MtuParams is a path MTU probe (§13.2).
type MtuParams struct {
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
	// Source and Target override what is probed. By default the probe runs over
	// the underlay — from the tunnel's local endpoint to its remote one —
	// because that is the path whose MTU decides the tunnel's.
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
	// ProbeTunnel probes through the tunnel itself instead of over the underlay.
	ProbeTunnel bool `json:"probe_tunnel,omitempty"`
	// TimeoutSecs bounds each probe.
	TimeoutSecs float64 `json:"timeout_seconds,omitempty"`
}

// MtuStep is one packet size the search tried.
type MtuStep struct {
	PacketSize int    `json:"packet_size"`
	Fits       bool   `json:"fits"`
	Detail     string `json:"detail,omitempty"`
	// ReportedMtu is the next-hop MTU a router volunteered, when it did.
	ReportedMtu int `json:"reported_mtu,omitempty"`
}

// MtuResult is what the probe discovered.
type MtuResult struct {
	Source string `json:"source"`
	Target string `json:"target"`
	// Path is what was probed: the underlay or the tunnel.
	Path string `json:"path"`

	// DiscoveredPathMtu is the largest IP packet that got through.
	DiscoveredPathMtu int `json:"discovered_path_mtu"`
	// ReportedPathMtu is what a router said directly, when one did. It is more
	// authoritative than the search, which can only bracket the answer.
	ReportedPathMtu int `json:"reported_path_mtu,omitempty"`

	// RecommendedTunnelMtu is the path MTU less this tunnel's encapsulation
	// overhead, which is the number the operator would put on the tunnel.
	RecommendedTunnelMtu int `json:"recommended_tunnel_mtu"`
	CurrentTunnelMtu     int `json:"current_tunnel_mtu"`
	// Overhead is the encapsulation cost the recommendation subtracted.
	Overhead int `json:"overhead"`
	// Matches reports whether the tunnel is already at the recommended MTU.
	Matches bool `json:"matches"`

	Steps   []MtuStep `json:"steps"`
	Detail  string    `json:"detail"`
	Applied bool      `json:"applied"`
}

// MtuProbe binary searches for the largest packet that gets through with the
// Don't-Fragment bit set (§13.2).
//
// The Don't-Fragment bit is what makes the search meaningful: without it an
// oversized packet is quietly split and every size succeeds, which measures
// nothing.
func (s *Service) MtuProbe(ctx context.Context, tunnelID int64, params MtuParams) (Run, MtuResult, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return Run{}, MtuResult{}, err
	}

	// Steps is initialised rather than left nil. A probe that finds no
	// constriction has nothing to report, which is the ordinary outcome, and a
	// nil slice would reach the browser as null for the panel to call .map on.
	result := MtuResult{Path: "underlay", Steps: []MtuStep{}}
	result.Source, result.Target = rec.LocalEndpoint, rec.RemoteEndpoint
	if params.ProbeTunnel {
		result.Path = "tunnel"
		result.Source, result.Target = probeEndpoints(rec)
	}
	if params.Source != "" {
		result.Source = params.Source
	}
	if params.Target != "" {
		result.Target = params.Target
	}
	if result.Source == "" || result.Target == "" {
		return Run{}, result, fmt.Errorf("there is no address pair to probe between")
	}

	low := params.Min
	if low <= 0 {
		low = int(s.settingInt("diagnostics.mtu_probe_min", 1200))
	}
	high := params.Max
	if high <= 0 {
		high = int(s.settingInt("diagnostics.mtu_probe_max", 1500))
	}
	if low > high {
		low, high = high, low
	}
	timeout := seconds(params.TimeoutSecs)
	if timeout <= 0 {
		timeout = time.Second
	}

	runID, err := s.begin(ctx, &tunnelID, model.DiagnosticTypeMtuProbe, params)
	if err != nil {
		return Run{}, result, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	release := s.track(runID, cancel)
	defer cancel()

	overhead := icmpEchoOverhead
	if isIPv6Address(result.Source) {
		overhead = icmpEchoOverheadIPv6
	}

	// Establish that the floor works at all. If the smallest size fails there is
	// nothing to search: the path is broken, not narrow.
	floor, floorStep := s.probeSize(runCtx, rec.TunnelID, result.Source, result.Target, low, overhead, timeout)
	result.Steps = append(result.Steps, floorStep)
	if floorStep.ReportedMtu > 0 {
		result.ReportedPathMtu = floorStep.ReportedMtu
	}
	if !floor {
		result.Detail = fmt.Sprintf("even a %d-byte packet did not get through, so this is not an MTU "+
			"problem: the path is not carrying traffic at all.", low)
		s.finishMtu(ctx, runID, result, false)
		release()
		return s.finalRun(ctx, runID, Run{
			TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypeMtuProbe,
			Type: TypeName(model.DiagnosticTypeMtuProbe), Params: params, Result: result,
		}), result, nil
	}
	result.DiscoveredPathMtu = low

	// Binary search between the known-good floor and the untested ceiling.
	lower, upper := low, high
	for lower < upper && runCtx.Err() == nil {
		middle := (lower + upper + 1) / 2
		fits, step := s.probeSize(runCtx, rec.TunnelID, result.Source, result.Target, middle, overhead, timeout)
		result.Steps = append(result.Steps, step)
		if step.ReportedMtu > 0 && (result.ReportedPathMtu == 0 || step.ReportedMtu < result.ReportedPathMtu) {
			result.ReportedPathMtu = step.ReportedMtu
		}
		if fits {
			lower = middle
			result.DiscoveredPathMtu = middle
		} else {
			upper = middle - 1
		}
	}

	// A router that volunteered the next-hop MTU knows better than the search.
	if result.ReportedPathMtu > 0 && result.ReportedPathMtu < result.DiscoveredPathMtu {
		result.DiscoveredPathMtu = result.ReportedPathMtu
	}

	result.Overhead = validate.OverheadOf(inputFor(rec))
	result.CurrentTunnelMtu = int(rec.Mtu)
	if result.Path == "underlay" {
		result.RecommendedTunnelMtu = result.DiscoveredPathMtu - result.Overhead
	} else {
		// Probing through the tunnel measures what the tunnel already carries,
		// so the discovered figure is the tunnel MTU rather than the underlay's.
		result.RecommendedTunnelMtu = result.DiscoveredPathMtu
	}
	if result.RecommendedTunnelMtu < 0 {
		result.RecommendedTunnelMtu = 0
	}
	result.Matches = result.RecommendedTunnelMtu == result.CurrentTunnelMtu

	switch {
	case result.Matches:
		result.Detail = fmt.Sprintf("the path carries %d-byte packets, and this tunnel's MTU of %d is "+
			"already the right value for it.", result.DiscoveredPathMtu, result.CurrentTunnelMtu)
	case result.Path == "underlay":
		result.Detail = fmt.Sprintf("the path carries %d-byte packets. Less %d bytes of encapsulation "+
			"that makes a tunnel MTU of %d; this tunnel is set to %d.",
			result.DiscoveredPathMtu, result.Overhead, result.RecommendedTunnelMtu, result.CurrentTunnelMtu)
	default:
		result.Detail = fmt.Sprintf("the tunnel carries %d-byte packets; its MTU is set to %d.",
			result.DiscoveredPathMtu, result.CurrentTunnelMtu)
	}

	s.finishMtu(ctx, runID, result, true)
	release()
	run := s.finalRun(ctx, runID, Run{
		TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypeMtuProbe,
		Type: TypeName(model.DiagnosticTypeMtuProbe), Params: params, Result: result, IsSuccess: true,
	})
	return run, result, nil
}

func (s *Service) finishMtu(ctx context.Context, runID int64, result MtuResult, success bool) {
	if err := s.finish(ctx, runID, result, success); err != nil {
		s.log.Error("recording an MTU probe result failed", "run_id", runID, "error", err)
	}
}

// probeSize sends one packet of the given total IP size and reports whether it
// got through.
func (s *Service) probeSize(ctx context.Context, tunnelID int64, source, target string,
	packetSize, overhead int, timeout time.Duration) (bool, MtuStep) {

	step := MtuStep{PacketSize: packetSize}
	payload := packetSize - overhead
	if payload < monitor.MinPacketSize {
		step.Detail = fmt.Sprintf("a %d-byte packet is too small to carry a probe", packetSize)
		return false, step
	}

	// Two attempts, because a single lost packet is not evidence that the size
	// is too large: the whole point of the exercise is telling one from the
	// other.
	for attempt := 0; attempt < 2; attempt++ {
		result, err := monitor.Ping(ctx, s.dialer, monitor.PingRequest{
			TunnelID: tunnelID, Source: source, Target: target,
			Count: 1, Interval: timeout, Timeout: timeout,
			PacketSize: payload, DontFragment: true,
		}, nil)
		if err != nil {
			step.Detail = err.Error()
			return false, step
		}
		if result.ReportedMtu > 0 {
			step.ReportedMtu = result.ReportedMtu
			step.Detail = fmt.Sprintf("a router on the path reported an MTU of %d", result.ReportedMtu)
			return false, step
		}
		if result.TooLargeToSend {
			// The packet never left the host, so there was never a reply to
			// wait for and a second attempt would fail identically. This is the
			// most definite evidence the search can get.
			step.Detail = fmt.Sprintf(
				"the kernel refused to send %d bytes without fragmenting, so it is larger than the outgoing interface allows",
				packetSize)
			return false, step
		}
		if result.Received > 0 {
			step.Fits = true
			step.Detail = "the packet got through"
			return true, step
		}
		if ctx.Err() != nil {
			break
		}
	}
	step.Detail = "no reply, so the packet did not get through"
	return false, step
}

func isIPv6Address(address string) bool {
	for i := 0; i < len(address); i++ {
		if address[i] == ':' {
			return true
		}
	}
	return false
}

// inputFor reduces a stored tunnel to what the encapsulation overhead
// computation needs, so the recommendation uses exactly the same arithmetic the
// create form shows (§7.6).
func inputFor(rec tunnel.Record) validate.TunnelInput {
	return validate.TunnelInput{
		TunnelTypeID:      rec.TunnelTypeID,
		IKey:              rec.IKey,
		OKey:              rec.OKey,
		HasInputChecksum:  rec.HasInputChecksum,
		HasOutputChecksum: rec.HasOutputChecksum,
		HasInputSequence:  rec.HasInputSequence,
		HasOutputSequence: rec.HasOutputSequence,
	}
}
