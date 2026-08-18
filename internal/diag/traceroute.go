package diag

import (
	"context"
	"fmt"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
)

// TracerouteParams is a path trace.
type TracerouteParams struct {
	MaxHops     int     `json:"max_hops,omitempty"`
	Probes      int     `json:"probes,omitempty"`
	TimeoutSecs float64 `json:"timeout_seconds,omitempty"`
	Source      string  `json:"source,omitempty"`
	Target      string  `json:"target,omitempty"`
	// ProbeTunnel traces through the tunnel instead of over the underlay.
	ProbeTunnel bool `json:"probe_tunnel,omitempty"`
}

// Hop is one step along the path.
type Hop struct {
	Ttl int `json:"ttl"`
	// Addresses are the routers that answered at this distance. More than one
	// means the path is load balanced.
	Addresses []string  `json:"addresses,omitempty"`
	RttsMs    []float64 `json:"rtts_ms,omitempty"`
	// Reached marks the hop where the target itself answered.
	Reached bool   `json:"reached"`
	Timeout bool   `json:"timeout"`
	Detail  string `json:"detail,omitempty"`
}

// TracerouteResult is the whole path.
type TracerouteResult struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Path   string `json:"path"`
	Hops   []Hop  `json:"hops"`
	// Reached reports whether the target answered at all.
	Reached bool   `json:"reached"`
	Detail  string `json:"detail"`
}

// Traceroute walks the path by sending echo requests with an increasing hop
// limit and reading the time-exceeded errors they provoke.
//
// It is implemented on the same ICMP socket as everything else rather than by
// running the traceroute program: the reply matching, the identifier and the
// error attribution are already here, and shelling out would add a dependency
// on another program's output format for no gain.
func (s *Service) Traceroute(ctx context.Context, tunnelID int64, params TracerouteParams) (Run, TracerouteResult, error) {
	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return Run{}, TracerouteResult{}, err
	}

	result := TracerouteResult{Path: "underlay", Hops: []Hop{}}
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
		return Run{}, result, fmt.Errorf("there is no address pair to trace between")
	}

	maxHops := params.MaxHops
	if maxHops <= 0 || maxHops > 64 {
		maxHops = 30
	}
	probes := params.Probes
	if probes <= 0 || probes > 5 {
		probes = 3
	}
	timeout := seconds(params.TimeoutSecs)
	if timeout <= 0 {
		timeout = time.Second
	}

	runID, err := s.begin(ctx, &tunnelID, model.DiagnosticTypeTraceroute, params)
	if err != nil {
		return Run{}, result, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	release := s.track(runID, cancel)
	defer cancel()

	for ttl := 1; ttl <= maxHops && runCtx.Err() == nil; ttl++ {
		hop := Hop{Ttl: ttl}
		seen := map[string]bool{}

		for probe := 0; probe < probes && runCtx.Err() == nil; probe++ {
			reply, err := monitor.Ping(runCtx, s.dialer, monitor.PingRequest{
				TunnelID: rec.TunnelID, Source: result.Source, Target: result.Target,
				Count: 1, Interval: timeout, Timeout: timeout, Ttl: ttl,
			}, nil)
			if err != nil {
				hop.Detail = err.Error()
				break
			}
			for _, address := range reply.Answered {
				if !seen[address] {
					seen[address] = true
					hop.Addresses = append(hop.Addresses, address)
				}
			}
			if reply.Received > 0 {
				// The target itself answered, so this is the last hop.
				hop.Reached = true
				if reply.RttAvgMs != nil {
					hop.RttsMs = append(hop.RttsMs, *reply.RttAvgMs)
				}
			}
			for _, packet := range reply.Packets {
				if packet.RttMs != nil && !packet.Success {
					hop.RttsMs = append(hop.RttsMs, *packet.RttMs)
				}
			}
		}

		if len(hop.Addresses) == 0 && !hop.Reached {
			hop.Timeout = true
			if hop.Detail == "" {
				hop.Detail = "no answer, which is common: many routers do not reply to a hop limit expiring"
			}
		}
		result.Hops = append(result.Hops, hop)
		if hop.Reached {
			result.Reached = true
			break
		}
	}

	if result.Reached {
		result.Detail = fmt.Sprintf("%s answered after %d hops.", result.Target, len(result.Hops))
	} else {
		result.Detail = fmt.Sprintf("%s did not answer within %d hops. That does not prove the path is "+
			"broken: routers commonly drop the probes a trace depends on, and GRE can work while ICMP "+
			"is filtered.", result.Target, maxHops)
	}

	if err := s.finish(ctx, runID, result, true); err != nil {
		s.log.Error("recording a traceroute result failed", "run_id", runID, "error", err)
	}
	release()
	run := s.finalRun(ctx, runID, Run{
		TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypeTraceroute,
		Type: TypeName(model.DiagnosticTypeTraceroute), Params: params, Result: result, IsSuccess: true,
	})
	return run, result, nil
}
