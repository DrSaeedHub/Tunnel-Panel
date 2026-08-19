package route

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// fakeProber answers the destination probe with whatever a test wants.
type fakeProber struct{ result ReachabilityResult }

func (f *fakeProber) Probe(ctx context.Context, params ReachabilityParams) ReachabilityResult {
	out := f.result
	out.Address, out.Port = params.Address, params.Port
	if out.Protocol == "" {
		out.Protocol = params.Protocol
	}
	if out.Detail == "" {
		out.Detail = "probed"
	}
	return out
}

// diagHarness is a whole diagnostics service over a fake kernel.
type diagHarness struct {
	ctx        context.Context
	repo       *Repo
	diag       *Diagnostics
	backend    *rules.Fake
	conntrack  *FakeConntrack
	prober     *fakeProber
	forwarding *Forwarding
	dir        string
	tunnels    *fakeTunnels
}

// fakeTunnels answers the tunnel health question.
type fakeTunnels struct {
	health TunnelHealth
	known  bool
}

func (f *fakeTunnels) TunnelHealth(ctx context.Context, tunnelID int64) (TunnelHealth, bool) {
	return f.health, f.known
}

func newDiagHarness(t *testing.T, mutate func(*validate.RouteInput)) *diagHarness {
	t.Helper()
	ctx, _, repo := openRepo(t)

	in := validate.RouteInput{
		RouteRuleTitle:  "Web relay",
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		NatModeID: model.NatModeMasquerade,
		IsEnabled: true,
	}
	if mutate != nil {
		mutate(&in)
	}
	if _, err := repo.Insert(ctx, in); err != nil {
		t.Fatalf("storing the rule failed: %v", err)
	}

	dir := t.TempDir()
	procDir := filepath.Join(dir, "proc", "sys", "net", "ipv4")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "ip_forward"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	backend := rules.NewFake()
	records, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := backend.Render(DesiredOf(records))
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := backend.Apply(ctx, payload); err != nil {
		t.Fatalf("applying to the fake kernel failed: %v", err)
	}

	conntrack := NewFakeConntrack()
	prober := &fakeProber{result: ReachabilityResult{Reachable: true, Conclusive: true,
		Detail: "connected", LatencyMs: 1.2}}
	forwarding := &Forwarding{Root: dir, SysctlPath: filepath.Join(dir, "sysctl.conf")}
	tunnels := &fakeTunnels{}

	diag := NewDiagnostics(DiagnosticsDeps{
		Repo: repo, Backend: backend, Forwarding: forwarding,
		Conntrack: conntrack, Prober: prober, Tunnels: tunnels,
	})
	return &diagHarness{
		ctx: ctx, repo: repo, diag: diag, backend: backend, conntrack: conntrack,
		prober: prober, forwarding: forwarding, dir: dir, tunnels: tunnels,
	}
}

// established returns a healthy-looking flow through the rule.
func established(source string, tx, rx uint64) Flow {
	return Flow{
		Protocol: "tcp", SourceAddress: source, SourcePort: 51234,
		BindAddress: "203.0.113.10", BindPort: 2044,
		DestinationAddress: "198.51.100.20", DestinationPort: 2044,
		State:     "ESTABLISHED",
		TxPackets: tx, RxPackets: rx, TxBytes: tx * 100, RxBytes: rx * 100,
	}
}

func hits(id int64) map[int64]rules.Counter {
	return map[int64]rules.Counter{id: {
		RouteRuleID: id, TxPackets: 120, TxBytes: 90_000, RxPackets: 110, RxBytes: 800_000,
	}}
}

// TestAnalyzeDecisionTree walks §8 verdict by verdict. Each case arranges
// exactly the state that verdict describes and asserts the analysis reaches it
// and nothing above it.
func TestAnalyzeDecisionTree(t *testing.T) {
	t.Run("a disabled rule is not reported as a fault", func(t *testing.T) {
		h := newDiagHarness(t, func(in *validate.RouteInput) { in.IsEnabled = false })
		result := h.analyze(t)
		if result.Verdict != VerdictDisabled {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictDisabled, result.Summary)
		}
	})

	t.Run("rules absent from the kernel", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		if err := h.backend.Flush(h.ctx); err != nil {
			t.Fatal(err)
		}
		result := h.analyze(t)
		if result.Verdict != VerdictRuleMissing {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictRuleMissing, result.Summary)
		}
		if len(result.SuggestedFix) == 0 {
			t.Error("a verdict was returned with nothing to do about it")
		}
	})

	t.Run("forwarding turned off", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		h.setForwarding(t, "0")
		result := h.analyze(t)
		if result.Verdict != VerdictForwardingDisabled {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictForwardingDisabled, result.Summary)
		}
	})

	t.Run("nothing has reached this server", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		result := h.analyze(t)
		if result.Verdict != VerdictNoInboundTraffic {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictNoInboundTraffic, result.Summary)
		}
		// It is not a confident verdict: nobody connecting looks the same as an
		// upstream firewall dropping the packets.
		if result.Confidence != ConfidenceLow {
			t.Errorf("confidence %s, want %s", result.Confidence, ConfidenceLow)
		}
	})

	t.Run("translated but not forwarded", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		// The destination NAT matched and created a flow; the counters in the
		// forward hook never moved.
		h.conntrack.List = []Flow{established("192.0.2.5", 4, 3)}
		result := h.analyze(t)
		if result.Verdict != VerdictForwardBlocked {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictForwardBlocked, result.Summary)
		}
	})

	t.Run("destination unreachable", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		h.conntrack.List = []Flow{established("192.0.2.5", 4, 3)}
		h.backend.SetCounters(hits(1))
		h.prober.result = ReachabilityResult{
			Conclusive: true, Detail: "198.51.100.20:2044 refused the connection",
		}
		result := h.analyze(t)
		if result.Verdict != VerdictDestinationUnreachable {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictDestinationUnreachable, result.Summary)
		}
	})

	t.Run("a tunnel the rule depends on is down", func(t *testing.T) {
		tunnelID := int64(3)
		h := newDiagHarness(t, func(in *validate.RouteInput) { in.TunnelID = &tunnelID })
		h.tunnels.known = true
		h.tunnels.health = TunnelHealth{
			TunnelID: 3, InterfaceName: "gre-a-1", IsEnabled: true, IsUp: false,
		}
		h.conntrack.List = []Flow{established("192.0.2.5", 4, 3)}
		h.backend.SetCounters(hits(1))

		result := h.analyze(t)
		if result.Verdict != VerdictTunnelDown {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictTunnelDown, result.Summary)
		}
		// The point of the verdict is that it names the tunnel rather than
		// blaming the forwarding rule.
		if !contains(result.Summary, "gre-a-1") {
			t.Errorf("the summary does not name the tunnel: %s", result.Summary)
		}
	})

	t.Run("a foreign rule shadows this one", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		h.backend.SetForeign(rules.ForeignView{Rules: []rules.ForeignRule{{
			Table: "ip nat", Chain: "DOCKER", Manager: "Docker",
			Protocol: "tcp", Address: "203.0.113.10", Port: 2044,
			Text: "ip daddr 203.0.113.10 tcp dport 2044 dnat to 172.17.0.2:80",
		}}})
		result := h.analyze(t)
		if result.Verdict != VerdictRuleShadowed {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictRuleShadowed, result.Summary)
		}
		if !contains(result.Summary, "Docker") {
			t.Errorf("the shadowing rule was not named: %s", result.Summary)
		}
	})

	t.Run("connections establish and then stall", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		// Established, sending, and almost nothing coming back: the handshake
		// fitted and the first full-size segment did not.
		h.conntrack.List = []Flow{established("192.0.2.5", 40, 4)}
		h.backend.SetCounters(hits(1))

		result := h.analyze(t)
		if result.Verdict != VerdictMtuProblem {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictMtuProblem, result.Summary)
		}
		if len(result.SuggestedFix) == 0 || !contains(result.SuggestedFix[0], "MSS") {
			t.Errorf("the fix does not recommend MSS clamping: %v", result.SuggestedFix)
		}
	})

	t.Run("healthy", func(t *testing.T) {
		h := newDiagHarness(t, nil)
		h.conntrack.List = []Flow{established("192.0.2.5", 40, 38)}
		h.backend.SetCounters(hits(1))

		result := h.analyze(t)
		if result.Verdict != VerdictHealthy {
			t.Fatalf("verdict %s, want %s: %s", result.Verdict, VerdictHealthy, result.Summary)
		}
	})
}

// TestAnalyzeCarriesItsEvidence: a verdict with no evidence is the opaque
// status word this whole subsystem exists to replace.
func TestAnalyzeCarriesItsEvidence(t *testing.T) {
	h := newDiagHarness(t, nil)
	h.conntrack.List = []Flow{established("192.0.2.5", 40, 38)}
	h.backend.SetCounters(hits(1))

	result := h.analyze(t)
	names := map[string]bool{}
	for _, evidence := range result.Evidence {
		names[evidence.Name] = true
		if evidence.Detail == "" {
			t.Errorf("the %q evidence says nothing", evidence.Name)
		}
	}
	for _, want := range []string{"ruleset", "ip_forwarding", "connections", "counters",
		"foreign_rules", "destination_probe"} {
		if !names[want] {
			t.Errorf("the analysis did not report %q as evidence", want)
		}
	}
}

// TestReachabilityTestRunsBeforeTheRuleExists is the pre-flight of §8: the
// probe takes an address and a port, so an operator gets the answer before
// committing rather than by creating the rule and watching.
func TestReachabilityTestRunsBeforeTheRuleExists(t *testing.T) {
	h := newDiagHarness(t, nil)

	result, err := h.diag.Test(h.ctx, 0, ReachabilityParams{
		Address: "198.51.100.99", Port: 8080, Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("the pre-flight failed: %v", err)
	}
	if result.Address != "198.51.100.99" || result.Port != 8080 {
		t.Errorf("the probe went to %s:%d", result.Address, result.Port)
	}

	// And with no address it falls back to the stored rule's destination, so
	// the same endpoint serves the on-demand check.
	result, err = h.diag.Test(h.ctx, 1, ReachabilityParams{})
	if err != nil {
		t.Fatalf("the on-demand test failed: %v", err)
	}
	if result.Address != "198.51.100.20" || result.Port != 2044 {
		t.Errorf("the probe went to %s:%d, want the rule's destination", result.Address, result.Port)
	}
}

// TestUdpSilenceIsNotReportedAsAnAnswer: UDP has no handshake, so a
// non-reply proves nothing, and the result says so rather than guessing.
func TestUdpSilenceIsNotReportedAsAnAnswer(t *testing.T) {
	// A port on a discard address that nothing will answer.
	result := NetProber{}.Probe(context.Background(), ReachabilityParams{
		Address: "127.0.0.1", Port: 9, Protocol: "udp", TimeoutSeconds: 0.2,
	})
	if result.Reachable {
		t.Error("an unanswered UDP probe was reported as reachable")
	}
	if result.Detail == "" {
		t.Error("the result explains nothing")
	}
	// Either the host refused the datagram — which is conclusive — or nothing
	// came back, which is not. Neither is ever reported as reachable.
	if !result.Conclusive && !contains(result.Detail, "proves nothing") {
		t.Errorf("an inconclusive probe does not say so: %s", result.Detail)
	}
}

// TestConnectionListSaysWhenTrackingCannotBeRead: an empty list from a host
// that refused the read must not be presented as "nobody is using it".
func TestConnectionListSaysWhenTrackingCannotBeRead(t *testing.T) {
	h := newDiagHarness(t, nil)
	h.conntrack.Ready = false
	h.conntrack.Note = "the conntrack module is not loaded"

	list, err := h.diag.Connections(h.ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if list.Available {
		t.Error("the list claims connection tracking was readable")
	}
	if list.Detail == "" {
		t.Error("the list does not say why it is empty")
	}
}

func TestConnectionListReportsOnlyThisRulesFlows(t *testing.T) {
	h := newDiagHarness(t, nil)
	h.conntrack.List = []Flow{
		established("192.0.2.5", 10, 10),
		established("192.0.2.6", 10, 10),
		{Protocol: "tcp", SourceAddress: "192.0.2.7", SourcePort: 4444,
			BindAddress: "203.0.113.10", BindPort: 22},
	}
	list, err := h.diag.Connections(h.ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 2 {
		t.Errorf("the rule was credited with %d connections, want its own 2", list.Total)
	}
	if list.BySource["192.0.2.5"] != 1 {
		t.Errorf("the per-source breakdown is wrong: %v", list.BySource)
	}
}

// A load-balanced rule raises a question a total cannot answer: is the traffic
// actually being spread, and is one of the destinations taking none of it. The
// answer comes from the reply tuple, which is where packets went rather than
// where the rule says they should go.
func TestConnectionsAreBrokenDownByWhereTheyActuallyWent(t *testing.T) {
	h := newDiagHarness(t, nil)

	toSecond := func(source string) Flow {
		flow := established(source, 5, 5)
		flow.DestinationAddress = "198.51.100.21"
		return flow
	}
	h.conntrack.List = []Flow{
		established("192.0.2.5", 10, 10),
		established("192.0.2.6", 10, 10),
		established("192.0.2.7", 10, 10),
		toSecond("192.0.2.8"),
	}

	// Truncated to one row on purpose: the breakdown is about every flow the
	// rule has, not about the page of them the list carries.
	list, err := h.diag.Connections(h.ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Connections) != 1 {
		t.Fatalf("the list returned %d rows, want the one it was limited to", len(list.Connections))
	}
	if len(list.ByDestination) != 2 {
		t.Fatalf("by destination = %+v, want both destinations", list.ByDestination)
	}

	// Busiest first, so the reading leads with where the traffic is.
	first, second := list.ByDestination[0], list.ByDestination[1]
	if first.Address != "198.51.100.20" || first.Connections != 3 {
		t.Errorf("the busiest destination is %+v, want 198.51.100.20 with 3", first)
	}
	if second.Address != "198.51.100.21" || second.Connections != 1 {
		t.Errorf("the quieter destination is %+v, want 198.51.100.21 with 1", second)
	}
	if first.RxBytes != 3000 || first.TxBytes != 3000 {
		t.Errorf("the bytes on the busiest destination are %d/%d, want 3000/3000",
			first.RxBytes, first.TxBytes)
	}
}

func TestCountersComeFromTheFilterHooksAndSaySoAccurately(t *testing.T) {
	h := newDiagHarness(t, nil)
	h.backend.SetCounters(hits(1))

	report, err := h.diag.Counters(h.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Hit {
		t.Error("a rule with counters reports no hits")
	}
	// Provenance is the point of this field, and it stopped being the whole
	// truth when locally-originated traffic started being counted: such traffic
	// is never forwarded, so its counters sit on the output and input hooks.
	// Naming only the forward hook would have been a small, quiet inaccuracy in
	// exactly the sentence an operator reads to decide whether to trust the
	// number.
	for _, want := range []string{"forward", "output", "input"} {
		if !contains(report.Source, want) {
			t.Errorf("the counters' provenance does not mention the %s hook: %s", want, report.Source)
		}
	}
	if contains(report.Source, "nat") {
		t.Errorf("the counters are attributed to a nat chain, which sees only "+
			"the first packet of a connection: %s", report.Source)
	}
	if report.Note == "" {
		t.Error("the two sets of figures are returned without the note that separates them")
	}
}

// ---------------------------------------------------------------- helpers

func (h *diagHarness) analyze(t *testing.T) AnalyzeResult {
	t.Helper()
	result, err := h.diag.Analyze(h.ctx, 1, AnalyzeParams{})
	if err != nil {
		t.Fatalf("Analyze returned an unexpected error: %v", err)
	}
	if result.Verdict == "" {
		t.Fatal("the analysis returned no verdict")
	}
	return result
}

func (h *diagHarness) setForwarding(t *testing.T, value string) {
	t.Helper()
	path := filepath.Join(h.dir, "proc", "sys", "net", "ipv4", "ip_forward")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
