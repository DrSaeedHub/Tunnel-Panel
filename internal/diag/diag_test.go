package diag

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// ---------------------------------------------------------------- fake network

// fakeConn is an in-memory ICMP socket whose answers a test decides.
type fakeConn struct {
	mu       sync.Mutex
	closed   bool
	inbound  chan []byte
	deadline time.Time

	dontFragment bool
	ttl          int

	// answer decides what comes back for each request. Returning nil is
	// silence, which is how a lost packet is simulated.
	answer func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte

	// refuseLargerThan, when set, makes the socket behave the way the kernel
	// does when a packet exceeds the outgoing interface's MTU and the
	// Don't-Fragment bit forbids splitting it: the send fails outright and the
	// packet never leaves the host.
	refuseLargerThan int
}

func (c *fakeConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	closed, df, ttl, answer := c.closed, c.dontFragment, c.ttl, c.answer
	refuse := c.refuseLargerThan
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if df && refuse > 0 && len(b)+20 > refuse {
		return 0, &net.OpError{Op: "write", Net: "ip4:icmp", Err: syscall.EMSGSIZE}
	}

	if answer != nil {
		if message, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b); err == nil {
			if echo, ok := message.Body.(*icmp.Echo); ok {
				if reply := answer(c, echo.ID, echo.Seq, echo.Data, len(b), df, ttl); reply != nil {
					c.deliver(reply)
				}
			}
		}
	}
	return len(b), nil
}

// deliver queues an inbound packet under the lock that Close also takes: the
// queue is buffered and the send is non-blocking, so nothing waits here, and
// sending outside the lock would race the close of the channel being sent on.
func (c *fakeConn) deliver(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	select {
	case c.inbound <- data:
	default:
	}
}

func (c *fakeConn) ReadFrom(b []byte) (int, net.Addr, error) {
	c.mu.Lock()
	closed, deadline := c.closed, c.deadline
	c.mu.Unlock()
	if closed {
		return 0, nil, net.ErrClosed
	}

	var timer <-chan time.Time
	if !deadline.IsZero() {
		wait := time.Until(deadline)
		if wait <= 0 {
			return 0, nil, timeoutError{}
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timer = t.C
	}
	select {
	case packet, ok := <-c.inbound:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(b, packet)
		return n, &net.IPAddr{IP: net.ParseIP("172.17.1.2")}, nil
	case <-timer:
		return 0, nil, timeoutError{}
	}
}

func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	return nil
}

func (c *fakeConn) SetDontFragment(on bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dontFragment = on
	return nil
}

func (c *fakeConn) SetTTL(ttl int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
	return nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.inbound)
	}
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string { return "i/o timeout" }
func (timeoutError) Timeout() bool { return true }

type fakeDialer struct {
	answer func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte
	// refuseLargerThan is passed to every socket this dialer creates.
	refuseLargerThan int
}

func (d *fakeDialer) Listen(source string) (monitor.PacketConn, error) {
	return &fakeConn{
		inbound: make(chan []byte, 64), answer: d.answer,
		refuseLargerThan: d.refuseLargerThan,
	}, nil
}

// alwaysAnswer echoes every request back, which is a reachable peer.
func alwaysAnswer(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
	return echoReply(id, sequence, payload)
}

func echoReply(id, sequence int, payload []byte) []byte {
	message := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: id, Seq: sequence, Data: append([]byte(nil), payload...)},
	}
	raw, _ := message.Marshal(nil)
	return raw
}

// fragmentationNeeded is what a router sends when a packet is too big and the
// Don't-Fragment bit forbids splitting it.
func fragmentationNeeded(id, sequence, mtu int) []byte {
	quoted := make([]byte, 20+8)
	quoted[0] = 0x45
	quoted[20] = 8
	quoted[24] = byte(id >> 8)
	quoted[25] = byte(id)
	quoted[26] = byte(sequence >> 8)
	quoted[27] = byte(sequence)

	raw := make([]byte, 8+len(quoted))
	raw[0] = 3 // destination unreachable
	raw[1] = 4 // fragmentation needed
	raw[6] = byte(mtu >> 8)
	raw[7] = byte(mtu)
	copy(raw[8:], quoted)
	return raw
}

// ---------------------------------------------------------------- harness

type harness struct {
	service  *Service
	repo     *tunnel.Repo
	links    *link.Fake
	runner   *exec.FakeRunner
	settings *settings.Store
	tunnelID int64
}

func newHarness(t *testing.T, answer func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte) *harness {
	t.Helper()
	return newHarnessWith(t, &fakeDialer{answer: answer})
}

// newHarnessWith builds the harness around a dialer a test has configured, for
// the cases where what matters is how the socket behaves rather than what
// answers come back.
func newHarnessWith(t *testing.T, dialer *fakeDialer) *harness {
	t.Helper()
	ctx := context.Background()

	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}
	store, err := settings.New(ctx, database)
	if err != nil {
		t.Fatal(err)
	}

	repo := tunnel.NewRepo(database)
	peer := "172.17.1.2"
	id, err := repo.Insert(ctx, validate.TunnelInput{
		TunnelTypeID:      model.TunnelTypeGRE,
		TunnelSideID:      model.TunnelSideA,
		PersistenceTypeID: model.PersistenceTypeRuntime,
		InterfaceName:     "gre-a-1",
		LocalEndpoint:     "203.0.113.10",
		RemoteEndpoint:    "198.51.100.20",
		Ttl:               255, Tos: "inherit", Mtu: 1472,
		IKey: int64Ptr(2749365187), OKey: int64Ptr(2749365187),
		Addresses: []validate.AddressInput{
			{Address: "172.17.1.1", PrefixLength: 30, PeerAddress: peer, IsPrimary: true},
		},
		IsEnabled: true,
	}, true, true)
	if err != nil {
		t.Fatalf("seeding a tunnel failed: %v", err)
	}

	links := link.NewFakeWithHost()
	links.AddLink(link.Link{
		Name: "gre-a-1", Index: 5, MTU: 1472, Kind: link.KindGRE,
		OperState: "UNKNOWN", IsUp: true, IsLowerUp: true,
		Flags: []string{"POINTOPOINT", "NOARP", "UP", "LOWER_UP"},
		Tunnel: &link.TunnelAttrs{
			Local: "203.0.113.10", Remote: "198.51.100.20", Ttl: 255,
		},
		Addresses:  []link.Address{{Address: "172.17.1.1", PrefixLength: 30, Family: link.FamilyIPv4, Scope: "global"}},
		Statistics: &link.Statistics{RxBytes: 1000, TxBytes: 2000},
	})

	runner := exec.NewFakeRunner()
	service := New(Deps{
		DB: database, Repo: repo, Links: links,
		Dialer: dialer, Runner: runner, Settings: store,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return &harness{service: service, repo: repo, links: links, runner: runner, settings: store, tunnelID: id}
}

func int64Ptr(v int64) *int64 { return &v }

// ---------------------------------------------------------------- ping

func TestPingStreamsEveryPacketAndRecordsTheRun(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	var (
		mu       sync.Mutex
		packets  []monitor.PingPacket
		startRun Run
	)
	run, err := h.service.Ping(ctx, h.tunnelID, PingParams{Count: 4, IntervalSecs: 0.01, TimeoutSecs: 0.5},
		func(r Run) { startRun = r },
		func(p monitor.PingPacket) {
			mu.Lock()
			packets = append(packets, p)
			mu.Unlock()
		})
	if err != nil {
		t.Fatalf("the ping failed: %v", err)
	}

	if startRun.DiagnosticRunID == 0 {
		t.Fatal("the run identifier must be reported as soon as it exists, so a client can cancel it")
	}
	if !startRun.Running {
		t.Fatal("the run must be reported as running when it starts")
	}
	if len(packets) != 4 {
		t.Fatalf("streamed %d packets, want 4", len(packets))
	}
	for i, packet := range packets {
		if !packet.Success || packet.RttMs == nil {
			t.Fatalf("packet %d = %+v, want a successful measurement", i, packet)
		}
	}

	if run.Type != "ping" || !run.IsSuccess {
		t.Fatalf("run = %+v", run)
	}
	if run.FinishedDate == "" {
		t.Fatal("a completed run must record when it finished")
	}
	if run.Running {
		t.Fatal("a completed run must not still be reported as running")
	}

	// The result is stored as real JSON, not JSON inside a string.
	result, ok := run.Result.(map[string]any)
	if !ok {
		t.Fatalf("the stored result is %T", run.Result)
	}
	summary, ok := result["summary"].(map[string]any)
	if !ok || summary["received"].(float64) != 4 {
		t.Fatalf("the stored summary is wrong: %+v", result["summary"])
	}
}

func TestPingCountIsBoundedBySettings(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	// The default count has to move with the maximum: the settings store refuses
	// a maximum below the default, and rightly so.
	if _, err := h.settings.Update(ctx, map[string]any{
		"diagnostics.manual_ping_count":     int64(3),
		"diagnostics.manual_ping_max_count": int64(3),
	}, nil); err != nil {
		t.Fatal(err)
	}

	var count int
	run, err := h.service.Ping(ctx, h.tunnelID, PingParams{Count: 100, IntervalSecs: 0.01, TimeoutSecs: 0.2},
		nil, func(monitor.PingPacket) { count++ })
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("sent %d packets, want the configured maximum of 3", count)
	}
	if !run.IsSuccess {
		t.Fatal("a bounded run is still a successful one")
	}
}

// Deleting a run cancels it, and what it measured before being stopped is kept
// rather than thrown away (§13.1).
func TestDeletingARunCancelsIt(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	started := make(chan int64, 1)
	done := make(chan error, 1)
	go func() {
		_, err := h.service.Ping(ctx, h.tunnelID,
			PingParams{Count: 10000, IntervalSecs: 0.01, TimeoutSecs: 0.5},
			func(r Run) { started <- r.DiagnosticRunID },
			nil)
		done <- err
	}()

	runID := <-started
	// Give it a moment to send a few packets before stopping it.
	time.Sleep(50 * time.Millisecond)

	cancelled, err := h.service.DeleteRun(ctx, runID)
	if err != nil {
		t.Fatalf("deleting the run failed: %v", err)
	}
	if !cancelled {
		t.Fatal("deleting an in-flight run must cancel it")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a cancelled ping reported an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled ping did not stop")
	}

	// The run is gone from the listing, because deleting is what cancelling is.
	if _, err := h.service.RunByID(ctx, runID); err == nil {
		t.Fatal("a deleted run must no longer be listed")
	}
}

// ---------------------------------------------------------------- MTU probe

// The search finds the largest packet that gets through, and the Don't-Fragment
// bit is what makes that measurement mean anything (§13.2).
func TestMtuProbeFindsTheLargestPacketThatFits(t *testing.T) {
	const pathMtu = 1400

	h := newHarness(t, func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
		if !df {
			// Without the bit set a router would fragment and every size would
			// appear to fit, which measures nothing.
			return echoReply(id, sequence, payload)
		}
		// size is the ICMP message; the IP header is another 20 bytes.
		if size+20 > pathMtu {
			return nil
		}
		return echoReply(id, sequence, payload)
	})

	run, result, err := h.service.MtuProbe(context.Background(), h.tunnelID,
		MtuParams{Min: 1200, Max: 1500, TimeoutSecs: 0.2})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}

	if result.DiscoveredPathMtu != pathMtu {
		t.Fatalf("discovered path MTU = %d, want %d", result.DiscoveredPathMtu, pathMtu)
	}
	// The tunnel MTU is the path less this tunnel's encapsulation overhead,
	// which for IPv4 GRE with a key is 28 bytes.
	if result.Overhead != 28 {
		t.Fatalf("overhead = %d, want 28", result.Overhead)
	}
	if result.RecommendedTunnelMtu != pathMtu-28 {
		t.Fatalf("recommended tunnel MTU = %d, want %d", result.RecommendedTunnelMtu, pathMtu-28)
	}
	if result.CurrentTunnelMtu != 1472 || result.Matches {
		t.Fatalf("the current MTU should not match: %+v", result)
	}
	if len(result.Steps) < 2 {
		t.Fatalf("the search took %d steps", len(result.Steps))
	}
	if result.Detail == "" {
		t.Fatal("the result must explain itself")
	}
	if run.Type != "mtu-probe" || !run.IsSuccess {
		t.Fatalf("run = %+v", run)
	}
}

// When the kernel refuses to send the probe at all, the search must say so.
//
// A packet larger than the outgoing interface's MTU with the Don't-Fragment
// bit set never leaves the host: the send fails with EMSGSIZE. Reporting that
// as "no reply" is wrong in a way that matters, because it is the difference
// between the strongest evidence the search can get and the weakest — and it
// makes the search wait out a timeout, twice, for a reply that was never
// provoked.
func TestMtuProbeReportsAPacketTheKernelRefusedToSend(t *testing.T) {
	const pathMtu = 1400

	h := newHarnessWith(t, &fakeDialer{answer: alwaysAnswer, refuseLargerThan: pathMtu})

	_, result, err := h.service.MtuProbe(context.Background(), h.tunnelID,
		MtuParams{Min: 1200, Max: 1500, TimeoutSecs: 0.2})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if result.DiscoveredPathMtu != pathMtu {
		t.Fatalf("discovered path MTU = %d, want %d", result.DiscoveredPathMtu, pathMtu)
	}

	var refused *MtuStep
	for i := range result.Steps {
		if !result.Steps[i].Fits {
			refused = &result.Steps[i]
			break
		}
	}
	if refused == nil {
		t.Fatalf("no step was rejected, so the Don't-Fragment bit was not honoured: %+v", result.Steps)
	}
	if !strings.Contains(refused.Detail, "refused to send") {
		t.Fatalf("a locally refused packet was reported as %q, which reads as a lost packet", refused.Detail)
	}
}

// A router that reports the next-hop MTU knows better than the search.
func TestMtuProbeUsesAReportedMtu(t *testing.T) {
	h := newHarness(t, func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
		if df && size+20 > 1300 {
			return fragmentationNeeded(id, sequence, 1300)
		}
		return echoReply(id, sequence, payload)
	})

	_, result, err := h.service.MtuProbe(context.Background(), h.tunnelID,
		MtuParams{Min: 1200, Max: 1500, TimeoutSecs: 0.2})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if result.ReportedPathMtu != 1300 {
		t.Fatalf("reported path MTU = %d, want 1300", result.ReportedPathMtu)
	}
	if result.DiscoveredPathMtu != 1300 {
		t.Fatalf("discovered = %d; a reported MTU is more authoritative than the search",
			result.DiscoveredPathMtu)
	}
}

// A path that carries nothing at all is not an MTU problem, and saying so is
// more useful than a number.
func TestMtuProbeSaysWhenThePathCarriesNothing(t *testing.T) {
	h := newHarness(t, func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
		return nil
	})

	_, result, err := h.service.MtuProbe(context.Background(), h.tunnelID,
		MtuParams{Min: 1200, Max: 1500, TimeoutSecs: 0.05})
	if err != nil {
		t.Fatalf("the probe failed: %v", err)
	}
	if result.DiscoveredPathMtu != 0 {
		t.Fatalf("discovered %d on a dead path", result.DiscoveredPathMtu)
	}
	if !contains(result.Detail, "not carrying traffic at all") {
		t.Fatalf("detail = %q", result.Detail)
	}
}

// ---------------------------------------------------------------- analyze

func TestAnalyzeReportsAMissingInterface(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()
	if err := h.links.Delete(ctx, "gre-a-1"); err != nil {
		t.Fatal(err)
	}

	_, result, err := h.service.Analyze(ctx, h.tunnelID, AnalyzeParams{SampleSeconds: 0.05})
	if err != nil {
		t.Fatalf("the analysis failed: %v", err)
	}
	if result.Verdict != VerdictInterfaceMissing {
		t.Fatalf("verdict = %q, want %q", result.Verdict, VerdictInterfaceMissing)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("every verdict must carry the evidence it rests on")
	}
	if len(result.SuggestedFix) == 0 {
		t.Fatal("every verdict must suggest what to do about it")
	}
}

func TestAnalyzeReportsADownInterface(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()
	if err := h.links.SetDown(ctx, "gre-a-1"); err != nil {
		t.Fatal(err)
	}

	_, result, err := h.service.Analyze(ctx, h.tunnelID, AnalyzeParams{SampleSeconds: 0.05})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictInterfaceDown {
		t.Fatalf("verdict = %q, want %q", result.Verdict, VerdictInterfaceDown)
	}
}

func TestAnalyzeReportsHealthyWhenEverythingAnswers(t *testing.T) {
	h := newHarness(t, alwaysAnswer)

	_, result, err := h.service.Analyze(context.Background(), h.tunnelID, AnalyzeParams{SampleSeconds: 0.05})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictHealthy {
		t.Fatalf("verdict = %q with summary %q", result.Verdict, result.Summary)
	}
	// Even a healthy verdict carries what it observed, never a bare word.
	if len(result.Evidence) < 3 {
		t.Fatalf("evidence = %+v", result.Evidence)
	}
	if result.Summary == "" {
		t.Fatal("a verdict must be a sentence, not a status word")
	}
}

// A local rule that blocks protocol 47 explains everything downstream of it, so
// it is reported rather than the symptom it causes (§13.4).
func TestAnalyzeReportsALocalFirewallBlock(t *testing.T) {
	h := newHarness(t, func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
		return nil // nothing answers
	})
	h.service.nftBin = "/usr/sbin/nft"
	h.runner.Responses["/usr/sbin/nft list ruleset"] = exec.Result{
		Stdout: "table inet filter {\n  chain input {\n    ip protocol 47 drop\n  }\n}\n",
	}

	_, result, err := h.service.Analyze(context.Background(), h.tunnelID, AnalyzeParams{SampleSeconds: 0.05})
	if err != nil {
		t.Fatal(err)
	}
	if result.Verdict != VerdictLocalFirewall {
		t.Fatalf("verdict = %q, want %q (summary %q)", result.Verdict, VerdictLocalFirewall, result.Summary)
	}

	var firewall *Evidence
	for i := range result.Evidence {
		if result.Evidence[i].Name == "firewall" {
			firewall = &result.Evidence[i]
		}
	}
	if firewall == nil {
		t.Fatal("the verdict must quote the firewall evidence it rests on")
	}
	data := firewall.Data.(map[string]any)
	if rules := data["rules"].([]string); len(rules) == 0 {
		t.Fatal("the evidence must quote the offending rule")
	}
}

func TestAnalyzeWithoutAFirewallToolSaysSo(t *testing.T) {
	h := newHarness(t, alwaysAnswer)

	_, result, err := h.service.Analyze(context.Background(), h.tunnelID, AnalyzeParams{SampleSeconds: 0.05})
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range result.Evidence {
		if evidence.Name == "firewall" {
			if !contains(evidence.Detail, "not inspected") {
				t.Fatalf("with no tool available the evidence should say so: %q", evidence.Detail)
			}
			return
		}
	}
	t.Fatal("the firewall check must be reported even when it could not run")
}

func TestGreRuleDetection(t *testing.T) {
	ruleset := `table inet filter {
  chain forward {
    ip protocol 47 accept
    tcp dport 22 accept
  }
}`
	rules := greRules(ruleset)
	if len(rules) != 1 {
		t.Fatalf("matched %d rules, want 1: %v", len(rules), rules)
	}
	if blocksGre(rules) {
		t.Fatal("an accept rule does not block")
	}
	if !blocksGre([]string{"ip protocol 47 drop"}) {
		t.Fatal("a drop rule blocks")
	}
	if !blocksGre([]string{"-A INPUT -p 47 -j REJECT"}) {
		t.Fatal("a reject rule blocks")
	}
}

// ---------------------------------------------------------------- traceroute

func TestTracerouteWalksThePath(t *testing.T) {
	// The target answers only once the hop limit reaches three; before that a
	// router reports the limit expiring.
	h := newHarness(t, func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
		if ttl >= 3 {
			return echoReply(id, sequence, payload)
		}
		return timeExceeded(id, sequence)
	})

	_, result, err := h.service.Traceroute(context.Background(), h.tunnelID,
		TracerouteParams{MaxHops: 8, Probes: 1, TimeoutSecs: 0.2})
	if err != nil {
		t.Fatalf("the trace failed: %v", err)
	}
	if !result.Reached {
		t.Fatalf("the trace did not reach the target: %+v", result.Hops)
	}
	if len(result.Hops) != 3 {
		t.Fatalf("the trace took %d hops, want 3", len(result.Hops))
	}
	if !result.Hops[2].Reached {
		t.Fatalf("the last hop should be the target: %+v", result.Hops[2])
	}
}

func timeExceeded(id, sequence int) []byte {
	quoted := make([]byte, 20+8)
	quoted[0] = 0x45
	quoted[20] = 8
	quoted[24] = byte(id >> 8)
	quoted[25] = byte(id)
	quoted[26] = byte(sequence >> 8)
	quoted[27] = byte(sequence)

	message := icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Body: &icmp.TimeExceeded{Data: quoted},
	}
	raw, _ := message.Marshal(nil)
	return raw
}

// ---------------------------------------------------------------- counters

func TestCountersReportTotalsAndMovement(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	go func() {
		time.Sleep(30 * time.Millisecond)
		h.links.AddLink(link.Link{
			Name: "gre-a-1", Index: 5, MTU: 1472, Kind: link.KindGRE,
			OperState: "UNKNOWN", IsUp: true, IsLowerUp: true,
			Statistics: &link.Statistics{RxBytes: 3000, TxBytes: 5000},
		})
	}()

	snapshot, err := h.service.Counters(ctx, h.tunnelID, 0.1)
	if err != nil {
		t.Fatalf("reading counters failed: %v", err)
	}
	if snapshot.Counters.RxBytes != 3000 {
		t.Fatalf("counters = %+v", snapshot.Counters)
	}
	if snapshot.Deltas.RxBytes != 2000 || snapshot.Deltas.TxBytes != 3000 {
		t.Fatalf("deltas = %+v", snapshot.Deltas)
	}
	if snapshot.RxBytesPerSecond <= 0 {
		t.Fatalf("rate = %v", snapshot.RxBytesPerSecond)
	}
}

// ---------------------------------------------------------------- listing

func TestRunsArePaginatedAndFilterable(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := h.service.Ping(ctx, h.tunnelID,
			PingParams{Count: 1, IntervalSecs: 0.01, TimeoutSecs: 0.1}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := h.service.Analyze(ctx, h.tunnelID, AnalyzeParams{SampleSeconds: 0.05}); err != nil {
		t.Fatal(err)
	}

	runs, total, err := h.service.Runs(ctx, RunFilter{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if len(runs) != 2 {
		t.Fatalf("returned %d runs, want the requested 2", len(runs))
	}

	pingType := int64(model.DiagnosticTypePing)
	runs, total, err = h.service.Runs(ctx, RunFilter{TypeID: &pingType})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Fatalf("filtered total = %d, want 3", total)
	}
	for _, run := range runs {
		if run.Type != "ping" {
			t.Fatalf("the filter returned a %s run", run.Type)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
