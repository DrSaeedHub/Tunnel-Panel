//go:build integration

package route

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	osexec "os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/validate"
)

// The integration suite of §13: a client namespace, a relay, and a destination
// namespace, with the panel driving the relay's netfilter configuration for
// real.
//
// Nothing here touches the host's own network namespace. The three namespaces
// are created for the test, every netfilter command the panel runs is executed
// inside the relay namespace by wrapping its process runner, and everything is
// torn down in a cleanup that runs even when a test fails.
//
// The reason the suite exists is that unit tests can only prove the panel
// renders what it meant to. They cannot prove that a rendered ruleset moves a
// packet, that masquerade actually replaces the source address the destination
// observes, or that a counter's bytes correspond to bytes that really crossed
// the machine. Those are the claims this file makes, and it makes them by
// sending traffic and looking at what arrived.

const (
	// integrationEnv gates the suite. It installs and flushes real netfilter
	// rules and creates real namespaces, so it never runs by accident.
	integrationEnv = "GRE_PANEL_INTEGRATION"

	relayNS  = "grep-it-relay"
	clientNS = "grep-it-client"
	destNS   = "grep-it-dest"

	// The relay's two legs. Both are deliberately narrower than the hosts on
	// either side, which is what gives the MSS clamping test a path MTU lower
	// than either endpoint's — the case clamping exists for.
	relayToClient = "10.90.1.1"
	clientAddr    = "10.90.1.2"
	relayToDest   = "10.90.2.1"
	destAddr      = "10.90.2.2"

	labMTU  = 1280
	hostMTU = 1500

	ipBin  = "/sbin/ip"
	nftBin = "/usr/sbin/nft"
)

// ---------------------------------------------------------------- helpers

// The roles this test binary re-execs itself as, inside a namespace. Running
// the test binary again is how a listener is placed inside the destination
// namespace without the test process having to change its own.
const (
	roleEnv    = "GRE_PANEL_ITEST_ROLE"
	addrEnv    = "GRE_PANEL_ITEST_ADDR"
	payloadEnv = "GRE_PANEL_ITEST_PAYLOAD"
	timeoutEnv = "GRE_PANEL_ITEST_TIMEOUT"
	roleServer = "server"
	roleClient = "client"
)

// TestMain dispatches the helper roles before running any test.
func TestMain(m *testing.M) {
	switch os.Getenv(roleEnv) {
	case roleServer:
		os.Exit(runServer())
	case roleClient:
		os.Exit(runClient())
	}
	os.Exit(m.Run())
}

// runServer is the destination service.
//
// It reports the peer address it observed on every connection, which is the
// whole basis of the NAT-mode assertion: the address is read from the
// destination's own socket rather than inferred from the rule that put the
// packet there.
func runServer() int {
	listener, err := net.Listen("tcp", os.Getenv(addrEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		return 1
	}
	defer listener.Close()

	payload := atoiEnv(payloadEnv, 0)
	// The harness waits for this before starting a client, so a connection
	// refused is never a race.
	fmt.Println("READY")

	for {
		conn, err := listener.Accept()
		if err != nil {
			return 0
		}
		go func(c net.Conn) {
			defer c.Close()
			peer, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			_ = c.SetDeadline(time.Now().Add(60 * time.Second))

			reader := bufio.NewReader(c)
			if _, err := reader.ReadString('\n'); err != nil {
				return
			}
			if _, err := fmt.Fprintf(c, "PEER=%s\n", peer); err != nil {
				return
			}
			if payload > 0 {
				block := make([]byte, 4096)
				for i := range block {
					block[i] = 'x'
				}
				for sent := 0; sent < payload; {
					size := len(block)
					if remaining := payload - sent; remaining < size {
						size = remaining
					}
					n, err := c.Write(block[:size])
					if err != nil {
						return
					}
					sent += n
				}
			}
		}(conn)
	}
}

// runClient connects, reads the peer line and counts the payload that follows.
func runClient() int {
	timeout := time.Duration(atoiEnv(timeoutEnv, 10)) * time.Second
	conn, err := net.DialTimeout("tcp", os.Getenv(addrEnv), timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := fmt.Fprintln(conn, "GET"); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		return 1
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return 1
	}
	received, err := io.Copy(io.Discard, reader)
	if err != nil {
		// A stalled transfer ends here, which is the failure the MSS test
		// asserts. What was received before the stall is still reported.
		fmt.Printf("%s BYTES=%d STALLED=1\n", strings.TrimSpace(line), received)
		return 2
	}
	fmt.Printf("%s BYTES=%d STALLED=0\n", strings.TrimSpace(line), received)
	return 0
}

func atoiEnv(key string, fallback int) int {
	if value, err := strconv.Atoi(os.Getenv(key)); err == nil {
		return value
	}
	return fallback
}

// ---------------------------------------------------------------- the lab

type lab struct {
	t *testing.T
	// runner runs every panel command inside the relay namespace.
	runner exec.Runner
	// refuseApplies is how many ruleset submissions to fail, for the rollback
	// test.
	refuseApplies *atomic.Int32
	backend       *rules.Nftables
	service       *Service
	repo          *Repo
	acct          *Accounting
	dir           string
	ctx           context.Context
}

// requireIntegrationHost skips unless this is a root Linux host that has opted
// in and has the tools the lab needs.
func requireIntegrationHost(t *testing.T) {
	t.Helper()
	if os.Getenv(integrationEnv) != "1" {
		t.Skipf("set %s=1 to run the integration suite; it creates namespaces and "+
			"installs real netfilter rules", integrationEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("the integration suite needs root to create namespaces and configure netfilter")
	}
	for _, binary := range []string{ipBin, nftBin} {
		if _, err := os.Stat(binary); err != nil {
			t.Skipf("%s is not installed here", binary)
		}
	}
}

// nsRunner prefixes every command with `ip netns exec <namespace>`.
//
// This is what keeps the host out of it: the panel believes it is configuring
// the machine, and every nft invocation it makes lands in the relay namespace
// instead. The panel's own code is unchanged and unaware.
type nsRunner struct {
	namespace string
	inner     exec.Runner

	// failApplies is how many ruleset submissions still have to fail. It is a
	// count rather than a flag because the rollback is a submission too: a
	// test that wants a clean rollback fails exactly one, and the second one —
	// putting the previous ruleset back — has to be allowed to work.
	failApplies *atomic.Int32
}

func (r nsRunner) Run(ctx context.Context, argv []string) (exec.Result, error) {
	if r.failApplies != nil && isRulesetApply(argv) && r.failApplies.Add(-1) >= 0 {
		return exec.Result{
			ExitCode: 1,
			Stderr:   "Error: Could not process rule: Operation not supported",
			Argv:     argv,
		}, fmt.Errorf("nft exited 1")
	}
	prefixed := append([]string{ipBin, "netns", "exec", r.namespace}, argv...)
	res, err := r.inner.Run(ctx, prefixed)
	// The panel logs and reports the argv it asked for, so the wrapper is
	// invisible in any message a test prints.
	res.Argv = argv
	return res, err
}

// isRulesetApply recognises the one command that submits a ruleset.
func isRulesetApply(argv []string) bool {
	for i, arg := range argv {
		if arg == "-f" && i+1 < len(argv) {
			return true
		}
	}
	return false
}

// newLab builds the three namespaces, wires them together, and returns a route
// service whose netfilter changes land in the relay namespace.
func newLab(t *testing.T) *lab {
	t.Helper()
	requireIntegrationHost(t)

	// Anything left by an interrupted run goes first, so a previous failure
	// cannot make this one fail for the wrong reason.
	teardownNamespaces()
	t.Cleanup(teardownNamespaces)

	for _, ns := range []string{relayNS, clientNS, destNS} {
		mustRun(t, ipBin, "netns", "add", ns)
		mustRun(t, ipBin, "netns", "exec", ns, ipBin, "link", "set", "lo", "up")
	}

	// The relay's legs, one to each side.
	mustRun(t, ipBin, "link", "add", "vrc", "type", "veth", "peer", "name", "vcl")
	mustRun(t, ipBin, "link", "set", "vrc", "netns", relayNS)
	mustRun(t, ipBin, "link", "set", "vcl", "netns", clientNS)
	mustRun(t, ipBin, "link", "add", "vrd", "type", "veth", "peer", "name", "vds")
	mustRun(t, ipBin, "link", "set", "vrd", "netns", relayNS)
	mustRun(t, ipBin, "link", "set", "vds", "netns", destNS)

	// Both of the relay's legs are narrower than the hosts on either side.
	// That is the situation MSS clamping exists for: neither endpoint can see
	// the constraint from its own interface, so both advertise a segment size
	// the path cannot carry.
	configureLeg(t, relayNS, "vrc", relayToClient, labMTU)
	configureLeg(t, relayNS, "vrd", relayToDest, labMTU)
	configureLeg(t, clientNS, "vcl", clientAddr, hostMTU)
	configureLeg(t, destNS, "vds", destAddr, hostMTU)

	// Each end routes everything back through the relay. The destination's
	// default route is what makes NAT mode None testable at all: without a
	// return path through the relay, preserving the client address would send
	// the reply nowhere.
	mustRun(t, ipBin, "netns", "exec", clientNS, ipBin, "route", "add", "default", "via", relayToClient)
	mustRun(t, ipBin, "netns", "exec", destNS, ipBin, "route", "add", "default", "via", relayToDest)

	// The relay forwards. The panel writes its own sysctl file for this, but a
	// file cannot describe another namespace's kernel, so the real parameter is
	// set here and the panel's bookkeeping is pointed at a fixture below.
	mustRun(t, ipBin, "netns", "exec", relayNS, "/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1")

	dir := t.TempDir()
	procDir := filepath.Join(dir, "proc", "sys", "net", "ipv4")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "ip_forward"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatalf("opening the database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the database failed: %v", err)
	}

	refuse := &atomic.Int32{}
	runner := nsRunner{namespace: relayNS, inner: exec.NewRunner(), failApplies: refuse}
	rulesDir := filepath.Join(dir, "rules")
	backend := rules.NewNftables(nftBin, rulesDir, runner)
	store := persist.NewStore(filepath.Join(dir, "systemd"), filepath.Join(dir, "networkd"), "", runner)
	renderer := persist.NewRenderer(ipBin, "/sbin/modprobe", "/bin/ping")

	guard := safety.NewRouteGuard(8443, nil, rulesDir)
	guard.SysctlFile = filepath.Join(dir, "sysctl.conf")
	forwarding := &Forwarding{
		Root: dir, SysctlPath: guard.SysctlFile, Store: store, Renderer: renderer, Guard: guard,
	}

	repo := NewRepo(database)
	accounting := NewAccounting(AccountingDeps{
		Repo: NewCounterRepo(database), Routes: repo, Backend: backend,
		Conntrack: NewFakeConntrack(), Log: quietLogger(),
	})
	if err := accounting.Load(ctx); err != nil {
		t.Fatalf("loading the accounting failed: %v", err)
	}

	service := New(Deps{
		Repo: repo, Backend: backend, Runner: runner, Renderer: renderer, Store: store,
		Validator: validate.NewRouteValidator(link.NewFakeWithHost(), repo.ForValidation(), nil, nil),
		Guard:     guard, Forwarding: forwarding, Counters: accounting,
		Log: quietLogger(),
	})

	// Whatever a test leaves behind, the panel's own namespace goes.
	t.Cleanup(func() {
		_ = backend.Flush(context.Background())
	})

	return &lab{
		t: t, runner: runner, refuseApplies: refuse, backend: backend, service: service,
		repo: repo, acct: accounting, dir: dir, ctx: ctx,
	}
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func configureLeg(t *testing.T, ns, device, address string, mtu int) {
	t.Helper()
	mustRun(t, ipBin, "netns", "exec", ns, ipBin, "addr", "add", address+"/30", "dev", device)
	mustRun(t, ipBin, "netns", "exec", ns, ipBin, "link", "set", device, "mtu", strconv.Itoa(mtu))
	mustRun(t, ipBin, "netns", "exec", ns, ipBin, "link", "set", device, "up")
}

// teardownNamespaces removes the lab. Deleting a namespace takes its veth ends
// with it, so nothing is left on the host either way.
func teardownNamespaces() {
	for _, ns := range []string{relayNS, clientNS, destNS} {
		_ = osexec.Command(ipBin, "netns", "del", ns).Run()
	}
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := osexec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// nsExec runs a command inside a namespace and returns its combined output.
func nsExec(t *testing.T, ns string, args ...string) (string, error) {
	t.Helper()
	out, err := osexec.Command(ipBin, append([]string{"netns", "exec", ns}, args...)...).CombinedOutput()
	return string(out), err
}

// ---------------------------------------------------------------- traffic

// destination is the service running inside the destination namespace.
type destination struct {
	cmd  *osexec.Cmd
	port int
}

// startDestination puts a listener in the destination namespace and waits for
// it to be ready.
func (l *lab) startDestination(port, payload int) *destination {
	l.t.Helper()

	cmd := osexec.Command(ipBin, "netns", "exec", destNS, os.Args[0])
	cmd.Env = append(os.Environ(),
		roleEnv+"="+roleServer,
		addrEnv+"="+net.JoinHostPort("0.0.0.0", strconv.Itoa(port)),
		payloadEnv+"="+strconv.Itoa(payload),
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		l.t.Fatalf("starting the destination service failed: %v", err)
	}
	l.t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case line := <-ready:
		if line != "READY" {
			l.t.Fatalf("the destination service said %q instead of READY", line)
		}
	case <-time.After(10 * time.Second):
		l.t.Fatal("the destination service did not become ready")
	}

	return &destination{cmd: cmd, port: port}
}

// clientResult is what the client observed.
type clientResult struct {
	// Peer is the source address the destination saw, which is the NAT-mode
	// evidence.
	Peer    string
	Bytes   int
	Stalled bool
	Err     error
}

// connect runs a client inside the client namespace against the relay.
func (l *lab) connect(address string, port int, timeoutSeconds int) clientResult {
	l.t.Helper()

	cmd := osexec.Command(ipBin, "netns", "exec", clientNS, os.Args[0])
	cmd.Env = append(os.Environ(),
		roleEnv+"="+roleClient,
		addrEnv+"="+net.JoinHostPort(address, strconv.Itoa(port)),
		timeoutEnv+"="+strconv.Itoa(timeoutSeconds),
	)
	out, err := cmd.Output()

	result := clientResult{Err: err}
	for _, field := range strings.Fields(strings.TrimSpace(string(out))) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "PEER":
			result.Peer = value
		case "BYTES":
			result.Bytes, _ = strconv.Atoi(value)
		case "STALLED":
			result.Stalled = value == "1"
		}
	}
	return result
}

// ---------------------------------------------------------------- requests

// routeRequest is a plain relay from the relay's client-facing address to the
// destination namespace.
func routeRequest(title string, bindPort, destPort int, natMode int64) Request {
	return Request{RouteInput: validate.RouteInput{
		RouteRuleTitle:  title,
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     relayToClient, BindPort: bindPort,
		DestinationAddress: destAddr, DestinationPort: destPort,
		NatModeID: natMode, IsEnabled: true,
	}}
}

// liveRuleset is the relay namespace's whole ruleset, for assertions about what
// is and is not installed.
func (l *lab) liveRuleset() string {
	l.t.Helper()
	out, err := nsExec(l.t, relayNS, nftBin, "list", "ruleset")
	if err != nil {
		l.t.Fatalf("listing the relay ruleset failed: %v\n%s", err, out)
	}
	return out
}

// counters reads the panel's own accounting straight from the relay's kernel.
func (l *lab) counters(routeRuleID int64) rules.Counter {
	l.t.Helper()
	all, err := l.backend.Counters(l.ctx)
	if err != nil {
		l.t.Fatalf("reading the counters failed: %v", err)
	}
	return all[routeRuleID]
}

// counterIDs are the rules the kernel currently holds counter objects for,
// which is not the same question as what any one of them reads.
func (l *lab) counterIDs() []int64 {
	l.t.Helper()
	all, err := l.backend.Counters(l.ctx)
	if err != nil {
		l.t.Fatalf("reading the counters failed: %v", err)
	}
	out := make([]int64, 0, len(all))
	for id := range all {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
