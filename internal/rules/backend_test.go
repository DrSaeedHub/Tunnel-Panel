package rules

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	panelexec "github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/model"
)

func simpleRuleset() Ruleset { return Ruleset{Routes: []RouteSpec{baseSpec()}} }

// TestNftablesApplyIsOneTransaction covers the atomicity requirement: the whole
// desired state goes to the kernel in a single nft invocation, so there is
// never a window with half a ruleset live.
func TestNftablesApplyIsOneTransaction(t *testing.T) {
	dir := t.TempDir()
	runner := panelexec.NewFakeRunner()
	backend := NewNftables("/usr/sbin/nft", dir, runner)

	payload, err := backend.Render(simpleRuleset())
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := backend.Apply(context.Background(), payload); err != nil {
		t.Fatalf("Apply returned an unexpected error: %v", err)
	}

	calls := runner.CommandLines()
	want := fmt.Sprintf("/usr/sbin/nft -f %s", filepath.Join(dir, NftFileName))
	if len(calls) != 1 || calls[0] != want {
		t.Fatalf("Apply ran %v, want exactly one call: %q", calls, want)
	}

	written, err := os.ReadFile(filepath.Join(dir, NftFileName))
	if err != nil {
		t.Fatalf("the payload was not written: %v", err)
	}
	if string(written) != payload.Parts[0].Text {
		t.Error("the file written is not the payload that was previewed")
	}
	if !strings.HasPrefix(string(written), OwnershipMarker) {
		t.Error("the written payload carries no ownership marker, so the panel could not tell it is its own")
	}
	if !strings.Contains(string(written), "flush table inet gre_panel") {
		t.Error("the transaction does not begin by flushing the panel's own table")
	}
}

// TestApplyRefusesToOverwriteAFileItDoesNotOwn is invariant §6.3.2 at the file
// level: a file at the panel's path that the panel did not write belongs to
// whatever created it.
func TestApplyRefusesToOverwriteAFileItDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, NftFileName)
	if err := os.WriteFile(path, []byte("# somebody else's ruleset\n"), 0o644); err != nil {
		t.Fatalf("seeding a foreign file failed: %v", err)
	}

	runner := panelexec.NewFakeRunner()
	backend := NewNftables("/usr/sbin/nft", dir, runner)
	payload, err := backend.Render(simpleRuleset())
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	err = backend.Apply(context.Background(), payload)
	if !errors.Is(err, ErrNotPanelOwned) {
		t.Fatalf("Apply returned %v, want ErrNotPanelOwned", err)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "# somebody else's ruleset\n" {
		t.Error("the foreign file was overwritten")
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("nothing should have been executed after the refusal, got %v", runner.CommandLines())
	}
}

// TestIptablesApplyInstallsOnlyTheMissingJumps is the idempotency property the
// legacy script lacked: applying twice must not leave two of anything.
func TestIptablesApplyInstallsOnlyTheMissingJumps(t *testing.T) {
	dir := t.TempDir()
	runner := panelexec.NewFakeRunner()
	backend := NewIptables("/usr/sbin/iptables", "/usr/sbin/iptables-restore",
		"/usr/sbin/ip6tables", "/usr/sbin/ip6tables-restore", dir, runner)

	// Every jump is present except the one into the nat table's PREROUTING,
	// which is what a host looks like after another tool flushed that chain.
	missing := "/usr/sbin/iptables -t nat -C PREROUTING -j " + ChainPre
	runner.Errors[missing] = errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")

	payload, err := backend.Render(simpleRuleset())
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := backend.Apply(context.Background(), payload); err != nil {
		t.Fatalf("Apply returned an unexpected error: %v", err)
	}

	var installs []string
	for _, line := range runner.CommandLines() {
		if strings.Contains(line, " -I ") {
			installs = append(installs, line)
		}
	}
	want := "/usr/sbin/iptables -t nat -I PREROUTING 1 -j " + ChainPre
	if len(installs) != 1 || installs[0] != want {
		t.Fatalf("Apply installed %v, want only the missing jump: %q", installs, want)
	}

	// Both families' payloads are restored, always, so a family whose last rule
	// was just deleted is left with an empty ruleset rather than stale rules.
	restores := 0
	allowed := map[string]bool{
		"/usr/sbin/iptables": true, "/usr/sbin/iptables-restore": true,
		"/usr/sbin/ip6tables": true, "/usr/sbin/ip6tables-restore": true,
	}
	for _, call := range runner.Calls() {
		if strings.Contains(call[0], "restore") {
			restores++
		}
		// Persistence is the panel's own file and its own restore, never a
		// package that snapshots the whole system's ruleset and puts it back
		// later, so nothing else is ever executed.
		if !allowed[call[0]] {
			t.Errorf("the apply ran a program the panel does not own: %v", call)
		}
	}
	if restores != 2 {
		t.Errorf("got %d restore calls, want one per address family", restores)
	}
}

// TestIptablesApplySkipsIPv6WhenTheToolsAreAbsent: a host without ip6tables can
// still relay IPv4, and failing the whole apply would take the working half
// down with the missing one.
func TestIptablesApplySkipsIPv6WhenTheToolsAreAbsent(t *testing.T) {
	dir := t.TempDir()
	runner := panelexec.NewFakeRunner()
	backend := NewIptables("/usr/sbin/iptables", "/usr/sbin/iptables-restore", "", "", dir, runner)

	payload, err := backend.Render(simpleRuleset())
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := backend.Apply(context.Background(), payload); err != nil {
		t.Fatalf("Apply returned an unexpected error: %v", err)
	}
	for _, line := range runner.CommandLines() {
		if strings.Contains(line, "ip6tables") {
			t.Errorf("the apply ran an IPv6 command on a host with no ip6tables: %s", line)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, Ip6tablesFileName)); err == nil {
		t.Error("an IPv6 payload was written on a host with no ip6tables")
	}
	if backend.Capabilities().Features[FeatureIPv6] {
		t.Error("capabilities claim IPv6 support on a host with no ip6tables")
	}
}

// TestNftablesReadBackAttributesEveryRule parses a ruleset recorded from a real
// kernel after applying one of the golden payloads to it.
func TestNftablesReadBackAttributesEveryRule(t *testing.T) {
	recorded, err := os.ReadFile(filepath.Join("testdata", "nftables", "live-table.txt"))
	if err != nil {
		t.Fatalf("reading the recorded kernel ruleset failed: %v", err)
	}

	runner := panelexec.NewFakeRunner()
	runner.Responses["/usr/sbin/nft list table inet gre_panel"] = panelexec.Result{Stdout: string(recorded)}
	backend := NewNftables("/usr/sbin/nft", t.TempDir(), runner)

	live, err := backend.ReadBack(context.Background())
	if err != nil {
		t.Fatalf("ReadBack returned an unexpected error: %v", err)
	}
	if len(live.Rules) == 0 {
		t.Fatal("ReadBack found no rules in a ruleset that has them")
	}
	structural := 0
	for _, rule := range live.Rules {
		if rule.Chain == "" {
			t.Errorf("a live rule was not attributed to a chain: %+v", rule)
		}
		if rule.Structural {
			structural++
			continue
		}
		if rule.RouteRuleID != 1 {
			t.Errorf("a live rule was not attributed to its row: %+v", rule)
		}
	}
	// Every line inside the panel's namespace is accounted for: either it came
	// from a row, or it is the ruleset's own scaffolding. Anything else would be
	// reported as unmanaged, and a false positive there teaches an operator to
	// ignore the reconcile report.
	if structural != 1 {
		t.Errorf("got %d structural rules, want exactly the conntrack accept", structural)
	}
	if !live.IDs()[1] {
		t.Error("the live ruleset does not report the rule it contains")
	}
	// The counter and set declarations are objects rather than rules, and the
	// chain declarations are structure; neither is a rule that drifted.
	for _, rule := range live.Rules {
		if strings.HasPrefix(rule.Text, "type ") || strings.HasPrefix(rule.Text, "packets ") {
			t.Errorf("a declaration was reported as a rule: %+v", rule)
		}
	}
}

// TestNftablesReadBackOnAHostWithNoTable: a table that is not there is an empty
// ruleset, which is exactly what a host that has never applied one has.
func TestNftablesReadBackOnAHostWithNoTable(t *testing.T) {
	runner := panelexec.NewFakeRunner()
	runner.Handler = func(argv []string) (panelexec.Result, error) {
		res := panelexec.Result{ExitCode: 1, Stderr: "Error: No such file or directory"}
		return res, errors.New("nft exited 1")
	}
	backend := NewNftables("/usr/sbin/nft", t.TempDir(), runner)

	live, err := backend.ReadBack(context.Background())
	if err != nil {
		t.Fatalf("ReadBack on a host with no table returned an error: %v", err)
	}
	if len(live.Rules) != 0 {
		t.Errorf("got %d rules from a host with no table", len(live.Rules))
	}
}

// TestFlushTouchesOnlyThePanelsNamespace is invariant §6.3.2 at the command
// level.
func TestFlushTouchesOnlyThePanelsNamespace(t *testing.T) {
	runner := panelexec.NewFakeRunner()
	nft := NewNftables("/usr/sbin/nft", t.TempDir(), runner)
	if err := nft.Flush(context.Background()); err != nil {
		t.Fatalf("Flush returned an unexpected error: %v", err)
	}
	if got := runner.CommandLines(); len(got) != 1 ||
		got[0] != "/usr/sbin/nft delete table inet gre_panel" {
		t.Errorf("nftables Flush ran %v, want only the panel's own table to be deleted", got)
	}

	runner = panelexec.NewFakeRunner()
	ipt := NewIptables("/usr/sbin/iptables", "/usr/sbin/iptables-restore", "", "", t.TempDir(), runner)
	if err := ipt.Flush(context.Background()); err != nil {
		t.Fatalf("Flush returned an unexpected error: %v", err)
	}
	for _, line := range runner.CommandLines() {
		fields := strings.Fields(line)
		chain := fields[len(fields)-1]
		switch {
		case strings.Contains(line, " -F ") || strings.Contains(line, " -X "):
			if !IsPanelChain(chain) {
				t.Errorf("Flush touched a chain the panel does not own: %s", line)
			}
		case strings.Contains(line, " -D "):
			// Deleting a jump rule from a built-in chain removes the panel's own
			// rule, and nothing else in that chain.
			if !IsPanelChain(chain) {
				t.Errorf("Flush deleted something other than the panel's jump rule: %s", line)
			}
		}
	}
}

func TestDetectPrefersNftablesAndReportsWhy(t *testing.T) {
	runner := panelexec.NewFakeRunner()
	runner.Responses["/usr/sbin/nft --version"] = panelexec.Result{Stdout: "nftables v1.0.9 (Old Doc Yak #3)\n"}
	runner.Responses["/usr/sbin/iptables --version"] = panelexec.Result{Stdout: "iptables v1.8.10 (nf_tables)\n"}

	d := Detect(context.Background(), Options{
		NftBin: "/usr/sbin/nft", IptablesBin: "/usr/sbin/iptables",
		IptablesRestoreBin: "/usr/sbin/iptables-restore", Runner: runner, Dir: t.TempDir(),
	})
	if d.Backend.Name() != BackendNftables {
		t.Errorf("Detect chose %q, want nftables where nft is available", d.Backend.Name())
	}
	if d.NftVersion != "nftables v1.0.9 (Old Doc Yak #3)" {
		t.Errorf("the nft version was not captured: %q", d.NftVersion)
	}
	if d.IptablesIsLegacy {
		t.Error("iptables reporting nf_tables was classified as legacy")
	}
	if d.Reason == "" {
		t.Error("Detect gave no reason for its choice")
	}
	if !d.Backend.Capabilities().Available {
		t.Error("the chosen backend reports itself unavailable")
	}
}

func TestDetectFallsBackAndClassifiesTheIptablesBackend(t *testing.T) {
	runner := panelexec.NewFakeRunner()
	runner.Responses["/usr/sbin/iptables --version"] = panelexec.Result{Stdout: "iptables v1.8.10 (legacy)\n"}

	d := Detect(context.Background(), Options{
		IptablesBin: "/usr/sbin/iptables", IptablesRestoreBin: "/usr/sbin/iptables-restore",
		Runner: runner, Dir: t.TempDir(),
	})
	if d.Backend.Name() != BackendIptablesLegacy {
		t.Errorf("Detect chose %q, want the legacy iptables backend", d.Backend.Name())
	}
	if !d.IptablesIsLegacy {
		t.Error("an iptables reporting (legacy) was not classified as legacy")
	}

	// And the same binaries speaking nf_tables are a different backend, because
	// a legacy host does not share tables with nftables rules at all.
	runner.Responses["/usr/sbin/iptables --version"] = panelexec.Result{Stdout: "iptables v1.8.10 (nf_tables)\n"}
	d = Detect(context.Background(), Options{
		IptablesBin: "/usr/sbin/iptables", IptablesRestoreBin: "/usr/sbin/iptables-restore",
		Runner: runner, Dir: t.TempDir(),
	})
	if d.Backend.Name() != BackendIptablesNft {
		t.Errorf("Detect chose %q, want the nf_tables iptables backend", d.Backend.Name())
	}
}

// TestDetectNeverReturnsAFakeOnARealHost: a fake reports success for rules that
// were never installed, which is the one failure mode this project exists to
// prevent.
func TestDetectNeverReturnsAFakeOnARealHost(t *testing.T) {
	d := Detect(context.Background(), Options{Runner: panelexec.NewFakeRunner(), Dir: t.TempDir()})
	if d.Backend.Name() == BackendFake {
		t.Fatal("Detect returned a fake backend on a host with no netfilter tools")
	}
	if d.Backend.Capabilities().Available {
		t.Error("a backend with no binary reports itself available")
	}
	if err := d.Backend.Apply(context.Background(), Payload{}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("applying with no backend returned %v, want ErrUnavailable", err)
	}

	// Development mode is the one place the fake belongs.
	d = Detect(context.Background(), Options{DevMode: true, Runner: panelexec.NewFakeRunner(), Dir: t.TempDir()})
	if d.Backend.Name() != BackendFake {
		t.Errorf("development mode chose %q, want the fake", d.Backend.Name())
	}
}

func TestForcingIptablesIsHonoured(t *testing.T) {
	runner := panelexec.NewFakeRunner()
	runner.Responses["/usr/sbin/nft --version"] = panelexec.Result{Stdout: "nftables v1.0.9\n"}
	runner.Responses["/usr/sbin/iptables --version"] = panelexec.Result{Stdout: "iptables v1.8.10 (nf_tables)\n"}

	d := Detect(context.Background(), Options{
		NftBin: "/usr/sbin/nft", IptablesBin: "/usr/sbin/iptables",
		IptablesRestoreBin: "/usr/sbin/iptables-restore",
		ForceIptables:      true, Runner: runner, Dir: t.TempDir(),
	})
	if d.Backend.Name() != BackendIptablesNft {
		t.Errorf("forcing iptables chose %q", d.Backend.Name())
	}
}

// TestTheFakeRendersWhatWouldActuallyBeApplied is what makes the preview
// endpoint trustworthy: the operator reads the payload their own host would
// receive, not an approximation of it.
func TestTheFakeRendersWhatWouldActuallyBeApplied(t *testing.T) {
	for _, real := range []Backend{nftBackend(), iptBackend()} {
		fake := NewFakeFor(real)
		wantPayload, err := real.Render(simpleRuleset())
		if err != nil {
			t.Fatalf("%s: %v", real.Name(), err)
		}
		gotPayload, err := fake.Render(simpleRuleset())
		if err != nil {
			t.Fatalf("fake for %s: %v", real.Name(), err)
		}
		if len(gotPayload.Parts) != len(wantPayload.Parts) {
			t.Fatalf("the fake rendered %d parts, want %d", len(gotPayload.Parts), len(wantPayload.Parts))
		}
		for i := range wantPayload.Parts {
			if gotPayload.Parts[i].Text != wantPayload.Parts[i].Text {
				t.Errorf("the fake's %s payload differs from what %s would apply",
					gotPayload.Parts[i].Kind, real.Name())
			}
		}
		if !strings.Contains(gotPayload.Backend, real.Name()) {
			t.Errorf("the fake payload does not say which backend it stands in for: %q", gotPayload.Backend)
		}
	}
}

func TestTheFakeChangesNothingAndRemembersEverything(t *testing.T) {
	// The fake renders into a directory belonging to this test rather than into
	// the installed panel's own. Asserting that nothing exists at the production
	// path proves nothing on a host where the panel is installed: the file is
	// there because the real panel wrote it, and the assertion failed on both
	// test servers for that reason alone while the fake was behaving perfectly.
	dir := t.TempDir()
	fake := NewFakeFor(NewNftables(DefaultNftBin, dir, nil))
	payload, err := fake.Render(simpleRuleset())
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if !strings.HasPrefix(payload.Parts[0].Path, dir) {
		t.Fatalf("the fake rendered to %s, which this test does not own", payload.Parts[0].Path)
	}
	if err := fake.Apply(context.Background(), payload); err != nil {
		t.Fatalf("Apply returned an unexpected error: %v", err)
	}
	if len(fake.Applied()) != 1 {
		t.Errorf("the fake recorded %d applies, want 1", len(fake.Applied()))
	}
	if _, err := os.Stat(payload.Parts[0].Path); err == nil {
		t.Error("the fake wrote a file to the host")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading the render directory failed: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the fake left %d file(s) behind in its render directory", len(entries))
	}

	live, err := fake.ReadBack(context.Background())
	if err != nil {
		t.Fatalf("ReadBack returned an unexpected error: %v", err)
	}
	if !live.IDs()[1] {
		t.Error("the fake does not report back the rule it was given")
	}

	fake.FailOn = errors.New("simulated failure")
	if err := fake.Apply(context.Background(), payload); err == nil {
		t.Error("the fake did not fail when it was told to")
	}
}

// TestBackendNamesMatchTheDataModel keeps the rule layer's vocabulary and the
// lookup tables in step without either package importing the other.
func TestBackendNamesMatchTheDataModel(t *testing.T) {
	for id, want := range map[int64]string{
		model.RuleBackendTypeNftables:       BackendNftables,
		model.RuleBackendTypeIptablesNft:    BackendIptablesNft,
		model.RuleBackendTypeIptablesLegacy: BackendIptablesLegacy,
	} {
		if got := model.RuleBackendTypeName(id); got != want {
			t.Errorf("model.RuleBackendTypeName(%d) = %q, want %q", id, got, want)
		}
		if back, ok := model.RuleBackendTypeForName(want); !ok || back != id {
			t.Errorf("model.RuleBackendTypeForName(%q) = %d, %v; want %d, true", want, back, ok, id)
		}
	}
	for id, want := range map[int64]Protocol{
		model.RouteProtocolTCP:  ProtocolTCP,
		model.RouteProtocolUDP:  ProtocolUDP,
		model.RouteProtocolBoth: ProtocolBoth,
	} {
		if got := model.RouteProtocolName(id); got != string(want) {
			t.Errorf("model.RouteProtocolName(%d) = %q, want %q", id, got, want)
		}
	}
	for id, want := range map[int64]NatMode{
		model.NatModeMasquerade: NatMasquerade,
		model.NatModeSnat:       NatSnat,
		model.NatModeNone:       NatNone,
	} {
		if got := model.NatModeName(id); got != string(want) {
			t.Errorf("model.NatModeName(%d) = %q, want %q", id, got, want)
		}
	}
	for id, want := range map[int64]LoadBalanceMode{
		model.LoadBalanceModeNone:       LoadBalanceNone,
		model.LoadBalanceModeRoundRobin: LoadBalanceRoundRobin,
		model.LoadBalanceModeSourceHash: LoadBalanceSourceHash,
		model.LoadBalanceModeWeighted:   LoadBalanceWeighted,
	} {
		if got := model.LoadBalanceModeName(id); got != string(want) {
			t.Errorf("model.LoadBalanceModeName(%d) = %q, want %q", id, got, want)
		}
	}
	// The backend a host is running is recorded in the database, so every
	// backend except the fake has to map to a lookup row.
	for _, name := range []string{BackendNftables, BackendIptablesNft, BackendIptablesLegacy} {
		if BackendTypeName(name) == "" {
			t.Errorf("the backend %q has no RuleBackendType row", name)
		}
	}
}

// nftCheckersEnv names the nft parsers to certify the goldens against.
//
// Entries are separated by ';' and each is a command that will be given
// `-c -f -` with the payload on standard input. That indirection is the whole
// point: the parser that matters is usually not the one on the machine running
// the tests, and `nft -c -f -` reads a ruleset from a pipe, so one run can put
// every golden through the nft of every host the panel supports:
//
//	GRE_PANEL_NFT_CHECKERS='/usr/sbin/nft;ssh -o BatchMode=yes root@jammy nft' go test ./internal/rules
//
// With nothing set, the local nft is the only checker, which is not enough to
// certify anything on its own — see the end of the test.
const nftCheckersEnv = "GRE_PANEL_NFT_CHECKERS"

// nftChecker is one parser the goldens are put through.
type nftChecker struct {
	argv    []string
	version string
	label   string
}

// nftCheckers assembles the parsers available to this run.
func nftCheckers(t *testing.T) []nftChecker {
	t.Helper()

	var commands [][]string
	if configured := strings.TrimSpace(os.Getenv(nftCheckersEnv)); configured != "" {
		for _, entry := range strings.Split(configured, ";") {
			if fields := strings.Fields(entry); len(fields) > 0 {
				commands = append(commands, fields)
			}
		}
	} else if os.Geteuid() == 0 {
		// Only as root: without a netlink socket nft cannot tell a ruleset it
		// dislikes from one it cannot look at, and answers both the same way.
		if _, err := exec.LookPath("nft"); err == nil {
			commands = append(commands, []string{"nft"})
		}
	}

	var out []nftChecker
	for _, argv := range commands {
		version := nftVersion(t, argv)
		if version == "" {
			t.Errorf("%q does not answer --version with an nftables version, so it cannot be "+
				"used to certify the goldens", strings.Join(argv, " "))
			continue
		}
		out = append(out, nftChecker{argv: argv, version: version,
			label: fmt.Sprintf("nft %s (%s)", version, strings.Join(argv, " "))})
	}
	return out
}

var nftVersionPattern = regexp.MustCompile(`nftables v(\d+\.\d+\.\d+)`)

func nftVersion(t *testing.T, argv []string) string {
	t.Helper()
	out, err := exec.Command(argv[0], append(argv[1:], "--version")...).CombinedOutput()
	if err != nil {
		return ""
	}
	match := nftVersionPattern.FindStringSubmatch(string(out))
	if match == nil {
		return ""
	}
	return match[1]
}

// olderOrEqual compares two dotted versions numerically, because "1.0.10" is
// newer than "1.0.9" and string order says otherwise.
func olderOrEqual(a, b string) bool {
	parse := func(v string) []int {
		var out []int
		for _, part := range strings.Split(v, ".") {
			n, _ := strconv.Atoi(part)
			out = append(out, n)
		}
		return out
	}
	left, right := parse(a), parse(b)
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) <= len(right)
}

// TestGoldenPayloadsParseOnEveryNft hands every golden to every nft it can
// reach, and refuses to be satisfied by the newest one alone.
//
// The version this ran against used to be whichever happened to be installed
// beside the tests. It passed on nftables 1.0.9 while the same goldens were
// rejected outright by 1.0.2 — `mss` is a keyword there and cannot name a
// chain, and the nat output hook will not take a symbolic priority — so the
// whole feature was unusable on Ubuntu 22.04 and the suite said nothing. A
// compatibility floor that is never exercised is not a floor, so this fails
// when the oldest parser it saw is newer than the one the panel claims to
// support.
func TestGoldenPayloadsParseOnEveryNft(t *testing.T) {
	checkers := nftCheckers(t)
	if len(checkers) == 0 {
		t.Skipf("no nft to check against: run as root, or set %s to the parsers to certify "+
			"against (see the constant's documentation)", nftCheckersEnv)
	}

	for _, checker := range checkers {
		t.Run(checker.version, func(t *testing.T) {
			for _, tc := range cases() {
				payload, err := os.ReadFile(filepath.Join("testdata", "nftables", tc.name+".nft"))
				if err != nil {
					t.Fatalf("reading the golden failed: %v", err)
				}
				command := exec.Command(checker.argv[0], append(checker.argv[1:], "-c", "-f", "-")...)
				command.Stdin = strings.NewReader(string(payload))
				if out, err := command.CombinedOutput(); err != nil {
					t.Errorf("%s rejected %s: %v\n%s", checker.label, tc.name, err, out)
				}
			}
		})
	}

	// iptables is checked locally only: unlike nft it takes the ruleset from a
	// file rather than a pipe, and its syntax has been stable across the
	// releases in question.
	if os.Geteuid() == 0 {
		for _, tc := range cases() {
			for _, ipt := range []struct{ bin, file string }{
				{"iptables-restore", tc.name + ".rules"},
				{"ip6tables-restore", tc.name + ".6rules"},
			} {
				if _, err := exec.LookPath(ipt.bin); err != nil {
					continue
				}
				out, err := exec.Command(ipt.bin, "--test", "--noflush",
					filepath.Join("testdata", "iptables", ipt.file)).CombinedOutput()
				if err != nil {
					t.Errorf("%s rejected %s: %v\n%s", ipt.bin, tc.name, err, out)
				}
			}
		}
	}

	// The loud part. Everything above can pass while the panel is broken on
	// every host the team actually installs it on.
	oldest := checkers[0].version
	for _, checker := range checkers[1:] {
		if olderOrEqual(checker.version, oldest) {
			oldest = checker.version
		}
	}
	if !olderOrEqual(oldest, OldestSupportedNft) {
		versions := make([]string, 0, len(checkers))
		for _, checker := range checkers {
			versions = append(versions, checker.version)
		}
		t.Errorf("the goldens were only certified against nft %s, and the oldest release the "+
			"panel supports is %s. Passing here proves nothing about that host: this is exactly "+
			"how a ruleset that no 22.04 machine could parse shipped. Point %s at an nft %s or "+
			"older as well, for example %s='%s;ssh -o BatchMode=yes root@<22.04 host> nft'.",
			strings.Join(versions, ", "), OldestSupportedNft, nftCheckersEnv, OldestSupportedNft,
			nftCheckersEnv, DefaultNftBin)
	}
}
