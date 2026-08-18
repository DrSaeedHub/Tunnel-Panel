package scripts

import (
	"github.com/drs/gre-panel/internal/persist"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The installer is 593 lines of shell with no way to drive it from a test: no
// --dry-run, no --check, and running it for real would install a panel on the
// machine running the suite.
//
// What can be checked without running it is its contract with everything
// around it, by parsing it the way internal/persist already parses the unit it
// embeds. These are the invariants where being wrong is invisible until an
// operator hits them: an exit code the README promises that the script cannot
// produce, or a stamp the release build silently drops.

func readScript(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return strings.ReplaceAll(string(body), "\r\n", "\n")
}

// TestTheDocumentedExitCodesAreTheOnesTheInstallerCanProduce holds the two
// halves of §3.4's requirement to prove every documented exit code.
//
// The README is the contract other tooling reads: a wrapper that treats 16 as
// "checksum failed" is relying on it. So a code the README documents has to
// exist in the script and be reachable, and a code the script can exit with has
// to be documented — an undocumented one is a failure mode nobody can handle
// deliberately.
func TestTheDocumentedExitCodesAreTheOnesTheInstallerCanProduce(t *testing.T) {
	script := readScript(t, "install.sh")
	readme, err := os.ReadFile(filepath.Join("..", "README.md"))
	if err != nil {
		t.Fatalf("reading the README: %v", err)
	}

	// The constants the script declares, by value.
	declared := map[int]string{}
	for _, match := range regexp.MustCompile(`(?m)^readonly (EXIT_[A-Z_]+)=(\d+)`).
		FindAllStringSubmatch(script, -1) {
		code, convErr := strconv.Atoi(match[2])
		if convErr != nil {
			t.Fatalf("exit constant %s has a non-numeric value %q", match[1], match[2])
		}
		if existing, clash := declared[code]; clash {
			t.Errorf("%s and %s are both %d, so a caller cannot tell them apart",
				existing, match[1], code)
		}
		declared[code] = match[1]
	}
	if len(declared) < 5 {
		t.Fatalf("only %d exit constants were found; the pattern is not matching", len(declared))
	}

	// The codes the README's table documents.
	documented := map[int]bool{}
	table := regexp.MustCompile(`(?m)^\|\s*(\d+)\s*\|`)
	section := string(readme)
	if at := strings.Index(section, "### Exit codes"); at >= 0 {
		section = section[at:]
	}
	for _, match := range table.FindAllStringSubmatch(section, -1) {
		code, _ := strconv.Atoi(match[1])
		documented[code] = true
	}
	if len(documented) < 5 {
		t.Fatalf("only %d exit codes were found in the README", len(documented))
	}

	var undocumented, unimplemented, unused []string
	for code, name := range declared {
		if !documented[code] {
			undocumented = append(undocumented, name+" = "+strconv.Itoa(code))
		}
		// Declared and never used is a code the script cannot actually produce,
		// which is the same promise broken from the other end.
		if strings.Count(script, name) < 2 {
			unused = append(unused, name)
		}
	}
	for code := range documented {
		if _, ok := declared[code]; !ok {
			unimplemented = append(unimplemented, strconv.Itoa(code))
		}
	}
	sort.Strings(undocumented)
	sort.Strings(unimplemented)
	sort.Strings(unused)

	if len(undocumented) > 0 {
		t.Errorf("the installer can exit with %d code(s) the README does not document, so nothing "+
			"calling it can handle them deliberately:\n  %s",
			len(undocumented), strings.Join(undocumented, "\n  "))
	}
	if len(unimplemented) > 0 {
		t.Errorf("the README documents %d exit code(s) the installer does not define:\n  %s",
			len(unimplemented), strings.Join(unimplemented, "\n  "))
	}
	if len(unused) > 0 {
		t.Errorf("%d exit constant(s) are declared and never used, so the README promises a code "+
			"the installer cannot produce:\n  %s", len(unused), strings.Join(unused, "\n  "))
	}
}

// TestTheReleaseBuildAcceptsAStampFromTheEnvironment is the regression for the
// change that let a release built from an exported tree identify itself.
//
// The documented way to deploy is to build a release and carry it to the
// target, and a tree that arrived by `git archive` or scp has no .git to ask.
// The stamp then fell back to "unknown" and the panel could no longer report
// which commit it was running — the one thing the version banner exists for.
//
// Checked by parsing rather than by running, because running it builds a binary
// for every architecture.
func TestTheReleaseBuildAcceptsAStampFromTheEnvironment(t *testing.T) {
	script := readScript(t, "build-release.sh")

	for _, tc := range []struct{ variable, fallback string }{
		{"GRE_PANEL_BUILD_COMMIT", "git rev-parse"},
		{"GRE_PANEL_BUILD_DATE", "git show"},
	} {
		// The override has to be consulted...
		assignment := regexp.MustCompile(`\$\{` + tc.variable + `:-`)
		if !assignment.MatchString(script) {
			t.Errorf("%s is not honoured, so a build from a tree with no .git cannot identify "+
				"itself", tc.variable)
			continue
		}
		// ...and it has to be a default-if-unset, so a checkout still asks git.
		if !strings.Contains(script, tc.fallback) {
			t.Errorf("%s has no %s fallback, so a normal checkout would stop stamping itself",
				tc.variable, tc.fallback)
		}
	}

	// The stamp reaches the binary, or none of the above matters.
	for _, flag := range []string{"-X main.version=", "-X main.commit=", "-X main.buildDate="} {
		if !strings.Contains(script, flag) {
			t.Errorf("the link flags do not carry %s, so the value is computed and thrown away", flag)
		}
	}
}

// TestTheStaticCheckIsActuallyInvoked pins finding 11 at the integration point:
// check-static.sh classifies correctly (see check_static_test.go), but only if
// the release build still calls it.
func TestTheStaticCheckIsActuallyInvoked(t *testing.T) {
	script := readScript(t, "build-release.sh")

	if !strings.Contains(script, "check-static.sh") {
		t.Fatal("build-release.sh no longer runs the static-linking check, so a release could " +
			"ship dynamically linked with nothing noticing")
	}
	// The old inline check is gone. It was inverted — `ldd | grep -qv "not a
	// dynamic executable"` is true for almost any output — and it treated a host
	// that could not read the binary as one that had read it and found it clean.
	if strings.Contains(script, `grep -qv "not a dynamic executable"`) {
		t.Error("the inverted inline ldd check is back in build-release.sh")
	}
}

// The unit's capability set is a safety invariant, not just hardening.
//
// The panel refuses to forward the port the live SSH daemon is listening on,
// and it finds that port by reading which process holds the listening socket —
// walking /proc/<pid>/fd for the socket's inode. Reading another process's file
// descriptors is a ptrace-mode operation: same-uid is not enough when the
// target holds capabilities the reader does not, and sshd holds the full set
// while the panel deliberately holds seven. Without CAP_SYS_PTRACE the walk is
// denied for every process except the panel itself, the owner map comes back
// empty, and SshPorts() reports that nothing is listening on SSH at all.
//
// Measured on both live hosts, in both sshd configurations:
//
//	shipping unit                -> SshPorts: []
//	shipping unit + SYS_PTRACE   -> SshPorts: [22]
//	shipping unit + DAC_READ_SEARCH -> SshPorts: []   (not sufficient)
//
// The invariant still held, because an unidentified daemon falls back to
// protecting port 22 as a precaution. But the fallback protects the
// conventional port, not the live one: an installation that had moved SSH to
// 2222 would have been protected on 22 and left forwardable on 2222, which is
// the exact failure the socket-activation handling was written to prevent.
// That handling could never run, because there was no candidate to choose
// between.
//
// This pins the capability so a later hardening pass cannot quietly remove it
// and take the protection with it.
func TestTheUnitCanIdentifyTheProcessHoldingAPort(t *testing.T) {
	script := readScript(t, "install.sh")

	for _, directive := range []string{"AmbientCapabilities", "CapabilityBoundingSet"} {
		line := directiveLine(t, script, directive)
		if !strings.Contains(line, "CAP_SYS_PTRACE") {
			t.Errorf("%s does not grant CAP_SYS_PTRACE:\n    %s\n"+
				"Without it the panel cannot read another process's /proc/<pid>/fd, so it "+
				"cannot tell which port the live SSH daemon holds and protects the "+
				"conventional port instead of the real one.", directive, line)
		}
	}
}

// directiveLine returns the single unit directive with this name.
func directiveLine(t *testing.T, script, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + `=.*$`)
	found := pattern.FindAllString(script, -1)
	if len(found) == 0 {
		t.Fatalf("the installer declares no %s at all", name)
	}
	if len(found) > 1 {
		t.Fatalf("the installer declares %s %d times; this test would check the wrong one",
			name, len(found))
	}
	return found[0]
}

// --purge-tunnels has to remove the tunnels the panel actually wrote.
//
// It globbed /etc/systemd/system/gre-panel-tunnel-*.service, and the panel has
// never written a file by that name: persist.UnitName is the interface name
// plus ".service", so the units are gre-a-1.service and the like. The glob
// matched nothing, the loop body never ran, and the flag removed no tunnels at
// all — while printing "Removing panel-managed tunnels" and reporting
// "purged_tunnels": true.
//
// Observed on a live host: a panel-managed tunnel and its unit were both still
// present after --purge-tunnels reported success.
//
// Selecting by name cannot work anyway, because a legacy unit adopted from a
// previous setup is named for its interface too and must NOT be removed. The
// only safe discriminator is the ownership marker the panel writes into every
// file it generates, which is what adoption already uses to decide whether a
// unit is the panel's to overwrite.
func TestPurgeRemovesTheUnitsThePanelActuallyWrites(t *testing.T) {
	script := readScript(t, "install.sh")

	purge := sectionBetween(script, "if [[ $PURGE_TUNNELS -eq 1 ]]; then", "rm -f \"$UNIT_PATH\"")
	if purge == "" {
		t.Fatal("could not find the --purge-tunnels block; this test would pass vacuously")
	}

	// A prefix the panel never generates cannot select anything it wrote.
	if strings.Contains(purge, "gre-panel-tunnel-") {
		t.Errorf("the purge block still selects gre-panel-tunnel-*, which persist.UnitName never "+
			"produces:\n%s", indent(purge))
	}

	// The ownership marker is the discriminator. The script may hold it in a
	// variable, so what matters is that the block consults it and that the
	// string the script defines is byte-for-byte the one the panel writes —
	// a copy that drifts would silently stop matching anything.
	const markerVar = "PANEL_FILE_MARKER"
	if !strings.Contains(purge, markerVar) && !strings.Contains(purge, persist.OwnershipMarker) {
		t.Errorf("the purge block consults neither %s nor the marker literal, so it cannot tell a "+
			"unit the panel wrote from a legacy one adopted from a previous setup:\n%s",
			markerVar, indent(purge))
	}

	declared := regexp.MustCompile(`(?m)^readonly ` + markerVar + `="([^"]*)"`).FindStringSubmatch(script)
	if declared == nil {
		t.Fatalf("the script does not declare %s, so nothing pins it to the panel's own marker", markerVar)
	}
	if declared[1] != persist.OwnershipMarker {
		t.Errorf("the installer looks for %q but the panel writes %q; a purge would match nothing",
			declared[1], persist.OwnershipMarker)
	}
}

// The installer has to install the management CLI, and remove it again.
//
// It is not an optional extra: re-running the installer hands over to it, and
// changing the panel's port or resetting a forgotten password are things only
// it can do. An installer that quietly skipped it would leave a host where the
// documented recovery path does not exist.
func TestTheInstallerShipsAndRemovesTheManagementCli(t *testing.T) {
	script := readScript(t, "install.sh")

	for _, needed := range []struct{ fragment, why string }{
		{`readonly CLI_PATH="/usr/local/bin/tnp"`, "the CLI has no install location"},
		{"tnp-linux-", "the CLI artefact is never downloaded"},
		{`install -m 0755 "$STAGING/tnp" "$CLI_PATH"`, "the downloaded CLI is never installed"},
		{`"$STAGING/tnp" version`, "the downloaded CLI is never smoke-tested, so a broken one is installed"},
		{"EXIT_CHECKSUM_FAILED", "the CLI download is not checksum-verified"},
	} {
		if !strings.Contains(script, needed.fragment) {
			t.Errorf("%s: the installer does not contain %q", needed.why, needed.fragment)
		}
	}

	// A missing artefact and a wrong one are different facts. An older release
	// tag predates the CLI and must still install; a checksum mismatch is a
	// download that cannot be trusted and must stop.
	cliBlock := sectionBetween(script, "step \"Downloading the $CLI_NAME management CLI\"", "# ---------------------------------------------------------------- install")
	if cliBlock == "" {
		t.Fatal("could not find the CLI download block; this test would pass vacuously")
	}
	if !strings.Contains(cliBlock, "warn ") {
		t.Errorf("a release with no CLI published is not warned about, so it would install "+
			"silently without one:\n%s", indent(cliBlock))
	}
	if !strings.Contains(cliBlock, "EXIT_CHECKSUM_FAILED") {
		t.Errorf("a CLI checksum mismatch is not fatal:\n%s", indent(cliBlock))
	}

	// And uninstall has to be able to take it away again.
	uninstall := sectionBetween(script, `if [[ "$MODE" == "uninstall" ]]; then`, "# ---------------------------------------------------------------- gather input")
	if uninstall == "" {
		t.Fatal("could not find the uninstall block")
	}
	if !strings.Contains(uninstall, "REMOVE_CLI") || !strings.Contains(uninstall, `rm -f "$CLI_PATH"`) {
		t.Errorf("uninstall cannot remove the CLI:\n%s", indent(uninstall))
	}
	// Removing the panel must not remove the CLI by default: the CLI is how it
	// gets reinstalled, and taking both away in one step leaves nothing.
	if !strings.Contains(uninstall, `elif [[ -x "$CLI_PATH" ]]`) {
		t.Error("uninstall does not say that the CLI was left behind, so an operator is not told " +
			"the tool that reinstalls the panel is still there")
	}
}

// Re-running the installer on a host that already has the CLI opens it.
//
// The three conditions are the contract. Dropping the argument check would
// break every automated path — --upgrade and --uninstall would open a menu
// instead of doing what they say.
func TestABareRerunHandsOverToTheCli(t *testing.T) {
	script := readScript(t, "install.sh")

	handoff := sectionBetween(script, "# ------------------------------------------------------- hand over to the CLI",
		"command -v systemctl")
	if handoff == "" {
		t.Fatal("there is no handoff to the CLI at all")
	}

	for _, condition := range []struct{ fragment, why string }{
		{"ARGUMENT_COUNT == 0", "any argument must bypass the handoff, or --upgrade and --uninstall would open a menu"},
		{`-x "$CLI_PATH"`, "there must be a CLI to hand over to"},
		{"-e /dev/tty", "the menu has nowhere to draw itself without a terminal"},
		{`"$NO_MENU" != "1"`, "there must be a documented way past it, for reinstalling over a working installation"},
		{`exec "$CLI_PATH"`, "the handoff must replace this process so the CLI's exit code is the one the caller sees"},
	} {
		if !strings.Contains(handoff, condition.fragment) {
			t.Errorf("the handoff does not check %q — %s:\n%s", condition.fragment, condition.why, indent(handoff))
		}
	}

	// The bypass is reachable from the environment as well as from a flag,
	// because the documented invocation is a curl pipe where adding a flag is
	// awkward.
	if !strings.Contains(script, `NO_MENU="${GRE_PANEL_NO_MENU:-0}"`) {
		t.Error("GRE_PANEL_NO_MENU does not bypass the handoff")
	}
	if !strings.Contains(script, "--no-menu) NO_MENU=1") {
		t.Error("--no-menu does not bypass the handoff")
	}

	// It has to happen after the root check: the CLI needs root too, and
	// "must run as root" from the installer is a better message than the CLI
	// failing three steps later.
	rootAt := strings.Index(script, "This installer must run as root")
	handoffAt := strings.Index(script, "hand over to the CLI")
	if rootAt < 0 || handoffAt < 0 || rootAt > handoffAt {
		t.Error("the handoff does not come after the root check")
	}
}

// An empty web path is a supported configuration, and the installer is where
// it was impossible: require_value rejected --web-path '' outright, the
// non-interactive check demanded a value for it, and every URL was built by
// interpolating it between two slashes.
func TestTheInstallerAcceptsAnEmptyWebPath(t *testing.T) {
	script := readScript(t, "install.sh")

	if !strings.Contains(script, `--web-path) require_present`) {
		t.Error("--web-path still goes through require_value, which rejects an empty value as a " +
			"missing one; there would be no way to ask for the root")
	}
	if !strings.Contains(script, "WEB_PATH_GIVEN") {
		t.Error("nothing distinguishes an empty web path from an absent one, so --non-interactive " +
			"would demand a value the operator has already declined")
	}
	if strings.Contains(script, `missing+=("--web-path")`) &&
		!strings.Contains(script, `(( WEB_PATH_GIVEN )) || missing+=("--web-path")`) {
		t.Error("the non-interactive check tests the web path's value rather than whether it was given")
	}

	// No URL may be built by interpolating the web path between slashes: with
	// an empty one that produces a double slash, and http://host:8443// is not
	// the URL the panel serves.
	//
	// Comments are stripped first. The comment explaining this hazard contains
	// the very pattern being searched for, and the first version of this test
	// failed on it — a check that reads prose is measuring the wrong thing, and
	// the fix that a failure like that invites is deleting the explanation.
	for i, line := range strings.Split(withoutComments(script), "\n") {
		if strings.Contains(line, `/$WEB_PATH/`) {
			t.Errorf("line %d builds a URL as .../$WEB_PATH/..., which becomes a double slash when "+
				"the web path is empty:\n    %s", i+1, strings.TrimSpace(line))
		}
	}
	if !strings.Contains(script, "base_path()") {
		t.Error("there is no single place that knows an empty web path renders as /")
	}
}

// After an upgrade the environment file is only a seed: the panel stores where
// it serves in its database and can be moved from the browser, which it cannot
// write back to /etc. Polling the file's port would then health-check an
// address nothing is on and report a working panel as a failed install.
func TestTheInstallerAsksThePanelWhereItListens(t *testing.T) {
	script := readScript(t, "install.sh")

	if !strings.Contains(script, "--print-address") {
		t.Fatal("the installer never asks the panel where it listens, so its readiness poll uses " +
			"the environment file, which is not authoritative after an upgrade")
	}
	if !strings.Contains(script, "resolve_address") {
		t.Error("there is no function resolving the panel's real address")
	}
	// And it has to actually be called on the paths where the file and the
	// stored value can differ. Matched on the guard's contents rather than on
	// its exact text: pinning the literal made this fail the moment a second
	// condition was added for reinstalling over a kept database, which is a
	// path with the same problem and therefore the same answer.
	call := strings.Index(script, "resolve_address; then")
	if call < 0 {
		t.Fatal("resolve_address is defined but never called")
	}
	// Look backwards from the call rather than forwards from a guard: there are
	// several conditions mentioning UPGRADE_EXISTING and only the one directly
	// above this call is the one under test. Searching forwards found the last
	// of them, which is a different block entirely, and failed whatever the
	// script said.
	from := call - 200
	if from < 0 {
		from = 0
	}
	if !strings.Contains(script[from:call], "UPGRADE_EXISTING") {
		t.Error("resolve_address is called, but not from a guard that mentions UPGRADE_EXISTING, " +
			"so an upgrade may still poll the environment file")
	}
}

// sectionBetween returns the text between two markers, exclusive of the end.
func sectionBetween(text, start, end string) string {
	from := strings.Index(text, start)
	if from < 0 {
		return ""
	}
	rest := text[from:]
	to := strings.Index(rest, end)
	if to < 0 {
		return rest
	}
	return rest[:to]
}

// withoutComments blanks out shell comment lines, so a test searching for a
// hazardous construct does not find the comment warning against it.
//
// Whole lines only: a trailing comment after real code is rare here and
// stripping it properly would need to know about quoting, which is exactly the
// kind of half-parser that produces a wrong answer confidently.
func withoutComments(script string) string {
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// expandInstallerConstants substitutes the installer's own readonly variables
// into a string, so a test can look for the path an operator would see rather
// than for the shell expression that produces it.
func expandInstallerConstants(script, text string) string {
	pattern := regexp.MustCompile(`(?m)^readonly ([A-Z_]+)="([^"]*)"`)
	values := map[string]string{}
	for _, match := range pattern.FindAllStringSubmatch(script, -1) {
		values[match[1]] = match[2]
	}
	// Two passes: a constant may be defined in terms of another one, as
	// CACHED_INSTALLER is in terms of SUPPORT_DIR.
	for pass := 0; pass < 2; pass++ {
		for name, value := range values {
			expanded := value
			for inner, innerValue := range values {
				expanded = strings.ReplaceAll(expanded, "$"+inner, innerValue)
			}
			values[name] = expanded
			text = strings.ReplaceAll(text, "$"+name, expanded)
		}
	}
	return text
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

// The unit names the environment file without a leading dash, so systemd
// refuses to start when it is missing. UPGRADE_EXISTING is set when the unit or
// the binary is present, and uninstall removes the environment file — so a host
// part-way between the two is an "upgrade" with nothing to read, and the panel
// never gets far enough to say why:
//
//	gre-panel.service: Failed to load environment files: No such file or directory
//
// Measured on server B, which sat in exactly that state.
func TestTheEnvironmentFileIsWrittenWheneverItIsMissing(t *testing.T) {
	script := readScript(t, "install.sh")

	if !strings.Contains(script, `if [[ $UPGRADE_EXISTING -eq 0 || ! -f "$ENV_PATH" ]]; then`) {
		t.Error("the environment file is only written on a fresh install, so an upgrade that " +
			"finds it missing leaves systemd unable to start the service")
	}
	// And it must be written before the service is started, not after.
	write := strings.Index(script, "\n  write_env_file\n")
	start := strings.Index(script, `step "Starting the service"`)
	if write < 0 || start < 0 {
		t.Fatal("could not locate the write and the start to compare their order")
	}
	if write > start {
		t.Error("the environment file is written after the service is started, which is too late " +
			"for the start that needs it")
	}
}

// Bash resolves a function name when the call runs, not when the file ends, so
// a helper defined below its first caller is a plain "command not found".
//
// That happened: reordering moved the resolve_address call earlier and left the
// definition where it was. Every call took the failure branch, and the message
// blamed the database - "the kept database would not report a port" - for a
// function that had never been reached. Nothing noticed, because bash parses a
// call to a not-yet-defined function without complaint, and the failure looked
// exactly like the failure it was meant to report.
//
// Scoped to the one function this went wrong for. A general "every function is
// defined before its first call" analyser was written first and quietly passed
// the mutation that moves this definition to the end of the file: telling a
// top-level call from one inside another function needs brace tracking that a
// regex does not do, and a check that cannot fail is worse than none.
func TestResolveAddressIsDefinedBeforeItIsCalled(t *testing.T) {
	script := readScript(t, "install.sh")

	define := strings.Index(script, "\nresolve_address() {")
	call := strings.Index(script, "if resolve_address; then")
	if define < 0 {
		t.Fatal("resolve_address is not defined at all")
	}
	if call < 0 {
		t.Fatal("resolve_address is never called")
	}
	if define > call {
		t.Errorf("resolve_address is called at byte %d but defined at byte %d; bash resolves the "+
			"name when the call runs, so that call is a 'command not found' and the branch it "+
			"guards never executes", call, define)
	}
}
