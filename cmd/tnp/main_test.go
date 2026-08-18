package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/address"
	"github.com/drs/gre-panel/internal/config"
)

func TestGlobalFlagsAreAcceptedOnEitherSideOfTheSubcommand(t *testing.T) {
	for _, args := range [][]string{
		{"--json", "status"},
		{"status", "--json"},
		{"--yes", "set-port", "9000", "--json"},
		{"set-port", "--json", "9000", "--yes"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			a := newApp()
			command, rest, err := a.parseGlobals(args)
			if err != nil {
				t.Fatalf("parsing: %v", err)
			}
			if !a.jsonOut {
				t.Error("--json was not recognised")
			}
			switch command {
			case "status":
				if len(rest) != 0 {
					t.Errorf("leftover arguments %v", rest)
				}
			case "set-port":
				if len(rest) != 1 || rest[0] != "9000" {
					t.Errorf("the port did not survive parsing: %v", rest)
				}
				if !a.assumeYes {
					t.Error("--yes was not recognised")
				}
			default:
				t.Errorf("command = %q", command)
			}
		})
	}
}

// A bare `tnp --json` would open the menu, which has no machine-readable form.
// Something parsing the output would see a hang rather than an error.
func TestJsonWithNoSubcommandIsRefused(t *testing.T) {
	a := newApp()
	if _, _, err := a.parseGlobals([]string{"--json"}); err == nil {
		t.Error("--json with no subcommand was accepted")
	}
}

func TestEnvFileFlagRedirectsTheWholeCli(t *testing.T) {
	a := newApp()
	command, _, err := a.parseGlobals([]string{"--env-file", "/tmp/somewhere.env", "status"})
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if command != "status" || a.envPath != "/tmp/somewhere.env" {
		t.Errorf("command %q envPath %q", command, a.envPath)
	}
	if _, _, err := a.parseGlobals([]string{"--env-file"}); err == nil {
		t.Error("--env-file with no value was accepted")
	}
}

// The menu is supposed to be a thin wrapper over the subcommands. If an option
// exists only in the menu, it cannot be driven non-interactively and cannot be
// proven; that is the failure this guards.
func TestEveryMenuOptionIsAlsoASubcommand(t *testing.T) {
	usage := &bytes.Buffer{}
	a := &app{out: usage, err: usage}
	a.usage()
	help := usage.String()

	// Every subcommand dispatch knows about, taken from the switch itself so a
	// new one cannot be added without appearing here.
	subcommands := []string{
		"status", "url", "set-port", "set-web-path", "set-username", "reset-password",
		"restart", "logs", "update", "reinstall", "uninstall",
	}
	for _, name := range subcommands {
		if !strings.Contains(help, "tnp "+name) {
			t.Errorf("the subcommand %q is not in the help text, so nobody can find it", name)
		}
	}

	items := menuItems()
	if len(items) < len(subcommands)-1 {
		t.Errorf("the menu offers %d options against %d subcommands; something is only reachable "+
			"by typing it", len(items), len(subcommands))
	}
	// Every menu entry has to do something.
	for i, item := range items {
		if item.label == "" || item.run == nil {
			t.Errorf("menu item %d is incomplete: %+v", i, item)
		}
	}
}

// The exit codes are a contract: a script wrapping this needs to tell a change
// that was rolled back from one that could not be.
func TestTheExitCodesAreDocumentedAndDistinct(t *testing.T) {
	codes := map[string]int{
		"exitOK": exitOK, "exitUsage": exitUsage, "exitNotRoot": exitNotRoot,
		"exitFailed": exitFailed, "exitRolledBack": exitRolledBack,
		"exitRollbackFailed": exitRollbackFailed, "exitCancelled": exitCancelled,
	}
	seen := map[int]string{}
	for name, code := range codes {
		if other, clash := seen[code]; clash {
			t.Errorf("%s and %s are both %d, so a caller cannot tell them apart", other, name, code)
		}
		seen[code] = name
	}

	usage := &bytes.Buffer{}
	a := &app{out: usage, err: usage}
	a.usage()
	// The heading is located rather than assumed. This used to slice from the
	// index of "Exit codes:" without checking it had been found, so renaming
	// the heading panicked the test with a slice bound of -1 instead of failing
	// it with something a reader could act on.
	text := usage.String()
	at := strings.Index(text, "Exit codes")
	if at < 0 {
		t.Fatal("the help text has no exit-code section, so none of the codes below were checked")
	}
	documented := regexp.MustCompile(`\b(\d+)\b`).FindAllString(text[at:], -1)
	found := map[string]bool{}
	for _, d := range documented {
		found[d] = true
	}
	for name, code := range codes {
		if !found[fmt.Sprint(code)] {
			t.Errorf("exit code %d (%s) is not documented in the help text", code, name)
		}
	}
}

func TestHelpAndVersionNeedNoRootAndNoInstallation(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"version"}} {
		out := &bytes.Buffer{}
		a := &app{out: out, err: out, envPath: filepath.Join(t.TempDir(), "absent.env")}
		command, rest, err := a.parseGlobals(args)
		if err != nil {
			t.Fatalf("parsing %v: %v", args, err)
		}
		if code := a.dispatch(context.Background(), command, rest); code != exitOK {
			t.Errorf("tnp %v exited %d, want 0", args, code)
		}
		if out.Len() == 0 {
			t.Errorf("tnp %v printed nothing", args)
		}
	}
}

// --json puts the machine-readable answer on stdout and nothing else, so a
// caller can pipe it straight into a parser.
func TestJsonOutputIsAloneOnStdout(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	a := &app{out: stdout, err: stderr, jsonOut: true}

	a.sayf("this is for a human")
	a.emit(map[string]string{"answer": "42"}, func() { t.Error("the human form ran with --json set") })

	if strings.Contains(stdout.String(), "human") {
		t.Errorf("human output reached stdout: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), `"answer": "42"`) {
		t.Errorf("stdout does not carry the JSON: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "human") {
		t.Errorf("the human line did not reach stderr: %q", stderr.String())
	}
}

// Without --json the human form runs and stdout stays empty, so `tnp status`
// in a terminal reads as prose and `tnp status | jq` still gets nothing
// confusing.
func TestWithoutJsonTheHumanFormRuns(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	a := &app{out: stdout, err: stderr}

	ran := false
	a.emit(map[string]string{"answer": "42"}, func() { ran = true })
	if !ran {
		t.Error("the human form did not run")
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout is not empty: %q", stdout.String())
	}
}

// Setting the address to what it already is must be a no-op that says so,
// rather than a restart nobody asked for.
func TestSettingTheAddressToWhatItAlreadyIsChangesNothing(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	change, err := a.setAddress(ctx, 18443, "abc123")
	if err != nil {
		t.Fatalf("setting: %v", err)
	}
	if !change.Applied || change.Restarted {
		t.Errorf("change = %+v, want applied with no restart", change)
	}
	if !strings.Contains(change.Detail, "already") {
		t.Errorf("detail = %q, want it to say nothing needed doing", change.Detail)
	}

	// And nothing was written: the stored row should not have appeared.
	database, err := a.openDB(mustEnv(t, a))
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	defer database.Close()
	stored, err := address.Load(ctx, database)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if stored.Exists {
		t.Error("a no-op change wrote a row")
	}
}

func TestValidatePortRefusesTheImpossibleBeforeAnythingIsWritten(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")
	env := mustEnv(t, a)

	for _, port := range []int{0, -1, 65536, 70000} {
		if err := a.validatePort(ctx, env, 18443, port); err == nil {
			t.Errorf("port %d was accepted", port)
		}
	}
	if err := a.validatePort(ctx, env, 18443, 18443); err != nil {
		t.Errorf("the port already in use by the panel itself was refused: %v", err)
	}
}

// A web path the router cannot serve must be refused by the CLI too, using the
// panel's own normaliser rather than a second copy of the rules.
func TestTheCliUsesThePanelsOwnWebPathRules(t *testing.T) {
	for _, bad := range []string{"has/slash", "..", "has space", "has%percent"} {
		if _, err := config.NormalizeWebPath(bad); err == nil {
			t.Errorf("%q is accepted by the shared normaliser; this test's premise is wrong", bad)
		}
	}
	for input, want := range map[string]string{
		"":          "",
		"/abc123/":  "abc123",
		"  ":        "",
		"a.b_c~d-e": "a.b_c~d-e",
	} {
		got, err := config.NormalizeWebPath(input)
		if err != nil || got != want {
			t.Errorf("NormalizeWebPath(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func mustEnv(t *testing.T, a *app) *panelEnv {
	t.Helper()
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		t.Fatalf("reading the environment: %v", err)
	}
	return env
}

// The paths the CLI acts on are the ones the installer creates. They are
// repeated in two languages, so a test holds them together; scripts/
// installer_contract_test.go checks the same thing from the installer's side.
func TestTheCliAndTheInstallerAgreeAboutWhereThingsAre(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "install.sh"))
	if err != nil {
		t.Fatalf("reading the installer: %v", err)
	}
	body := strings.ReplaceAll(string(script), "\r\n", "\n")
	// The installer builds some of these out of its own variables, so the
	// literal never appears. Expanding its readonly declarations compares the
	// paths that end up on the machine rather than the expressions that produce
	// them — which is what has to agree.
	body = expandShellConstants(body)

	for name, path := range map[string]string{
		"the panel binary":      panelBinary,
		"the CLI binary":        cliBinary,
		"the data directory":    dataDir,
		"the unit file":         unitPath,
		"the support directory": supportDir,
		"the cached installer":  cachedInstall,
	} {
		if !strings.Contains(body, path) {
			t.Errorf("the CLI expects %s at %s, and the installer never mentions that path",
				name, path)
		}
	}
	if !strings.Contains(body, DefaultReleaseBase) {
		t.Errorf("the CLI defaults to the release base %s, which the installer does not use",
			DefaultReleaseBase)
	}
	if !strings.Contains(body, `SERVICE_NAME="`+serviceName+`"`) {
		t.Errorf("the CLI manages the service %q, which the installer does not install", serviceName)
	}
}

// expandShellConstants replaces the installer's readonly variables with their
// values throughout the script, twice, since one may be defined in terms of
// another.
func expandShellConstants(script string) string {
	pattern := regexp.MustCompile(`(?m)^readonly ([A-Z_]+)="([^"]*)"`)
	values := map[string]string{}
	for _, match := range pattern.FindAllStringSubmatch(script, -1) {
		values[match[1]] = match[2]
	}
	for pass := 0; pass < 2; pass++ {
		for name, value := range values {
			for inner, innerValue := range values {
				value = strings.ReplaceAll(value, "$"+inner, innerValue)
			}
			values[name] = value
			script = strings.ReplaceAll(script, "$"+name, value)
		}
	}
	return script
}

func TestTheCliIsBuiltForTheHostItManages(t *testing.T) {
	// A reminder in the suite rather than a comment: the terminal handling has
	// a non-unix stub so a Windows workstation can build and vet the package,
	// and that stub must never be what a real installation runs.
	if runtime.GOOS == "linux" && !isTerminalStubAbsent() {
		t.Error("the non-unix terminal stub was compiled into a Linux build")
	}
}

// isTerminalStubAbsent reports whether the real implementation is present, by
// asking whether reading a password from a non-terminal fails the way the unix
// implementation fails rather than the way the stub does.
func isTerminalStubAbsent() bool {
	f, err := os.Open(os.DevNull)
	if err != nil {
		return true
	}
	defer f.Close()
	_, err = readPasswordNoEcho(f)
	return err == nil || !strings.Contains(err.Error(), "not supported on this platform")
}
