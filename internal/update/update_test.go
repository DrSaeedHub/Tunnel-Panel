package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/exec"
)

// The rule this whole feature rests on: a build that did not come from a
// release is never told a release is newer than it. A development build stamps
// itself 0.0.0-<sha>, and comparing that numerically would tell every developer
// running one that they are three versions behind something they are ahead of.
func TestNewerOnlyAnswersForReleaseBuilds(t *testing.T) {
	cases := []struct {
		current, latest string
		want            bool
		why             string
	}{
		{"v0.1.5", "v0.1.6", true, "a patch bump is an update"},
		{"v0.1.5", "v0.2.0", true, "a minor bump is an update"},
		{"v0.1.5", "v1.0.0", true, "a major bump is an update"},
		{"v0.1.5", "v0.1.5", false, "the same version is not an update"},
		{"v0.1.6", "v0.1.5", false, "an older release is not an update"},
		{"0.1.5", "v0.1.6", true, "the v is optional on either side"},
		{"0.0.0-abc1234", "v0.1.6", false, "an untagged build came from no release"},
		{"dev", "v0.1.6", false, "a bare development build cannot be compared"},
		{"v0.1.5", "not-a-version", false, "an unreadable tag is not an update"},
		{"v0.1.5", "", false, "no answer from the release host is not an update"},
		{"v0.2.0-rc1", "v0.2.0", false, "a prerelease build came from no release either"},
	}
	for _, c := range cases {
		if got := Newer(c.current, c.latest); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v: %s", c.current, c.latest, got, c.want, c.why)
		}
	}
}

func TestParseVersionRejectsWhatItCannotOrder(t *testing.T) {
	for _, bad := range []string{"", "v", "1.2", "1.2.3.4", "v1.x.3", "v-1.2.3", "latest"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) claimed to understand it", bad)
		}
	}
	v, ok := ParseVersion("v1.2.3-rc2")
	if !ok || v.Major != 1 || v.Minor != 2 || v.Patch != 3 || v.Pre != "rc2" || v.Raw != "v1.2.3-rc2" {
		t.Fatalf("ParseVersion(v1.2.3-rc2) = %+v, %v", v, ok)
	}
	if v.IsRelease() {
		t.Error("a prerelease reported itself as a release build")
	}
}

// The check has to follow the installation. A fork's panel that checked this
// repository would offer its operator a version its own release base does not
// serve, and the install would then fail on a 404.
func TestTheRepositoryFollowsTheReleaseBase(t *testing.T) {
	cases := map[string]string{
		DefaultReleaseBase: "DrSaeedHub/Tunnel-Panel",
		"https://github.com/someone/their-fork/releases/download": "someone/their-fork",
		// Not a GitHub URL, and an offline bundle's local directory: neither
		// names a repository, and the default is the only place left to ask.
		"https://mirror.example.com/panel": "DrSaeedHub/Tunnel-Panel",
		"/opt/gre-panel-bundle/artifacts":  "DrSaeedHub/Tunnel-Panel",
		"":                                 "DrSaeedHub/Tunnel-Panel",
	}
	for base, want := range cases {
		if got := repositoryOf(base); got != want {
			t.Errorf("repositoryOf(%q) = %q, want %q", base, got, want)
		}
	}
}

// fixedSettings stands in for the settings store.
type fixedSettings struct {
	enabled bool
	hours   int64
}

func (f fixedSettings) Bool(string) bool { return f.enabled }
func (f fixedSettings) Int(string) int64 { return f.hours }

func releaseServer(t *testing.T, tag string, hits *int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if r.Header.Get("User-Agent") == "" {
			t.Error("the check sent no User-Agent, which the release host refuses")
		}
		_ = json.NewEncoder(w).Encode(githubRelease{
			TagName: tag, Name: "Panel " + tag,
			HTMLURL: "https://example.invalid/releases/" + tag,
			Body:    "Fixed things.", PublishedAt: "2026-08-01T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func TestAnAvailableUpdateIsReportedWithWhereItCameFrom(t *testing.T) {
	hits := 0
	server := releaseServer(t, "v0.2.0", &hits)

	checker := NewChecker(CheckerDeps{
		CurrentVersion: "v0.1.5", APIURL: server.URL, Client: server.Client(),
		Settings: fixedSettings{enabled: true, hours: 6},
	})

	status := checker.Refresh(context.Background())
	if !status.UpdateAvailable {
		t.Fatalf("no update reported: %+v", status)
	}
	if status.Latest.Version != "v0.2.0" || status.Latest.Notes == "" {
		t.Errorf("the release was not carried back whole: %+v", status.Latest)
	}
	if status.CheckedAt == "" || status.Error != "" {
		t.Errorf("a successful check reported %q at %q", status.Error, status.CheckedAt)
	}
	if status.Source != "DrSaeedHub/Tunnel-Panel" {
		t.Errorf("source = %q", status.Source)
	}
}

// A cached answer is the whole reason this is not a passthrough: every
// dashboard load asks, and every one of those must not become a request to the
// release host.
func TestTheAnswerIsCachedForTheConfiguredInterval(t *testing.T) {
	hits := 0
	server := releaseServer(t, "v0.2.0", &hits)

	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	checker := NewChecker(CheckerDeps{
		CurrentVersion: "v0.1.5", APIURL: server.URL, Client: server.Client(),
		Settings: fixedSettings{enabled: true, hours: 6},
		Now:      func() time.Time { return now },
	})

	checker.Refresh(context.Background())
	if hits != 1 {
		t.Fatalf("the first check made %d requests, want 1", hits)
	}

	for i := 0; i < 5; i++ {
		if status := checker.Status(context.Background()); !status.UpdateAvailable {
			t.Fatal("the cached answer was lost")
		}
	}
	if hits != 1 {
		t.Errorf("reading the status made %d requests; the cache is not holding", hits)
	}

	// Past the interval, the next read refreshes — in the background, so the
	// read itself still answers from the cache.
	now = now.Add(7 * time.Hour)
	checker.Status(context.Background())
	waitFor(t, func() bool { return hits == 2 }, "the stale answer was never refreshed")
}

func TestCheckingIsSkippedWhenTheOperatorTurnedItOff(t *testing.T) {
	hits := 0
	server := releaseServer(t, "v0.2.0", &hits)
	checker := NewChecker(CheckerDeps{
		CurrentVersion: "v0.1.5", APIURL: server.URL, Client: server.Client(),
		Settings: fixedSettings{enabled: false, hours: 6},
	})

	status := checker.Status(context.Background())
	if hits != 0 {
		t.Errorf("automatic checking is off and the release host was asked %d times", hits)
	}
	if status.Enabled {
		t.Error("the status claims automatic checking is on")
	}

	// The explicit button still works: what the setting turns off is the panel
	// reaching out by itself.
	if status = checker.Refresh(context.Background()); !status.UpdateAvailable {
		t.Errorf("an explicit check was refused: %+v", status)
	}
}

// A panel with no outbound access is an ordinary installation, not a fault. It
// must report the failure and keep answering.
func TestAnUnreachableReleaseHostIsReportedNotFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	checker := NewChecker(CheckerDeps{
		CurrentVersion: "v0.1.5", APIURL: server.URL, Client: server.Client(),
		Settings: fixedSettings{enabled: true, hours: 6},
	})
	status := checker.Refresh(context.Background())
	if status.Error == "" {
		t.Fatal("a failed check reported no error")
	}
	if status.UpdateAvailable {
		t.Error("a failed check claimed an update is available")
	}
	if status.CurrentVersion != "v0.1.5" {
		t.Errorf("the running version was lost: %q", status.CurrentVersion)
	}
}

// The footer shows a version and a state; "no update" and "cannot be compared"
// look identical there unless the backend says which it is.
func TestADevelopmentBuildIsToldWhyItIsNotOffered(t *testing.T) {
	hits := 0
	server := releaseServer(t, "v0.2.0", &hits)
	checker := NewChecker(CheckerDeps{
		CurrentVersion: "0.0.0-abc1234", APIURL: server.URL, Client: server.Client(),
		Settings: fixedSettings{enabled: true, hours: 6},
	})

	status := checker.Refresh(context.Background())
	if status.UpdateAvailable {
		t.Fatal("a development build was offered a release as an update")
	}
	if status.Note == "" {
		t.Error("nothing explained why the newer release was not offered")
	}
	if status.Latest.Version != "v0.2.0" {
		t.Errorf("the latest release was withheld: %+v", status.Latest)
	}
}

// ---------------------------------------------------------------- applying

func newApplier(t *testing.T, runner exec.Runner, adjust func(*ApplierDeps)) (*Applier, string) {
	t.Helper()
	dir := t.TempDir()
	cli := filepath.Join(dir, "tnp")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("writing the fake CLI: %v", err)
	}
	deps := ApplierDeps{
		CurrentVersion: "v0.1.5", DataDir: dir, CLIBin: cli,
		SystemdRunBin: "/usr/bin/systemd-run", SystemctlBin: "/usr/bin/systemctl",
		JournalctlBin: "/usr/bin/journalctl", UnderSystemd: true,
		Runner: runner, Euid: func() int { return 0 },
	}
	if adjust != nil {
		adjust(&deps)
	}
	return NewApplier(deps), dir
}

// The install must not be a child of the panel: the installer restarts
// gre-panel.service, and systemd kills the whole cgroup when it does. This is
// the assertion that keeps the launch in a transient unit of its own.
func TestTheInstallerRunsInATransientUnitOutsideThePanel(t *testing.T) {
	runner := exec.NewFakeRunner()
	applier, dir := newApplier(t, runner, nil)

	state, err := applier.Start(context.Background(), "v0.2.0", "admin")
	if err != nil {
		t.Fatalf("starting the update failed: %v", err)
	}
	if state.Stage != StageRunning {
		t.Fatalf("stage = %q, want running", state.Stage)
	}

	launch := ""
	for _, line := range runner.CommandLines() {
		if strings.Contains(line, "systemd-run") {
			launch = line
		}
	}
	if launch == "" {
		t.Fatalf("nothing was launched through systemd-run: %v", runner.CommandLines())
	}
	for _, want := range []string{
		"--unit=" + UnitName,
		// Without this the transient unit is garbage collected the moment it
		// ends, and the panel it restarted comes back with no way to find out
		// whether the update worked.
		"--remain-after-exit",
		"tnp update --yes --version v0.2.0",
	} {
		if !strings.Contains(launch, want) {
			t.Errorf("the launch is missing %q:\n  %s", want, launch)
		}
	}

	// The record has to be on disk before the restart, because the process that
	// started the update is not the one that will report on it.
	body, err := os.ReadFile(filepath.Join(dir, "update-state.json"))
	if err != nil {
		t.Fatalf("no state was recorded: %v", err)
	}
	var stored State
	if err := json.Unmarshal(body, &stored); err != nil {
		t.Fatalf("the state file is not readable: %v", err)
	}
	if stored.Stage != StageRunning || stored.TargetVersion != "v0.2.0" ||
		stored.FromVersion != "v0.1.5" || stored.StartedBy != "admin" {
		t.Errorf("the stored state does not describe the run: %+v", stored)
	}
}

// A second press while one is going would run two installers over one binary.
func TestASecondUpdateIsRefusedWhileOneIsRunning(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Handler = func(argv []string) (exec.Result, error) {
		if strings.Contains(strings.Join(argv, " "), "systemctl show") {
			return exec.Result{Stdout: "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\n"}, nil
		}
		return exec.Result{}, nil
	}
	applier, _ := newApplier(t, runner, nil)

	if _, err := applier.Start(context.Background(), "v0.2.0", "admin"); err != nil {
		t.Fatalf("the first update failed: %v", err)
	}
	if _, err := applier.Start(context.Background(), "v0.2.0", "admin"); err != ErrUpdateRunning {
		t.Fatalf("the second update returned %v, want ErrUpdateRunning", err)
	}
}

// What the panel says after it comes back is read off the unit, because the
// process that knew is gone.
func TestTheOutcomeIsReadBackFromTheUnitAfterTheRestart(t *testing.T) {
	cases := []struct {
		name   string
		show   string
		want   Stage
		hasWhy bool
	}{
		{"finished cleanly", "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\n",
			StageSucceeded, false},
		{"installer failed", "LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\n",
			StageFailed, true},
		{"exited non-zero", "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=3\n",
			StageFailed, true},
		{"still going", "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\n",
			StageRunning, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			show := "LoadState=not-found\n"
			runner := exec.NewFakeRunner()
			runner.Handler = func(argv []string) (exec.Result, error) {
				if strings.Contains(strings.Join(argv, " "), "systemctl show") {
					return exec.Result{Stdout: show}, nil
				}
				return exec.Result{}, nil
			}
			applier, dir := newApplier(t, runner, nil)

			if _, err := applier.Start(context.Background(), "v0.2.0", "admin"); err != nil {
				t.Fatalf("starting the update failed: %v", err)
			}
			// What the installer wrote is what an operator reads when it fails.
			if err := os.WriteFile(filepath.Join(dir, "update.log"), []byte("step: downloading\nstep: done\n"), 0o600); err != nil {
				t.Fatalf("writing the log: %v", err)
			}
			show = c.show

			state := applier.State(context.Background())
			if state.Stage != c.want {
				t.Fatalf("stage = %q, want %q", state.Stage, c.want)
			}
			if c.hasWhy && state.Error == "" {
				t.Error("a failed update explained nothing")
			}
			if len(state.Log) == 0 {
				t.Error("the installer's output was not carried back")
			}
			// The decision is written down, so the next reader does not make it
			// again from a unit that may have been cleaned up by then.
			if c.want != StageRunning {
				if again := applier.State(context.Background()); again.Stage != c.want {
					t.Errorf("the resolved stage was not kept: %q", again.Stage)
				}
			}
		})
	}
}

// The installer colours its progress lines. A terminal renders that; the
// log pane in the browser renders the escape bytes themselves, so what the
// operator reads is the evidence wrapped in `[1;34m`. They come off on the
// way out, where both sources of the log pass through.
func TestTheInstallersColoursDoNotReachTheBrowser(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Handler = func(argv []string) (exec.Result, error) {
		if strings.Contains(strings.Join(argv, " "), "systemctl show") {
			return exec.Result{Stdout: "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\nExecMainStatus=0\n"}, nil
		}
		return exec.Result{}, nil
	}
	applier, dir := newApplier(t, runner, nil)

	if _, err := applier.Start(context.Background(), "v0.2.0", "admin"); err != nil {
		t.Fatalf("starting the update failed: %v", err)
	}

	coloured := "\x1b[1;34m==>\x1b[0m Installing to /usr/local/bin/gre-panel\n" +
		"\x1b[1;32mdone\x1b[0m\n"
	if err := os.WriteFile(filepath.Join(dir, "update.log"), []byte(coloured), 0o600); err != nil {
		t.Fatalf("writing the log: %v", err)
	}

	state := applier.State(context.Background())
	if len(state.Log) != 2 {
		t.Fatalf("log = %q, want the two lines the installer wrote", state.Log)
	}
	if state.Log[0] != "==> Installing to /usr/local/bin/gre-panel" {
		t.Errorf("log[0] = %q, want the line without its colours", state.Log[0])
	}
	for _, line := range state.Log {
		if strings.ContainsRune(line, 0x1b) {
			t.Errorf("an escape byte survived into %q", line)
		}
	}
}

// A host that rebooted mid-update has no unit left to ask. The running version
// is then the only evidence, and it is good evidence.
func TestAVanishedUnitIsResolvedFromTheRunningVersion(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Handler = func(argv []string) (exec.Result, error) {
		if strings.Contains(strings.Join(argv, " "), "systemctl show") {
			return exec.Result{Stdout: "LoadState=not-found\nActiveState=inactive\n"}, nil
		}
		return exec.Result{}, nil
	}
	applier, dir := newApplier(t, runner, nil)
	if _, err := applier.Start(context.Background(), "v0.2.0", "admin"); err != nil {
		t.Fatalf("starting the update failed: %v", err)
	}

	// The panel that comes back is a different build, which is what an update
	// is. A fresh applier is what that process would construct.
	restarted := NewApplier(ApplierDeps{
		CurrentVersion: "v0.2.0", DataDir: dir, CLIBin: filepath.Join(dir, "tnp"),
		SystemdRunBin: "/usr/bin/systemd-run", SystemctlBin: "/usr/bin/systemctl",
		UnderSystemd: true, Runner: runner, Euid: func() int { return 0 },
	})
	if state := restarted.State(context.Background()); state.Stage != StageSucceeded {
		t.Fatalf("stage = %q, want succeeded: %+v", state.Stage, state)
	}
}

func TestAnUpdateThatNeverFinishesIsGivenUpOn(t *testing.T) {
	runner := exec.NewFakeRunner()
	runner.Handler = func(argv []string) (exec.Result, error) {
		if strings.Contains(strings.Join(argv, " "), "systemctl show") {
			return exec.Result{Stdout: "LoadState=loaded\nActiveState=active\nSubState=running\n"}, nil
		}
		return exec.Result{}, nil
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	applier, _ := newApplier(t, runner, func(d *ApplierDeps) {
		d.Now = func() time.Time { return now }
	})
	if _, err := applier.Start(context.Background(), "latest", "admin"); err != nil {
		t.Fatalf("starting the update failed: %v", err)
	}

	now = now.Add(maxRun + time.Minute)
	state := applier.State(context.Background())
	if state.Stage != StageFailed || state.Error == "" {
		t.Fatalf("a run stuck for half an hour reported %q / %q", state.Stage, state.Error)
	}
}

// Every one of these is a real installation, and each deserves the reason
// rather than a button that fails when it is pressed.
func TestWhatCannotUpdateSaysWhy(t *testing.T) {
	cases := []struct {
		name   string
		adjust func(*ApplierDeps)
		needle string
	}{
		{"not under systemd", func(d *ApplierDeps) { d.UnderSystemd = false }, "systemd"},
		{"no systemd-run", func(d *ApplierDeps) { d.SystemdRunBin = "" }, "systemd-run"},
		{"no CLI", func(d *ApplierDeps) { d.CLIBin = "/nonexistent/tnp" }, "tnp"},
		{"not root", func(d *ApplierDeps) { d.Euid = func() int { return 1000 } }, "root"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			applier, _ := newApplier(t, exec.NewFakeRunner(), c.adjust)
			err := applier.Available()
			if err == nil {
				t.Fatal("this installation claims it can update itself")
			}
			var unavailable *Unavailable
			if !asUnavailable(err, &unavailable) {
				t.Fatalf("error type = %T, want *Unavailable", err)
			}
			if !strings.Contains(strings.ToLower(err.Error()), c.needle) {
				t.Errorf("the reason does not mention %q: %s", c.needle, err)
			}
			if _, startErr := applier.Start(context.Background(), "latest", "admin"); startErr == nil {
				t.Error("starting an update succeeded on a host that cannot")
			}
		})
	}
}

func TestOnlyAVersionOrLatestIsAccepted(t *testing.T) {
	applier, _ := newApplier(t, exec.NewFakeRunner(), nil)
	for _, bad := range []string{"; reboot", "main", "v0.1", "../../etc"} {
		if _, err := applier.Start(context.Background(), bad, "admin"); err == nil {
			t.Errorf("%q was accepted as a version to install", bad)
		}
	}
}

func asUnavailable(err error, target **Unavailable) bool {
	u, ok := err.(*Unavailable)
	if ok {
		*target = u
	}
	return ok
}

func waitFor(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}
