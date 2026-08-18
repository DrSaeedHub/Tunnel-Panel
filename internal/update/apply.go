package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/exec"
)

// Stage is where an update has got to. It is deliberately coarse: the detail
// lives in the log, and an operator watching a progress dialog needs to know
// whether it is going, done, or broken.
type Stage string

const (
	// StageIdle is a panel that has never updated itself from here.
	StageIdle Stage = "idle"
	// StageRunning covers everything from the installer being launched to it
	// exiting, including the stretch where the panel itself is restarted and
	// this process is not the one that started the update.
	StageRunning   Stage = "running"
	StageSucceeded Stage = "succeeded"
	StageFailed    Stage = "failed"
)

// UnitName is the transient service the installer runs inside.
//
// The name is fixed rather than generated so that a panel which restarted in
// the middle of an update — which is what an update does — can find the run it
// started before it was replaced.
const UnitName = "gre-panel-update"

// maxRun bounds how long a run may stay unresolved. The installer downloads a
// binary, writes a unit and waits for the panel to answer; twenty minutes is
// far beyond any of that and short enough that a stuck run does not leave the
// button disabled forever.
const maxRun = 20 * time.Minute

// logTailLines is how much of the installer's output is carried back to the
// browser. Enough to show what failed, not so much that the status endpoint
// becomes a log viewer.
const logTailLines = 200

// State is one update run, as it is stored and as it is reported.
type State struct {
	Stage Stage `json:"stage"`
	// TargetVersion is what was asked for, which may be the literal "latest".
	TargetVersion string `json:"target_version,omitempty"`
	// FromVersion is the build that was running when the update started, so a
	// finished run can say what it changed.
	FromVersion string `json:"from_version,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Error       string `json:"error,omitempty"`
	Unit        string `json:"unit,omitempty"`
	// StartedBy is the operator who pressed the button, for the same reason the
	// audit log records it: an update that arrives unannounced has an author.
	StartedBy string `json:"started_by,omitempty"`
	// Log is the tail of the installer's own output. It is not stored in the
	// state file; it is read from the log when the state is reported.
	Log []string `json:"log,omitempty"`
}

// Running reports whether an update is in flight.
func (s State) Running() bool { return s.Stage == StageRunning }

// ApplierDeps is what an Applier needs.
type ApplierDeps struct {
	// CurrentVersion is the running build, which is how a finished run is told
	// from one that changed nothing.
	CurrentVersion string
	// DataDir holds the state file and the installer log. It is the one
	// directory the panel's unit is allowed to write to.
	DataDir string
	// CLIBin is the tnp binary that fronts the installer.
	CLIBin string
	// SystemdRunBin launches the installer outside this service. Empty means
	// this host has no systemd-run, and updating from the panel is not offered.
	SystemdRunBin string
	// SystemctlBin reads back what the transient unit did.
	SystemctlBin string
	// JournalctlBin is the fallback source of the installer's output on a
	// systemd too old to redirect a transient unit's output to a file.
	JournalctlBin string
	// UnderSystemd gates the whole feature: without it there is no unit to
	// restart and no transient scope to run in.
	UnderSystemd bool
	Runner       exec.Runner
	Log          *slog.Logger
	Now          func() time.Time
	// Euid answers who the panel is running as. Injectable so the root check
	// can be exercised on a machine where the answer is fixed.
	Euid func() int
}

// Applier starts an update and reports on the one it started.
//
// It does not install anything itself. It launches `tnp update` in a transient
// systemd service, which is the only way this can work at all: the installer
// restarts gre-panel.service, and anything the panel forked would be a child in
// the panel's own cgroup, killed by that restart halfway through writing a
// binary. A transient unit belongs to systemd, not to the panel, so it survives
// the restart of the service that asked for it. The panel's own sandbox is the
// second reason — ProtectSystem=full makes /usr read-only for this process and
// everything under it, and the installer's whole job is writing to /usr/local.
type Applier struct {
	current    string
	statePath  string
	logPath    string
	cli        string
	systemdRun string
	systemctl  string
	journalctl string
	underSysd  bool
	runner     exec.Runner
	log        *slog.Logger
	now        func() time.Time
	euid       func() int

	// mu serialises the read-modify-write of the state file. Two operators
	// pressing the button at the same moment must not produce two installers.
	mu sync.Mutex
}

// NewApplier builds an applier. Nothing is probed here: what the host can do is
// answered by Available, so the reason is available to a caller rather than
// disappearing into a nil.
func NewApplier(d ApplierDeps) *Applier {
	now := d.Now
	if now == nil {
		now = time.Now
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	euid := d.Euid
	if euid == nil {
		euid = os.Geteuid
	}
	return &Applier{
		current:    d.CurrentVersion,
		statePath:  filepath.Join(d.DataDir, "update-state.json"),
		logPath:    filepath.Join(d.DataDir, "update.log"),
		cli:        d.CLIBin,
		systemdRun: d.SystemdRunBin,
		systemctl:  d.SystemctlBin,
		journalctl: d.JournalctlBin,
		underSysd:  d.UnderSystemd,
		runner:     d.Runner,
		log:        log,
		now:        now,
		euid:       euid,
	}
}

// ErrUpdateRunning is returned when a second update is asked for while one is
// still going.
var ErrUpdateRunning = errors.New("an update is already running")

// Unavailable explains why this installation cannot update itself. It is an
// error type rather than a bare string so a handler can answer 503 with the
// reason rather than a generic failure.
type Unavailable struct{ Reason string }

func (e *Unavailable) Error() string { return e.Reason }

// Available reports whether the button can be offered, and why not when it
// cannot. Every reason here is a real installation: a development panel run
// from a checkout, a container with no systemd, an install whose CLI was
// removed.
func (a *Applier) Available() error {
	switch {
	case !a.underSysd:
		return &Unavailable{"This panel is not running under systemd, so it cannot restart itself into a new version. Update it the way it was installed."}
	case a.runner == nil:
		return &Unavailable{"This instance cannot run commands, so it cannot start an update."}
	case a.systemdRun == "":
		return &Unavailable{"systemd-run was not found on this host, and the update has to run outside the panel's own service to survive the restart in the middle of it."}
	case a.cli == "" || !fileExists(a.cli):
		return &Unavailable{"The tnp command-line tool is not installed, and it is what runs the installer. Reinstall it, or update the panel from a shell."}
	case a.euid() != 0:
		return &Unavailable{"The panel is not running as root, so it cannot install a new version."}
	}
	return nil
}

// Start launches the update and returns the state it starts in.
//
// The answer goes back to the browser before anything restarts, which matters:
// the connection carrying it is one of the ones the restart ends, and a client
// that never got a reply cannot tell a refused update from a started one.
func (a *Applier) Start(ctx context.Context, version, startedBy string) (State, error) {
	if err := a.Available(); err != nil {
		return State{}, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if current := a.resolve(ctx, a.read()); current.Running() {
		return current, ErrUpdateRunning
	}

	target := strings.TrimSpace(version)
	if target == "" {
		target = "latest"
	}
	if !validTarget(target) {
		return State{}, fmt.Errorf("%q is not a version this panel can install", version)
	}

	// A previous run left its unit loaded on purpose, so its result could be
	// read after the restart. It has been read by now; clearing it is what
	// makes the unit name free for this run.
	a.clearUnit(ctx)
	a.truncateLog()

	state := State{
		Stage: StageRunning, TargetVersion: target, FromVersion: a.current,
		StartedAt: a.stamp(), Unit: UnitName, StartedBy: startedBy,
	}
	// Written before the launch rather than after it. The installer restarts
	// this process, and a state file written afterwards can lose that race and
	// leave a panel that has just been replaced with no record of why.
	a.write(state)

	if err := a.launch(ctx, target); err != nil {
		state.Stage = StageFailed
		state.FinishedAt = a.stamp()
		state.Error = err.Error()
		a.write(state)
		return a.withLog(ctx, state), err
	}
	return a.withLog(ctx, state), nil
}

// validTarget accepts "latest" and release tags, and nothing else. The value
// reaches a command line, and while it is passed as an argv element and never
// through a shell, a version is still a version.
func validTarget(target string) bool {
	if target == "latest" {
		return true
	}
	_, ok := ParseVersion(target)
	return ok
}

// launch starts the transient unit.
//
// The output is redirected into the panel's data directory so the browser can
// be shown what the installer said, including on the failure path, where it is
// the only evidence there is. Redirecting a transient unit's output to a file
// needs systemd 240; on anything older the properties are refused, so the run
// is retried without them and the journal is read instead.
func (a *Applier) launch(ctx context.Context, target string) error {
	argv := append(a.systemdRunArgs(true), a.installArgs(target)...)
	if _, err := a.runner.Run(ctx, argv); err == nil {
		return nil
	} else {
		a.log.Warn("starting the update with redirected output failed; retrying without it",
			"error", err)
	}

	a.clearUnit(ctx)
	argv = append(a.systemdRunArgs(false), a.installArgs(target)...)
	if _, err := a.runner.Run(ctx, argv); err != nil {
		return fmt.Errorf("the update could not be started: %w", err)
	}
	return nil
}

func (a *Applier) systemdRunArgs(redirect bool) []string {
	argv := []string{
		a.systemdRun,
		"--unit=" + UnitName,
		"--description=Tunnel Panel update",
		// The unit stays loaded after the command exits, which is what lets the
		// panel — restarted by that very command — come back and read whether
		// it worked. Without this a successful transient unit is garbage
		// collected the moment it ends, and the result goes with it.
		"--remain-after-exit",
	}
	if redirect {
		argv = append(argv,
			"--property=StandardOutput=append:"+a.logPath,
			"--property=StandardError=append:"+a.logPath,
		)
	}
	return argv
}

// installArgs is the command the transient unit runs: the same one an operator
// would type. --yes because there is nobody at a terminal to answer a prompt.
func (a *Applier) installArgs(target string) []string {
	return []string{a.cli, "update", "--yes", "--version", target}
}

// State reports the current run, resolving one that was still open.
func (a *Applier) State(ctx context.Context) State {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withLog(ctx, a.resolve(ctx, a.read()))
}

// resolve decides what became of a run that was still marked running.
//
// This is where the restart is accounted for. The process that started the
// update is not the process that reports on it, so the outcome cannot be held
// in memory: it is read back from the transient unit, and, when the unit is
// gone entirely — a reboot, or an operator cleaning up — inferred from whether
// the running version actually changed.
func (a *Applier) resolve(ctx context.Context, state State) State {
	if !state.Running() {
		return state
	}

	unit := a.unitStatus(ctx)
	switch {
	case unit.loaded && unit.active:
		if a.startedLongAgo(state) {
			return a.finish(state, StageFailed,
				"The update has been running for longer than twenty minutes. Check the log below, and the panel's service.")
		}
		return state

	case unit.loaded && unit.failed:
		detail := unit.result
		if detail == "" {
			detail = "the installer exited non-zero"
		}
		return a.finish(state, StageFailed, "The installer did not finish: "+detail+".")

	case unit.loaded && unit.exited:
		if unit.status == 0 {
			return a.finish(state, StageSucceeded, "")
		}
		return a.finish(state, StageFailed,
			fmt.Sprintf("The installer exited with status %d.", unit.status))

	default:
		// The unit is not there at all. Either it never started, or the host
		// rebooted, or somebody reset it. The version is the only evidence
		// left, and it is good evidence: this process is the one the installer
		// would have replaced.
		if a.startedLongAgo(state) || a.current != state.FromVersion {
			if a.current != state.FromVersion {
				return a.finish(state, StageSucceeded, "")
			}
			return a.finish(state, StageFailed,
				"The update service is no longer there and the panel is still on the same version.")
		}
		return state
	}
}

func (a *Applier) startedLongAgo(state State) bool {
	started, err := time.Parse(time.RFC3339, state.StartedAt)
	if err != nil {
		return false
	}
	return a.now().Sub(started) > maxRun
}

// finish writes the terminal state once, so the next caller reads a decision
// rather than making it again — and so the reason survives a restart.
func (a *Applier) finish(state State, stage Stage, reason string) State {
	state.Stage = stage
	state.FinishedAt = a.stamp()
	state.Error = reason
	if stage == StageSucceeded {
		state.Error = ""
	}
	a.write(state)
	return state
}

// unitState is what systemctl says about the transient unit.
type unitState struct {
	loaded bool
	active bool
	exited bool
	failed bool
	result string
	status int
}

func (a *Applier) unitStatus(ctx context.Context) unitState {
	if a.systemctl == "" || a.runner == nil {
		return unitState{}
	}
	res, err := a.runner.Run(ctx, []string{
		a.systemctl, "show", UnitName + ".service",
		"--property=LoadState", "--property=ActiveState", "--property=SubState",
		"--property=Result", "--property=ExecMainStatus",
	})
	if err != nil {
		return unitState{}
	}

	fields := map[string]string{}
	for _, line := range strings.Split(res.Stdout, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok {
			fields[key] = value
		}
	}

	out := unitState{
		loaded: fields["LoadState"] == "loaded",
		result: fields["Result"],
	}
	if out.result == "success" {
		out.result = ""
	}
	fmt.Sscanf(fields["ExecMainStatus"], "%d", &out.status) //nolint:errcheck // absent means zero
	switch fields["ActiveState"] {
	case "activating", "reloading":
		out.active = true
	case "active":
		// RemainAfterExit keeps a finished unit active; SubState is what tells
		// a command that is still running from one that has ended.
		if fields["SubState"] == "exited" || fields["SubState"] == "dead" {
			out.exited = true
		} else {
			out.active = true
		}
	case "failed":
		out.failed = true
	case "deactivating":
		out.active = true
	}
	return out
}

// clearUnit frees the unit name for the next run. Both calls are expected to
// fail when there is nothing there, which is the common case.
func (a *Applier) clearUnit(ctx context.Context) {
	if a.systemctl == "" || a.runner == nil {
		return
	}
	_, _ = a.runner.Run(ctx, []string{a.systemctl, "stop", UnitName + ".service"})         //nolint:errcheck // best effort
	_, _ = a.runner.Run(ctx, []string{a.systemctl, "reset-failed", UnitName + ".service"}) //nolint:errcheck // best effort
}

// withLog attaches the installer's output to a state for reporting.
func (a *Applier) withLog(ctx context.Context, state State) State {
	if state.Stage == StageIdle {
		return state
	}
	state.Log = a.tail(ctx)
	return state
}

// tail reads the end of the installer's output, from the file if the redirect
// took, and from the journal if it did not.
func (a *Applier) tail(ctx context.Context) []string {
	body, err := os.ReadFile(a.logPath)
	if err == nil && len(strings.TrimSpace(string(body))) > 0 {
		return lastLines(string(body), logTailLines)
	}
	if a.journalctl == "" || a.runner == nil {
		return nil
	}
	res, err := a.runner.Run(ctx, []string{
		a.journalctl, "-u", UnitName + ".service",
		"-n", fmt.Sprintf("%d", logTailLines), "--no-pager", "--output=cat",
	})
	if err != nil {
		return nil
	}
	return lastLines(res.Stdout, logTailLines)
}

// ansiRe matches the escape sequences the installer colours its output
// with. The browser is not a terminal: left in, they reach the log pane as
// literal `[1;34m` noise wrapped around every line the installer meant to
// highlight, and the operator reads the evidence through it.
var ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\\\-_]")

func lastLines(body string, n int) []string {
	lines := []string{}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		line = ansiRe.ReplaceAllString(line, "")
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// read returns the stored state, or an idle one. A state file that cannot be
// parsed is treated as no state at all: it is a progress record, and refusing
// to work because a progress record is corrupt would be the wrong trade.
func (a *Applier) read() State {
	body, err := os.ReadFile(a.statePath)
	if err != nil {
		return State{Stage: StageIdle}
	}
	var state State
	if err := json.Unmarshal(body, &state); err != nil || state.Stage == "" {
		return State{Stage: StageIdle}
	}
	return state
}

func (a *Applier) write(state State) {
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return
	}
	if err := os.WriteFile(a.statePath, append(body, '\n'), 0o600); err != nil {
		a.log.Warn("the update state could not be recorded", "path", a.statePath, "error", err)
	}
}

// truncateLog starts each run with an empty log, so what an operator reads
// during an update is this update and not the last one.
func (a *Applier) truncateLog() {
	if err := os.WriteFile(a.logPath, nil, 0o600); err != nil {
		a.log.Warn("the update log could not be cleared", "path", a.logPath, "error", err)
	}
}

func (a *Applier) stamp() string { return a.now().UTC().Format(time.RFC3339) }

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
