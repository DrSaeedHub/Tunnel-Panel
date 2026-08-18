package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Everything the CLI knows about the installation it manages. These mirror the
// installer's own constants; installer_contract_test.go pins them together so
// the two cannot drift into disagreeing about where the panel lives.
const (
	serviceName   = "gre-panel"
	panelBinary   = "/usr/local/bin/gre-panel"
	cliBinary     = "/usr/local/bin/tnp"
	dataDir       = "/var/lib/gre-panel"
	unitPath      = "/etc/systemd/system/gre-panel.service"
	supportDir    = "/usr/local/share/gre-panel"
	cachedInstall = supportDir + "/install.sh"
	cliEnvFile    = supportDir + "/cli.env"
)

// systemctl runs a systemctl subcommand and returns its combined output.
func systemctl(ctx context.Context, args ...string) (string, error) {
	binary, err := exec.LookPath("systemctl")
	if err != nil {
		return "", fmt.Errorf("systemctl is not on PATH, so the service cannot be managed: %w", err)
	}
	out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// systemctlShow reads one unit property. It returns an empty string rather than
// an error when systemd has nothing to say, because "no such unit" is a normal
// answer here — the CLI is expected to run on a host where the panel has just
// been removed.
func systemctlShow(ctx context.Context, property string) string {
	out, err := systemctl(ctx, "show", serviceName, "-p", property, "--value")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// serviceState is what systemd reports about the unit.
type serviceState struct {
	Installed  bool   `json:"installed"`
	Active     string `json:"active"`
	Enabled    string `json:"enabled"`
	MainPID    int    `json:"main_pid"`
	StartedAt  string `json:"started_at,omitempty"`
	ResultText string `json:"result,omitempty"`
}

func readServiceState(ctx context.Context) serviceState {
	out := serviceState{}
	if _, err := os.Stat(unitPath); err != nil {
		return out
	}
	out.Installed = true
	out.Active, _ = systemctl(ctx, "is-active", serviceName)
	out.Enabled, _ = systemctl(ctx, "is-enabled", serviceName)
	out.MainPID, _ = strconv.Atoi(systemctlShow(ctx, "MainPID"))
	out.StartedAt = systemctlShow(ctx, "ExecMainStartTimestamp")
	out.ResultText = systemctlShow(ctx, "Result")
	return out
}

// restartService restarts the panel and waits for systemd to finish.
//
// This is the CLI, which is not inside the panel's cgroup, so restarting it
// from here is an ordinary systemctl call. The panel itself cannot do this —
// KillMode=control-group means the restart would kill the process issuing it
// halfway through — which is why the panel applies its own address changes by
// exiting instead.
func restartService(ctx context.Context) error {
	out, err := systemctl(ctx, "restart", serviceName)
	if err != nil {
		return fmt.Errorf("systemctl restart %s failed: %w\n%s", serviceName, err, out)
	}
	return nil
}

// journalTail returns the last lines of the unit's log, for a failure message
// that says what actually went wrong rather than telling the operator to go and
// look.
func journalTail(ctx context.Context, lines int) string {
	binary, err := exec.LookPath("journalctl")
	if err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, binary,
		"-u", serviceName, "--no-pager", "-n", strconv.Itoa(lines), "-o", "cat").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// binaryVersion runs a binary's --version and returns the first two lines
// folded into one, which is the version label and the commit.
func binaryVersion(ctx context.Context, path string) string {
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "--version").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(strings.ReplaceAll(strings.TrimSpace(string(out)), "\n", " "))
	if len(fields) == 0 {
		return ""
	}
	// "gre-panel v0.1.0 commit: 1a2b3c4 built: ..." -> "v0.1.0 (1a2b3c4)"
	var label, commit string
	for i, f := range fields {
		switch {
		case i == 1 && label == "":
			label = f
		case f == "commit:" && i+1 < len(fields):
			commit = fields[i+1]
		}
	}
	if commit != "" {
		return label + " (" + commit + ")"
	}
	return label
}
