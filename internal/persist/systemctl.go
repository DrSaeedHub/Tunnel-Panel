package persist

import (
	"context"
	"fmt"
	"strings"
)

// DaemonReloadArgs, EnableArgs and the rest build the systemctl invocations.
// They are exported so the plan can carry the exact argv it will run and the
// preview endpoint can show it before anything happens (§9.2).

// DaemonReloadArgs rereads unit files.
//
// It is always daemon-reload and never daemon-reexec. The legacy script
// re-executed PID 1 on every install, which is unnecessary, affects the whole
// system, and has nothing to do with picking up a new unit file (§9.4).
func DaemonReloadArgs(systemctlBin string) []string {
	return []string{systemctlBin, "daemon-reload"}
}

// EnableArgs marks a unit to start at boot.
func EnableArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "enable", unit}
}

// DisableArgs removes that marking.
func DisableArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "disable", unit}
}

// StartArgs, StopArgs and RestartArgs drive the unit now.
func StartArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "start", unit}
}

func StopArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "stop", unit}
}

func RestartArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "restart", unit}
}

// IsEnabledArgs and IsActiveArgs query the unit, which §9.3 requires before a
// systemd-persisted tunnel may be reported as applied.
func IsEnabledArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "is-enabled", unit}
}

func IsActiveArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "is-active", unit}
}

// ResetFailedArgs clears a unit's failed state, so a later start is not
// refused because of an earlier failure.
func ResetFailedArgs(systemctlBin, unit string) []string {
	return []string{systemctlBin, "reset-failed", unit}
}

// JournalArgs reads the tail of a unit's log. A failed apply returns this
// output, because "the unit failed" without the reason is what the legacy
// script's opaque status view offered (§9.1).
func JournalArgs(unit string, lines int) []string {
	return []string{"journalctl", "-u", unit, "-n", fmt.Sprintf("%d", lines), "--no-pager"}
}

// DaemonReload rereads unit files.
func (s *Store) DaemonReload(ctx context.Context) error {
	if err := s.requireSystemctl(); err != nil {
		return err
	}
	_, err := s.Runner.Run(ctx, DaemonReloadArgs(s.SystemctlBin))
	return err
}

// Enable, Disable, Start, Stop and Restart drive one unit.
func (s *Store) Enable(ctx context.Context, unit string) error {
	return s.simple(ctx, EnableArgs, unit)
}

func (s *Store) Disable(ctx context.Context, unit string) error {
	return s.simple(ctx, DisableArgs, unit)
}

func (s *Store) Start(ctx context.Context, unit string) error {
	return s.simple(ctx, StartArgs, unit)
}

func (s *Store) Stop(ctx context.Context, unit string) error {
	return s.simple(ctx, StopArgs, unit)
}

func (s *Store) Restart(ctx context.Context, unit string) error {
	return s.simple(ctx, RestartArgs, unit)
}

// ResetFailed clears a unit's failed state, ignoring the failure that comes
// from a unit systemd has never heard of.
func (s *Store) ResetFailed(ctx context.Context, unit string) {
	if s.requireSystemctl() != nil {
		return
	}
	_, _ = s.Runner.Run(ctx, ResetFailedArgs(s.SystemctlBin, unit))
}

func (s *Store) simple(ctx context.Context, build func(string, string) []string, unit string) error {
	if err := s.requireSystemctl(); err != nil {
		return err
	}
	_, err := s.Runner.Run(ctx, build(s.SystemctlBin, unit))
	return err
}

// IsEnabled reports whether a unit is enabled. systemctl exits non-zero for a
// disabled unit, which is an answer rather than a failure, so the exit code is
// read from the result instead of being treated as an error.
func (s *Store) IsEnabled(ctx context.Context, unit string) (bool, string, error) {
	if err := s.requireSystemctl(); err != nil {
		return false, "", err
	}
	res, _ := s.Runner.Run(ctx, IsEnabledArgs(s.SystemctlBin, unit))
	state := strings.TrimSpace(res.Stdout)
	if state == "" {
		state = strings.TrimSpace(res.Stderr)
	}
	// "enabled" and "enabled-runtime" both mean it starts at boot; "static" and
	// "indirect" mean it is pulled in by something else, which for a unit the
	// panel wrote would be a misconfiguration.
	return state == "enabled" || state == "enabled-runtime", state, nil
}

// IsActive reports whether a unit is running. A oneshot unit with
// RemainAfterExit=yes reports "active" once its ExecStart steps have succeeded,
// which is exactly the signal §9.3 needs.
func (s *Store) IsActive(ctx context.Context, unit string) (bool, string, error) {
	if err := s.requireSystemctl(); err != nil {
		return false, "", err
	}
	res, _ := s.Runner.Run(ctx, IsActiveArgs(s.SystemctlBin, unit))
	state := strings.TrimSpace(res.Stdout)
	if state == "" {
		state = strings.TrimSpace(res.Stderr)
	}
	return state == "active", state, nil
}

// JournalTail returns the last lines of a unit's log, for the error a failed
// apply reports (§9.1). A failure to read the journal is not itself reported as
// an error: the caller is already handling one.
func (s *Store) JournalTail(ctx context.Context, unit string, lines int) string {
	if lines <= 0 {
		lines = 50
	}
	res, err := s.Runner.Run(ctx, JournalArgs(unit, lines))
	if err != nil && strings.TrimSpace(res.Stdout) == "" {
		return ""
	}
	return strings.TrimSpace(res.Stdout)
}

func (s *Store) requireSystemctl() error {
	if strings.TrimSpace(s.SystemctlBin) == "" {
		return fmt.Errorf("systemctl was not found on this system, so systemd persistence is unavailable")
	}
	return nil
}

// SystemdAvailable reports whether systemd persistence can be offered here.
func (s *Store) SystemdAvailable() bool { return strings.TrimSpace(s.SystemctlBin) != "" }

// NetworkdActive reports whether systemd-networkd is running, which decides
// whether networkd persistence may be offered (§9.4).
func (s *Store) NetworkdActive(ctx context.Context) bool {
	if !s.SystemdAvailable() {
		return false
	}
	active, _, err := s.IsActive(ctx, "systemd-networkd.service")
	return err == nil && active
}
