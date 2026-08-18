package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/config"
)

func writeEnv(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gre-panel.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}

// Editing one value must leave the rest of the file exactly as it was.
//
// systemd reads this file, and an operator may have added a variable to it. A
// tool that regenerates it from a template throws all of that away silently,
// which is the failure this is written against.
func TestEditingOneValueLeavesTheRestOfTheFileAlone(t *testing.T) {
	const original = `# Written by the installer.
GRE_PANEL_DATA_DIR=/var/lib/gre-panel
GRE_PANEL_BIND_HOST=0.0.0.0
GRE_PANEL_BIND_PORT=8443
GRE_PANEL_WEB_PATH=panel-a1b2c3
GRE_PANEL_LANGUAGE=fa

# Something the operator added by hand.
GRE_PANEL_LOG_LEVEL=debug
`
	path := writeEnv(t, original)
	file, err := loadEnvFile(path)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	file.Set(config.EnvBindPort, "9000")
	if err := file.Write(); err != nil {
		t.Fatalf("writing: %v", err)
	}

	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	got := string(written)

	want := strings.Replace(original, "GRE_PANEL_BIND_PORT=8443", "GRE_PANEL_BIND_PORT=9000", 1)
	if got != want {
		t.Errorf("the file changed in more than the one value.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	if !strings.Contains(got, "# Something the operator added by hand.") {
		t.Error("a comment was dropped")
	}
	if !strings.Contains(got, "GRE_PANEL_LOG_LEVEL=debug") {
		t.Error("an unrelated key was dropped")
	}
}

// A key that is absent is appended rather than lost.
func TestSettingAnAbsentKeyAppendsIt(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_BIND_PORT=8443\n")
	file, _ := loadEnvFile(path)
	file.Set(config.EnvWebPath, "")
	if err := file.Write(); err != nil {
		t.Fatalf("writing: %v", err)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "GRE_PANEL_WEB_PATH=\n") {
		t.Errorf("the empty web path was not appended:\n%s", body)
	}
}

// Present-and-empty is not the same as absent, and the empty web path is the
// case where confusing them changes behaviour.
func TestAnEmptyValueIsPresent(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_WEB_PATH=\nGRE_PANEL_BIND_PORT=8443\n")
	file, _ := loadEnvFile(path)

	value, present := file.Get(config.EnvWebPath)
	if !present {
		t.Error("an empty assignment was reported as absent")
	}
	if value != "" {
		t.Errorf("value = %q, want empty", value)
	}
	if _, present := file.Get("GRE_PANEL_NOT_THERE"); present {
		t.Error("a key that is not in the file was reported as present")
	}
}

func TestQuotedValuesAreUnwrapped(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_WEB_PATH=\"abc123\"\nGRE_PANEL_DATA_DIR='/srv/panel'\n")
	env, err := readPanelEnv(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if env.WebPath != "abc123" {
		t.Errorf("web path = %q, want abc123 with the quotes removed", env.WebPath)
	}
	if env.DataDir != "/srv/panel" {
		t.Errorf("data dir = %q", env.DataDir)
	}
}

// The CLI has to work on a host where the file is missing entirely, which is
// what an installation that has been uninstalled looks like. The defaults it
// falls back to must be the panel's own.
func TestAMissingFileFallsBackToThePanelsDefaults(t *testing.T) {
	env, err := readPanelEnv(filepath.Join(t.TempDir(), "absent.env"))
	if err != nil {
		t.Fatalf("reading a missing file should not fail: %v", err)
	}
	if env.DataDir != config.DefaultDataDir {
		t.Errorf("data dir = %q, want %q", env.DataDir, config.DefaultDataDir)
	}
	if env.Port != config.DefaultBindPort {
		t.Errorf("port = %d, want %d", env.Port, config.DefaultBindPort)
	}
	if env.Host != config.DefaultBindHost {
		t.Errorf("host = %q, want %q", env.Host, config.DefaultBindHost)
	}
	if env.WebPath != "" {
		t.Errorf("web path = %q, want empty", env.WebPath)
	}
	if want := filepath.Join(config.DefaultDataDir, config.DefaultDBFileName); env.DBPath != want {
		t.Errorf("database path = %q, want %q", env.DBPath, want)
	}
}

func TestAGarbledPortIsReportedRatherThanIgnored(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_BIND_PORT=eight-thousand\n")
	if _, err := readPanelEnv(path); err == nil {
		t.Error("a non-numeric port was accepted; the panel would then be somewhere unexpected")
	}
}

func TestAnInvalidWebPathIsReportedRatherThanIgnored(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_WEB_PATH=has/slash\n")
	if _, err := readPanelEnv(path); err == nil {
		t.Error("a web path the router cannot serve was accepted")
	}
}

// The written file must stay 0600. It is systemd's input to a service that runs
// as root.
func TestTheWrittenFileIsNotReadableByAnyoneElse(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_BIND_PORT=8443\n")
	file, _ := loadEnvFile(path)
	file.Set(config.EnvBindPort, "9000")
	if err := file.Write(); err != nil {
		t.Fatalf("writing: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permissions = %v, want 0600", perm)
	}
	// And no temporary file is left in the directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".gre-panel.env.") {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}
}

// restoreEnv is the rollback path, and the case that matters is the key that
// was not in the file to begin with.
func TestRestoringPutsBackWhatWasThere(t *testing.T) {
	path := writeEnv(t, "GRE_PANEL_BIND_PORT=8443\n")
	env, err := readPanelEnv(path)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	previousPort, _ := env.file.Get(config.EnvBindPort)
	previousWebPath, hadWebPath := env.file.Get(config.EnvWebPath)
	if hadWebPath {
		t.Fatal("the fixture has a web path; this test is about the case where it does not")
	}

	env.file.Set(config.EnvBindPort, "9000")
	env.file.Set(config.EnvWebPath, "moved")
	restoreEnv(env, previousPort, previousWebPath, hadWebPath)

	if got, _ := env.file.Get(config.EnvBindPort); got != "8443" {
		t.Errorf("port after the rollback = %q, want 8443", got)
	}
	// The web path is written back as an explicit empty value rather than
	// removed. Absent and empty mean the same thing to the panel, and an
	// explicit line is better than a file that says nothing about where the
	// panel is.
	got, present := env.file.Get(config.EnvWebPath)
	if !present || got != "" {
		t.Errorf("web path after the rollback = %q present=%v, want an explicit empty value",
			got, present)
	}
}
