package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The regression this file exists for: the installer asks the binary where the
// panel listens by running it from a plain shell, which has not sourced the
// environment file. Before EnvFileGetenv, BindPort fell back to
// DefaultBindPort, the address resolver read that default as an operator edit,
// and the installer health-checked a port nothing was on — reporting a working
// panel as a failed install.
//
// The test that would have caught it is this one: an EMPTY process environment
// against a file holding a different port, asserting the file's value rather
// than the default.
func TestAnEmptyEnvironmentStillFindsTheEnvironmentFile(t *testing.T) {
	path := writeEnvFile(t, "GRE_PANEL_BIND_PORT=8443\nGRE_PANEL_WEB_PATH=panel-a1b2c3\n")

	empty := func(string) string { return "" } // a plain shell: nothing set
	getenv := EnvFileGetenv(path, empty)

	cfg, err := Load(nil, getenv, os.Stderr)
	if err != nil {
		t.Fatalf("loading with a file-backed environment: %v", err)
	}
	if cfg.BindPort != 8443 {
		t.Errorf("BindPort = %d, want 8443 from the file; %d is the built-in default, "+
			"which is what the installer health-checked when nothing read the file",
			cfg.BindPort, DefaultBindPort)
	}
	if cfg.SeedBindPort != 8443 {
		t.Errorf("SeedBindPort = %d, want 8443; the seed is what the drift check compares "+
			"against, so a wrong seed makes the file look edited", cfg.SeedBindPort)
	}
	if cfg.WebPath != "panel-a1b2c3" {
		t.Errorf("WebPath = %q, want %q from the file", cfg.WebPath, "panel-a1b2c3")
	}
}

// The process environment is authoritative. systemd sets these variables from
// the same file, so the file must never override what is already set, or an
// explicit variable would silently lose to a stale file.
func TestTheProcessEnvironmentBeatsTheFile(t *testing.T) {
	path := writeEnvFile(t, "GRE_PANEL_BIND_PORT=8443\n")

	getenv := EnvFileGetenv(path, func(key string) string {
		if key == EnvBindPort {
			return "9001"
		}
		return ""
	})

	cfg, err := Load(nil, getenv, os.Stderr)
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if cfg.BindPort != 9001 {
		t.Errorf("BindPort = %d, want 9001 from the process environment, not the file", cfg.BindPort)
	}
}

// A host before its first install has no such file. That is not an error, and
// the defaults are the whole truth then.
func TestAMissingEnvironmentFileIsNotAnError(t *testing.T) {
	getenv := EnvFileGetenv(filepath.Join(t.TempDir(), "absent.env"), func(string) string { return "" })

	cfg, err := Load(nil, getenv, os.Stderr)
	if err != nil {
		t.Fatalf("a missing environment file must not fail the load: %v", err)
	}
	if cfg.BindPort != DefaultBindPort {
		t.Errorf("BindPort = %d, want the default %d", cfg.BindPort, DefaultBindPort)
	}
}

// Comments, blank lines and quoted values, because an operator locked out of
// the panel edits this file by hand and systemd accepts all three.
func TestTheFileParsesWhatSystemdAccepts(t *testing.T) {
	path := writeEnvFile(t, "# moved for the reverse proxy\n\nGRE_PANEL_BIND_PORT=\"8443\"\nGRE_PANEL_WEB_PATH='panel'\n")

	getenv := EnvFileGetenv(path, func(string) string { return "" })
	if got := getenv(EnvBindPort); got != "8443" {
		t.Errorf("quoted port = %q, want %q", got, "8443")
	}
	if got := getenv(EnvWebPath); got != "panel" {
		t.Errorf("single-quoted web path = %q, want %q", got, "panel")
	}
}

func writeEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gre-panel.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}
	return path
}
