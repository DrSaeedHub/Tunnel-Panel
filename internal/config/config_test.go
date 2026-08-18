package config

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// envFunc builds a getenv function over a map, so tests never touch the real
// process environment.
func envFunc(pairs map[string]string) func(string) string {
	return func(key string) string { return pairs[key] }
}

func TestNormalizeWebPath(t *testing.T) {
	valid := []struct {
		name string
		in   string
		want string
	}{
		{"empty means serve at the root", "", ""},
		{"plain segment", "abc123", "abc123"},
		{"leading slash stripped", "/abc123", "abc123"},
		{"trailing slash stripped", "abc123/", "abc123"},
		{"both slashes stripped", "/abc123/", "abc123"},
		{"repeated slashes stripped", "///abc123///", "abc123"},
		{"only slashes is empty", "///", ""},
		{"surrounding whitespace trimmed", "  abc123  ", "abc123"},
		{"unreserved characters allowed", "a.b_c~d-e", "a.b_c~d-e"},
		{"single dot inside a name is allowed", "panel.v2", "panel.v2"},
		{"digits only", "0123456789", "0123456789"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeWebPath(tc.in)
			if err != nil {
				t.Fatalf("NormalizeWebPath(%q) returned an unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeWebPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	invalid := []struct {
		name string
		in   string
		// wantFragment appears in the error, so the operator is told what is
		// actually wrong rather than just "invalid".
		wantFragment string
	}{
		{"parent directory", "..", "traversal"},
		{"traversal prefix", "../etc", "traversal"},
		{"traversal suffix", "abc/..", "traversal"},
		{"traversal in the middle", "a/../b", "traversal"},
		{"current directory", ".", "traversal"},
		{"embedded slash", "a/b", "not allowed"},
		{"percent encoding", "%2e%2e", "not allowed"},
		{"space inside", "a b", "not allowed"},
		{"null byte", "a\x00b", "not allowed"},
		{"backslash", "a\\b", "not allowed"},
		{"question mark", "a?b", "not allowed"},
		{"hash", "a#b", "not allowed"},
		{"colon", "a:b", "not allowed"},
		{"non-ascii", "پنل", "not allowed"},
		{"too long", strings.Repeat("a", 129), "maximum is 128"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeWebPath(tc.in)
			if err == nil {
				t.Fatalf("NormalizeWebPath(%q) = %q, want an error", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("NormalizeWebPath(%q) error = %q, want it to mention %q",
					tc.in, err.Error(), tc.wantFragment)
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(nil, envFunc(nil), io.Discard)
	if err != nil {
		t.Fatalf("Load returned an unexpected error: %v", err)
	}
	if c.DataDir != DefaultDataDir {
		t.Errorf("DataDir = %q, want %q", c.DataDir, DefaultDataDir)
	}
	if want := filepath.Join(DefaultDataDir, DefaultDBFileName); c.DBPath != want {
		t.Errorf("DBPath = %q, want %q", c.DBPath, want)
	}
	if c.BindHost != DefaultBindHost {
		t.Errorf("BindHost = %q, want %q", c.BindHost, DefaultBindHost)
	}
	if c.BindPort != DefaultBindPort {
		t.Errorf("BindPort = %d, want %d", c.BindPort, DefaultBindPort)
	}
	if c.WebPath != "" {
		t.Errorf("WebPath = %q, want it empty by default", c.WebPath)
	}
	if c.SystemdDir != DefaultSystemdDir {
		t.Errorf("SystemdDir = %q, want %q", c.SystemdDir, DefaultSystemdDir)
	}
	if c.NetworkdDir != DefaultNetworkdDir {
		t.Errorf("NetworkdDir = %q, want %q", c.NetworkdDir, DefaultNetworkdDir)
	}
	if c.LogLevel != DefaultLogLevel {
		t.Errorf("LogLevel = %q, want %q", c.LogLevel, DefaultLogLevel)
	}
	if c.DevMode {
		t.Error("DevMode = true, want false by default")
	}
}

func TestLoadFromEnvironment(t *testing.T) {
	env := envFunc(map[string]string{
		EnvDataDir:      "/srv/panel",
		EnvDBPath:       "/srv/panel/custom.db",
		EnvBindHost:     "127.0.0.1",
		EnvBindPort:     "9000",
		EnvWebPath:      "/secret/",
		EnvSystemdDir:   "/tmp/units",
		EnvNetworkdDir:  "/tmp/networkd",
		EnvIPBin:        "/opt/bin/ip",
		EnvSystemctlBin: "/opt/bin/systemctl",
		EnvLogLevel:     "debug",
		EnvDevMode:      "true",
	})
	c, err := Load(nil, env, io.Discard)
	if err != nil {
		t.Fatalf("Load returned an unexpected error: %v", err)
	}
	checks := map[string][2]string{
		"DataDir":      {c.DataDir, "/srv/panel"},
		"DBPath":       {c.DBPath, "/srv/panel/custom.db"},
		"BindHost":     {c.BindHost, "127.0.0.1"},
		"WebPath":      {c.WebPath, "secret"},
		"SystemdDir":   {c.SystemdDir, "/tmp/units"},
		"NetworkdDir":  {c.NetworkdDir, "/tmp/networkd"},
		"IPBin":        {c.IPBin, "/opt/bin/ip"},
		"SystemctlBin": {c.SystemctlBin, "/opt/bin/systemctl"},
		"LogLevel":     {c.LogLevel, "debug"},
	}
	for field, pair := range checks {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", field, pair[0], pair[1])
		}
	}
	if c.BindPort != 9000 {
		t.Errorf("BindPort = %d, want 9000", c.BindPort)
	}
	if !c.DevMode {
		t.Error("DevMode = false, want true")
	}
}

// TestFlagsTakePrecedenceOverEnvironment covers the rule of §5.1: every value is
// settable both ways, and the flag wins.
func TestFlagsTakePrecedenceOverEnvironment(t *testing.T) {
	env := envFunc(map[string]string{
		EnvDataDir:      "/from/env",
		EnvBindHost:     "0.0.0.0",
		EnvBindPort:     "1111",
		EnvWebPath:      "fromenv",
		EnvSystemdDir:   "/env/units",
		EnvNetworkdDir:  "/env/networkd",
		EnvIPBin:        "/env/ip",
		EnvSystemctlBin: "/env/systemctl",
		EnvLogLevel:     "error",
		EnvDevMode:      "false",
	})
	args := []string{
		"--data-dir=/from/flag",
		"--bind-host=127.0.0.1",
		"--bind-port=2222",
		"--web-path=fromflag",
		"--systemd-dir=/flag/units",
		"--networkd-dir=/flag/networkd",
		"--ip-bin=/flag/ip",
		"--systemctl-bin=/flag/systemctl",
		"--log-level=warn",
		"--dev-mode=true",
	}
	c, err := Load(args, env, io.Discard)
	if err != nil {
		t.Fatalf("Load returned an unexpected error: %v", err)
	}

	checks := map[string][2]string{
		"DataDir":      {c.DataDir, "/from/flag"},
		"BindHost":     {c.BindHost, "127.0.0.1"},
		"WebPath":      {c.WebPath, "fromflag"},
		"SystemdDir":   {c.SystemdDir, "/flag/units"},
		"NetworkdDir":  {c.NetworkdDir, "/flag/networkd"},
		"IPBin":        {c.IPBin, "/flag/ip"},
		"SystemctlBin": {c.SystemctlBin, "/flag/systemctl"},
		"LogLevel":     {c.LogLevel, "warn"},
	}
	for field, pair := range checks {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want the flag value %q", field, pair[0], pair[1])
		}
	}
	if c.BindPort != 2222 {
		t.Errorf("BindPort = %d, want the flag value 2222", c.BindPort)
	}
	if !c.DevMode {
		t.Error("DevMode = false, want the flag value true")
	}
	// DBPath was set by neither, so it derives from the flag-supplied data dir.
	if want := filepath.Join("/from/flag", DefaultDBFileName); c.DBPath != want {
		t.Errorf("DBPath = %q, want it derived from the flag data dir as %q", c.DBPath, want)
	}
}

func TestLoadRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name         string
		args         []string
		env          map[string]string
		wantFragment string
	}{
		{"port out of range", []string{"--bind-port=70000"}, nil, "out of range"},
		{"port zero", []string{"--bind-port=0"}, nil, "out of range"},
		{"port not a number in env", nil, map[string]string{EnvBindPort: "http"}, "not an integer"},
		{"dev mode not a boolean", nil, map[string]string{EnvDevMode: "yes please"}, "not a boolean"},
		{"unknown log level", []string{"--log-level=chatty"}, nil, "invalid log level"},
		{"web path traversal", []string{"--web-path=../etc"}, nil, "traversal"},
		{"web path bad character", []string{"--web-path=a b"}, nil, "not allowed"},
		{"empty bind host", []string{"--bind-host= "}, nil, "must not be empty"},
		{"stray positional argument", []string{"unexpected"}, nil, "unexpected argument"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.args, envFunc(tc.env), io.Discard)
			if err == nil {
				t.Fatalf("Load(%v) succeeded, want an error", tc.args)
			}
			if !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("Load(%v) error = %q, want it to mention %q", tc.args, err, tc.wantFragment)
			}
		})
	}
}

func TestVersionFlag(t *testing.T) {
	_, err := Load([]string{"--version"}, envFunc(nil), io.Discard)
	if err != ErrVersionRequested {
		t.Fatalf("Load(--version) error = %v, want ErrVersionRequested", err)
	}
}

func TestPathHelpers(t *testing.T) {
	withPath := &Config{WebPath: "abc123", BindHost: "127.0.0.1", BindPort: 8787}
	if got, want := withPath.PathPrefix(), "/abc123"; got != want {
		t.Errorf("PathPrefix() = %q, want %q", got, want)
	}
	if got, want := withPath.BasePath(), "/abc123/"; got != want {
		t.Errorf("BasePath() = %q, want %q", got, want)
	}
	if got, want := withPath.APIBasePath(), "/abc123/api/v1"; got != want {
		t.Errorf("APIBasePath() = %q, want %q", got, want)
	}
	if got, want := withPath.ListenAddress(), "127.0.0.1:8787"; got != want {
		t.Errorf("ListenAddress() = %q, want %q", got, want)
	}

	rootMounted := &Config{WebPath: "", BindHost: "::1", BindPort: 80}
	if got := rootMounted.PathPrefix(); got != "" {
		t.Errorf("PathPrefix() = %q, want it empty when no web path is set", got)
	}
	if got, want := rootMounted.BasePath(), "/"; got != want {
		t.Errorf("BasePath() = %q, want %q", got, want)
	}
	if got, want := rootMounted.APIBasePath(), "/api/v1"; got != want {
		t.Errorf("APIBasePath() = %q, want %q", got, want)
	}
	if got, want := rootMounted.ListenAddress(), "[::1]:80"; got != want {
		t.Errorf("ListenAddress() = %q, want %q", got, want)
	}
}

func TestIsLoopbackBind(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1": true,
		"127.0.0.2": true,
		"localhost": true,
		"::1":       true,
		"0.0.0.0":   false,
		"10.0.0.5":  false,
		"::":        false,
	}
	for host, want := range cases {
		c := &Config{BindHost: host}
		if got := c.IsLoopbackBind(); got != want {
			t.Errorf("IsLoopbackBind() for %q = %v, want %v", host, got, want)
		}
	}
}
