package config

import (
	"bufio"
	"os"
	"strings"
)

// EnvFileGetenv returns a getenv that falls back to the environment file when a
// variable is absent from the process environment.
//
// The binary is normally started by systemd, which reads EnvFilePath itself, so
// the process environment already carries these values and the file is never
// consulted. The case this exists for is every other caller: the installer runs
// `gre-panel --print-address` from a plain shell to ask where the panel is
// before health-checking it, and a plain shell has not sourced that file.
//
// Without this, BindPort fell back to DefaultBindPort, and address.Resolve
// compared that default against the seed recorded at the last start, found them
// different, and concluded an operator had edited the file — so the environment
// "won" and the panel reported a port it was not on. Measured on a live host:
//
//	gre-panel --print-address                          -> port 8787, source "environment"
//	( . /etc/gre-panel.env; gre-panel --print-address ) -> port 8443, source "database"
//
// The installer then health-checked 8787, found nothing, and reported a working
// panel as a failed install. The drift check is right about the case it was
// written for; it simply cannot tell an operator's edit from a process that
// never loaded the file at all. Reading the file here removes the ambiguity at
// the source rather than teaching every caller to remember.
//
// The process environment always wins, so systemd's values are never overridden
// and an explicit variable still beats the file.
func EnvFileGetenv(path string, base func(string) string) func(string) string {
	if base == nil {
		base = func(string) string { return "" }
	}
	var (
		loaded bool
		values map[string]string
	)
	return func(key string) string {
		if v := base(key); v != "" {
			return v
		}
		if !loaded {
			loaded = true
			values = readEnvFile(path)
		}
		return values[key]
	}
}

// readEnvFile parses the KEY=VALUE lines systemd's EnvironmentFile= accepts.
// A missing or unreadable file is not an error: it is what a host looks like
// before the first install, and the defaults are the whole truth then.
func readEnvFile(path string) map[string]string {
	out := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close() //nolint:errcheck // read-only

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// systemd accepts quoted values; the installer does not write them, but
		// an operator editing the file by hand reasonably might.
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key != "" {
			out[key] = value
		}
	}
	return out
}
