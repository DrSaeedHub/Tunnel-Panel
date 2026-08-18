// Package config loads the bootstrap configuration — the values that must be
// known before the database can be opened (§5.1). Everything else is a runtime
// setting living in the database; see internal/settings.
//
// Every value is settable by environment variable and by command-line flag,
// with the flag taking precedence.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Defaults for every bootstrap value (§5.1).
const (
	DefaultDataDir      = "/var/lib/gre-panel"
	DefaultBindHost     = "0.0.0.0"
	DefaultBindPort     = 8787
	DefaultSystemdDir   = "/etc/systemd/system"
	DefaultNetworkdDir  = "/etc/systemd/network"
	DefaultLogLevel     = "info"
	DefaultDBFileName   = "panel.db"
	DefaultKeyFileName  = "jwt.key"
	DefaultLockFileName = "gre-panel.lock"
)

// EnvFilePath is the environment file the installer writes and systemd reads.
//
// The panel cannot write it — the unit runs ProtectSystem=full — so it is named
// here only to be reported: a port changed through the panel leaves this file
// saying something else, and an operator reading it deserves to be told that
// rather than to be quietly wrong. The CLI, which is not sandboxed, keeps it in
// step when it is the one making the change.
const EnvFilePath = "/etc/gre-panel.env"

// Environment variable names (§5.1).
const (
	EnvDataDir      = "GRE_PANEL_DATA_DIR"
	EnvDBPath       = "GRE_PANEL_DB_PATH"
	EnvBindHost     = "GRE_PANEL_BIND_HOST"
	EnvBindPort     = "GRE_PANEL_BIND_PORT"
	EnvWebPath      = "GRE_PANEL_WEB_PATH"
	EnvSystemdDir   = "GRE_PANEL_SYSTEMD_DIR"
	EnvNetworkdDir  = "GRE_PANEL_NETWORKD_DIR"
	EnvIPBin        = "GRE_PANEL_IP_BIN"
	EnvSystemctlBin = "GRE_PANEL_SYSTEMCTL_BIN"
	EnvLogLevel     = "GRE_PANEL_LOG_LEVEL"
	EnvDevMode      = "GRE_PANEL_DEV_MODE"
)

// ErrVersionRequested is returned by Load when --version was passed. The caller
// prints the version banner and exits successfully.
var ErrVersionRequested = errors.New("version requested")

// ErrHelpRequested is returned by Load when -h/--help was passed; usage has
// already been written to the output writer.
var ErrHelpRequested = errors.New("help requested")

// Config is the resolved bootstrap configuration.
type Config struct {
	DataDir      string
	DBPath       string
	BindHost     string
	BindPort     int
	WebPath      string // normalised: no leading or trailing slash, possibly empty
	SystemdDir   string
	NetworkdDir  string
	IPBin        string
	SystemctlBin string
	LogLevel     string
	DevMode      bool

	// The port and the web path are no longer settled here. They are stored in
	// the database, which the panel can write and /etc is not, and what this
	// file resolves is the seed that database is arbitrated against — see
	// internal/address. BindPort and WebPath above hold the seed until that
	// arbitration replaces them, so that a caller who never opens a database
	// (--print-address on a host with no data directory, a test) still gets a
	// usable answer.
	//
	// SeedBindPort and SeedWebPath keep the environment's own values even when
	// a flag overrode them, because the drift check compares the file against
	// what the file said last time, not against whatever was passed on the
	// command line this once.
	SeedBindPort int
	SeedWebPath  string
	// SeedBindPortSet and SeedWebPathSet record that the environment supplied
	// the value at all. See the assignment in Load for why the distinction
	// matters.
	SeedBindPortSet  bool
	SeedWebPathSet   bool
	BindPortFromFlag bool
	WebPathFromFlag  bool

	// PrintAddress asks the binary to report where it would listen and exit.
	// The installer uses it: after an upgrade the environment file is no longer
	// authoritative, so polling the port it names would health-check the wrong
	// URL and report a working panel as failed.
	PrintAddress bool
}

// LockPath is the advisory lock file guarding the data directory (§16).
func (c *Config) LockPath() string { return filepath.Join(c.DataDir, DefaultLockFileName) }

// SecretKeyPath is the persisted JWT signing key (§18).
func (c *Config) SecretKeyPath() string { return filepath.Join(c.DataDir, DefaultKeyFileName) }

// ListenAddress is the host:port the HTTP server binds.
func (c *Config) ListenAddress() string {
	return net.JoinHostPort(c.BindHost, strconv.Itoa(c.BindPort))
}

// PathPrefix returns the router mount prefix: "/abc123", or "" when no web path
// is configured. It never ends in a slash.
func (c *Config) PathPrefix() string {
	if c.WebPath == "" {
		return ""
	}
	return "/" + c.WebPath
}

// BasePath returns the prefix as a browser base href: always ends in a slash.
func (c *Config) BasePath() string {
	if c.WebPath == "" {
		return "/"
	}
	return "/" + c.WebPath + "/"
}

// APIBasePath returns the base path of the JSON API, e.g. "/abc123/api/v1".
func (c *Config) APIBasePath() string { return c.PathPrefix() + "/api/v1" }

// IsLoopbackBind reports whether the configured bind host is a loopback address.
// Binding anywhere else without TLS in front warrants a loud warning (§18).
func (c *Config) IsLoopbackBind() bool {
	switch c.BindHost {
	case "127.0.0.1", "::1", "localhost", "[::1]":
		return true
	}
	return strings.HasPrefix(c.BindHost, "127.")
}

// Load resolves the bootstrap configuration from environment and arguments.
// getenv is injected so tests never touch the process environment; pass
// os.Getenv in production. args excludes the program name.
func Load(args []string, getenv func(string) string, out io.Writer) (*Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}

	// Environment values become the flag defaults, which gives flags precedence
	// over the environment for free while keeping a single validation path.
	c := &Config{
		DataDir:      envString(getenv, EnvDataDir, DefaultDataDir),
		DBPath:       envString(getenv, EnvDBPath, ""),
		BindHost:     envString(getenv, EnvBindHost, DefaultBindHost),
		SystemdDir:   envString(getenv, EnvSystemdDir, DefaultSystemdDir),
		NetworkdDir:  envString(getenv, EnvNetworkdDir, DefaultNetworkdDir),
		IPBin:        envString(getenv, EnvIPBin, ""),
		SystemctlBin: envString(getenv, EnvSystemctlBin, ""),
		LogLevel:     envString(getenv, EnvLogLevel, DefaultLogLevel),
	}

	port, err := envInt(getenv, EnvBindPort, DefaultBindPort)
	if err != nil {
		return nil, err
	}
	devMode, err := envBool(getenv, EnvDevMode, false)
	if err != nil {
		return nil, err
	}
	rawWebPath := envString(getenv, EnvWebPath, "")

	fs := flag.NewFlagSet("gre-panel", flag.ContinueOnError)
	fs.SetOutput(out)
	showVersion := fs.Bool("version", false, "print version information and exit")
	fs.BoolVar(&c.PrintAddress, "print-address", false,
		"print the address the panel would listen on, as JSON, and exit")
	fs.StringVar(&c.DataDir, "data-dir", c.DataDir, "directory holding the database, secret key and backups ($"+EnvDataDir+")")
	fs.StringVar(&c.DBPath, "db-path", c.DBPath, "SQLite database file (default <data-dir>/"+DefaultDBFileName+") ($"+EnvDBPath+")")
	fs.StringVar(&c.BindHost, "bind-host", c.BindHost, "listen address ($"+EnvBindHost+")")
	fs.IntVar(&port, "bind-port", port, "listen port ($"+EnvBindPort+")")
	fs.StringVar(&rawWebPath, "web-path", rawWebPath, "secret URL path prefix the panel is served under ($"+EnvWebPath+")")
	fs.StringVar(&c.SystemdDir, "systemd-dir", c.SystemdDir, "systemd unit output directory ($"+EnvSystemdDir+")")
	fs.StringVar(&c.NetworkdDir, "networkd-dir", c.NetworkdDir, "systemd-networkd output directory ($"+EnvNetworkdDir+")")
	fs.StringVar(&c.IPBin, "ip-bin", c.IPBin, "path to the ip binary, autodetected when empty ($"+EnvIPBin+")")
	fs.StringVar(&c.SystemctlBin, "systemctl-bin", c.SystemctlBin, "path to the systemctl binary, autodetected when empty ($"+EnvSystemctlBin+")")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "debug, info, warn or error ($"+EnvLogLevel+")")
	fs.BoolVar(&devMode, "dev-mode", devMode, "relax the root requirement and enable the fake link manager ($"+EnvDevMode+")")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, ErrHelpRequested
		}
		return nil, err
	}
	if *showVersion {
		return nil, ErrVersionRequested
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}

	c.BindPort = port
	c.DevMode = devMode

	// Which of the two were given on the command line rather than inherited
	// from the environment. flag has no way to ask after the fact, so the set
	// flags are walked; the alternative — comparing the value against the
	// default — cannot tell a flag that happens to match from one that was
	// never passed.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "bind-port":
			c.BindPortFromFlag = true
		case "web-path":
			c.WebPathFromFlag = true
		}
	})
	// The seed is the environment's own value, so a flag this once does not
	// rewrite what the next start compares the file against.
	c.SeedBindPort, err = envInt(getenv, EnvBindPort, DefaultBindPort)
	if err != nil {
		return nil, err
	}
	// Whether anything actually supplied these, as opposed to them being the
	// compiled defaults. An absent value is not an instruction, and the address
	// resolver needs to tell the two apart: without it, a host whose
	// environment file had been removed served on the default while its own
	// database said otherwise.
	_, c.SeedBindPortSet = lookup(getenv, EnvBindPort)
	_, c.SeedWebPathSet = lookup(getenv, EnvWebPath)
	seedWebPath, err := NormalizeWebPath(envString(getenv, EnvWebPath, ""))
	if err != nil {
		return nil, fmt.Errorf("invalid web path in $%s: %w", EnvWebPath, err)
	}
	c.SeedWebPath = seedWebPath

	webPath, err := NormalizeWebPath(rawWebPath)
	if err != nil {
		return nil, fmt.Errorf("invalid web path: %w", err)
	}
	c.WebPath = webPath

	if err := c.finalize(); err != nil {
		return nil, err
	}
	return c, nil
}

// finalize fills derived values, autodetects binaries and validates the result.
func (c *Config) finalize() error {
	c.DataDir = strings.TrimSpace(c.DataDir)
	if c.DataDir == "" {
		return errors.New("data directory must not be empty")
	}
	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("resolving data directory: %w", err)
	}
	c.DataDir = abs

	if strings.TrimSpace(c.DBPath) == "" {
		c.DBPath = filepath.Join(c.DataDir, DefaultDBFileName)
	} else if abs, err := filepath.Abs(c.DBPath); err == nil {
		c.DBPath = abs
	}

	if c.BindPort < 1 || c.BindPort > 65535 {
		return fmt.Errorf("bind port %d out of range 1-65535", c.BindPort)
	}
	if strings.TrimSpace(c.BindHost) == "" {
		return errors.New("bind host must not be empty")
	}

	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "debug", "info", "warn", "warning", "error":
		c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	default:
		return fmt.Errorf("invalid log level %q: want debug, info, warn or error", c.LogLevel)
	}

	// Binary paths are autodetected rather than hardcoded the way the legacy
	// script hardcoded /sbin/ip, and the resolved values are reported by the
	// system-info endpoint.
	if strings.TrimSpace(c.IPBin) == "" {
		c.IPBin = lookBinary("ip", "/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip")
	}
	if strings.TrimSpace(c.SystemctlBin) == "" {
		c.SystemctlBin = lookBinary("systemctl", "/bin/systemctl", "/usr/bin/systemctl", "/sbin/systemctl")
	}
	return nil
}

// Web path characters permitted by §5.2.
func isWebPathRune(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		return true
	case r == '.' || r == '_' || r == '~' || r == '-':
		return true
	}
	return false
}

// NormalizeWebPath applies the rules of §5.2: strip leading and trailing
// slashes, reject path traversal, and reject any character outside
// [A-Za-z0-9._~-]. An empty input is valid and means "serve at the root".
//
// Note that an interior slash is rejected by the character rule, so the prefix
// is always exactly one path segment.
func NormalizeWebPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "/")
	if s == "" {
		return "", nil
	}
	// Traversal is checked before the character rule so that the error names the
	// real problem instead of blaming the dot.
	if s == "." || s == ".." || strings.Contains(s, "..") {
		return "", fmt.Errorf("path traversal is not allowed in %q", raw)
	}
	for _, r := range s {
		if !isWebPathRune(r) {
			return "", fmt.Errorf("character %q is not allowed; use only A-Z a-z 0-9 . _ ~ -", string(r))
		}
	}
	if len(s) > 128 {
		return "", fmt.Errorf("web path is %d characters; the maximum is 128", len(s))
	}
	return s, nil
}

func envString(getenv func(string) string, key, def string) string {
	if v, ok := lookup(getenv, key); ok {
		return v
	}
	return def
}

func envInt(getenv func(string) string, key string, def int) (int, error) {
	v, ok := lookup(getenv, key)
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not an integer", key, v)
	}
	return n, nil
}

func envBool(getenv func(string) string, key string, def bool) (bool, error) {
	v, ok := lookup(getenv, key)
	if !ok {
		return def, nil
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean", key, v)
	}
	return b, nil
}

// lookup treats an empty value as unset, so an exported-but-blank variable
// falls back to the default rather than blanking a required path.
func lookup(getenv func(string) string, key string) (string, bool) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return "", false
	}
	return v, true
}

// lookBinary resolves name on PATH, falling back to well-known absolute paths.
// It returns "" when nothing is found; callers report that as a missing
// capability rather than failing at startup.
func lookBinary(name string, fallbacks ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, p := range fallbacks {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
