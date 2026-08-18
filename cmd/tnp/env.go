package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/config"
)

// envFile is /etc/gre-panel.env, held as the lines it is made of.
//
// It is edited rather than rewritten. systemd reads this file, an operator may
// have added a variable to it, and a tool that regenerates it from a template
// silently throws away anything it did not expect. Keeping the lines means an
// unknown key, a comment and the file's own ordering all survive a change to
// one value.
type envFile struct {
	path  string
	lines []string
}

func loadEnvFile(path string) (*envFile, error) {
	f := &envFile{path: path}
	handle, err := os.Open(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer handle.Close()

	scanner := bufio.NewScanner(handle)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		f.lines = append(f.lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return f, nil
}

// Get returns a value and whether the key is present at all. Present-but-empty
// and absent are different: GRE_PANEL_WEB_PATH= is a deliberate instruction to
// serve at the root.
func (f *envFile) Get(key string) (string, bool) {
	for _, line := range f.lines {
		name, value, ok := splitEnvLine(line)
		if ok && name == key {
			return value, true
		}
	}
	return "", false
}

// Set replaces a key's value in place, or appends it when the key is absent.
func (f *envFile) Set(key, value string) {
	for i, line := range f.lines {
		name, _, ok := splitEnvLine(line)
		if ok && name == key {
			f.lines[i] = key + "=" + value
			return
		}
	}
	f.lines = append(f.lines, key+"="+value)
}

// Render returns the file's bytes, with the trailing newline a text file wants.
func (f *envFile) Render() []byte {
	if len(f.lines) == 0 {
		return nil
	}
	return []byte(strings.Join(f.lines, "\n") + "\n")
}

// Write replaces the file atomically.
//
// The temporary file is created in the same directory so the rename cannot
// cross a filesystem, and the mode is 0600 from the start rather than chmodded
// afterwards: this file has held nothing secret so far, but it is systemd's
// input to a service that runs as root, and a window where it is world-readable
// or world-writable is not worth having.
func (f *envFile) Write() error {
	dir := filepath.Dir(f.path)
	temp, err := os.CreateTemp(dir, ".gre-panel.env.")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	name := temp.Name()
	defer os.Remove(name) //nolint:errcheck // a no-op once the rename succeeds

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return fmt.Errorf("restricting %s: %w", name, err)
	}
	if _, err := temp.Write(f.Render()); err != nil {
		temp.Close()
		return fmt.Errorf("writing %s: %w", name, err)
	}
	// fsync before the rename, or a crash can leave the new name pointing at a
	// file whose contents never reached the disk.
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("flushing %s: %w", name, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", name, err)
	}
	if err := os.Rename(name, f.path); err != nil {
		return fmt.Errorf("replacing %s: %w", f.path, err)
	}
	return nil
}

// splitEnvLine parses one line of an EnvironmentFile. Comments and blanks are
// not assignments and are reported as such so they are preserved untouched.
func splitEnvLine(line string) (key, value string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	name, rest, found := strings.Cut(trimmed, "=")
	if !found {
		return "", "", false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}
	// systemd allows the value to be quoted. Unwrapping matched quotes means a
	// value written by hand as "abc123" is read as abc123 rather than as a web
	// path containing quotation marks.
	rest = strings.TrimSpace(rest)
	if len(rest) >= 2 {
		if (rest[0] == '"' && rest[len(rest)-1] == '"') || (rest[0] == '\'' && rest[len(rest)-1] == '\'') {
			rest = rest[1 : len(rest)-1]
		}
	}
	return name, rest, true
}

// panelEnv is what the CLI needs out of the environment file.
type panelEnv struct {
	file    *envFile
	DataDir string
	DBPath  string
	Host    string
	Port    int
	WebPath string
	// PortSet and WebPathSet record that the file supplied these, as opposed to
	// them being the defaults filled in below. The address resolver needs the
	// difference: an absent value is not an instruction, and treating the
	// compiled default as one made the CLI report the default port on a host
	// whose environment file an uninstall had removed, while the database said
	// something else.
	PortSet    bool
	WebPathSet bool
}

// readPanelEnv loads the environment file and fills in the same defaults the
// panel's own bootstrap applies, so the CLI and the panel agree about where the
// database is even when the file is missing a key.
func readPanelEnv(path string) (*panelEnv, error) {
	file, err := loadEnvFile(path)
	if err != nil {
		return nil, err
	}
	out := &panelEnv{
		file:    file,
		DataDir: config.DefaultDataDir,
		Host:    config.DefaultBindHost,
		Port:    config.DefaultBindPort,
	}
	if v, ok := file.Get(config.EnvDataDir); ok && strings.TrimSpace(v) != "" {
		out.DataDir = strings.TrimSpace(v)
	}
	if v, ok := file.Get(config.EnvBindHost); ok && strings.TrimSpace(v) != "" {
		out.Host = strings.TrimSpace(v)
	}
	if v, ok := file.Get(config.EnvBindPort); ok && strings.TrimSpace(v) != "" {
		port, convErr := strconv.Atoi(strings.TrimSpace(v))
		if convErr != nil {
			return nil, fmt.Errorf("%s in %s is %q, which is not a number", config.EnvBindPort, path, v)
		}
		out.Port = port
		out.PortSet = true
	}
	// An absent key and an empty one both mean the root, which is also what the
	// panel concludes, so they are not distinguished here.
	if v, ok := file.Get(config.EnvWebPath); ok {
		webPath, convErr := config.NormalizeWebPath(v)
		if convErr != nil {
			return nil, fmt.Errorf("%s in %s is invalid: %w", config.EnvWebPath, path, convErr)
		}
		out.WebPath = webPath
		out.WebPathSet = true
	}
	out.DBPath = filepath.Join(out.DataDir, config.DefaultDBFileName)
	if v, ok := file.Get(config.EnvDBPath); ok && strings.TrimSpace(v) != "" {
		out.DBPath = strings.TrimSpace(v)
	}
	return out, nil
}
