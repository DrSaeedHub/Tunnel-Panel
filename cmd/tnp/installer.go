package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DefaultReleaseBase mirrors the installer's own default. The value the
// installation was actually created with is recorded in cli.env and wins over
// this; a test pins the two literals together.
const DefaultReleaseBase = "https://github.com/DrSaeedHub/Tunnel-Panel/releases/download"

// DefaultInstallerURL is where a fresh copy of the installer comes from. GitHub
// serves release assets and repository files from different hosts, so this is
// not derivable from DefaultReleaseBase.
const DefaultInstallerURL = "https://raw.githubusercontent.com/DrSaeedHub/Tunnel-Panel/main/scripts/install.sh"

// installerConfig is what the installer left behind about itself, so that
// updating uses the same release base the installation came from rather than a
// default that may point somewhere else entirely.
type installerConfig struct {
	ReleaseBase  string
	InstallerURL string
	Version      string
}

func readInstallerConfig() installerConfig {
	out := installerConfig{ReleaseBase: DefaultReleaseBase, InstallerURL: DefaultInstallerURL}
	file, err := loadEnvFile(cliEnvFile)
	if err != nil {
		return out
	}
	if v, ok := file.Get("GRE_PANEL_RELEASE_BASE"); ok && strings.TrimSpace(v) != "" {
		out.ReleaseBase = strings.TrimSpace(v)
	}
	if v, ok := file.Get("GRE_PANEL_INSTALLER_URL"); ok && strings.TrimSpace(v) != "" {
		out.InstallerURL = strings.TrimSpace(v)
	}
	if v, ok := file.Get("GRE_PANEL_VERSION"); ok {
		out.Version = strings.TrimSpace(v)
	}
	return out
}

// installerScript returns a path to an installer to run.
//
// Update fetches a fresh one: a newer release can need a newer installer, and
// running last year's script against this year's artefacts is how an upgrade
// quietly skips a step. Everything else prefers the cached copy, because
// uninstalling should not require the network — the most likely reason an
// operator is uninstalling is that something is wrong.
func (a *app) installerScript(ctx context.Context, preferFresh bool) (path string, cleanup func(), err error) {
	cfg := readInstallerConfig()
	noop := func() {}

	if preferFresh {
		if downloaded, derr := downloadInstaller(ctx, cfg.InstallerURL); derr == nil {
			return downloaded, func() { os.Remove(downloaded) }, nil //nolint:errcheck // best effort
		} else if !exists(cachedInstall) {
			return "", noop, fmt.Errorf("could not download the installer from %s (%w), and there is "+
				"no cached copy at %s", cfg.InstallerURL, derr, cachedInstall)
		} else {
			a.sayf("warning: could not download a fresh installer (%v); using the cached copy at %s",
				derr, cachedInstall)
		}
	}

	if exists(cachedInstall) {
		return cachedInstall, noop, nil
	}
	downloaded, derr := downloadInstaller(ctx, cfg.InstallerURL)
	if derr != nil {
		return "", noop, fmt.Errorf("there is no installer at %s and it could not be downloaded "+
			"from %s: %w", cachedInstall, cfg.InstallerURL, derr)
	}
	return downloaded, func() { os.Remove(downloaded) }, nil //nolint:errcheck // best effort
}

func downloadInstaller(ctx context.Context, url string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	// A release host that answers 200 with an error page would otherwise be
	// handed to bash. It costs nothing to check that this is a script.
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "#!") {
		return "", fmt.Errorf("what %s returned does not begin with a shebang, so it is not the installer", url)
	}

	file, err := os.CreateTemp("", "gre-panel-install-*.sh")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write(body); err != nil {
		os.Remove(file.Name()) //nolint:errcheck // already failing
		return "", err
	}
	if err := os.Chmod(file.Name(), 0o700); err != nil {
		os.Remove(file.Name()) //nolint:errcheck // already failing
		return "", err
	}
	return file.Name(), nil
}

// runInstaller executes the installer, streaming its output to the operator.
//
// GRE_PANEL_NO_MENU is set for the child: the installer hands control to this
// CLI when it is run with no arguments and finds itself installed, and a CLI
// invoking an installer that invokes the CLI would be a loop. Arguments are
// always passed here, so the handoff would not trigger anyway; setting it makes
// that a guarantee rather than a coincidence.
func (a *app) runInstaller(ctx context.Context, script string, args ...string) error {
	bash, err := exec.LookPath("bash")
	if err != nil {
		return fmt.Errorf("bash is required to run the installer: %w", err)
	}
	cmd := exec.CommandContext(ctx, bash, append([]string{script}, args...)...)
	cmd.Stdout = a.err
	cmd.Stderr = a.err
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(), "GRE_PANEL_NO_MENU=1")

	a.sayf("Running %s %s", filepath.Base(script), strings.Join(args, " "))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("the installer failed: %w", err)
	}
	return nil
}

// update installs what the release base is serving.
//
// It goes through the installer rather than replacing the binary directly,
// because the installer is what writes the unit, creates the directories the
// sandbox needs, verifies the checksum and waits for the panel to answer. A CLI
// that copied a binary over the old one would skip every one of those and
// report success.
func (a *app) update(ctx context.Context, wantVersion string) error {
	cfg := readInstallerConfig()
	if wantVersion == "" {
		wantVersion = "latest"
	}
	script, cleanup, err := a.installerScript(ctx, true)
	if err != nil {
		return err
	}
	defer cleanup()

	before := binaryVersion(ctx, panelBinary)
	if err := a.runInstaller(ctx, script,
		"--upgrade", "--yes", "--version", wantVersion, "--release-base", cfg.ReleaseBase); err != nil {
		return err
	}
	after := binaryVersion(ctx, panelBinary)

	// Report what actually happened. "Updated" when nothing changed is the kind
	// of claim that makes an operator stop reading output.
	switch {
	case before == after && before != "":
		a.sayf("The panel is still %s — %s was already the installed build.", after, wantVersion)
	case after == "":
		a.sayf("The panel binary did not report a version after the upgrade.")
	default:
		a.sayf("The panel went from %s to %s.", orNone(before), after)
	}
	return nil
}

// reinstall re-applies the installation without changing the version.
//
// It repairs the things an update would also repair — a damaged unit file, a
// missing directory, a binary someone overwrote — while deliberately staying on
// the build that is already there, so an operator fixing a broken installation
// does not also inherit whatever changed upstream.
func (a *app) reinstall(ctx context.Context) error {
	cfg := readInstallerConfig()
	script, cleanup, err := a.installerScript(ctx, false)
	if err != nil {
		return err
	}
	defer cleanup()

	target := cfg.Version
	if target == "" {
		target = "latest"
		a.sayf("warning: this installation did not record which version it came from, so " +
			"reinstalling will fetch the current one")
	}
	return a.runInstaller(ctx, script,
		"--upgrade", "--yes", "--version", target, "--release-base", cfg.ReleaseBase)
}

// uninstallPanel removes the panel and leaves the CLI, so the operator can
// still reinstall from the same shell.
func (a *app) uninstallPanel(ctx context.Context, purgeTunnels, purgeData bool) error {
	script, cleanup, err := a.installerScript(ctx, false)
	if err != nil {
		return err
	}
	defer cleanup()

	args := []string{"--uninstall", "--yes"}
	if purgeTunnels {
		args = append(args, "--purge-tunnels")
	}
	if purgeData {
		args = append(args, "--purge-data")
	}
	if err := a.runInstaller(ctx, script, args...); err != nil {
		return err
	}
	a.sayf("The panel is gone. This CLI is still installed at %s; remove it with "+
		"`tnp uninstall --cli --yes`.", cliBinary)
	return nil
}

// uninstallCLI removes this binary and its support directory.
//
// Deleting the running executable is fine on Linux: the file is unlinked and
// the running process keeps its open image until it exits.
func (a *app) uninstallCLI() ([]string, error) {
	var removed []string
	var failures []string
	for _, path := range []string{cachedInstall, cliEnvFile, supportDir, cliBinary} {
		err := os.Remove(path)
		switch {
		case err == nil:
			removed = append(removed, path)
		case os.IsNotExist(err):
			// Nothing to do, and not worth reporting as a failure: uninstall is
			// idempotent on purpose.
		default:
			failures = append(failures, fmt.Sprintf("%s: %v", path, err))
		}
	}
	if len(failures) > 0 {
		return removed, fmt.Errorf("some files could not be removed: %s", strings.Join(failures, "; "))
	}
	return removed, nil
}
