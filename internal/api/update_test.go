package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/update"
)

// updateHarness builds a panel whose release host is a test server and whose
// installer is a fake runner, so the whole endpoint runs without the network
// and without installing anything.
func updateHarness(t *testing.T, tag string, adjust func(*update.ApplierDeps)) (*harness, *exec.FakeRunner) {
	t.Helper()

	releases := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"` + tag + `","name":"Panel ` + tag +
			`","html_url":"https://example.invalid/r/` + tag + `","body":"Notes."}`))
	}))
	t.Cleanup(releases.Close)

	dir := t.TempDir()
	cli := filepath.Join(dir, "tnp")
	if err := os.WriteFile(cli, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatalf("writing the fake CLI: %v", err)
	}
	installer := exec.NewFakeRunner()

	h := newHarnessWith(t, testWebPath, func(d *Deps) {
		applierDeps := update.ApplierDeps{
			CurrentVersion: "v0.1.5", DataDir: dir, CLIBin: cli,
			SystemdRunBin: "/usr/bin/systemd-run", SystemctlBin: "/usr/bin/systemctl",
			UnderSystemd: true, Runner: installer, Euid: func() int { return 0 },
		}
		if adjust != nil {
			adjust(&applierDeps)
		}
		d.Build = BuildInfo{Version: "v0.1.5", Commit: "abcdef", Date: "2026-01-01"}
		d.Updates = &Updates{
			Checker: update.NewChecker(update.CheckerDeps{
				CurrentVersion: "v0.1.5", APIURL: releases.URL,
				Client: releases.Client(), Settings: d.Settings,
			}),
			Applier: update.NewApplier(applierDeps),
		}
	})
	return h, installer
}

func readUpdate(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decoding the update status failed: %v\nbody: %s", err, body)
	}
	return decoded
}

// The footer reads this on every dashboard load. It must answer from the panel
// alone — the check that reaches the release host happens behind it.
func TestTheUpdateStatusReportsWhatIsRunningAndWhatIsServed(t *testing.T) {
	h, _ := updateHarness(t, "v0.2.0", nil)
	c, api := session(t, h)

	// The explicit check is the one that waits, which is what makes this
	// assertion about the answer rather than about timing.
	resp, body := c.request(http.MethodPost, api+"/system/update/check", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /system/update/check = %d\nbody: %s", resp.StatusCode, body)
	}
	status := readUpdate(t, body)

	if status["current_version"] != "v0.1.5" {
		t.Errorf("current_version = %v, want the running build", status["current_version"])
	}
	if status["update_available"] != true {
		t.Errorf("update_available = %v, want true\nbody: %s", status["update_available"], body)
	}
	latest, _ := status["latest"].(map[string]any)
	if latest["version"] != "v0.2.0" || latest["notes"] == "" {
		t.Errorf("the release was not carried back whole: %+v", latest)
	}
	if status["can_apply"] != true {
		t.Errorf("can_apply = %v with a working systemd and CLI: %v", status["can_apply"], status["reason"])
	}

	// And the cheap read answers the same thing without asking again.
	resp, body = c.request(http.MethodGet, api+"/system/update", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /system/update = %d\nbody: %s", resp.StatusCode, body)
	}
	if again := readUpdate(t, body); again["update_available"] != true {
		t.Errorf("the status endpoint lost the answer: %s", body)
	}
}

// Pressing the button has to reach the installer, and it has to reach it
// through systemd-run: everything else is killed by the restart it triggers.
func TestStartingAnUpdateLaunchesTheInstallerAndRecordsIt(t *testing.T) {
	h, installer := updateHarness(t, "v0.2.0", nil)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/system/update", map[string]string{"version": "v0.2.0"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /system/update = %d, want 202\nbody: %s", resp.StatusCode, body)
	}
	status := readUpdate(t, body)
	state, _ := status["state"].(map[string]any)
	if state["stage"] != "running" || state["target_version"] != "v0.2.0" {
		t.Fatalf("the response does not describe a started update: %+v", state)
	}

	launched := false
	for _, line := range installer.CommandLines() {
		if strings.Contains(line, "systemd-run") && strings.Contains(line, "tnp update") {
			launched = true
		}
	}
	if !launched {
		t.Fatalf("the installer was never launched: %v", installer.CommandLines())
	}

	// The audit entry is written before the restart, because after it this
	// process no longer exists to write anything.
	resp, body = c.request(http.MethodGet, api+"/audit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /audit = %d\nbody: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "PanelUpdate") {
		t.Errorf("the update was not recorded in the audit log: %s", body)
	}
}

// A second press while one is running would put two installers over one binary.
func TestASecondUpdateIsRefusedWhileOneIsRunning(t *testing.T) {
	h, installer := updateHarness(t, "v0.2.0", nil)
	installer.Handler = func(argv []string) (exec.Result, error) {
		if strings.Contains(strings.Join(argv, " "), "systemctl show") {
			return exec.Result{Stdout: "LoadState=loaded\nActiveState=active\nSubState=running\n"}, nil
		}
		return exec.Result{}, nil
	}
	c, api := session(t, h)

	if resp, body := c.request(http.MethodPost, api+"/system/update", nil); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("the first update = %d\nbody: %s", resp.StatusCode, body)
	}
	resp, body := c.request(http.MethodPost, api+"/system/update", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("the second update = %d, want 409\nbody: %s", resp.StatusCode, body)
	}
}

// A panel that cannot update itself has to say so before the button is pressed,
// and refuse with the same reason when it is.
func TestAPanelThatCannotUpdateItselfSaysWhy(t *testing.T) {
	h, _ := updateHarness(t, "v0.2.0", func(d *update.ApplierDeps) { d.UnderSystemd = false })
	c, api := session(t, h)

	_, body := c.request(http.MethodGet, api+"/system/update", nil)
	status := readUpdate(t, body)
	if status["can_apply"] != false {
		t.Errorf("can_apply = %v without systemd", status["can_apply"])
	}
	if reason, _ := status["reason"].(string); !strings.Contains(reason, "systemd") {
		t.Errorf("reason = %q, want it to name systemd", reason)
	}

	resp, body := c.request(http.MethodPost, api+"/system/update", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST /system/update = %d, want 503\nbody: %s", resp.StatusCode, body)
	}
	if code := decodeErrorBody(t, body).Error.Code; code != CodeUnavailable {
		t.Errorf("error code = %q, want %q", code, CodeUnavailable)
	}
}

func TestOnlyAVersionTagCanBeInstalled(t *testing.T) {
	h, _ := updateHarness(t, "v0.2.0", nil)
	c, api := session(t, h)

	resp, body := c.request(http.MethodPost, api+"/system/update", map[string]string{"version": "main"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("installing %q = %d, want 422\nbody: %s", "main", resp.StatusCode, body)
	}
}

// Every update endpoint changes or reveals what this server runs, so none of
// them answers without a session.
func TestTheUpdateEndpointsNeedASession(t *testing.T) {
	h, _ := updateHarness(t, "v0.2.0", nil)
	_, api := session(t, h)
	// A client of its own, so it carries no cookies: the panel is set up, and
	// what is being checked is the guard rather than the setup gate.
	anonymous := newClient(t, h)

	// The two refusals are different and both are correct: a read is rejected
	// for want of a session, and a write never gets that far because the CSRF
	// guard runs first and there is no token to echo.
	for _, call := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/system/update", http.StatusUnauthorized},
		{http.MethodPost, "/system/update/check", http.StatusForbidden},
		{http.MethodPost, "/system/update", http.StatusForbidden},
	} {
		resp, _ := anonymous.request(call.method, api+call.path, nil)
		if resp.StatusCode != call.want {
			t.Errorf("%s %s = %d without a session, want %d",
				call.method, call.path, resp.StatusCode, call.want)
		}
	}
}

// The audit action has to have a name, or the history page prints the number.
func TestThePanelUpdateActionIsNamed(t *testing.T) {
	for _, table := range model.LookupTables() {
		if table.Name != "AuditAction" {
			continue
		}
		for _, value := range table.Values {
			if value.ID == model.AuditActionPanelUpdate {
				if value.Title != "PanelUpdate" {
					t.Errorf("the update action is titled %q", value.Title)
				}
				return
			}
		}
	}
	t.Fatal("the PanelUpdate audit action is not declared")
}

func decodeErrorBody(t *testing.T, body []byte) ErrorEnvelope {
	t.Helper()
	var env ErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("decoding the error envelope failed: %v\nbody: %s", err, body)
	}
	return env
}
