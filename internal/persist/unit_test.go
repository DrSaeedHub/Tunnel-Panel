package persist_test

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/rules"
)

// The installed unit runs the panel under ProtectSystem=full, which makes /usr,
// /boot and /etc read-only for the service — running as root does not exempt
// it. Anything the panel writes outside that has to be named in ReadWritePaths,
// and a path that is missing there does not fail at install time or at startup:
// it fails much later, the first time an operator presses the button that needs
// it, as a 500 with "read-only file system" buried in the journal.
//
// That is what happened to the sysctl file: /etc/systemd/system was carved out
// because the tunnel units live there, so tunnels worked and forwarding could
// never be turned on. This test ties the unit back to the paths the Go code
// actually writes, so adding a new one without carving it out fails here.
func installScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "scripts", "install.sh")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the installer failed: %v", err)
	}
	return string(content)
}

// readWritePaths returns the directories the installed unit leaves writable.
func readWritePaths(t *testing.T, script string) []string {
	t.Helper()
	line := regexp.MustCompile(`(?m)^ReadWritePaths=(.*)$`).FindStringSubmatch(script)
	if line == nil {
		t.Fatal("the installer's unit declares no ReadWritePaths at all")
	}
	var out []string
	for _, field := range strings.Fields(line[1]) {
		// A leading "-" marks a path systemd may skip when it is absent.
		out = append(out, strings.TrimPrefix(field, "-"))
	}
	return out
}

func TestTheUnitLeavesEveryPathThePanelWritesWritable(t *testing.T) {
	script := installScript(t)
	writable := readWritePaths(t, script)

	// The files the panel writes outside its own data directory, each named by
	// the constant the writing code uses rather than repeated as a literal.
	//
	// These are paths on the Linux host the panel manages, so they are taken
	// apart with path rather than filepath: on a Windows checkout filepath.Dir
	// answers "\etc\sysctl.d", which matches nothing in ReadWritePaths and
	// reports every carve-out as missing.
	needed := map[string]string{
		persist.SysctlPath: "the sysctl file that makes IP forwarding survive a reboot",
		path.Join("/etc/systemd/system", persist.RulesUnitName): "the boot-time ruleset restore unit",
		"/etc/systemd/network/gre-panel.netdev":                 "the networkd files for a tunnel",
		rules.DefaultDir + "/gre-panel.nft":                     "the rendered ruleset",
	}

	for target, what := range needed {
		dir := path.Dir(target)
		covered := false
		for _, allowed := range writable {
			// $DATA_DIR is expanded by the shell at install time; the unit is
			// written with the real path in it.
			if allowed == "$DATA_DIR" {
				allowed = "/var/lib/gre-panel"
			}
			if dir == allowed || strings.HasPrefix(dir+"/", strings.TrimSuffix(allowed, "/")+"/") {
				covered = true
				break
			}
		}
		if !covered {
			t.Errorf("the unit makes %s read-only, so the panel cannot write %s (%s)\n"+
				"ReadWritePaths: %v", dir, target, what, writable)
		}
	}
}

// TestEveryWritablePathIsCreatedByTheInstaller: systemd refuses to start a unit
// whose ReadWritePaths names a directory that does not exist, so a carve-out
// for a directory the host happens to lack would take the whole panel down
// rather than only the feature that needed it.
func TestEveryWritablePathIsCreatedByTheInstaller(t *testing.T) {
	script := installScript(t)
	created := regexp.MustCompile(`(?m)^install -d [^\n]*`).FindAllString(script, -1)

	for _, path := range readWritePaths(t, script) {
		switch path {
		case "$DATA_DIR", "/run/systemd":
			// The data directory is created by name above; /run/systemd belongs
			// to systemd itself and exists wherever systemd is running.
			continue
		}
		found := false
		for _, line := range created {
			if strings.Contains(line, path) {
				found = true
			}
		}
		if !found {
			t.Errorf("the unit leaves %s writable but the installer never creates it, so the "+
				"service will not start on a host without it", path)
		}
	}
}

// TestTheHardeningCommentDescribesProtectSystemCorrectly guards a comment,
// which is unusual — but this one is the reason the sysctl carve-out was missing
// in the first place. It claimed /etc stays writable under ProtectSystem=full.
// It does not: yes covers /usr and /boot, full adds /etc, strict covers the
// whole filesystem. Anyone reading the wrong version has no reason to look for
// the bug this file exists to prevent.
func TestTheHardeningCommentDescribesProtectSystemCorrectly(t *testing.T) {
	script := installScript(t)
	comment := ""
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "ProtectSystem=full") && strings.HasPrefix(strings.TrimSpace(line), "#") {
			comment = line
		}
	}
	if comment == "" {
		t.Fatal("the unit's hardening block no longer explains ProtectSystem=full")
	}
	if strings.Contains(comment, "/etc stays writable") {
		t.Errorf("the hardening comment still claims /etc stays writable under "+
			"ProtectSystem=full, which is what hid the read-only sysctl file: %s", comment)
	}
	if !strings.Contains(comment, "/etc") {
		t.Errorf("the hardening comment does not mention /etc, which is the part of "+
			"ProtectSystem=full that catches people out: %s", comment)
	}
}
