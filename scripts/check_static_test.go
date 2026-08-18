// Package scripts holds tests for the shell scripts that build and install a
// release. They are here rather than beside the shell because `go test ./...`
// is what actually gets run, and a check nobody runs is the thing this file
// exists to prevent.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bashOrSkip finds a bash to drive the script under test.
func bashOrSkip(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this host, so the release scripts cannot be exercised here")
	}
	return path
}

// classify runs the script's own classify_ldd against a recorded ldd result.
//
// The decision is tested rather than the ELF inspection, because the defect was
// in the decision: a host that could not read the binary was treated the same
// as a host that had read it and found it clean.
func classify(t *testing.T, status, output string) string {
	t.Helper()
	bash := bashOrSkip(t)
	script := filepath.Join("check-static.sh")
	cmd := exec.Command(bash, "-c",
		`source "$1"; classify_ldd "$2" "$3"`, "--", script, status, output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running classify_ldd failed: %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestTheStaticCheckKnowsWhatItDidNotCheck is the regression for a guarantee
// that only appeared to have been verified.
//
// The release script promised to "prove it rather than assume it" and then, on
// a host whose ldd cannot read a Linux ELF — Git Bash on Windows, or any
// cross-build — printed ldd's raw "Exec format error" and carried on to report
// success. An operator reading that sees an error immediately followed by
// "Done", which is worse than no check at all: it looks like something was
// established. Nothing was.
func TestTheStaticCheckKnowsWhatItDidNotCheck(t *testing.T) {
	for _, tc := range []struct {
		name, status, output, want string
	}{
		{
			name:   "a static Linux binary, as ldd reports it",
			status: "1", output: "\tnot a dynamic executable",
			want: "static",
		},
		{
			name:   "the other wording some ldd builds use",
			status: "0", output: "\tstatically linked",
			want: "static",
		},
		{
			name:   "a dynamically linked binary",
			status: "0",
			output: "\tlinux-vdso.so.1 (0x00007ffe1efa2000)\n" +
				"\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f25ba0a5000)",
			want: "dynamic",
		},
		{
			// The case that was silently passing: Git Bash's ldd on a Linux ELF.
			name:   "a host whose ldd cannot read the target",
			status: "1", output: "ldd: dist/gre-panel-linux-amd64: Exec format error",
			want: "unverified",
		},
		{
			name:   "ldd that says nothing at all",
			status: "127", output: "",
			want: "unverified",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(t, tc.status, tc.output); got != tc.want {
				t.Errorf("classify_ldd(%q) = %q, want %q", tc.output, got, tc.want)
			}
		})
	}
}

// TestTheStaticCheckReadsTheBuildSettings covers the portable half, which is
// what makes the guarantee meaningful on a host that cannot run ldd at all.
// CGO_ENABLED=0 is what makes this project's binaries static, and it is
// recorded inside the binary, so it can be read anywhere.
func TestTheStaticCheckReadsTheBuildSettings(t *testing.T) {
	bash := bashOrSkip(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go on PATH to build a binary to inspect")
	}

	built := filepath.Join(t.TempDir(), "probe")
	if runtime.GOOS == "windows" {
		built += ".exe"
	}
	// The panel itself, because it is the artefact the guarantee is about.
	build := exec.Command("go", "build", "-o", built, "../cmd/gre-panel")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("could not build a binary to inspect: %v\n%s", err, out)
	}

	cmd := exec.Command(bash, "-c",
		`source "$1"; cgo_disabled "$2" && echo yes || echo "no:$?"`, "--", "check-static.sh", built)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("running cgo_disabled failed: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "yes" {
		t.Errorf("a binary built with CGO_ENABLED=0 was reported as %q", got)
	}
}
