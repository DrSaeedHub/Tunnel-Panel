package exec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/audit"
)

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), []string{"/bin/sh", "-c", "printf out; printf err 1>&2; exit 3"})
	if err == nil {
		t.Fatal("a non-zero exit must be reported as an error")
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", res.ExitCode)
	}
	if res.Stdout != "out" || res.Stderr != "err" {
		t.Fatalf("stdout = %q, stderr = %q", res.Stdout, res.Stderr)
	}
	if res.Duration <= 0 {
		t.Fatal("duration was not measured")
	}
	if strings.Join(res.Argv, " ") != "/bin/sh -c printf out; printf err 1>&2; exit 3" {
		t.Fatalf("argv was not captured verbatim: %q", res.Argv)
	}
}

// The runner takes an argv slice, so a value containing shell metacharacters is
// an argument and never a command. This is §17.6 stated as a test.
func TestRunNeverInterpretsAShell(t *testing.T) {
	r := NewRunner()
	res, err := r.Run(context.Background(), []string{"/bin/echo", "a; rm -rf /tmp/nothing && echo pwned"})
	if err != nil {
		t.Fatalf("echo failed: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "a; rm -rf /tmp/nothing && echo pwned" {
		t.Fatalf("the argument was interpreted rather than passed through: %q", res.Stdout)
	}
}

func TestRunEnforcesATimeout(t *testing.T) {
	r := &CommandRunner{Timeout: 100 * time.Millisecond}
	start := time.Now()
	res, err := r.Run(context.Background(), []string{"/bin/sleep", "10"})
	if err == nil {
		t.Fatal("a command that outlives its timeout must fail")
	}
	if !res.TimedOut {
		t.Fatal("the result must record that the deadline elapsed")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the timeout was not enforced; the call took %s", elapsed)
	}
}

func TestRunRejectsAnEmptyArgv(t *testing.T) {
	r := NewRunner()
	if _, err := r.Run(context.Background(), nil); !errors.Is(err, ErrNoBinary) {
		t.Fatalf("error = %v, want ErrNoBinary", err)
	}
}

func TestRunAppendsToTheOperationTrace(t *testing.T) {
	tr := audit.NewTrace()
	ctx := audit.WithTrace(context.Background(), tr)

	r := NewRunner()
	if _, err := r.Run(ctx, []string{"/bin/echo", "hello"}); err != nil {
		t.Fatalf("echo failed: %v", err)
	}
	_, _ = r.Run(ctx, []string{"/bin/sh", "-c", "exit 7"})

	ops := tr.Operations()
	if len(ops) != 2 {
		t.Fatalf("recorded %d operations, want 2", len(ops))
	}
	if ops[0].Kind != audit.KindCommand || ops[0].ExitCode == nil || *ops[0].ExitCode != 0 {
		t.Fatalf("first operation recorded wrongly: %+v", ops[0])
	}
	if ops[1].ExitCode == nil || *ops[1].ExitCode != 7 || ops[1].Error == "" {
		t.Fatalf("a failing command must record its exit code and error: %+v", ops[1])
	}
}

func TestFakeRunnerRecordsWithoutExecuting(t *testing.T) {
	f := NewFakeRunner()
	f.Responses["/bin/systemctl is-active gre-a-1"] = Result{Stdout: "active\n"}
	f.Errors["/bin/systemctl start broken"] = errors.New("unit failed")

	res, err := f.Run(context.Background(), []string{"/bin/systemctl", "is-active", "gre-a-1"})
	if err != nil || res.Stdout != "active\n" {
		t.Fatalf("canned response not returned: %+v, %v", res, err)
	}
	if _, err := f.Run(context.Background(), []string{"/bin/systemctl", "start", "broken"}); err == nil {
		t.Fatal("a forced error must be returned")
	}
	// A command with no canned answer succeeds silently, which is what makes the
	// fake usable as a default for the whole apply pipeline.
	if _, err := f.Run(context.Background(), []string{"/sbin/ip", "link", "del", "gre-a-1"}); err != nil {
		t.Fatalf("unconfigured command failed: %v", err)
	}

	lines := f.CommandLines()
	want := []string{
		"/bin/systemctl is-active gre-a-1",
		"/bin/systemctl start broken",
		"/sbin/ip link del gre-a-1",
	}
	if len(lines) != len(want) {
		t.Fatalf("recorded %d calls, want %d: %v", len(lines), len(want), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("call %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestFakeRunnerHandler(t *testing.T) {
	f := NewFakeRunner()
	f.Handler = func(argv []string) (Result, error) {
		if argv[1] == "is-enabled" {
			return Result{Stdout: "enabled\n"}, nil
		}
		return Result{}, nil
	}
	res, err := f.Run(context.Background(), []string{"/bin/systemctl", "is-enabled", "x"})
	if err != nil || strings.TrimSpace(res.Stdout) != "enabled" {
		t.Fatalf("handler result = %+v, %v", res, err)
	}
	if len(f.Calls()) != 1 {
		t.Fatal("the handler path must still record the call")
	}
}
