// Package exec is the single gateway through which the panel runs an external
// process (§8.2).
//
// Two rules are absolute here. Commands are always an argv slice and never a
// shell string, which removes shell injection as a class of bug rather than
// defending against it case by case (§17.6). And every call carries a timeout,
// so a hung `systemctl` can never wedge the panel.
//
// Every invocation is appended to the operation trace on the context, which is
// what the audit log records.
package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	osexec "os/exec"
	"strings"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/audit"
)

// DefaultTimeout bounds any call whose context carries no earlier deadline.
// systemctl and modprobe normally answer in milliseconds; anything approaching
// this is already a fault.
const DefaultTimeout = 30 * time.Second

// maxCapture caps how much of each stream is retained. Output is stored in the
// audit log, and an unbounded capture would let one runaway command bloat the
// database.
const maxCapture = 64 * 1024

// ErrNoBinary is returned when the argv slice is empty or names no program.
var ErrNoBinary = errors.New("exec: no program to run")

// Result is the complete outcome of one invocation.
type Result struct {
	Argv     []string      `json:"argv"`
	ExitCode int           `json:"exit_code"`
	Stdout   string        `json:"stdout"`
	Stderr   string        `json:"stderr"`
	Duration time.Duration `json:"duration"`
	// TimedOut reports that the process was killed because its deadline
	// elapsed, which an exit code alone cannot distinguish from a plain failure.
	TimedOut bool `json:"timed_out"`
}

// Failed reports whether the process exited non-zero.
func (r Result) Failed() bool { return r.ExitCode != 0 }

// CommandLine renders the argv for display. It is for humans and logs only:
// nothing ever parses or executes this string.
func (r Result) CommandLine() string { return strings.Join(r.Argv, " ") }

// Runner runs one external program.
//
// The argv slice is passed to the kernel unchanged; there is deliberately no
// variant that accepts a command string.
type Runner interface {
	Run(ctx context.Context, argv []string) (Result, error)
}

// Both implementations are checked against the interface at compile time.
var (
	_ Runner = (*CommandRunner)(nil)
	_ Runner = (*FakeRunner)(nil)
)

// CommandRunner is the real implementation.
type CommandRunner struct {
	// Timeout applies when the context carries no earlier deadline.
	Timeout time.Duration
}

// NewRunner returns a runner with the default timeout.
func NewRunner() *CommandRunner { return &CommandRunner{Timeout: DefaultTimeout} }

// Run executes argv and captures its outcome.
//
// A non-zero exit is reported through Result.ExitCode and as an error, so a
// caller may either check the field or handle the error; both describe the same
// event and neither can be missed by accident.
func (c *CommandRunner) Run(ctx context.Context, argv []string) (Result, error) {
	if len(argv) == 0 || strings.TrimSpace(argv[0]) == "" {
		return Result{Argv: argv}, ErrNoBinary
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	var stdout, stderr bytes.Buffer
	cmd := osexec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// A deliberately empty environment: nothing the panel runs reads one, and an
	// inherited PATH or LD_PRELOAD is an avoidable influence on a root process.
	cmd.Env = []string{}

	start := time.Now()
	runErr := cmd.Run()
	res := Result{
		Argv:     append([]string(nil), argv...),
		Stdout:   truncate(stdout.String()),
		Stderr:   truncate(stderr.String()),
		Duration: time.Since(start),
	}

	var exitErr *osexec.ExitError
	switch {
	case runErr == nil:
		res.ExitCode = 0
	case errors.As(runErr, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	default:
		// The program could not be started at all: not found, not executable.
		res.ExitCode = -1
	}
	if ctx.Err() != nil {
		res.TimedOut = true
	}

	record(ctx, res, runErr)

	if runErr != nil {
		return res, wrap(res, runErr)
	}
	return res, nil
}

// wrap turns a process failure into an error whose message names the command
// and quotes the tail of stderr, which is what an operator needs to see.
func wrap(res Result, err error) error {
	detail := strings.TrimSpace(res.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(res.Stdout)
	}
	if detail == "" {
		detail = err.Error()
	}
	if res.TimedOut {
		return fmt.Errorf("%s timed out after %s: %s", res.Argv[0], res.Duration.Round(time.Millisecond), detail)
	}
	return fmt.Errorf("%s exited %d: %s", res.Argv[0], res.ExitCode, detail)
}

// record appends the invocation to the trace on the context, if there is one.
func record(ctx context.Context, res Result, err error) {
	tr := audit.TraceFrom(ctx)
	if tr == nil {
		return
	}
	code := res.ExitCode
	op := audit.Operation{
		Kind:       audit.KindCommand,
		Argv:       res.Argv,
		ExitCode:   &code,
		Stdout:     res.Stdout,
		Stderr:     res.Stderr,
		DurationMs: res.Duration.Milliseconds(),
	}
	if err != nil {
		op.Error = err.Error()
	}
	tr.Add(op)
}

func truncate(s string) string {
	if len(s) <= maxCapture {
		return s
	}
	return s[:maxCapture] + "\n[output truncated]"
}

// FakeRunner records invocations without executing anything. It powers the
// preview endpoint (§9.2) and every hermetic test.
type FakeRunner struct {
	mu    sync.Mutex
	calls [][]string

	// Handler, when set, produces the result for each call. It receives the
	// argv slice and returns the result and error the runner should report.
	Handler func(argv []string) (Result, error)

	// Responses maps a whole command line to a canned result, for the common
	// case where only one or two commands need a specific answer.
	Responses map[string]Result

	// Errors maps a whole command line to a forced failure, which is how a test
	// makes one step of an apply plan fail.
	Errors map[string]error
}

// NewFakeRunner returns an empty fake.
func NewFakeRunner() *FakeRunner {
	return &FakeRunner{Responses: map[string]Result{}, Errors: map[string]error{}}
}

// Run records the call and returns the configured answer, defaulting to success
// with empty output.
func (f *FakeRunner) Run(ctx context.Context, argv []string) (Result, error) {
	if len(argv) == 0 {
		return Result{}, ErrNoBinary
	}
	line := strings.Join(argv, " ")

	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), argv...))
	handler := f.Handler
	res, hasRes := f.Responses[line]
	forced, hasErr := f.Errors[line]
	f.mu.Unlock()

	if handler != nil {
		out, err := handler(argv)
		out.Argv = append([]string(nil), argv...)
		record(ctx, out, err)
		return out, err
	}
	if !hasRes {
		res = Result{}
	}
	res.Argv = append([]string(nil), argv...)
	if hasErr && forced != nil {
		if res.ExitCode == 0 {
			res.ExitCode = 1
		}
		record(ctx, res, forced)
		return res, forced
	}
	record(ctx, res, nil)
	return res, nil
}

// Calls returns every argv slice passed to Run, in order.
func (f *FakeRunner) Calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = append([]string(nil), c...)
	}
	return out
}

// CommandLines returns every call rendered as a string, for readable assertions.
func (f *FakeRunner) CommandLines() []string {
	out := []string{}
	for _, c := range f.Calls() {
		out = append(out, strings.Join(c, " "))
	}
	return out
}

// Reset forgets every recorded call.
func (f *FakeRunner) Reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}
