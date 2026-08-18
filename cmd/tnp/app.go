// Command tnp is the management CLI for the GRE tunnel panel.
//
// It exists for the things the panel cannot do to itself. The panel runs under
// a systemd sandbox that makes /etc read-only, it cannot restart itself from
// inside its own cgroup without killing the request that asked, and every route
// that could reset a password requires the session the operator has lost. All
// three are jobs for a process standing outside it.
//
// Every option is a subcommand. The menu is a wrapper that calls the same
// functions with the same arguments, so what an operator does interactively and
// what a test drives non-interactively are the same code path — a menu that is
// the only way in is a menu nobody can prove works.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Stamped at link time by scripts/build-release.sh, exactly as the panel is.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Sentinel outcomes that map to exit codes. They are distinct because a script
// wrapping this needs to tell "the change failed and the panel is fine" from
// "the change failed and so did putting it back".
var (
	errChangeRolledBack = errors.New("the change was rolled back")
	errRollbackFailed   = errors.New("the change failed and could not be rolled back")
)

// Exit codes, documented in the help text and pinned by a test.
const (
	exitOK             = 0
	exitUsage          = 2
	exitNotRoot        = 10
	exitFailed         = 11
	exitRolledBack     = 12
	exitRollbackFailed = 13
	exitCancelled      = 14
)

// dbHandle is the database as the CLI uses it, so a test can hand in one it
// opened itself.
type dbHandle = *db.DB

// app carries what every subcommand needs.
type app struct {
	envPath   string
	out       io.Writer // machine-readable output: JSON only, nothing else
	err       io.Writer // everything a human reads
	in        io.Reader
	jsonOut   bool
	assumeYes bool
}

func newApp() *app {
	return &app{
		envPath: config.EnvFilePath,
		out:     os.Stdout,
		err:     os.Stderr,
		in:      os.Stdin,
	}
}

// sayf writes a line for a human. It never goes to stdout, so --json owns that
// stream entirely and a caller can pipe it into a parser without filtering.
func (a *app) sayf(format string, args ...any) {
	fmt.Fprintf(a.err, format+"\n", args...)
}

// failf is how a subcommand reports that it could not do what was asked.
//
// Colour is doing one job here: a wall of white text with one line in it that
// matters is how somebody misses the reason and retries the same command. Red
// is reserved for that line and nothing else, so it keeps meaning "this is why
// it stopped". paint() is a no-op off a terminal, so a log captures the words
// and none of the escapes.
func (a *app) failf(format string, args ...any) {
	fmt.Fprintf(a.err, "%s %s\n", red("error:"), fmt.Sprintf(format, args...))
}

// warnf is for something worth knowing that did not stop the command.
func (a *app) warnf(format string, args ...any) {
	fmt.Fprintf(a.err, "%s %s\n", yellow("warning:"), fmt.Sprintf(format, args...))
}

// okf is the one-line confirmation that something took effect.
func (a *app) okf(format string, args ...any) {
	fmt.Fprintf(a.err, "%s %s\n", green("ok:"), fmt.Sprintf(format, args...))
}

// emit writes the machine-readable result, or a human summary when --json was
// not asked for.
func (a *app) emit(value any, human func()) {
	if a.jsonOut {
		encoder := json.NewEncoder(a.out)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(value); err != nil {
			a.sayf("writing the result failed: %v", err)
		}
		return
	}
	human()
}

// confirm asks a yes/no question.
//
// It reads /dev/tty rather than stdin where it can. The installer hands over to
// this CLI, and the documented way to run the installer is
// bash <(curl -Ls ...), where stdin may be a pipe; a prompt that read stdin
// there would consume the script or see EOF and answer "no" to a question
// nobody was asked.
// confirm asks a yes/no question. Like prompt, it watches the context so Ctrl+C
// at a confirmation is an answer of "no" rather than a frozen terminal — and a
// confirmation is exactly where somebody reaches for Ctrl+C, because it is the
// last moment before something irreversible.
func (a *app) confirm(ctx context.Context, question string) (bool, error) {
	if a.assumeYes {
		return true, nil
	}
	reader := a.in
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		reader = tty
	}
	fmt.Fprintf(a.err, "%s [y/N] ", question)

	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(reader).ReadString('\n')
		done <- result{line, err}
	}()

	select {
	case <-ctx.Done():
		fmt.Fprintln(a.err)
		return false, ctx.Err()
	case got := <-done:
		if got.err != nil && got.line == "" {
			return false, fmt.Errorf("there is no terminal to confirm on; pass --yes to proceed without asking")
		}
		answer := strings.ToLower(strings.TrimSpace(got.line))
		return answer == "y" || answer == "yes", nil
	}
}

// prompt asks for a value, offering a default.
// prompt asks a question and returns the answer, or gives up when the context
// is cancelled.
//
// The context is the whole point of the signature. main installs a
// signal.NotifyContext for SIGINT, which stops Go terminating the process on
// Ctrl+C and cancels this context instead — so a read that ignores the context
// makes Ctrl+C do visibly nothing, which is what the menu used to do. Waiting on
// both the line and ctx.Done() is what gives the key its meaning back.
//
// The goroutine outlives a cancelled prompt, parked on a read nobody will
// collect. That is deliberate: there is no portable way to interrupt a blocking
// read on a tty, and the alternative — closing the descriptor underneath it —
// races with the runtime. The process is on its way out, and one parked
// goroutine costs a few kilobytes for the moment it has left.
func (a *app) prompt(ctx context.Context, label, fallback string) (string, error) {
	reader := a.in
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		reader = tty
	}
	if fallback != "" {
		fmt.Fprintf(a.err, "%s [%s]: ", label, fallback)
	} else {
		fmt.Fprintf(a.err, "%s: ", label)
	}

	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := bufio.NewReader(reader).ReadString('\n')
		done <- result{line, err}
	}()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case got := <-done:
		if got.err != nil && got.line == "" {
			return "", fmt.Errorf("there is no terminal to read from")
		}
		answer := strings.TrimSpace(got.line)
		if answer == "" {
			return fallback, nil
		}
		return answer, nil
	}
}

func (a *app) dbPath(env *panelEnv) string { return env.DBPath }

// openDB opens the panel's database read-write.
//
// The panel keeps it in WAL mode with a five-second busy timeout, so a second
// process can write while the panel is running: a password reset takes effect
// on the next request without anything being restarted. The file is required to
// exist — db.Open would otherwise create an empty one, and a CLI that silently
// invents a database is a CLI that reports success while changing nothing.
func (a *app) openDB(env *panelEnv) (dbHandle, error) {
	if _, err := os.Stat(env.DBPath); err != nil {
		return nil, fmt.Errorf("there is no panel database at %s. Is the panel installed on this "+
			"host? %w", env.DBPath, err)
	}
	database, err := db.Open(context.Background(), env.DBPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", env.DBPath, err)
	}
	// Init is idempotent and is what creates the PanelAddress table on an
	// installation that predates it. Without this, the CLI would be unable to
	// set an address on exactly the older installation most likely to need it.
	if err := db.Init(context.Background(), database); err != nil {
		database.Close() //nolint:errcheck // already failing
		return nil, fmt.Errorf("preparing %s: %w", env.DBPath, err)
	}
	return database, nil
}

// audit records what the CLI did, in the same log the panel writes.
//
// A change made from a shell is exactly the one that leaves no other trace, so
// it belongs here more than an ordinary one does. A failure to write it is
// reported and does not fail the command: the thing being audited has already
// happened, and refusing to report that would be a second, worse failure — the
// same reasoning the panel's own audit writer states.
func (a *app) audit(ctx context.Context, database dbHandle, action int64, success bool,
	request map[string]any, errText string) {

	writer := audit.New(database, nil)
	entry := audit.Entry{
		ActionID:   action,
		TargetType: "PanelCLI",
		TargetID:   hostnameOrEmpty(),
		Request:    request,
		IsSuccess:  success,
		// There is no client address: this did not arrive over the network.
		// Saying so is more useful than an empty string that reads like a bug.
		ClientIP:     "local console",
		ErrorMessage: errText,
	}
	writer.Write(ctx, entry)
	_ = model.NowUTC
}

func hostnameOrEmpty() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

// loopbackHost is where to probe the panel from this machine. A wildcard bind
// is not something to connect to.
func (a *app) loopbackHost(env *panelEnv) string {
	switch env.Host {
	case "0.0.0.0", "::", "":
		return "127.0.0.1"
	}
	return env.Host
}

// publicHost is what to put in a URL the operator will use. It is the bind
// address unless that is a wildcard, in which case the machine's own first
// address stands in — a URL saying 0.0.0.0 helps nobody.
func (a *app) publicHost(env *panelEnv) string {
	switch env.Host {
	case "0.0.0.0", "::", "":
		if addr := firstNonLoopbackAddress(); addr != "" {
			return addr
		}
		return "127.0.0.1"
	}
	return env.Host
}

func firstNonLoopbackAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP.String()
	}
	return ""
}
