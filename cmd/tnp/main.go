package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/drs/gre-panel/internal/config"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	a := newApp()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The global flags are accepted anywhere so that `tnp --json status` and
	// `tnp status --json` both work. An operator should not have to remember
	// which side a flag goes on.
	command, rest, err := a.parseGlobals(args)
	if err != nil {
		a.failf("%v", err)
		return exitUsage
	}

	if command == "" {
		return a.menu(ctx)
	}
	return a.dispatch(ctx, command, rest)
}

// parseGlobals pulls the flags that apply to every subcommand out of the
// argument list and returns the command and what is left.
func (a *app) parseGlobals(args []string) (command string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		// These read as flags and behave as commands, which is what every
		// operator expects of them. Without this they fall through to the
		// leftovers and `tnp --help` answers "must run as root".
		case "-h", "--help":
			if command == "" {
				command = "help"
			}
		case "--version":
			if command == "" {
				command = "version"
			}
		case "--json":
			a.jsonOut = true
		case "--yes", "-y":
			a.assumeYes = true
		case "--env-file":
			if i+1 >= len(args) {
				return "", nil, errors.New("--env-file needs a value")
			}
			i++
			a.envPath = args[i]
		default:
			if command == "" && !strings.HasPrefix(args[i], "-") {
				command = args[i]
				continue
			}
			rest = append(rest, args[i])
		}
	}
	// A bare `tnp --json` with no subcommand is a mistake worth catching: the
	// menu has no JSON form, and silently opening it would look like a hang to
	// whatever was parsing the output.
	if command == "" && a.jsonOut {
		return "", nil, errors.New("--json needs a subcommand; the menu has no machine-readable form")
	}
	return command, rest, nil
}

func (a *app) dispatch(ctx context.Context, command string, args []string) int {
	switch command {
	case "help", "-h", "--help":
		a.usage()
		return exitOK
	case "version", "--version":
		a.emit(map[string]string{
			"version": version, "commit": commit, "build_date": buildDate,
			"go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH,
		}, func() {
			a.sayf("tnp %s\ncommit:  %s\nbuilt:   %s\ngo:      %s %s/%s",
				version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		})
		return exitOK
	}

	// Everything below this line reads or writes the panel's own state.
	if code := a.requireRoot(); code != exitOK {
		return code
	}

	switch command {
	case "status":
		return a.cmdStatus(ctx)
	case "url":
		return a.cmdURL(ctx)
	case "set-port":
		return a.cmdSetPort(ctx, args)
	case "set-web-path":
		return a.cmdSetWebPath(ctx, args)
	case "set-username":
		return a.cmdSetUsername(ctx, args)
	case "reset-password":
		return a.cmdResetPassword(ctx, args)
	case "backup":
		newLink := false
		for _, arg := range args {
			if arg == "--new" {
				newLink = true
			}
		}
		if newLink {
			if code := a.backupRevoke(ctx); code != exitOK {
				return code
			}
		}
		// `backup <path>` writes a file; bare `backup` issues a link.
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				return a.backupSave(ctx, arg)
			}
		}
		return a.backupLink(ctx)
	case "backup-revoke":
		return a.backupRevoke(ctx)
	case "restore":
		path := ""
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				path = arg
				break
			}
		}
		return a.restoreFrom(ctx, path)
	case "restart":
		return a.cmdRestart(ctx)
	case "logs":
		return a.cmdLogs(ctx, args)
	case "update":
		return a.cmdUpdate(ctx, args)
	case "reinstall":
		return a.cmdReinstall(ctx)
	case "uninstall":
		return a.cmdUninstall(ctx, args)
	case "menu":
		return a.menu(ctx)
	default:
		a.sayf("tnp: unknown command %q", command)
		a.usage()
		return exitUsage
	}
}

// requireRoot refuses early and says why.
//
// Everything this tool does needs root: the database is 0600 in a 0700
// directory, /etc/gre-panel.env is 0600, and restarting a system service is not
// something an unprivileged user can do. Failing here beats failing three steps
// in with a permission error that does not name the cause.
func (a *app) requireRoot() int {
	if os.Geteuid() == 0 {
		return exitOK
	}
	a.sayf("tnp must run as root: the panel's database and its environment file are readable only " +
		"by root, and the service cannot be restarted without it.")
	return exitNotRoot
}

func (a *app) cmdStatus(ctx context.Context) int {
	report, err := a.status(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	a.emit(report, func() { a.printStatus(report) })
	return exitOK
}

func (a *app) cmdURL(ctx context.Context) int {
	report, err := a.status(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	// The URL goes to stdout even without --json: `tnp url` exists to be
	// substituted into another command.
	fmt.Fprintln(a.out, report.Address.URL)
	return exitOK
}

func (a *app) cmdSetPort(ctx context.Context, args []string) int {
	if len(args) != 1 {
		a.sayf("usage: tnp set-port <port> [--yes] [--json]")
		return exitUsage
	}
	port, err := strconv.Atoi(args[0])
	if err != nil {
		a.sayf("tnp set-port: %q is not a number", args[0])
		return exitUsage
	}
	current, err := a.currentAddress(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	return a.applyAddress(ctx, port, current.WebPath)
}

func (a *app) cmdSetWebPath(ctx context.Context, args []string) int {
	if len(args) != 1 {
		a.sayf("usage: tnp set-web-path <path>   (an empty string serves the panel at the root)")
		return exitUsage
	}
	webPath, err := config.NormalizeWebPath(args[0])
	if err != nil {
		a.sayf("tnp set-web-path: %v", err)
		return exitUsage
	}
	current, err := a.currentAddress(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	return a.applyAddress(ctx, current.Port, webPath)
}

// applyAddress runs the change and turns its outcome into an exit code.
func (a *app) applyAddress(ctx context.Context, port int, webPath string) int {
	change, err := a.setAddress(ctx, port, webPath)
	switch {
	case errors.Is(err, errRollbackFailed):
		a.emit(change, func() { a.sayf("%s", change.Detail) })
		return exitRollbackFailed
	case errors.Is(err, errChangeRolledBack):
		a.emit(change, func() { a.sayf("%s", change.Detail) })
		return exitRolledBack
	case err != nil:
		a.failf("%v", err)
		return exitFailed
	}
	if !change.Applied {
		a.emit(change, func() { a.sayf("%s", change.Detail) })
		return exitCancelled
	}
	a.emit(change, func() {
		a.sayf("%s", change.Detail)
		a.sayf("")
		a.sayf("  The panel is now at:  %s", change.URL)
		a.sayf("")
	})
	return exitOK
}

func (a *app) cmdSetUsername(ctx context.Context, args []string) int {
	var wanted, current string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--username":
			if i+1 >= len(args) {
				a.sayf("--username needs a value")
				return exitUsage
			}
			i++
			current = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				a.sayf("tnp set-username: unknown flag %q", args[i])
				return exitUsage
			}
			wanted = args[i]
		}
	}
	if wanted == "" {
		a.sayf("usage: tnp set-username <new name> [--username <current name>] [--json]")
		return exitUsage
	}
	change, err := a.setUsername(ctx, current, wanted)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	a.emit(change, func() { a.sayf("%s", change.Detail) })
	return exitOK
}

func (a *app) cmdResetPassword(ctx context.Context, args []string) int {
	var username, password string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--username":
			if i+1 >= len(args) {
				a.sayf("--username needs a value")
				return exitUsage
			}
			i++
			username = args[i]
		case "--password":
			if i+1 >= len(args) {
				a.sayf("--password needs a value")
				return exitUsage
			}
			i++
			password = args[i]
		default:
			a.sayf("tnp reset-password: unexpected argument %q", args[i])
			return exitUsage
		}
	}
	if password == "" {
		typed, err := a.readSecret("New password (at least 12 characters)")
		if err != nil {
			a.failf("%v", err)
			return exitUsage
		}
		password = typed
	}
	change, err := a.resetPassword(ctx, username, password)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	a.emit(change, func() { a.sayf("%s", change.Detail) })
	return exitOK
}

func (a *app) cmdRestart(ctx context.Context) int {
	if err := restartService(ctx); err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	report, err := a.status(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	a.emit(report, func() {
		if report.Health.Reachable {
			a.sayf("Restarted. The panel is answering at %s", report.Address.URL)
			return
		}
		a.sayf("Restarted, but nothing answered at %s yet.", report.Address.HealthURL)
	})
	if !report.Health.Reachable {
		return exitFailed
	}
	return exitOK
}

func (a *app) cmdLogs(ctx context.Context, args []string) int {
	lines := 50
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" && i+1 < len(args) {
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil {
				a.sayf("tnp logs: -n needs a number")
				return exitUsage
			}
			lines = n
		}
	}
	out := journalTail(ctx, lines)
	if out == "" {
		a.sayf("There is nothing in the journal for %s.", serviceName)
		return exitOK
	}
	fmt.Fprintln(a.err, out)
	return exitOK
}

func (a *app) cmdUpdate(ctx context.Context, args []string) int {
	wantVersion := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--version" && i+1 < len(args) {
			i++
			wantVersion = args[i]
		}
	}
	if err := a.update(ctx, wantVersion); err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	return a.cmdStatus(ctx)
}

func (a *app) cmdReinstall(ctx context.Context) int {
	if !a.assumeYes {
		ok, err := a.confirm(ctx, "Reinstall the panel at its current version? Tunnels and data are kept.")
		if err != nil || !ok {
			a.sayf("Nothing was changed.")
			return exitCancelled
		}
	}
	if err := a.reinstall(ctx); err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	return a.cmdStatus(ctx)
}

func (a *app) cmdUninstall(ctx context.Context, args []string) int {
	var panel, cli, purgeTunnels, purgeData bool
	for _, arg := range args {
		switch arg {
		case "--panel":
			panel = true
		case "--cli":
			cli = true
		case "--purge-tunnels":
			purgeTunnels = true
		case "--purge-data":
			purgeData = true
		default:
			a.sayf("tnp uninstall: unknown flag %q", arg)
			return exitUsage
		}
	}
	if !panel && !cli {
		a.sayf("usage: tnp uninstall --panel [--purge-tunnels] [--purge-data] --yes")
		a.sayf("       tnp uninstall --cli --yes")
		a.sayf("")
		a.sayf("--panel removes the panel and leaves this CLI, so it can be reinstalled from here.")
		a.sayf("--cli removes this CLI and leaves the panel running.")
		return exitUsage
	}

	if panel {
		if !a.assumeYes {
			// The two are reported separately because they are separate:
			// keeping the database is what makes a later reinstall come back
			// with the same accounts, tunnels, rules and address.
			a.sayf("  tunnels and rules: %s", pick(purgeTunnels, "DELETED", "kept and still running"))
			a.sayf("  database:          %s", pick(purgeData, "DELETED", "kept, so a reinstall restores everything"))
			ok, err := a.confirm(ctx, "Remove the panel?")
			if err != nil || !ok {
				a.sayf("Nothing was changed.")
				return exitCancelled
			}
		}
		if err := a.uninstallPanel(ctx, purgeTunnels, purgeData); err != nil {
			a.failf("%v", err)
			return exitFailed
		}
	}

	if cli {
		if !a.assumeYes {
			ok, err := a.confirm(ctx, "Remove the tnp CLI from this machine?")
			if err != nil || !ok {
				a.sayf("Nothing was changed.")
				return exitCancelled
			}
		}
		removed, err := a.uninstallCLI()
		if err != nil {
			a.failf("%v", err)
			return exitFailed
		}
		a.emit(map[string]any{"removed": removed}, func() {
			if len(removed) == 0 {
				a.sayf("The CLI was not installed here; nothing was removed.")
				return
			}
			a.sayf("Removed:")
			for _, path := range removed {
				a.sayf("  %s", path)
			}
		})
	}
	return exitOK
}

// usage prints the help.
//
// Coloured by role rather than decorated: the command you type is the thing you
// are looking for, so it is the only bright thing on the line, and the headings
// break a list of twenty into groups the eye can skip between. Everything goes
// through paint(), which is a no-op when stderr is not a terminal or NO_COLOR
// is set — the installer captures this output into a log, and escape codes in a
// log file are something somebody has to strip later.
func (a *app) usage() {
	cmd := func(name, description string) string {
		return fmt.Sprintf("  %s %s\n", bold(cyan(pad(name, 28))), description)
	}
	head := func(text string) string { return "\n" + bold(text) + "\n" }

	var b strings.Builder
	b.WriteString(bold("tnp") + dim(" — manage the GRE tunnel panel on this server.") + "\n")

	b.WriteString(head("Look"))
	b.WriteString(cmd("tnp", "open the menu"))
	b.WriteString(cmd("tnp status [--json]", "where the panel is, whether it answers, which build"))
	b.WriteString(cmd("tnp url", "print the panel's URL and nothing else"))
	b.WriteString(cmd("tnp logs [-n <lines>]", "the service's recent journal"))

	b.WriteString(head("Where it serves, and who can sign in"))
	b.WriteString(cmd("tnp set-port <port>", "move the panel to another port"))
	b.WriteString(cmd("tnp set-web-path <path>", `move it to another path; "" serves it at the root`))
	b.WriteString(cmd("tnp set-username <name>", "rename the operator account"))
	b.WriteString(cmd("tnp reset-password", "set a password without knowing the old one"))
	b.WriteString("  " + pad("", 28) + dim("[--username <name>] [--password <pw>]") + "\n")

	b.WriteString(head("The database"))
	b.WriteString(cmd("tnp backup", "a 15-minute link to download the database"))
	b.WriteString(cmd("tnp backup <file>", "write the database to a file instead"))
	b.WriteString(cmd("tnp backup --new", "revoke the live link and issue a fresh one"))
	b.WriteString(cmd("tnp restore <file>", "replace the database with a .db file on this server"))
	b.WriteString("  " + pad("", 28) + dim("to upload one from your computer, open /restore on the") + "\n")
	b.WriteString("  " + pad("", 28) + dim("panel; tnp backup prints the full URL") + "\n")

	b.WriteString(head("Install and remove"))
	b.WriteString(cmd("tnp restart", "restart the service and wait for it to answer"))
	b.WriteString(cmd("tnp update [--version <tag>]", "install what the release host is serving"))
	b.WriteString(cmd("tnp reinstall", "re-apply the current version, repairing the unit"))
	b.WriteString(cmd("tnp uninstall --panel", "remove the panel, keeping this CLI"))
	b.WriteString("  " + pad("", 28) + dim("[--purge-tunnels] [--purge-data] --yes") + "\n")
	b.WriteString(cmd("tnp uninstall --cli --yes", "remove this CLI, leaving the panel running"))

	b.WriteString(head("Global flags") + dim("  accepted before or after the subcommand") + "\n")
	b.WriteString(cmd("--json", "machine-readable output on stdout; the rest to stderr"))
	b.WriteString(cmd("--yes, -y", "do not ask for confirmation"))
	b.WriteString(cmd("--env-file <path>", "read the panel's environment from somewhere other"))
	b.WriteString("  " + pad("", 28) + dim("than "+config.EnvFilePath) + "\n")

	b.WriteString(head("Exit codes"))
	for _, e := range []struct{ code, meaning string }{
		{"0", "ok"},
		{"2", "usage"},
		{"10", "not root"},
		{"11", "failed"},
		{"12", "the change was rolled back and the panel is where it was"},
		{"13", "the change failed and the rollback did too"},
		{"14", "nothing was done because the confirmation was declined"},
	} {
		colour := green
		if e.code != "0" {
			colour = yellow
		}
		if e.code == "13" {
			colour = red
		}
		b.WriteString(fmt.Sprintf("  %s %s\n", colour(pad(e.code, 4)), e.meaning))
	}
	b.WriteString("\n")

	fmt.Fprint(a.err, b.String())
}

// pad widens s to n columns. It counts visible width, so a coloured cell still
// lines up with an uncoloured one.
func pad(s string, n int) string {
	if w := visibleLen(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}
