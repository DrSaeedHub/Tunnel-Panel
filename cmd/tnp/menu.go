package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/address"
)

// currentAddress resolves where the panel is, for the subcommands that change
// one half of the address and must leave the other alone.
func (a *app) currentAddress(ctx context.Context) (address.Effective, error) {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		return address.Effective{}, err
	}
	seed := address.Seed{Port: env.Port, WebPath: env.WebPath, PortProvided: env.PortSet, WebPathProvided: env.WebPathSet}
	if !exists(env.DBPath) {
		return address.Resolve(address.Stored{}, seed), nil
	}
	database, err := a.openDB(env)
	if err != nil {
		return address.Effective{}, err
	}
	defer database.Close() //nolint:errcheck // read-only use
	stored, err := address.Load(ctx, database)
	if err != nil {
		return address.Effective{}, err
	}
	return address.Resolve(stored, seed), nil
}

// readSecret reads a password without echoing it, and asks twice.
//
// It reads /dev/tty rather than stdin for the same reason confirm does, and
// falls back to a plain read when there is no terminal — a password piped in by
// a script is a deliberate choice, and refusing it would make the CLI
// unusable from automation.
func (a *app) readSecret(label string) (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		line, rerr := bufio.NewReader(a.in).ReadString('\n')
		if rerr != nil && line == "" {
			return "", fmt.Errorf("there is no terminal to type a password on; pass --password")
		}
		return strings.TrimSpace(line), nil
	}
	defer tty.Close()

	if !isTerminal(tty.Fd()) {
		return "", fmt.Errorf("there is no terminal to type a password on; pass --password")
	}
	for {
		fmt.Fprintf(a.err, "%s: ", label)
		first, err := readPasswordNoEcho(tty)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(a.err, "Type it again: ")
		second, err := readPasswordNoEcho(tty)
		if err != nil {
			return "", err
		}
		if first != second {
			a.sayf("Those do not match.")
			continue
		}
		return first, nil
	}
}

// menuItem is one line of the menu and the subcommand behind it.
//
// The menu is a presentation layer over the subcommands and nothing else. Every
// entry ends up in dispatch with the same arguments an operator could have
// typed, which is what makes the non-interactive tests evidence about the menu
// and not merely about a parallel implementation.
type menuItem struct {
	label string
	// startsGroup draws a rule above this entry. Grouping is what makes a list
	// of eleven readable at a glance: the things that change how you reach the
	// panel, the things that run it, and the things that install or remove it.
	startsGroup bool
	run         func(ctx context.Context, a *app) int
}

// menuItems is the single list the frame is drawn from and the tests enumerate,
// so the menu an operator sees cannot drift from the one under test.
func menuItems() []menuItem {
	return []menuItem{
		// A label names what the operator wants to do. It does not explain
		// where the value is kept: "Change Port" is the decision, and "from the
		// database" is our filing system, which is not their problem.
		{"View Settings", false,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "status", nil) }},
		{"Change Port", false,
			func(ctx context.Context, a *app) int { return a.menuSetPort(ctx) }},
		{"Change Web Path", false,
			func(ctx context.Context, a *app) int { return a.menuSetWebPath(ctx) }},
		{"Change Username", false,
			func(ctx context.Context, a *app) int { return a.menuSetUsername(ctx) }},
		{"Reset Password", false,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "reset-password", nil) }},

		{"Download Database", true,
			func(ctx context.Context, a *app) int { return a.backupLink(ctx) }},
		{"Restore Database", false,
			func(ctx context.Context, a *app) int { return a.menuRestore(ctx) }},

		{"Restart Panel", true,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "restart", nil) }},
		{"View Logs", false,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "logs", []string{"-n", "50"}) }},

		{"Update", true,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "update", nil) }},
		{"Reinstall", false,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "reinstall", nil) }},
		{"Uninstall Panel", false,
			func(ctx context.Context, a *app) int { return a.menuUninstallPanel(ctx) }},
		{"Uninstall CLI", false,
			func(ctx context.Context, a *app) int { return a.dispatch(ctx, "uninstall", []string{"--cli"}) }},
	}
}

// menu runs the interactive loop.
func (a *app) menu(ctx context.Context) int {
	if code := a.requireRoot(); code != exitOK {
		return code
	}
	if !a.hasTerminal() {
		a.sayf("tnp needs a terminal for the menu. Every option is also a subcommand:")
		a.usage()
		return exitUsage
	}

	items := menuItems()
	for {
		a.drawMenu(ctx, items)

		choice, err := a.prompt(ctx, fmt.Sprintf("Please enter your selection [0-%d]", len(items)), "0")
		if err != nil {
			// A cancelled context here is Ctrl+C, which is a way of leaving and
			// not an error to complain about.
			if ctx.Err() != nil {
				fmt.Fprintln(a.err)
				return exitOK
			}
			a.failf("%v", err)
			return exitUsage
		}
		choice = strings.ToLower(strings.TrimSpace(choice))
		if choice == "0" || choice == "q" || choice == "quit" || choice == "exit" {
			return exitOK
		}
		index, convErr := strconv.Atoi(choice)
		if convErr != nil || index < 1 || index > len(items) {
			a.sayf("\n  %s\n", red(fmt.Sprintf("%q is not one of the options.", choice)))
			continue
		}
		fmt.Fprintln(a.err)
		items[index-1].run(ctx, a)
		if ctx.Err() != nil {
			return exitOK
		}
		fmt.Fprintln(a.err)
		if _, err := a.prompt(ctx, dim("Press Enter to return to the menu"), ""); err != nil {
			return exitOK
		}
	}
}

// drawMenu renders the frame, the options and the state underneath it.
func (a *app) drawMenu(ctx context.Context, items []menuItem) {
	b := box{a.err}
	fmt.Fprintln(a.err)
	b.top()
	b.line(bold("Tunnel Panel — Management"))
	b.line(fmt.Sprintf("%s. %s", bold(" 0"), "Exit"))
	b.rule()
	for i, item := range items {
		if item.startsGroup {
			b.rule()
		}
		b.entry(i+1, item.label)
	}
	b.bottom()
	a.drawState(ctx)
}

// drawState is the footer: what an operator checks before choosing anything.
//
// It is deliberately four short lines of plain fact. The technical detail —
// which file a value came from, where the database lives, what the bind host is
// — belongs in `tnp status` for somebody diagnosing a problem, not in front of
// somebody trying to change a port.
func (a *app) drawState(ctx context.Context) {
	report, err := a.status(ctx)
	if err != nil {
		fmt.Fprintf(a.err, "\n%s %v\n\n", red("Panel state:"), err)
		return
	}

	state := red("Not running")
	if report.Service.Installed && strings.HasPrefix(report.Service.Active, "active") {
		state = green("Running")
	}
	autostart := red("No")
	if strings.HasPrefix(report.Service.Enabled, "enabled") {
		autostart = green("Yes")
	}
	answering := red("No")
	if report.Health.Reachable {
		answering = green("Yes")
	}

	fmt.Fprintf(a.err, "\n%s %s\n", bold("Panel state:"), state)
	fmt.Fprintf(a.err, "%s %s\n", bold("Start automatically:"), autostart)
	fmt.Fprintf(a.err, "%s %s\n", bold("Answering:"), answering)
	fmt.Fprintf(a.err, "%s %s\n", bold("Address:"), cyan(report.Address.URL))
	if report.Address.Fallback != nil {
		fmt.Fprintf(a.err, "%s port %d would not bind, so it is on %d\n",
			yellow("Note:"), report.Address.Fallback.Wanted, report.Address.Fallback.Serving)
	}
	fmt.Fprintln(a.err)
}

// menuHeader shows the state the operator is about to act on. A menu that does
// not say where the panel is invites changing the port of the wrong machine.
func (a *app) menuHeader(ctx context.Context) {
	fmt.Fprintf(a.err, "\n  tnp %s — %s\n", version, hostnameOrEmpty())

	report, err := a.status(ctx)
	if err != nil {
		fmt.Fprintf(a.err, "  (the panel's state could not be read: %v)\n\n", err)
		return
	}
	answering := "not answering"
	if report.Health.Reachable {
		answering = "answering"
	}
	fmt.Fprintf(a.err, "  %s — %s, %s\n", report.Address.URL, orNone(report.Panel.Version), answering)
	if report.Address.Fallback != nil {
		fmt.Fprintf(a.err, "  ! configured for port %d, which would not bind; serving on %d\n",
			report.Address.Fallback.Wanted, report.Address.Fallback.Serving)
	}
	fmt.Fprintln(a.err)
}

func (a *app) hasTerminal() bool {
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		return true
	}
	return isTerminal(os.Stdin.Fd())
}

func (a *app) menuSetPort(ctx context.Context) int {
	current, err := a.currentAddress(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	answer, err := a.prompt(ctx, "New port", strconv.Itoa(current.Port))
	if err != nil {
		a.failf("%v", err)
		return exitUsage
	}
	return a.dispatch(ctx, "set-port", []string{answer})
}

func (a *app) menuSetWebPath(ctx context.Context) int {
	current, err := a.currentAddress(ctx)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	shown := current.WebPath
	if shown == "" {
		shown = "(none)"
	}
	a.sayf("The web path is currently %s.", shown)
	a.sayf("Type a new one, or the word none to serve the panel at the root.")
	answer, err := a.prompt(ctx, "New web path", current.WebPath)
	if err != nil {
		a.failf("%v", err)
		return exitUsage
	}
	if strings.EqualFold(strings.TrimSpace(answer), "none") {
		answer = ""
	}
	// dispatch takes exactly one argument here, and an empty string is a
	// meaningful one — it is how the root is requested.
	return a.dispatch(ctx, "set-web-path", []string{answer})
}

func (a *app) menuSetUsername(ctx context.Context) int {
	answer, err := a.prompt(ctx, "New username", "")
	if err != nil {
		a.failf("%v", err)
		return exitUsage
	}
	if strings.TrimSpace(answer) == "" {
		a.sayf("Nothing was changed.")
		return exitCancelled
	}
	return a.dispatch(ctx, "set-username", []string{answer})
}

// menuRestore asks for the file, because the menu cannot take an argument.
//
// It prints the restore page's address rather than referring to it. The page is
// the only way to send a file from the machine an operator is sitting at, and
// naming it without saying where it is left them to guess a URL they have never
// seen — the panel is served under a secret prefix, so it is not a URL anyone
// can guess.
func (a *app) menuRestore(ctx context.Context) int {
	a.sayf("")
	a.sayf("Two ways to restore.")
	a.sayf("")
	a.sayf("  %s a file already on this server: give its path below.", bold("From"))
	a.sayf("  %s a file on your own computer: open the panel's restore page,", bold("From"))
	a.sayf("  which uploads it and shows the progress:")
	a.sayf("")
	a.sayf("    %s", cyan(a.restoreURL(ctx)))
	a.sayf("")
	answer, err := a.prompt(ctx, "Path to a .db file on this server (or Enter to cancel)", "")
	if err != nil {
		return exitCancelled
	}
	if strings.TrimSpace(answer) == "" {
		a.sayf("Nothing was changed. Use the page above to upload one instead.")
		return exitCancelled
	}
	return a.restoreFrom(ctx, answer)
}

// restoreURL is where the upload page lives, built from where the panel is
// actually serving rather than from the environment file.
func (a *app) restoreURL(ctx context.Context) string {
	effective, err := a.currentAddress(ctx)
	if err != nil {
		return "the panel's address could not be read; open the panel and add /restore"
	}
	base := fmt.Sprintf("http://%s:%d", panelHost(), effective.Port)
	if effective.WebPath != "" {
		base += "/" + effective.WebPath
	}
	return base + "/restore"
}

// menuUninstallPanel asks the two questions separately, because they are two
// decisions and the answers are usually different: somebody removing the panel
// to reinstall it wants to keep both, and somebody decommissioning a host wants
// neither. They used to be one question, so an operator who wanted their
// tunnels to keep running also kept a database they were trying to discard.
func (a *app) menuUninstallPanel(ctx context.Context) int {
	a.sayf("")
	a.sayf("Tunnels and forwarding rules are live traffic. Deleting them stops it.")
	tunnels, err := a.confirm(ctx, "Delete the tunnels and forwarding rules this panel manages?")
	if err != nil {
		return exitCancelled
	}

	a.sayf("")
	a.sayf("The database holds the accounts, tunnels, rules, port and web path.")
	a.sayf("Keep it and installing again brings all of that back, at the same address.")
	data, err := a.confirm(ctx, "Delete the panel database?")
	if err != nil {
		return exitCancelled
	}

	a.sayf("")
	a.sayf("About to remove the panel:")
	a.sayf("  tunnels and rules: %s", pick(tunnels, red("DELETED"), "kept and still running"))
	a.sayf("  database:          %s", pick(data, red("DELETED"), "kept"))
	a.sayf("")
	ok, err := a.confirm(ctx, "Continue?")
	if err != nil || !ok {
		a.sayf("Nothing was changed.")
		return exitCancelled
	}

	args := []string{"--panel", "--yes"}
	if tunnels {
		args = append(args, "--purge-tunnels")
	}
	if data {
		args = append(args, "--purge-data")
	}
	return a.dispatch(ctx, "uninstall", args)
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
