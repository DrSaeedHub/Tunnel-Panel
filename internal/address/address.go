// Package address owns where the panel listens: the port it binds and the web
// path it is served under.
//
// These two values used to live only in /etc/gre-panel.env, read by systemd and
// handed to the process as environment variables. That made them unchangeable
// from the panel itself, because the unit runs with ProtectSystem=full and
// carves out only the directories the panel writes during ordinary operation —
// /etc is read-only to it, measured on both live hosts:
//
//	touch: cannot touch '/etc/gre-panel.env.probe': Read-only file system
//
// So they moved into the database, which the panel already owns. The
// environment file keeps two jobs: it seeds the values on first run, and
// editing it remains a way to force a value back — the route an operator
// reaches for when they are locked out, and the one that has to keep working
// whatever the database says.
//
// # Precedence
//
// Highest first:
//
//  1. A command-line flag. Explicit, per-invocation, and never persisted.
//  2. The environment, but only when it differs from the seed recorded at the
//     last start. That difference is the signal that somebody edited the file
//     or the installer rewrote it; an unchanged file means nothing new is being
//     asked for and the database keeps its value.
//  3. The database.
//  4. The built-in default.
//
// Rule 2 is what makes the environment file an override without making it a
// second source of truth. Comparing against the recorded seed rather than
// against the effective value is the whole trick: without it, a value changed
// through the panel would be reverted by the unchanged file at the very next
// restart, and the panel would appear to forget every change it was told to
// make.
package address

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Source names where an effective value came from, so the panel and the CLI can
// both say why they are listening where they are rather than only where.
type Source string

const (
	SourceFlag        Source = "flag"
	SourceEnvironment Source = "environment"
	SourceDatabase    Source = "database"
	SourceDefault     Source = "default"
)

// Seed is what the bootstrap configuration resolved before the database was
// open: the environment file's values, or a flag if one was given.
type Seed struct {
	Port    int
	WebPath string
	// PortFromFlag and WebPathFromFlag record that the value came from an
	// explicit command-line flag rather than the environment. A flag is a
	// deliberate one-off and outranks everything.
	PortFromFlag    bool
	WebPathFromFlag bool
	// PortProvided and WebPathProvided record that something actually supplied
	// the value, as opposed to it being the compiled default.
	//
	// Without this the drift check cannot tell "an operator edited the file" from
	// "there is no file". Both look like an environment value that differs from
	// the recorded seed, so the compiled default won and the panel served on
	// 8787 while its own database said 8443 — measured on a host whose
	// environment file had been removed by an uninstall:
	//
	//	tnp url  ->  http://…:8787/     (database says 8443)
	//
	// An absent value is not an instruction. When nothing supplied one, the
	// database is the only thing that knows, and it wins.
	PortProvided    bool
	WebPathProvided bool
}

// Stored is the row the panel keeps for itself.
type Stored struct {
	Port    int
	WebPath string
	// LastGoodPort is the last port the panel actually managed to bind. It is
	// the fallback when the configured one cannot be bound, which is the
	// difference between a panel that is reachable somewhere and one that
	// crash-loops until somebody arrives with SSH.
	LastGoodPort int
	// SeedPort and SeedWebPath are the environment's values as of the last
	// start. Rule 2 above compares against these.
	SeedPort    int
	SeedWebPath string
	// Exists is false before the panel has ever written the row.
	Exists bool
}

// Effective is the resolved answer, with the reason for each half.
type Effective struct {
	Port          int
	WebPath       string
	PortSource    Source
	WebPathSource Source
}

// DefaultPort mirrors config.DefaultBindPort. It is repeated rather than
// imported because config resolves the bootstrap values this package then
// arbitrates, and importing it back would be a cycle.
const DefaultPort = 8787

// Resolve applies the precedence rules to a stored row and a seed. It is a pure
// function so the table of cases below is a test rather than a description.
func Resolve(stored Stored, seed Seed) Effective {
	out := Effective{}

	switch {
	case seed.PortFromFlag:
		out.Port, out.PortSource = seed.Port, SourceFlag
	case !stored.Exists:
		out.Port, out.PortSource = seed.Port, SourceEnvironment
	case !seed.PortProvided:
		// Nothing supplied a port, so this is the compiled default and not an
		// instruction. The database is the only thing that knows.
		out.Port, out.PortSource = stored.Port, SourceDatabase
	case seed.Port != stored.SeedPort:
		// The file changed since the last start, so it is asking for something.
		out.Port, out.PortSource = seed.Port, SourceEnvironment
	default:
		out.Port, out.PortSource = stored.Port, SourceDatabase
	}

	switch {
	case seed.WebPathFromFlag:
		out.WebPath, out.WebPathSource = seed.WebPath, SourceFlag
	case !stored.Exists:
		out.WebPath, out.WebPathSource = seed.WebPath, SourceEnvironment
	case !seed.WebPathProvided:
		out.WebPath, out.WebPathSource = stored.WebPath, SourceDatabase
	case seed.WebPath != stored.SeedWebPath:
		out.WebPath, out.WebPathSource = seed.WebPath, SourceEnvironment
	default:
		out.WebPath, out.WebPathSource = stored.WebPath, SourceDatabase
	}

	if out.Port < 1 || out.Port > 65535 {
		out.Port, out.PortSource = DefaultPort, SourceDefault
	}
	return out
}

// Load reads the stored row. A database with no row yet is not an error: it is
// what a first start looks like.
func Load(ctx context.Context, database *db.DB) (Stored, error) {
	var s Stored
	var lastGood, seedPort sql.NullInt64
	var webPath, seedWebPath sql.NullString
	err := database.Read.QueryRowContext(ctx,
		`SELECT BindPort, WebPath, LastGoodBindPort, SeedBindPort, SeedWebPath
		   FROM PanelAddress WHERE PanelAddressID = 1`).
		Scan(&s.Port, &webPath, &lastGood, &seedPort, &seedWebPath)
	if errors.Is(err, sql.ErrNoRows) {
		return Stored{}, nil
	}
	if err != nil {
		return Stored{}, fmt.Errorf("reading the panel address: %w", err)
	}
	s.Exists = true
	s.WebPath = webPath.String
	s.LastGoodPort = int(lastGood.Int64)
	s.SeedPort = int(seedPort.Int64)
	s.SeedWebPath = seedWebPath.String
	return s, nil
}

// Save writes the effective values and the seed they were resolved against.
//
// The seed is written on every start, not only when it changes, so that
// "the file differs from the seed" means "the file changed since the last
// start" rather than "the file has ever differed".
func Save(ctx context.Context, database *db.DB, eff Effective, seed Seed) error {
	now := model.NowUTC()
	_, err := database.Write.ExecContext(ctx,
		`INSERT INTO PanelAddress
			(PanelAddressID, BindPort, WebPath, SeedBindPort, SeedWebPath,
			 CreatedDate, UpdatedDate, IsDeleted)
		 VALUES (1, ?, ?, ?, ?, ?, ?, 0)
		 ON CONFLICT (PanelAddressID) DO UPDATE SET
			BindPort     = excluded.BindPort,
			WebPath      = excluded.WebPath,
			SeedBindPort = excluded.SeedBindPort,
			SeedWebPath  = excluded.SeedWebPath,
			UpdatedDate  = excluded.UpdatedDate`,
		eff.Port, eff.WebPath, seed.Port, seed.WebPath, now, now)
	if err != nil {
		return fmt.Errorf("storing the panel address: %w", err)
	}
	return nil
}

// Set records a deliberate change to the panel's address.
//
// The seed is refreshed to what the caller has just read from the environment
// file, rather than left alone or set to the new value. Both alternatives are
// wrong, and the reasons are worth stating because they are not symmetric:
//
//   - Setting the seed to the NEW value would make the next start compare the
//     environment file against a number that never came from it, so an
//     unchanged file would read as an edit and revert the change.
//   - Leaving it alone works once the panel has started at least once, and
//     fails before that: the CLI is used to fix an installation that will not
//     come up, there is no row, and a seed left at zero makes the next start
//     read the ordinary environment file as news and discard the repair.
//
// Refreshing it to what the caller observed means exactly "I have seen this
// file; it is not news", which is the claim the drift check is testing.
func Set(ctx context.Context, database *db.DB, port int, webPath string, seed Seed) error {
	now := model.NowUTC()
	res, err := database.Write.ExecContext(ctx,
		`UPDATE PanelAddress SET BindPort = ?, WebPath = ?, SeedBindPort = ?, SeedWebPath = ?,
			UpdatedDate = ? WHERE PanelAddressID = 1`,
		port, webPath, seed.Port, seed.WebPath, now)
	if err != nil {
		return fmt.Errorf("changing the panel address: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := database.Write.ExecContext(ctx,
			`INSERT INTO PanelAddress
				(PanelAddressID, BindPort, WebPath, SeedBindPort, SeedWebPath,
				 CreatedDate, UpdatedDate, IsDeleted)
			 VALUES (1, ?, ?, ?, ?, ?, ?, 0)`,
			port, webPath, seed.Port, seed.WebPath, now, now); err != nil {
			return fmt.Errorf("storing the panel address: %w", err)
		}
	}
	return nil
}

// RecordLastGood remembers a port the panel actually bound.
func RecordLastGood(ctx context.Context, database *db.DB, port int) error {
	_, err := database.Write.ExecContext(ctx,
		`UPDATE PanelAddress SET LastGoodBindPort = ?, UpdatedDate = ?
		  WHERE PanelAddressID = 1`, port, model.NowUTC())
	if err != nil {
		return fmt.Errorf("recording the last bindable port: %w", err)
	}
	return nil
}

// Fallback describes a configured port that could not be bound and what was
// served instead. A nil Fallback means the panel is where it was told to be.
type Fallback struct {
	// Wanted is the port that was configured and refused to bind.
	Wanted int `json:"wanted_port"`
	// Serving is the port actually bound.
	Serving int `json:"serving_port"`
	// Reason is the bind error, verbatim.
	Reason string `json:"reason"`
	// At is when the fallback happened.
	At string `json:"at"`
}

// Opener is the socket factory, with the signature of net.Listen.
//
// It is injected so the fallback below can be tested by deciding which port
// fails rather than by arranging for one to be genuinely unbindable. That is
// not a convenience: the workstation this is developed on runs WSL2, where a
// second listener on an already-bound 127.0.0.1 port succeeds —
//
//	first  listen ok on 127.0.0.1:65269
//	second listen on 127.0.0.1:65269 -> err=<nil>
//
// — so a test that takes a port and expects the next bind to fail passes
// vacuously there in the worst way: by never reaching the branch it is named
// after. The real-socket behaviour is covered separately, by a test that first
// checks whether this machine enforces exclusivity at all and says so when it
// does not.
type Opener func(network, address string) (net.Listener, error)

// Listen binds the first port in the candidate list that works.
//
// A stored port that cannot be bound must not take the panel down. With
// Restart=always in the unit, a process that exits because it cannot bind is a
// crash loop, and a crash loop over a value only the panel can change is a
// panel that can never be fixed from the panel. So the configured port is
// tried, then the last one known to work, then whatever else was offered, and
// the caller is told which it got and why.
func Listen(host string, candidates []int) (net.Listener, int, *Fallback, error) {
	return ListenWith(net.Listen, host, candidates)
}

// ListenWith is Listen against an injected socket factory.
func ListenWith(open Opener, host string, candidates []int) (net.Listener, int, *Fallback, error) {
	var first error
	var firstPort int
	seen := map[int]bool{}
	for _, port := range candidates {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		listener, err := open("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			if first == nil {
				return listener, port, nil, nil
			}
			return listener, port, &Fallback{
				Wanted:  firstPort,
				Serving: port,
				Reason:  first.Error(),
				At:      model.NowUTC(),
			}, nil
		}
		if first == nil {
			first, firstPort = err, port
		}
	}
	if first == nil {
		return nil, 0, nil, errors.New("no usable port was offered")
	}
	return nil, 0, nil, first
}

// Probe reports whether a port can be bound right now, without keeping it.
//
// This is the check that runs before a change is stored rather than after: a
// port that cannot be bound is refused with the reason, instead of being
// written down and discovered at the next restart. It is a real bind and
// release, not a scan of a socket table, so it answers the question actually
// being asked — can this process listen here — including the cases a table does
// not show, such as a privileged port without the capability to bind it.
func Probe(host string, port int) error { return ProbeWith(net.Listen, host, port) }

// ProbeWith is Probe against an injected socket factory.
func ProbeWith(open Opener, host string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port %d is outside the range 1-65535", port)
	}
	listener, err := open("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return listener.Close()
}

// EnforcesPortExclusivity reports whether this machine actually refuses a
// second listener on a bound port. It exists so a test can say "this
// environment cannot demonstrate the conflict" instead of quietly passing.
func EnforcesPortExclusivity() bool {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer held.Close()
	second, err := net.Listen("tcp", held.Addr().String())
	if err != nil {
		return true
	}
	second.Close()
	return false
}

// URL builds the panel's browser URL. An empty web path serves at the root, and
// the result must not carry the double slash that concatenating an empty
// segment produces — http://host:8443//  is a different URL from http://host:8443/
// to a strict client, and it is what every naive "$host:$port/$path/" template
// produces the moment the path is empty.
func URL(scheme, host string, port int, webPath string) string {
	base := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port))
	if webPath == "" {
		return base + "/"
	}
	return base + "/" + webPath + "/"
}

// HealthURL is the liveness endpoint for a given address, used by the installer,
// the CLI and the frontend's post-restart poll.
func HealthURL(scheme, host string, port int, webPath string) string {
	return URL(scheme, host, port, webPath) + "api/v1/system/health"
}

// WaitForHealth polls until the panel answers its own health endpoint at this
// exact address, or the deadline passes.
//
// It insists on the panel's own JSON envelope rather than on a 200. Two reasons,
// and both have a failure behind them: the endpoint answers 503 when a component
// is degraded, and a panel that is up but unhappy is still up, so requiring 200
// would report a working panel as failed. And a request to the wrong web path
// gets a bare 404 with an empty body, so accepting any HTTP response would
// report the old panel as proof that the new path works. The envelope is what
// distinguishes them.
func WaitForHealth(ctx context.Context, client HTTPDoer, url string, timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		body, status, err := get(ctx, client, url)
		switch {
		case err != nil:
			last = err
		case !isPanelHealthBody(body):
			last = fmt.Errorf("HTTP %d from %s, but the body is not this panel's health envelope", status, url)
		default:
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the panel did not answer at %s within %s: %w", url, timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
