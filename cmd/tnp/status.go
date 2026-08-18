package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/address"
)

// statusReport is everything `tnp status --json` answers with.
//
// It is deliberately more than a health check. The questions an operator
// actually arrives with are "where is it", "is it running", "which build is
// this", and "why is it not where I put it", and every one of those needs a
// different field. --json exists so a test can assert on them rather than
// scraping prose.
type statusReport struct {
	CLI       componentVersion  `json:"cli"`
	Panel     componentVersion  `json:"panel"`
	Service   serviceState      `json:"service"`
	Address   addressReport     `json:"address"`
	Health    healthReport      `json:"health"`
	Database  databaseReport    `json:"database"`
	Installed installedPaths    `json:"installed"`
	Warnings  []string          `json:"warnings"`
	Extra     map[string]string `json:"extra,omitempty"`
}

type componentVersion struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date,omitempty"`
	Path      string `json:"path,omitempty"`
	Present   bool   `json:"present"`
}

type addressReport struct {
	BindHost string `json:"bind_host"`
	Port     int    `json:"port"`
	// WebPath is "" when the panel is served at the root. That is a value, not
	// a gap, and the JSON says so by always carrying the key.
	WebPath       string            `json:"web_path"`
	ServedAtRoot  bool              `json:"served_at_root"`
	URL           string            `json:"url"`
	HealthURL     string            `json:"health_url"`
	PortSource    string            `json:"port_source"`
	WebPathSource string            `json:"web_path_source"`
	EnvFile       envFileReport     `json:"env_file"`
	Stored        storedAddrReport  `json:"stored"`
	Fallback      *address.Fallback `json:"fallback,omitempty"`
}

type envFileReport struct {
	Path      string `json:"path"`
	Present   bool   `json:"present"`
	Port      int    `json:"port"`
	WebPath   string `json:"web_path"`
	Disagrees bool   `json:"disagrees"`
}

type storedAddrReport struct {
	Present      bool   `json:"present"`
	Port         int    `json:"port"`
	WebPath      string `json:"web_path"`
	LastGoodPort int    `json:"last_good_port"`
}

type healthReport struct {
	Reachable  bool   `json:"reachable"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMs  int64  `json:"latency_ms,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

type databaseReport struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Bytes   int64  `json:"bytes"`
	Users   int    `json:"users"`
	Tunnels int    `json:"tunnels"`
	Routes  int    `json:"routes"`
}

type installedPaths struct {
	PanelBinary string `json:"panel_binary"`
	CLIBinary   string `json:"cli_binary"`
	Unit        string `json:"unit"`
	DataDir     string `json:"data_dir"`
	Installer   string `json:"cached_installer"`
}

func (a *app) status(ctx context.Context) (*statusReport, error) {
	report := &statusReport{Warnings: []string{}}

	report.CLI = componentVersion{Version: version, Commit: commit, BuildDate: buildDate,
		Path: cliBinary, Present: exists(cliBinary)}
	report.Panel = componentVersion{Path: panelBinary, Present: exists(panelBinary)}
	if report.Panel.Present {
		report.Panel.Version = binaryVersion(ctx, panelBinary)
	}
	report.Service = readServiceState(ctx)
	report.Installed = installedPaths{
		PanelBinary: panelBinary, CLIBinary: cliBinary, Unit: unitPath,
		DataDir: dataDir, Installer: cachedInstall,
	}

	env, err := readPanelEnv(a.envPath)
	if err != nil {
		return nil, err
	}
	report.Address.BindHost = env.Host
	report.Address.EnvFile = envFileReport{
		Path: a.envPath, Present: exists(a.envPath), Port: env.Port, WebPath: env.WebPath,
	}

	// Where the panel actually is, resolved exactly the way the panel resolves
	// it, rather than read off the environment file — reading the file is how a
	// tool ends up confidently reporting the wrong port.
	effective := address.Resolve(address.Stored{}, address.Seed{Port: env.Port, WebPath: env.WebPath, PortProvided: env.PortSet, WebPathProvided: env.WebPathSet})
	report.Database.Path = env.DBPath
	report.Database.Present = exists(env.DBPath)

	if report.Database.Present {
		database, dbErr := a.openDB(env)
		if dbErr != nil {
			report.Warnings = append(report.Warnings, dbErr.Error())
		} else {
			defer database.Close() //nolint:errcheck // read-only use
			if info, statErr := os.Stat(env.DBPath); statErr == nil {
				report.Database.Bytes = info.Size()
			}
			stored, loadErr := address.Load(ctx, database)
			if loadErr != nil {
				report.Warnings = append(report.Warnings, loadErr.Error())
			} else {
				report.Address.Stored = storedAddrReport{
					Present: stored.Exists, Port: stored.Port, WebPath: stored.WebPath,
					LastGoodPort: stored.LastGoodPort,
				}
				effective = address.Resolve(stored, address.Seed{Port: env.Port, WebPath: env.WebPath, PortProvided: env.PortSet, WebPathProvided: env.WebPathSet})
			}
			countInto(ctx, database, &report.Database, &report.Warnings)
		}
	}

	report.Address.Port = effective.Port
	report.Address.WebPath = effective.WebPath
	report.Address.ServedAtRoot = effective.WebPath == ""
	report.Address.PortSource = string(effective.PortSource)
	report.Address.WebPathSource = string(effective.WebPathSource)
	report.Address.URL = address.URL("http", a.publicHost(env), effective.Port, effective.WebPath)
	report.Address.HealthURL = address.HealthURL("http", a.loopbackHost(env), effective.Port, effective.WebPath)
	report.Address.EnvFile.Disagrees = env.Port != effective.Port || env.WebPath != effective.WebPath

	report.Health = probeHealth(ctx, report.Address.HealthURL)

	// The warnings are the part an operator reads first, so each one says what
	// is wrong and what to do rather than restating a field.
	if report.Address.EnvFile.Disagrees {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"%s still says port %d and web path %q, but the panel is serving on %d and %q. "+
				"The panel cannot write that file — /etc is read-only under its unit — so a change "+
				"made in the browser leaves it behind. It is only a seed, so nothing is broken.",
			a.envPath, env.Port, env.WebPath, effective.Port, effective.WebPath))
	}
	if report.Service.Installed && report.Service.Active != "active" {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"the %s service is %s, so the panel is not serving", serviceName, report.Service.Active))
	}
	if !report.Health.Reachable && report.Service.Active == "active" {
		report.Warnings = append(report.Warnings, fmt.Sprintf(
			"the service is running but nothing answered at %s: %s",
			report.Address.HealthURL, report.Health.Detail))
	}
	if !report.Panel.Present {
		report.Warnings = append(report.Warnings,
			"the panel binary is not installed at "+panelBinary)
	}
	return report, nil
}

func countInto(ctx context.Context, database dbHandle, into *databaseReport, warnings *[]string) {
	for _, q := range []struct {
		query string
		into  *int
	}{
		{`SELECT COUNT(*) FROM AppUser WHERE IsDeleted = 0`, &into.Users},
		{`SELECT COUNT(*) FROM Tunnel WHERE IsDeleted = 0`, &into.Tunnels},
		{`SELECT COUNT(*) FROM RouteRule WHERE IsDeleted = 0`, &into.Routes},
	} {
		if err := database.Read.QueryRowContext(ctx, q.query).Scan(q.into); err != nil {
			*warnings = append(*warnings, err.Error())
		}
	}
}

// probeHealth asks the panel, at the address just resolved, whether it is
// there. It insists on the panel's own envelope for the same reason the
// post-restart wait does: a 404 from the wrong web path is an answer, and it is
// not the answer to this question.
func probeHealth(ctx context.Context, url string) healthReport {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	started := time.Now()
	err := address.WaitForHealth(cctx, http.DefaultClient, url, 2*time.Second, 250*time.Millisecond)
	out := healthReport{LatencyMs: time.Since(started).Milliseconds()}
	if err != nil {
		out.Detail = err.Error()
		return out
	}
	out.Reachable = true
	out.StatusCode = http.StatusOK
	return out
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// printStatus is the human form. It answers the same questions in the order
// they get asked.
func (a *app) printStatus(r *statusReport) {
	// What an operator came here to read, and nothing about how it is stored.
	// Where a value was resolved from is a diagnostic — it is still in
	// `--json`, where something troubleshooting an override can find it — and
	// putting it in front of somebody who only wants to know their address made
	// the answer harder to see, not more honest.
	w := a.err
	fmt.Fprintf(w, "\n  %s\n\n", bold("Current Settings"))
	fmt.Fprintf(w, "  %-12s %s\n", "Address", cyan(r.Address.URL))
	fmt.Fprintf(w, "  %-12s %d\n", "Port", r.Address.Port)
	if r.Address.ServedAtRoot {
		fmt.Fprintf(w, "  %-12s %s\n", "Web path", dim("none — served at the root"))
	} else {
		fmt.Fprintf(w, "  %-12s %s\n", "Web path", r.Address.WebPath)
	}

	state := red("not installed")
	if r.Service.Installed {
		running := red(r.Service.Active)
		if strings.HasPrefix(r.Service.Active, "active") {
			running = green(r.Service.Active)
		}
		state = fmt.Sprintf("%s, %s", running, r.Service.Enabled)
	}
	fmt.Fprintf(w, "  %-12s %s\n", "Service", state)

	reachable := red("no")
	if r.Health.Reachable {
		reachable = green(fmt.Sprintf("yes, in %d ms", r.Health.LatencyMs))
	}
	fmt.Fprintf(w, "  %-12s %s\n", "Answering", reachable)
	fmt.Fprintf(w, "  %-12s %s\n", "Version", orNone(r.Panel.Version))
	fmt.Fprintf(w, "  %-12s %d tunnel(s), %d rule(s)\n", "Configured",
		r.Database.Tunnels, r.Database.Routes)

	if r.Address.Fallback != nil {
		fmt.Fprintf(w, "\n  ! Port %d could not be bound, so the panel is on %d instead:\n    %s\n",
			r.Address.Fallback.Wanted, r.Address.Fallback.Serving, r.Address.Fallback.Reason)
	}
	for _, warning := range r.Warnings {
		fmt.Fprintf(w, "\n  ! %s\n", warning)
	}
	fmt.Fprintln(w)
}

func orNone(s string) string {
	if s == "" {
		return "not installed"
	}
	return s
}
