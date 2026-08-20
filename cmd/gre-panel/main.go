// Command gre-panel is the GRE tunnel web panel: a single static binary that
// creates, manages, monitors, and diagnoses GRE tunnels on the host it runs on.
//
// It is installed independently on each server. There is no SSH to other hosts,
// no agent, and no central controller.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	osexec "os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/drs/gre-panel/internal/address"
	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/api"
	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/backup"
	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/diag"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/lock"
	"github.com/drs/gre-panel/internal/metrics"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/reconcile"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/sourcelist"
	"github.com/drs/gre-panel/internal/tuning"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/update"
	"github.com/drs/gre-panel/internal/validate"
)

// Stamped at link time with -ldflags "-X main.version=... -X main.commit=... -X main.buildDate=..." (§20).
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// shutdownTimeout bounds the graceful stop so a stuck connection cannot hold
// the service in a half-stopped state forever.
const shutdownTimeout = 15 * time.Second

// restartDelay is how long the panel waits after being asked to restart before
// it begins shutting down.
//
// The request that asks for it is answered first, carrying the URL the panel
// will be at. That answer has to reach the browser, or the operator watches the
// connection die without ever learning where to go — which is the whole failure
// this feature exists to avoid. A second is far longer than a local response
// needs and short enough that nobody wonders whether the button worked.
const restartDelay = time.Second

func main() {
	if err := run(); err != nil {
		// The logger may not exist yet, so failures during startup go to stderr
		// in plain text; everything after it is structured.
		fmt.Fprintf(os.Stderr, "gre-panel: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// The environment file backs the process environment rather than replacing
	// it. systemd sets these variables from the same file, so under the service
	// this changes nothing; it matters for every other caller, above all the
	// installer running `--print-address` from a plain shell that never sourced
	// it. See config.EnvFileGetenv for the failure that made this necessary.
	cfg, err := config.Load(os.Args[1:], config.EnvFileGetenv(config.EnvFilePath, os.Getenv), os.Stderr)
	switch {
	case errors.Is(err, config.ErrVersionRequested):
		fmt.Printf("gre-panel %s\ncommit:  %s\nbuilt:   %s\ngo:      %s %s/%s\n",
			version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	case errors.Is(err, config.ErrHelpRequested):
		return nil
	case err != nil:
		return err
	}

	// Answering "where would you listen?" needs the database, because that is
	// where the answer lives now, but it must not need a running panel, root,
	// or the data directory lock: the installer asks this immediately after an
	// upgrade, precisely because the environment file it used to read is no
	// longer authoritative.
	if cfg.PrintAddress {
		return printAddress(cfg)
	}

	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)

	if err := checkPrivileges(cfg, log); err != nil {
		return err
	}
	if err := prepareDataDir(cfg.DataDir); err != nil {
		return err
	}

	// Two instances managing one host would race on every kernel change, so the
	// lock is taken before anything else touches the data directory (§16).
	dataDirLock, err := acquireDataDirLock(cfg.LockPath())
	if err != nil {
		return err
	}
	defer dataDirLock.Release()
	if !dataDirLock.Held() {
		log.Warn("the data directory filesystem does not support advisory locking; "+
			"nothing prevents a second instance from managing this host",
			"data_dir", cfg.DataDir)
	}

	secret, err := auth.LoadOrCreateSecret(cfg.SecretKeyPath())
	if err != nil {
		return err
	}
	signer, err := auth.NewSigner(secret)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelStartup()

	database, err := db.Open(startupCtx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := database.Close(); cerr != nil {
			log.Error("closing the database failed", "error", cerr)
		}
	}()

	if err := db.Init(startupCtx, database); err != nil {
		return fmt.Errorf("initialising the database: %w", err)
	}
	schemaVersion, err := db.CurrentSchemaVersion(startupCtx, database)
	if err != nil {
		return fmt.Errorf("reading the schema version: %w", err)
	}
	log.Info("database ready", "path", cfg.DBPath, "schema_version", schemaVersion)

	// Where to listen is settled here, before anything is built, because the
	// router bakes the web path into the served index.html and the safety guard
	// is constructed with the port it must protect.
	seed := addressSeed(cfg)
	stored, err := address.Load(startupCtx, database)
	if err != nil {
		return err
	}
	effective := address.Resolve(stored, seed)
	if err := address.Save(startupCtx, database, effective, seed); err != nil {
		return err
	}
	cfg.WebPath = effective.WebPath

	listener, boundPort, fallback, err := address.Listen(cfg.BindHost, bindCandidates(effective, stored, seed))
	if err != nil {
		return fmt.Errorf("binding %s: %w", cfg.BindHost, err)
	}
	defer listener.Close() //nolint:errcheck // the HTTP server closes it first
	cfg.BindPort = boundPort

	if fallback != nil {
		// Loud, and repeated in the health report and the address endpoint, so
		// an operator who cannot find the panel where they put it is told why
		// rather than left to work it out from a port scan.
		log.Error("the configured port could not be bound, so the panel fell back to one that "+
			"could; it is NOT where it was configured to be. Fix the port or free it, then restart",
			"configured_port", fallback.Wanted,
			"serving_port", fallback.Serving,
			"reason", fallback.Reason)
	}
	if err := address.RecordLastGood(startupCtx, database, boundPort); err != nil {
		// Not fatal: the panel is bound and serving, and the only cost is that
		// the next start has one fewer candidate to fall back to.
		log.Warn("recording the bound port failed", "error", err, "port", boundPort)
	}

	store, err := settings.New(startupCtx, database)
	if err != nil {
		return err
	}
	authService, err := auth.NewService(startupCtx, database, store, signer)
	if err != nil {
		return err
	}
	auditWriter := audit.New(database, log)

	// The system interaction layer. In development mode the fake link manager
	// stands in for the kernel, so the panel can be run and demonstrated without
	// root and without touching the host.
	runner := exec.NewRunner()
	links := link.Select(link.Options{IPBin: cfg.IPBin, Runner: runner, DevMode: cfg.DevMode})
	renderer := persist.NewRenderer(cfg.IPBin, lookupBinary("modprobe", persist.DefaultModprobeBin),
		lookupBinary("ping", persist.DefaultPingBin))
	persistStore := persist.NewStore(cfg.SystemdDir, cfg.NetworkdDir, cfg.SystemctlBin, runner)

	// The netfilter backend for the port forwarding subsystem, chosen once at
	// startup and reported through the capabilities endpoint. nftables is
	// preferred wherever nft exists, because the panel's own table coexists
	// with rules Docker or firewalld installed instead of interleaving with
	// them in shared chains (§2.1 of the port forwarding specification).
	ruleBackend := rules.Detect(startupCtx, rules.Options{
		NftBin:              lookupBinary("nft", rules.DefaultNftBin),
		IptablesBin:         lookupBinary("iptables", rules.DefaultIptablesBin),
		IptablesRestoreBin:  lookupBinary("iptables-restore", rules.DefaultIptablesRestoreBin),
		Ip6tablesBin:        lookupBinary("ip6tables", rules.DefaultIp6tablesBin),
		Ip6tablesRestoreBin: lookupBinary("ip6tables-restore", rules.DefaultIp6tablesRestore),
		Dir:                 filepath.Join(cfg.DataDir, "rules"),
		Runner:              runner,
		DevMode:             cfg.DevMode,
	})
	log.Info("netfilter backend selected",
		"backend", ruleBackend.Backend.Name(),
		"available", ruleBackend.Backend.Capabilities().Available,
		"reason", ruleBackend.Reason,
		"nft_version", ruleBackend.NftVersion,
		"iptables_version", ruleBackend.IptablesVersion)
	if !ruleBackend.Backend.Capabilities().Available {
		log.Warn("no netfilter backend is available on this host, so port forwarding rules cannot be " +
			"applied here; install nftables or iptables")
	}

	// One global mutation lock, shared by every subsystem that changes kernel
	// state: a tunnel apply and a forwarding rule apply must never interleave,
	// because both reconfigure the same kernel and the second would be planning
	// against a picture the first is in the middle of changing (§16).
	mutation := lock.New()

	repo := tunnel.NewRepo(database)
	allocator := alloc.New(repo, links, store)
	tunnelService := tunnel.New(tunnel.Deps{
		Mutation:      mutation,
		Repo:          repo,
		Links:         links,
		Runner:        runner,
		Renderer:      renderer,
		Store:         persistStore,
		Alloc:         allocator,
		Validator:     validate.New(links, repo.ForValidation(), store, cfg.APIBasePath()+"/reconcile/adopt"),
		Guard:         safety.New(links, cfg.SystemdDir, cfg.NetworkdDir),
		Settings:      store,
		Log:           log,
		IPBin:         cfg.IPBin,
		SystemctlBin:  cfg.SystemctlBin,
		NetworkctlBin: lookupBinary("networkctl", ""),
	})
	reconcileService := reconcile.New(tunnelService, repo, links, persistStore, renderer, store)

	// The port forwarding subsystem. It shares the tunnel subsystem's mutation
	// lock, its persistence store and its renderer, because it is an extension
	// of the same architecture rather than a parallel one.
	routeRepo := route.NewRepo(database)
	sourceLists := sourcelist.NewRepo(database)
	if err := sourcelist.Seed(ctx, sourceLists, log); err != nil {
		return fmt.Errorf("seeding the source lists: %w", err)
	}
	sockets := rules.NewSocketReader()
	routeGuard := safety.NewRouteGuard(cfg.BindPort, sockets, filepath.Join(cfg.DataDir, "rules"))
	routeForwarding := route.NewForwarding(persistStore, renderer, routeGuard)
	kernelTuning := tuning.New(persistStore, renderer, routeGuard, log)
	routeAccounting := route.NewAccounting(route.AccountingDeps{
		Repo:     route.NewCounterRepo(database),
		Routes:   routeRepo,
		Backend:  ruleBackend.Backend,
		Settings: store,
		Log:      log,
	})
	routeService := route.New(route.Deps{
		Repo:         routeRepo,
		Backend:      ruleBackend.Backend,
		Runner:       runner,
		Renderer:     renderer,
		Store:        persistStore,
		Validator:    validate.NewRouteValidator(links, routeRepo.ForValidation(), sockets, store),
		Guard:        routeGuard,
		Forwarding:   routeForwarding,
		Counters:     routeAccounting,
		Settings:     store,
		Log:          log,
		Mutation:     mutation,
		SystemctlBin: cfg.SystemctlBin,
	})
	routeDiag := route.NewDiagnostics(route.DiagnosticsDeps{
		Repo: routeRepo, Backend: ruleBackend.Backend, Forwarding: routeForwarding,
		Accounting: routeAccounting, Tunnels: tunnelService, Log: log,
	})
	// Probing a rule's destinations. Reapply is the whole of what failover
	// does: the suppression is a column on the destination, so rebuilding the
	// ruleset from the records is what takes a dead backend out of it.
	routeMonitor := route.NewMonitor(route.MonitorDeps{
		Repo: routeRepo, Settings: store, Store: routeRepo, Log: log,
		Reapply: func(ctx context.Context) error {
			_, err := routeService.ApplyAll(ctx, route.Request{})
			return err
		},
	})

	// The two subsystems know about each other through narrow interfaces: a
	// rule asks whether the tunnel it relays over is up, and a tunnel asks what
	// would break if it went away (§10).
	routeService.SetTunnels(tunnelService)
	tunnelService.SetRouteDependants(routeRepo)
	reconcileService.SetRoutes(routeRepo, ruleBackend.Backend, routeForwarding)
	// The accounting re-reads which rules exist after every change, so a rule
	// that has just been deleted stops being sampled at once rather than at the
	// next sweep.
	routeService.OnChange(func() {
		if err := routeAccounting.RefreshRules(context.Background()); err != nil {
			log.Error("refreshing the forwarding accounting failed", "error", err)
		}
	})

	// The always-on subsystems. Each one is given the same link manager and the
	// same settings store, so a change in one place is seen everywhere.
	// Opening a raw ICMP socket needs root, so development mode probes a
	// loopback stand-in the same way it manages a fake link manager.
	var probeDialer monitor.Dialer
	if cfg.DevMode {
		probeDialer = monitor.LoopbackDialer{Latency: 3 * time.Millisecond}
	}
	monitorSupervisor := monitor.New(monitor.Deps{
		Tunnels: repo, Store: monitor.NewStore(database), Settings: store,
		Links: links, Log: log, Dialer: probeDialer,
		PanelPort: cfg.BindPort,
	})
	metricsSampler := metrics.New(metrics.Deps{
		Reader: metrics.NewReader(), Links: links,
		Counters: metrics.NewCounters(database), Settings: store, Log: log,
	})
	diagService := diag.New(diag.Deps{
		DB: database, Repo: repo, Links: links, Runner: runner, Settings: store, Log: log,
		Dialer:      probeDialer,
		PanelPort:   cfg.BindPort,
		TcpdumpBin:  lookupBinary("tcpdump", "/usr/bin/tcpdump"),
		NftBin:      lookupBinary("nft", "/usr/sbin/nft"),
		IptablesBin: lookupBinary("iptables", "/usr/sbin/iptables"),
	})

	// The tunnel service tells the supervisor when a tunnel changes, so a
	// prober starts or stops the moment one is created, deleted, enabled or
	// disabled rather than at the next sweep (§10.3).
	tunnelService.SetObserver(monitorSupervisor)
	// And the supervisor answers the peer reachability probe the apply pipeline
	// asks for, so there is one ICMP implementation rather than two (§9.3).
	tunnelService.SetPeerProber(monitorSupervisor)
	// A forwarding rule whose tunnel is up but carrying nothing is impaired
	// too, so the prober's verdict feeds the tunnel health a rule reads (§10).
	tunnelService.SetMonitorState(func(tunnelID int64) (string, bool) {
		snapshot, ok := monitorSupervisor.Snapshot(tunnelID)
		return snapshot.State, ok
	})
	// Relay traffic rides the metrics stream the frontend already subscribes
	// to, rather than a second stream and a second connection (§5.4).
	metricsSampler.SetRoutes(routeAccounting)
	// A settings change reconfigures live workers without a process restart
	// (§5.3).
	store.Subscribe(func(changed []string) { monitorSupervisor.SettingsChanged(changed) })

	// Whether a newer panel exists, and installing it from the panel itself.
	// The checker keeps its answer for as long as the interval setting says;
	// the applier runs the same `tnp update` an operator would run from a
	// shell, in a transient unit so that the restart in the middle of an
	// update does not kill the update.
	updates := &api.Updates{
		Checker: update.NewChecker(update.CheckerDeps{
			CurrentVersion: version, Settings: store, Log: log,
		}),
		Applier: update.NewApplier(update.ApplierDeps{
			CurrentVersion: version,
			DataDir:        cfg.DataDir,
			CLIBin:         lookupBinary("tnp", "/usr/local/bin/tnp"),
			SystemdRunBin:  lookupBinary("systemd-run", "/usr/bin/systemd-run"),
			SystemctlBin:   cfg.SystemctlBin,
			JournalctlBin:  lookupBinary("journalctl", "/usr/bin/journalctl"),
			UnderSystemd:   underSystemd(),
			Runner:         runner,
			Log:            log,
		}),
	}

	server, err := api.New(api.Deps{
		Config:          cfg,
		DB:              database,
		Settings:        store,
		Auth:            authService,
		Audit:           auditWriter,
		Log:             log,
		Build:           api.BuildInfo{Version: version, Commit: commit, Date: buildDate},
		Tunnels:         tunnelService,
		Reconcile:       reconcileService,
		Routes:          routeService,
		RouteAccounting: routeAccounting,
		RouteDiag:       routeDiag,
		RouteMonitor:    routeMonitor,
		SourceLists:     sourceLists,
		Tuning:          kernelTuning,
		Monitor:         monitorSupervisor,
		Metrics:         metricsSampler,
		Diag:            diagService,
		Persist:         persistStore,
		Updates:         updates,
		RuleBackend:     ruleBackend,
		RouteGuard:      routeGuard,
		AddressFallback: fallback,
		AddressSources: api.AddressSources{
			Port:    string(effective.PortSource),
			WebPath: string(effective.WebPathSource),
		},
		// Applying a new address means coming back on it, and the only way the
		// process can rebind is to be started again. Exiting cleanly is that:
		// the unit carries Restart=always, so systemd brings it straight back
		// and it reads the new value on the way up. Shelling out to systemctl
		// from inside the panel's own cgroup would kill the caller mid-command;
		// this needs nothing but the process ending.
		Restart:      restarter(stop, log),
		UnderSystemd: underSystemd(),
	})
	if err != nil {
		return err
	}
	server.RegisterCoreComponents()
	server.RegisterMonitorComponent(monitorSupervisor)
	server.RegisterMetricsComponent(metricsSampler)

	if err := monitorSupervisor.Start(ctx); err != nil {
		return fmt.Errorf("starting the monitoring supervisor: %w", err)
	}
	defer monitorSupervisor.Stop()

	if err := metricsSampler.Start(ctx); err != nil {
		return fmt.Errorf("starting the metrics sampler: %w", err)
	}
	defer metricsSampler.Stop()

	if err := routeAccounting.Start(ctx); err != nil {
		return fmt.Errorf("starting the forwarding traffic accounting: %w", err)
	}
	defer routeAccounting.Stop()

	// The destination monitor. It probes nothing until a rule asks for it,
	// so it costs a ticker on an installation that never turns it on.
	go routeMonitor.Run(ctx)

	// Keeping the connection tracking table big enough for the traffic the
	// rules carry.
	//
	// This is the one kernel parameter the panel maintains on its own
	// initiative, because filling that table does not make the host slow --
	// it refuses every new connection on it, the panel's own port and SSH
	// included, and writes one line to the kernel log that nobody is reading.
	// The panel's rules are what fill it. It only ever raises the ceiling and
	// shortens the timeout, so an operator who has sized it themselves keeps
	// their numbers.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !store.Bool("routes.manage_conntrack") {
					continue
				}
				live := 0
				if summary := routeAccounting.Summary(); summary.Routes > 0 {
					live = summary.ActiveConnections
				}
				if _, err := kernelTuning.EnsureSafety(ctx, live); err != nil {
					log.Debug("sizing the connection tracking table failed", "error", err)
				}
			}
		}
	}()

	// Expired database download links are deleted on a slow tick.
	//
	// This is housekeeping and not the control: a link is refused because its
	// stored expiry has passed, which is checked when it is redeemed, so a
	// sweep that never ran would leave rows behind and let nothing through. It
	// runs on the minute rather than on a timer per link precisely so that a
	// restart cannot lose it — there is nothing to lose.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := backup.Sweep(ctx, database, time.Now()); err != nil {
					log.Debug("sweeping expired download links failed", "error", err)
				} else if n > 0 {
					log.Info("expired database download links removed", "count", n)
				}
			}
		}
	}()

	// The panel's own state is authoritative, so the stored ruleset is
	// reinstalled at startup: after a reboot, or after something else changed
	// netfilter while the panel was not running, the rules are put back rather
	// than being trusted to still be there (§2.2).
	//
	// A failure here is reported and does not stop the panel: an operator needs
	// the panel running in order to see why its rules could not be installed.
	if err := routeService.Reassert(startupCtx); err != nil {
		log.Error("reasserting the forwarding rules at startup failed; the panel is running and its "+
			"rules may not be installed — see the reconcile report", "error", err)
	}

	// Reconciliation runs periodically as well as on demand (§12). Without this
	// the database and the kernel drift apart silently between whatever moments
	// somebody happens to open the report, and the two settings that describe
	// the behaviour — how often to compare, and what to do about drift — have
	// nothing reading them.
	sweeper := &reconcile.Sweeper{Service: reconcileService, Settings: store, Log: log}
	sweeper.Start(ctx)
	defer sweeper.Stop()

	// Retention pruning runs alongside them, on the same lifespan.
	pruneCtx, stopPruning := context.WithCancel(ctx)
	defer stopPruning()
	go pruneRetention(pruneCtx, store, auditWriter, diagService, routeAccounting, log)

	if hasUser, err := authService.HasUser(startupCtx); err == nil && !hasUser {
		log.Warn("no operator account exists yet; the panel serves only setup and health "+
			"until the first account is created",
			"setup_url", fmt.Sprintf("http://%s%s/auth/setup", cfg.ListenAddress(), cfg.APIBasePath()))
	}
	warnIfExposed(cfg, log)
	warnIfUnitsAreUnreachable(cfg, log)

	httpServer := &http.Server{
		Addr:    cfg.ListenAddress(),
		Handler: server.Handler(),
		// No WriteTimeout: the monitor and metrics endpoints stream server-sent
		// events, and a write deadline would sever a healthy stream. Read and
		// idle deadlines still bound a client that connects and says nothing.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening",
			"address", cfg.ListenAddress(),
			"url", fmt.Sprintf("http://%s%s", cfg.ListenAddress(), cfg.BasePath()),
			"web_path", cfg.WebPath,
			"port_from", effective.PortSource,
			"web_path_from", effective.WebPathSource,
			"version", version,
			"dev_mode", cfg.DevMode)
		// Serve rather than ListenAndServe: the socket was opened before any of
		// this was built, because which port it landed on decides what the
		// safety guard protects and what the served page says its base is.
		if err := httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case err := <-serveErr:
		if err != nil {
			return fmt.Errorf("serving: %w", err)
		}
		return nil
	case <-ctx.Done():
		log.Info("shutdown signal received; draining connections")
	}

	// Graceful shutdown: stop accepting, let in-flight requests finish, cancel
	// every prober, flush the traffic counters, then close the database (§20).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown did not finish in time", "error", err,
			"timeout_seconds", int(shutdownTimeout.Seconds()))
		_ = httpServer.Close()
	}

	stopPruning()
	monitorSupervisor.Stop()
	metricsSampler.Stop()
	// The in-memory totals are authoritative between writes, so the last thing
	// to happen before the database closes is writing them down (§11.3, §5.2).
	if err := metricsSampler.Flush(shutdownCtx); err != nil {
		log.Error("flushing the traffic counters failed", "error", err)
	}
	// Stop writes the forwarding totals down as it ends; this closes any last
	// aggregate bucket so the final interval is not lost with the process.
	routeAccounting.WriteAggregates(shutdownCtx)
	routeAccounting.Stop()
	if err := <-serveErr; err != nil {
		return fmt.Errorf("serving: %w", err)
	}
	log.Info("stopped")
	return nil
}

// addressSeed is the bootstrap configuration's contribution to deciding where
// to listen: the environment file's values, and whether a flag overrode them.
func addressSeed(cfg *config.Config) address.Seed {
	return address.Seed{
		Port:            cfg.SeedBindPort,
		WebPath:         cfg.SeedWebPath,
		PortFromFlag:    cfg.BindPortFromFlag,
		WebPathFromFlag: cfg.WebPathFromFlag,
		PortProvided:    cfg.SeedBindPortSet,
		WebPathProvided: cfg.SeedWebPathSet,
	}
}

// bindCandidates is the order to try ports in: what was asked for, then what
// last worked, then what the environment file says, then the built-in default.
//
// Everything after the first entry exists so that a port which cannot be bound
// leaves the panel reachable somewhere rather than in a restart loop. The order
// is deliberate — the last port that actually worked is the one an operator is
// most likely to still have open in a browser tab.
func bindCandidates(effective address.Effective, stored address.Stored, seed address.Seed) []int {
	out := []int{effective.Port}
	if stored.LastGoodPort > 0 {
		out = append(out, stored.LastGoodPort)
	}
	if seed.Port > 0 {
		out = append(out, seed.Port)
	}
	return append(out, config.DefaultBindPort)
}

// printAddress answers --print-address: where this installation would serve,
// and why, as JSON on stdout.
//
// The installer needs this. Before the address moved into the database it could
// health-check the port it had just written to the environment file; after an
// upgrade that file is only the seed, so polling it would test the wrong URL
// and report a working panel as a failed install.
func printAddress(cfg *config.Config) error {
	seed := addressSeed(cfg)
	effective := address.Resolve(address.Stored{}, seed)

	// A missing database is not an error here: it is what a host looks like
	// before the first start, and the seed is the whole truth then.
	if _, statErr := os.Stat(cfg.DBPath); statErr == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		database, err := db.Open(ctx, cfg.DBPath)
		if err != nil {
			return fmt.Errorf("reading the stored address from %s: %w", cfg.DBPath, err)
		}
		defer database.Close() //nolint:errcheck // read-only use
		stored, err := address.Load(ctx, database)
		if err != nil {
			return err
		}
		effective = address.Resolve(stored, seed)
	}

	host := cfg.BindHost
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	out, err := json.MarshalIndent(map[string]any{
		"bind_host":       cfg.BindHost,
		"port":            effective.Port,
		"web_path":        effective.WebPath,
		"base_path":       basePathFor(effective.WebPath),
		"url":             address.URL("http", host, effective.Port, effective.WebPath),
		"health_url":      address.HealthURL("http", host, effective.Port, effective.WebPath),
		"port_source":     string(effective.PortSource),
		"web_path_source": string(effective.WebPathSource),
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func basePathFor(webPath string) string {
	if webPath == "" {
		return "/"
	}
	return "/" + webPath + "/"
}

// restarter returns the function the API calls to put a new address into
// effect. It cancels the same context a SIGTERM would, so the shutdown is the
// ordinary graceful one — connections drained, counters flushed, database
// closed — and the process then exits 0 into systemd's Restart=always.
//
// The delay is what lets the answer already written to the operator's browser
// actually get there.
func restarter(stop context.CancelFunc, log *slog.Logger) func(string) {
	return func(reason string) {
		log.Warn("a restart was requested; the panel will stop and systemd will start it again",
			"reason", reason, "delay", restartDelay.String())
		go func() {
			time.Sleep(restartDelay)
			stop()
		}()
	}
}

// underSystemd reports whether this process was started by systemd.
//
// INVOCATION_ID is set by systemd for every unit it starts and by nothing else,
// so it distinguishes "exiting means systemd starts me again" from "exiting
// means the panel is gone". The API refuses to apply an address change that it
// cannot bring back.
func underSystemd() bool { return os.Getenv("INVOCATION_ID") != "" }

// lookupBinary resolves a program on PATH, falling back to a conventional
// location. Nothing here is hardcoded the way the legacy script hardcoded
// /sbin/ip, and what was actually resolved is reported by the system-info
// endpoint (§5.1).
func lookupBinary(name, fallback string) string {
	if path, err := osexec.LookPath(name); err == nil {
		return path
	}
	if fallback != "" {
		if st, err := os.Stat(fallback); err == nil && !st.IsDir() {
			return fallback
		}
	}
	return ""
}

// pruneRetention drops monitoring history, diagnostic runs and audit entries
// past their retention windows.
//
// It runs hourly rather than at startup only: a panel that stays up for months
// would otherwise never prune, and the retention settings would quietly mean
// nothing.
func pruneRetention(ctx context.Context, store *settings.Store, auditWriter *audit.Writer,
	diagService *diag.Service, accounting *route.Accounting, log *slog.Logger) {

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if removed, err := auditWriter.Prune(ctx, store.Int("system.audit_retention_days")); err != nil {
			log.Error("pruning the audit log failed", "error", err)
		} else if removed > 0 {
			log.Info("pruned audit entries past their retention window", "removed", removed)
		}
		if removed, err := diagService.PruneRuns(ctx, store.Int("system.audit_retention_days")); err != nil {
			log.Error("pruning diagnostic runs failed", "error", err)
		} else if removed > 0 {
			log.Info("pruned diagnostic runs past their retention window", "removed", removed)
		}
		if removed, err := accounting.Prune(ctx); err != nil {
			log.Error("pruning the forwarding traffic history failed", "error", err)
		} else if removed > 0 {
			log.Info("pruned forwarding traffic history past its retention window", "removed", removed)
		}
	}
}

// newLogger builds the structured logger. Output goes to stdout for journald.
func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

// checkPrivileges enforces the root requirement, which development mode relaxes
// so the panel can be worked on without it.
func checkPrivileges(cfg *config.Config, log *slog.Logger) error {
	if os.Geteuid() == 0 {
		return nil
	}
	if cfg.DevMode {
		log.Warn("running without root in development mode; tunnel management is unavailable",
			"uid", os.Geteuid())
		return nil
	}
	return fmt.Errorf("gre-panel must run as root to configure kernel networking "+
		"(effective uid is %d). Set %s=true to run without it for development",
		os.Geteuid(), config.EnvDevMode)
}

// prepareDataDir creates the data directory and restricts it to its owner. It
// holds the database and the signing key, so 0700 is not optional (§18).
func prepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating the data directory %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("restricting permissions on %s: %w", dir, err)
	}
	return nil
}

// systemdUnitDirs are the directories systemd actually loads units from. A
// panel writing anywhere else would enable units systemd has never heard of.
var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// warnIfUnitsAreUnreachable says so when the configured unit directory is not
// one systemd reads.
//
// Without this the first symptom is an apply that fails at the enable step with
// "unit file does not exist" — which is the correct outcome, since the panel
// refuses to report a tunnel as persisted when it is not, but it is a confusing
// way to learn about a misconfiguration.
func warnIfUnitsAreUnreachable(cfg *config.Config, log *slog.Logger) {
	dir := filepath.Clean(cfg.SystemdDir)
	for _, known := range systemdUnitDirs {
		if dir == known {
			return
		}
	}
	log.Warn("the configured unit directory is not one systemd loads from, so systemd persistence "+
		"will fail at the enable step; use one of the standard directories or choose runtime "+
		"persistence, which configures the kernel only",
		"systemd_dir", dir, "known_directories", strings.Join(systemdUnitDirs, ", "))
}

// warnIfExposed complains loudly about a panel reachable from the network
// without TLS in front of it (§18). It runs as root and configures kernel
// networking; credentials crossing a network in the clear is not acceptable.
func warnIfExposed(cfg *config.Config, log *slog.Logger) {
	if cfg.IsLoopbackBind() {
		return
	}
	log.Warn("SECURITY: the panel is bound to a non-loopback address and serves plain HTTP. "+
		"Passwords and session cookies will cross the network unencrypted. Put a TLS-terminating "+
		"reverse proxy in front of it, or bind to 127.0.0.1 and reach it through an SSH tunnel",
		"bind_host", cfg.BindHost, "bind_port", cfg.BindPort)
}
