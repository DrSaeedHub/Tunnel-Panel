package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drs/gre-panel/internal/address"
	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/config"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/diag"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/metrics"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/reconcile"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/update"
)

// Updates is the pair the update endpoints work through: what the release host
// is serving, and what this host can do about it. Both are optional together —
// a server built without them reports the feature as unavailable rather than
// pretending every installation is up to date.
type Updates struct {
	Checker *update.Checker
	Applier *update.Applier
}

// BuildInfo is stamped at link time and reported by --version and
// GET /system/info (§20).
type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Deps is everything the HTTP layer needs. Nothing is constructed here, so a
// test can substitute any of it.
type Deps struct {
	Config   *config.Config
	DB       *db.DB
	Settings *settings.Store
	Auth     *auth.Service
	Audit    *audit.Writer
	Log      *slog.Logger
	Build    BuildInfo
	// Tunnels and Reconcile are the services the tunnel endpoints call. They are
	// optional so a test can build a server without them, in which case those
	// routes report the feature as unavailable rather than panicking.
	Tunnels   *tunnel.Service
	Reconcile *reconcile.Service
	// Routes, RouteAccounting and RouteDiag are the port forwarding subsystem.
	// Each is optional; without one, its routes report the feature as
	// unavailable rather than disappearing, so a client sees why.
	Routes          *route.Service
	RouteAccounting *route.Accounting
	RouteDiag       *route.Diagnostics
	// RouteMonitor probes the destinations of the rules that ask for it.
	// Without it a rule reports its destinations as unmonitored rather than
	// as healthy, which is the difference between no answer and a good one.
	RouteMonitor *route.Monitor
	// Monitor, Metrics and Diag are the subsystems the live views need. Each is
	// optional; without one, its routes report the feature as unavailable
	// rather than disappearing, so a client sees why.
	Monitor *monitor.Supervisor
	Metrics *metrics.Sampler
	Diag    *diag.Service
	// Persist reports which persistence backends can actually be offered here.
	Persist *persist.Store
	// Updates answers whether a newer panel exists and installs it. Optional:
	// without it the update endpoints report the feature as unavailable, which
	// is the honest answer for a server built without the plumbing.
	Updates *Updates
	// RuleBackend is what startup concluded about this host's netfilter
	// interface. It is reported through the capabilities endpoint so the
	// frontend can explain which one is carrying the forwarding rules.
	RuleBackend rules.Detection
	// Health is optional; a fresh registry is created when it is nil. Passing
	// one in lets later subsystems register their own components.
	Health *HealthRegistry

	// RouteGuard answers which ports may not be taken. The address endpoint
	// needs it for the same reason a forwarding rule does: moving the panel
	// onto the live SSH port would lock the machine just as surely as
	// forwarding it would.
	RouteGuard *safety.RouteGuard
	// AddressFallback is non-nil when the configured port could not be bound
	// and the panel is serving somewhere else. It is reported so an operator
	// who cannot find the panel is told why.
	AddressFallback *address.Fallback
	// AddressSources says where the running port and web path came from.
	AddressSources AddressSources
	// Restart puts a new address into effect by ending the process, which
	// systemd's Restart=always then reverses. Nil means the panel cannot apply
	// an address change itself.
	Restart func(reason string)
	// UnderSystemd gates that: without it, exiting would simply stop the panel.
	UnderSystemd bool
}

// Server owns the router and the handler dependencies.
type Server struct {
	cfg          *config.Config
	db           *db.DB
	settings     *settings.Store
	auth         *auth.Service
	audit        *audit.Writer
	cookies      *auth.CookieWriter
	log          *slog.Logger
	build        BuildInfo
	health       *HealthRegistry
	static       *StaticHandler
	tunnels      *tunnel.Service
	reconcile    *reconcile.Service
	routes       *route.Service
	accounting   *route.Accounting
	routeDiag    *route.Diagnostics
	routeMonitor *route.Monitor
	monitor      *monitor.Supervisor
	metrics      *metrics.Sampler
	diag         *diag.Service
	persist      *persist.Store
	updates      *Updates
	ruleBackend  rules.Detection
	started      time.Time

	routeGuard      *safety.RouteGuard
	addressFallback *address.Fallback
	addressSources  AddressSources
	restart         func(reason string)
	underSystemd    bool

	// restoreState is the progress of the last database restore, which is the
	// only long operation the browser cannot measure for itself: it can see its
	// own upload, and nothing after it. Held in memory on purpose — a restore
	// ends by restarting the process, so this is gone by the time the panel
	// answers again, and the client stops asking here and starts watching
	// health instead.
	restoreState *restoreState

	// router is the application router, kept so the API description can be
	// walked off what is actually served rather than maintained by hand.
	router chi.Router

	// csrfExempt holds the fully qualified paths that skip the CSRF check.
	csrfExempt map[string]bool

	handler http.Handler
}

// New builds the server and its router.
func New(d Deps) (*Server, error) {
	if d.Config == nil {
		return nil, errors.New("api: config is required")
	}
	if d.Auth == nil {
		return nil, errors.New("api: auth service is required")
	}
	if d.Settings == nil {
		return nil, errors.New("api: settings store is required")
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	health := d.Health
	if health == nil {
		health = NewHealthRegistry()
	}

	static, err := NewStaticHandler(d.Config.BasePath(), d.Config.APIBasePath(), d.Build.Version)
	if err != nil {
		return nil, fmt.Errorf("api: preparing the embedded frontend: %w", err)
	}

	s := &Server{
		cfg:          d.Config,
		db:           d.DB,
		settings:     d.Settings,
		auth:         d.Auth,
		audit:        d.Audit,
		cookies:      auth.NewCookieWriter(d.Config.BasePath()),
		log:          log,
		build:        d.Build,
		health:       health,
		static:       static,
		tunnels:      d.Tunnels,
		reconcile:    d.Reconcile,
		routes:       d.Routes,
		accounting:   d.RouteAccounting,
		routeDiag:    d.RouteDiag,
		routeMonitor: d.RouteMonitor,
		monitor:      d.Monitor,
		metrics:      d.Metrics,
		diag:         d.Diag,
		persist:      d.Persist,
		updates:      d.Updates,
		ruleBackend:  d.RuleBackend,
		started:      time.Now(),

		routeGuard:      d.RouteGuard,
		addressFallback: d.AddressFallback,
		addressSources:  d.AddressSources,
		restart:         d.Restart,
		underSystemd:    d.UnderSystemd,
	}
	// Login is reached before the frontend has a token, and has no session to
	// protect. Setup is routed outside the guard entirely, and is listed here
	// so moving it under the guard later does not silently break it.
	//
	// The web path prefix is stripped before the application router runs, so
	// these are the paths the guard actually sees.
	s.csrfExempt = map[string]bool{
		"/api/v1/auth/setup": true,
		"/api/v1/auth/login": true,
	}
	s.handler = s.buildRouter()
	return s, nil
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Health exposes the registry so subsystems started after the server can
// register their own components.
func (s *Server) Health() *HealthRegistry { return s.health }

// buildRouter assembles the router. The entire application — API, SSE, and the
// embedded static assets — is mounted under the web path prefix, and anything
// outside it is a bare 404 that says nothing about what is running here (§5.2).
func (s *Server) buildRouter() http.Handler {
	app := chi.NewRouter()
	s.router = app
	app.Use(s.securityHeaders)
	app.Use(s.cors)

	app.Route("/api/v1", func(r chi.Router) {
		r.Use(s.noStore)

		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusNotFound, CodeNotFound, "No such endpoint.", "", nil)
		})
		r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			writeError(w, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
				"That method is not allowed on this endpoint.", "", nil)
		})

		// The two endpoints reachable before an operator account exists (§18).
		r.Get("/system/health", s.handleHealth)
		r.Post("/auth/setup", s.handleSetup)

		// The database download, which answers on a token instead of a session.
		//
		// It sits out here because a link that required a login would not be a
		// link — the point is that it can be pasted into curl or a browser that
		// has never seen this panel. The token is 256 bits, only its hash is
		// stored, it expires in fifteen minutes, and issuing one requires a
		// session. The upload that goes the other way is authenticated: a
		// download hands over a copy, while an upload replaces every account
		// the panel has.
		r.Get("/system/backup/download", s.handleBackupDownload)

		r.Group(func(r chi.Router) {
			// The setup gate runs before the CSRF guard, so an unconfigured
			// panel answers SETUP_REQUIRED rather than complaining about a
			// token the operator has no way to have yet.
			r.Use(s.requireSetup)
			r.Use(s.csrfGuard)

			// Reachable without a session, but only once setup is done.
			r.Post("/auth/login", s.handleLogin)
			r.Post("/auth/refresh", s.handleRefresh)
			r.Post("/auth/logout", s.handleLogout)

			r.Group(func(r chi.Router) {
				r.Use(s.requireAuth)

				r.Get("/auth/me", s.handleMe)
				r.Put("/auth/me", s.handleUpdateMe)

				r.Get("/settings", s.handleGetSettings)
				r.Get("/settings/schema", s.handleGetSettingsSchema)
				r.Put("/settings", s.handleUpdateSettings)
				r.Post("/settings/reset", s.handleResetSettings)

				r.Get("/system/info", s.handleSystemInfo)
				r.Get("/system/capabilities", s.handleCapabilities)
				r.Get("/system/interfaces", s.handleInterfaces)
				r.Get("/system/routes", s.handleRoutes)

				// Where the panel itself is served. Not a settings key: the
				// generated settings form would let a port be saved with no
				// bind test and no restart, which is a panel that looks
				// configured and is unreachable at the next boot.
				r.Get("/system/address", s.handleGetAddress)
				r.Post("/system/address", s.handleSetAddress)

				// Whether the release host is serving something newer, and
				// installing it. The status is separate from /system/info
				// because it is a live question with a network answer, while
				// the build stamp beside it in the footer is a constant.
				r.Group(func(r chi.Router) {
					r.Use(s.requireUpdates)

					r.Get("/system/update", s.handleUpdateStatus)
					r.Post("/system/update/check", s.handleUpdateCheck)
					r.Post("/system/update", s.handleUpdateStart)
				})

				// The tunnel endpoints need the lifecycle service; without it the
				// route answers that the feature is unavailable rather than
				// disappearing, so a client sees why.
				r.Group(func(r chi.Router) {
					r.Use(s.requireTunnels)

					r.Get("/tunnels", s.handleListTunnels)
					r.Post("/tunnels", s.handleCreateTunnel)
					r.Post("/tunnels/preview", s.handlePreviewTunnel)
					r.Get("/tunnels/side-info", s.handleSideInfo)
					r.Post("/tunnels/from-pairing-code", s.handleFromPairingCode)

					r.Route("/tunnels/{id}", func(r chi.Router) {
						r.Get("/", s.handleGetTunnel)
						r.Patch("/", s.handleUpdateTunnel)
						r.Delete("/", s.handleDeleteTunnel)

						r.Post("/up", s.tunnelAction("up", model.AuditActionTunnelEnable, s.tunnels.Up))
						r.Post("/down", s.tunnelAction("down", model.AuditActionTunnelDisable, s.tunnels.Down))
						r.Post("/restart", s.tunnelAction("restart", model.AuditActionTunnelReapply, s.tunnels.Restart))
						r.Post("/reapply", s.tunnelAction("reapply", model.AuditActionTunnelReapply, s.tunnels.Reapply))

						r.Get("/addresses", s.handleListAddresses)
						r.Post("/addresses", s.handleAddAddress)
						r.Delete("/addresses", s.handleRemoveAddress)

						r.Get("/pairing-code", s.handlePairingCode)
					})

					r.Get("/pools", s.handleListPools)
					r.Post("/pools", s.handleCreatePool)
					r.Get("/pools/{id}", s.handleGetPool)
					r.Put("/pools/{id}", s.handleUpdatePool)
					r.Delete("/pools/{id}", s.handleDeletePool)
					r.Get("/pools/{id}/next-free", s.handleNextFreePool)

					r.Get("/reconcile", s.handleReconcile)
					r.Post("/reconcile/adopt", s.handleAdopt)
					r.Post("/reconcile/ignore", s.handleIgnore)
					r.Post("/reconcile/{id}/reapply", s.handleReconcileReapply)
					r.Post("/reconcile/{id}/forget", s.handleForget)

					// Monitoring (§10.5).
					r.Group(func(r chi.Router) {
						r.Use(s.requireMonitor)

						r.Get("/monitor/summary", s.handleMonitorSummary)
						r.Get("/monitor/stream", s.handleMonitorStream)
						r.Get("/tunnels/{id}/status", s.handleTunnelStatus)
						r.Get("/tunnels/{id}/history", s.handleTunnelHistory)
						r.Post("/tunnels/{id}/monitor/enable", s.handleMonitorToggle(true))
						r.Post("/tunnels/{id}/monitor/disable", s.handleMonitorToggle(false))
					})

					// Diagnostics (§13).
					r.Group(func(r chi.Router) {
						r.Use(s.requireDiag)

						r.Post("/tunnels/{id}/diagnostics/ping", s.handleDiagPing)
						r.Post("/tunnels/{id}/diagnostics/mtu-probe", s.handleDiagMtuProbe)
						r.Post("/tunnels/{id}/diagnostics/traceroute", s.handleDiagTraceroute)
						r.Post("/tunnels/{id}/diagnostics/analyze", s.handleDiagAnalyze)
						r.Get("/tunnels/{id}/counters", s.handleTunnelCounters)
						r.Get("/diagnostics/runs", s.handleDiagRuns)
						r.Get("/diagnostics/runs/{id}", s.handleDiagRun)
						r.Delete("/diagnostics/runs/{id}", s.handleDeleteDiagRun)
					})

					// Backup (§15). It reads and writes tunnels, so it lives
					// with them rather than on its own.
					r.Get("/backup/export", s.handleBackupExport)
					r.Post("/backup/import", s.handleBackupImport)

					// The database file itself, as opposed to the
					// configuration export above. Different in kind: the
					// export deliberately carries no accounts, and this
					// carries all of them.
					r.Post("/system/backup/link", s.handleBackupLink)
					r.Delete("/system/backup/link", s.handleBackupRevoke)
					r.Post("/system/restore", s.handleRestoreUpload)
					r.Get("/system/restore", s.handleRestoreStatus)

					// The forwarding rules that relay over one tunnel, for the
					// tunnel detail page (§10).
					r.Get("/tunnels/{id}/routes", s.handleTunnelRoutes)
				})

				// Port forwarding (§11 of the port forwarding specification).
				r.Group(func(r chi.Router) {
					r.Use(s.requireRoutes)

					r.Get("/routes", s.handleListRoutes)
					r.Post("/routes", s.handleCreateRoute)
					r.Post("/routes/preview", s.handlePreviewRoute)
					r.Post("/routes/reorder", s.handleReorderRoutes)
					r.Post("/routes/apply-all", s.handleApplyAllRoutes)

					// The destination pre-flight, which runs before any rule
					// exists and so cannot live under one (§8).
					r.Group(func(r chi.Router) {
						r.Use(s.requireRouteDiag)
						r.Post("/routes/diagnostics/test", s.handleRouteTest)
					})

					// The traffic summary is above /routes/{id} because chi
					// would otherwise read "traffic" as an identifier.
					r.Group(func(r chi.Router) {
						r.Use(s.requireAccounting)
						r.Get("/routes/traffic/summary", s.handleRouteTrafficSummary)
					})

					r.Route("/routes/{id}", func(r chi.Router) {
						r.Get("/", s.handleGetRoute)
						r.Patch("/", s.handleUpdateRoute)
						r.Delete("/", s.handleDeleteRoute)

						r.Post("/enable", s.routeAction("enable", model.AuditActionRouteEnable,
							func(ctx context.Context, id int64, req route.Request) (route.Result, error) {
								return s.routes.SetEnabled(ctx, id, true, req)
							}))
						r.Post("/disable", s.routeAction("disable", model.AuditActionRouteDisable,
							func(ctx context.Context, id int64, req route.Request) (route.Result, error) {
								return s.routes.SetEnabled(ctx, id, false, req)
							}))
						r.Post("/reapply", s.routeAction("reapply", model.AuditActionRouteReapply,
							s.routes.Reapply))
						r.Post("/duplicate", s.handleDuplicateRoute)

						r.Get("/destinations", s.handleListDestinations)
						r.Post("/destinations", s.handleAddDestination)
						r.Delete("/destinations", s.handleRemoveDestination)

						r.Get("/allowed-sources", s.handleListAllowedSources)
						r.Post("/allowed-sources", s.handleAddAllowedSource)
						r.Delete("/allowed-sources", s.handleRemoveAllowedSource)

						// Traffic (§5). Live values also ride the existing
						// metrics stream rather than an endpoint of their own.
						r.Group(func(r chi.Router) {
							r.Use(s.requireAccounting)
							r.Get("/traffic", s.handleRouteTraffic)
							r.Get("/traffic/history", s.handleRouteTrafficHistory)
						})

						// Diagnostics (§8).
						r.Group(func(r chi.Router) {
							r.Use(s.requireRouteDiag)
							r.Post("/diagnostics/test", s.handleRouteTest)
							r.Post("/diagnostics/analyze", s.handleRouteAnalyze)
							r.Get("/connections", s.handleRouteConnections)
							r.Get("/counters", s.handleRouteCounters)
						})

						// What the destination monitor has found. It needs no
						// subsystem of its own to be available: a panel without
						// the monitor answers with an empty list, which is the
						// truth about what it knows.
						r.Get("/destinations/health", s.handleRouteDestinationHealth)
					})

					// The kernel parameters and the netfilter picture (§2.3).
					r.Get("/system/forwarding", s.handleForwarding)
					r.Post("/system/forwarding/enable", s.handleEnableForwarding)
				})

				// System metrics (§11.4).
				r.Group(func(r chi.Router) {
					r.Use(s.requireMetrics)

					r.Get("/system/metrics", s.handleMetrics)
					r.Get("/system/metrics/stream", s.handleMetricsStream)
					r.Get("/system/metrics/history", s.handleMetricsHistory)
				})

				r.Get("/audit", s.handleAudit)
			})
		})
	})

	// The API description lives beside the versioned API rather than inside it,
	// and is gated behind authentication like everything else (§15).
	app.Route("/api/docs", func(r chi.Router) {
		r.Use(s.noStore)
		r.Use(s.requireSetup)
		r.Use(s.csrfGuard)
		r.Use(s.requireAuth)
		r.Get("/", s.handleOpenAPI)
	})

	// Everything not under /api/v1 inside the prefix is the single-page app.
	app.NotFound(s.static.ServeHTTP)
	app.MethodNotAllowed(s.static.ServeHTTP)

	var root http.Handler = app
	if prefix := s.cfg.PathPrefix(); prefix != "" {
		stripped := http.StripPrefix(prefix, app)
		root = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == prefix:
				// Redirect the bare prefix to its slash form so the relative asset
				// URLs in index.html resolve against the prefix, not the root.
				http.Redirect(w, r, s.cfg.BasePath(), http.StatusMovedPermanently)
			case strings.HasPrefix(r.URL.Path, prefix+"/"):
				stripped.ServeHTTP(w, r)
			default:
				// Outside the prefix the panel is silent: a bare 404 with no body
				// and nothing that names the software or hints that it is here.
				silent404(w, r)
			}
		})
	}

	// The prefix is stripped before the application router sees the request, so
	// it routes on plain paths and chi's URL parameters keep working unchanged.
	return s.requestContext(s.recoverPanic(root))
}

func silent404(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

func newRequestID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "unknown"
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// requireTunnels answers clearly when the lifecycle service is not wired,
// rather than letting a nil dereference become a 500. In practice this only
// happens in a test that builds the HTTP layer on its own.
func (s *Server) requireTunnels(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.tunnels == nil || s.reconcile == nil {
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"Tunnel management is not available on this instance.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleInterfaces lists every interface on the host, classified so the
// frontend can tell a tunnel from a NIC without guessing from the name (§15).
func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if s.tunnels == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"Interface listing is not available on this instance.", "", nil)
		return
	}
	links, err := s.tunnels.Links().List(r.Context())
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	type item struct {
		link.Link
		Class string `json:"class"`
	}
	out := make([]item, 0, len(links))
	for _, l := range links {
		class := "other"
		switch {
		case l.IsLoopback():
			class = "loopback"
		case l.IsTunnel():
			class = "tunnel"
		case l.IsBridge():
			class = "bridge"
		case l.IsPhysical():
			class = "physical"
		}
		out = append(out, item{Link: l, Class: class})
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": out, "total": len(out)})
}

// handleRoutes returns the routing table, which is what the overlap check and
// the default-route safety rule are decided from (§7.4, §17.1).
func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	if s.tunnels == nil {
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"Route listing is not available on this instance.", "", nil)
		return
	}
	routes, err := s.tunnels.Links().Routes(r.Context())
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"routes":                routes,
		"total":                 len(routes),
		"default_route_devices": keysOf(link.DefaultRouteDevices(routes)),
	})
}

func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
