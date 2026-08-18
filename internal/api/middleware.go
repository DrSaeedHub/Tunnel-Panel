package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/model"
)

type contextKey string

const (
	ctxKeyUser      contextKey = "user"
	ctxKeyRequestID contextKey = "request_id"
)

// UserFromContext returns the authenticated user, if the request passed through
// requireAuth.
func UserFromContext(ctx context.Context) *model.AppUser {
	u, _ := ctx.Value(ctxKeyUser).(*model.AppUser)
	return u
}

// RequestIDFromContext returns the per-request identifier used in logs.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}

// statusRecorder captures the status code so the access log can report it.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush forwards to the underlying writer so SSE handlers keep working behind
// the recorder.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// requestContext assigns a request identifier and logs the outcome.
func (s *Server) requestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = newRequestID()
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)

		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(rec, r.WithContext(ctx))

		level := "debug"
		if rec.status >= 500 {
			level = "error"
		} else if rec.status >= 400 {
			level = "warn"
		}
		args := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", ClientIP(r),
			"request_id", id,
		}
		switch level {
		case "error":
			s.log.Error("request failed", args...)
		case "warn":
			s.log.Warn("request rejected", args...)
		default:
			s.log.Debug("request", args...)
		}
	})
}

// recoverPanic turns a panic into a 500 with the standard envelope rather than
// letting it kill the connection and, with it, every other in-flight request.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if errors.Is(toError(rec), http.ErrAbortHandler) {
					panic(rec) // the server handles this one itself
				}
				s.log.Error("handler panicked",
					"path", r.URL.Path, "panic", rec, "request_id", RequestIDFromContext(r.Context()))
				writeError(w, http.StatusInternalServerError, CodeInternal,
					"The request could not be completed.", "", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func toError(v any) error {
	if err, ok := v.(error); ok {
		return err
	}
	return nil
}

// connectSrc builds the connect-src directive: this origin, plus this same host
// on any port.
//
// The port is the whole reason. When an operator moves the panel, the page that
// asked for the move is still on the old port and has to poll the new one to
// know when to send them there. A different port is a different origin, so
// `connect-src 'self'` blocks that fetch — in the browser, before it is sent.
// Measured against a live panel moving 8443 -> 8444:
//
//	Connecting to 'http://…:8444/api/v1/system/health' violates the following
//	Content Security Policy directive: "connect-src 'self'". The action has
//	been blocked.
//
// The health endpoint's permissive CORS was correct and did nothing here: CORS
// is the server saying who may read a response, CSP is the browser saying where
// this page may send a request, and the request never left. The operator was
// left on a dead URL watching a page that could not tell them where the panel
// had gone — the exact failure the polling redirect exists to prevent.
//
// Widening to the same host on any port is the narrowest thing that works. It
// does not admit any other host, and the panel moving between ports on the host
// an operator already reached it on is precisely the case the product creates.
// A bare "*" would have been the easy fix and would have let the page talk to
// anywhere on the internet.
func connectSrc(requestHost string) string {
	const self = "connect-src 'self'"
	host := hostWithoutPort(requestHost)
	if host == "" {
		return self
	}
	return self + " http://" + host + ":* https://" + host + ":*"
}

// hostWithoutPort returns the host of a Host header, keeping the brackets an
// IPv6 literal needs to be a valid CSP host-source.
func hostWithoutPort(hostPort string) string {
	if hostPort == "" {
		return ""
	}
	host := hostPort
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return ""
	}
	// A CSP host-source containing colons is an IPv6 literal and must be
	// bracketed, or the colon reads as a port separator.
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// securityHeaders sets the headers of §18 on every response. The content
// security policy is tight because the panel serves only its own bundle: no
// third-party scripts, no remote fonts, no framing.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	// The bootstrap script index.html carries is inline of necessity — it holds
	// the web path, which is chosen at install time — so script-src names its
	// exact hash. Allowing 'unsafe-inline' instead would permit any inline
	// script on the page, which is the thing this policy exists to prevent.
	scriptSrc := "script-src 'self'"
	if hash := s.static.ScriptHash(); hash != "" {
		scriptSrc += " " + hash
	}

	cspHead := "default-src 'self'; " +
		scriptSrc + "; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self' data:; "
	cspTail := "; object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), interest-cohort=()")
		h.Set("Content-Security-Policy", cspHead+connectSrc(r.Host)+cspTail)
		// Only assert HSTS when the request actually arrived over TLS; sending it
		// over plain HTTP would be ignored at best and lock out a panel reached
		// by IP at worst.
		if r.TLS != nil || strings.EqualFold(firstForwardedProto(r), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func firstForwardedProto(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	first, _, _ := strings.Cut(proto, ",")
	return strings.TrimSpace(first)
}

// noStore marks API responses as uncacheable. Settings, status and metrics all
// change constantly and a cached 200 would be actively misleading.
func (s *Server) noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, r)
	})
}

// cors implements the strict policy of §18: with no configured origins the API
// is same-origin only and no CORS headers are sent at all.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// The health endpoint, and only the health endpoint, answers any
		// origin.
		//
		// Changing the panel's port moves it to a new origin, and the page that
		// asked for the change is still on the old one. It has to be able to
		// tell when the panel is back before sending the operator there, and
		// the alternative — redirecting blind and hoping — is how an operator
		// ends up on a dead URL with no way to know whether the change failed
		// or is merely slow.
		//
		// What this exposes is the health envelope: a status word, an uptime,
		// whether setup is required, and per-component states. No configuration
		// and no identifiers. It is also the endpoint that answers before any
		// account exists, so it is already the least privileged thing here.
		// security.allowed_origins is untouched and still governs every other
		// route, credentials are never allowed on this one, and a cross-origin
		// caller therefore cannot use it to reach anything with a session.
		if isHealthPath(r.URL.Path) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", "*")
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Accept, Content-Type")
				h.Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Read live from settings so changing the list takes effect without a
		// process restart.
		allowed := false
		for _, candidate := range s.settings.StringSlice("security.allowed_origins") {
			if strings.EqualFold(candidate, origin) {
				allowed = true
				break
			}
		}

		if !allowed {
			// A same-origin request also carries an Origin header on mutations;
			// let it through rather than breaking the panel's own frontend.
			if sameOrigin(r, origin) {
				next.ServeHTTP(w, r)
				return
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeError(w, http.StatusForbidden, CodeOriginNotAllowed,
				"This origin is not allowed to call the API. Add it to security.allowed_origins.",
				"", map[string]any{"origin": origin})
			return
		}

		h := w.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Add("Vary", "Origin")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+auth.CSRFHeader)
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether the Origin header names this very server.
// healthPath is the one route with a permissive CORS policy. The web path
// prefix is stripped before the application router runs, so this is the path
// the middleware actually sees, whatever the panel is served under — including
// the empty web path, where it is the whole URL.
const healthPath = "/api/v1/system/health"

func isHealthPath(path string) bool {
	return path == healthPath || path == healthPath+"/"
}

func sameOrigin(r *http.Request, origin string) bool {
	host := r.Host
	if host == "" {
		return false
	}
	for _, scheme := range []string{"http://", "https://"} {
		if strings.EqualFold(origin, scheme+host) {
			return true
		}
	}
	return false
}

// requireSetup implements §18: until an operator account exists, every endpoint
// except setup and health answers 503 SETUP_REQUIRED. Those two exceptions are
// routed outside this middleware rather than special-cased inside it.
func (s *Server) requireSetup(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, err := s.auth.HasUser(r.Context())
		if err != nil {
			s.log.Error("checking setup state failed", "error", err)
			writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
				"The panel could not read its database.", "", nil)
			return
		}
		if !ok {
			s.ensureCSRFCookie(w, r)
			writeError(w, http.StatusServiceUnavailable, CodeSetupRequired,
				"No operator account exists yet. Create the first account before using the panel.",
				"", map[string]any{"setup_path": s.cfg.APIBasePath() + "/auth/setup"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAuth resolves the access token from the cookie, or from an
// Authorization header for scripted clients, and rejects tokens invalidated by
// a password change.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := auth.CookieValue(r, auth.CookieAccess)
		if token == "" {
			token = auth.BearerToken(r)
		}
		if token == "" {
			writeError(w, http.StatusUnauthorized, CodeUnauthenticated,
				"Authentication is required.", "", nil)
			return
		}

		user, _, err := s.auth.ResolveToken(r.Context(), token, auth.UseAccess)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrTokenSuperseded):
				writeError(w, http.StatusUnauthorized, CodeUnauthenticated,
					"This session ended when the password was changed. Sign in again.", "", nil)
			case errors.Is(err, auth.ErrAccountInactive):
				writeError(w, http.StatusForbidden, CodeAccountInactive,
					"This account is not active.", "", nil)
			case errors.Is(err, auth.ErrTokenInvalid), errors.Is(err, auth.ErrTokenWrongUse):
				writeError(w, http.StatusUnauthorized, CodeUnauthenticated,
					"The session is not valid. Sign in again.", "", nil)
			default:
				s.log.Error("resolving access token failed", "error", err)
				writeError(w, http.StatusInternalServerError, CodeInternal,
					"The session could not be verified.", "", nil)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKeyUser, user)))
	})
}

// csrfGuard enforces the double-submit token on mutating requests (§18).
//
// It is skipped for requests authenticated by an Authorization header, which
// carry no ambient credential a browser could attach on their behalf, and for
// setup and login, which have no session to protect and are reached before the
// frontend has a token.
func (s *Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if auth.BearerToken(r) != "" {
			next.ServeHTTP(w, r)
			return
		}
		if s.csrfExempt[normalizePath(r.URL.Path)] {
			next.ServeHTTP(w, r)
			return
		}
		if !auth.CheckCSRF(r) {
			writeError(w, http.StatusForbidden, CodeCSRFRequired,
				"This request is missing a valid CSRF token. Send the value of the "+
					auth.CookieCSRF+" cookie in the "+auth.CSRFHeader+" header.", "", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizePath(p string) string {
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// ensureCSRFCookie seeds a CSRF token when the client does not have one, so the
// frontend can make its first mutating request after a single GET.
func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if auth.CookieValue(r, auth.CookieCSRF) != "" {
		return
	}
	token, err := auth.NewCSRFToken()
	if err != nil {
		s.log.Error("generating CSRF token failed", "error", err)
		return
	}
	s.cookies.SetCSRF(w, r, token)
}

// ClientIP returns the address the request came from. Forwarded headers are
// deliberately ignored: the panel is normally reached directly, and trusting a
// client-supplied header would let an attacker sidestep the per-address rate
// limit and forge the address recorded in the audit log.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
