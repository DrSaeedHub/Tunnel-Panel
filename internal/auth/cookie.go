package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"
)

// Cookie names. Tokens are held in httpOnly cookies so a script injected into
// the panel cannot read them; the CSRF cookie is deliberately readable, because
// the frontend has to echo it back in a header (§18).
const (
	CookieAccess  = "gre_panel_access"
	CookieRefresh = "gre_panel_refresh"
	CookieCSRF    = "gre_panel_csrf"
)

// CSRFHeader is the header the frontend echoes the CSRF cookie back in.
const CSRFHeader = "X-CSRF-Token"

// CookieWriter issues and clears the panel's cookies for one configured
// installation. Path is the panel base path, so an unrelated application on
// another path of the same host never receives these cookies.
type CookieWriter struct {
	Path string
}

// NewCookieWriter returns a writer for the given base path, which must begin
// and end with a slash.
func NewCookieWriter(basePath string) *CookieWriter {
	if basePath == "" {
		basePath = "/"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return &CookieWriter{Path: basePath}
}

// isSecureRequest reports whether the response will travel over TLS, directly
// or through a terminating proxy. The Secure attribute cannot simply be set
// unconditionally: a browser silently drops a Secure cookie sent over plain
// HTTP, which would lock an operator out of a panel reached over a private
// network or an SSH tunnel.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		return false
	}
	// The header may list several values when proxies are chained; the first is
	// the scheme the client used.
	first, _, _ := strings.Cut(proto, ",")
	return strings.EqualFold(strings.TrimSpace(first), "https")
}

func (w *CookieWriter) base(r *http.Request, name, value string, httpOnly bool, expires time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     w.Path,
		HttpOnly: httpOnly,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	}
	if !expires.IsZero() {
		c.Expires = expires.UTC()
		if secs := int(time.Until(expires).Seconds()); secs > 0 {
			c.MaxAge = secs
		}
	}
	return c
}

// SetSession writes the access, refresh, and CSRF cookies.
func (w *CookieWriter) SetSession(rw http.ResponseWriter, r *http.Request, access string, accessExpiry time.Time, refresh string, refreshExpiry time.Time, csrf string) {
	http.SetCookie(rw, w.base(r, CookieAccess, access, true, accessExpiry))
	http.SetCookie(rw, w.base(r, CookieRefresh, refresh, true, refreshExpiry))
	http.SetCookie(rw, w.base(r, CookieCSRF, csrf, false, refreshExpiry))
}

// SetCSRF writes only the CSRF cookie, used to seed a token before login.
func (w *CookieWriter) SetCSRF(rw http.ResponseWriter, r *http.Request, csrf string) {
	http.SetCookie(rw, w.base(r, CookieCSRF, csrf, false, time.Now().Add(24*time.Hour)))
}

// Clear expires every cookie the panel sets.
func (w *CookieWriter) Clear(rw http.ResponseWriter, r *http.Request) {
	for _, name := range []string{CookieAccess, CookieRefresh, CookieCSRF} {
		c := w.base(r, name, "", name != CookieCSRF, time.Time{})
		c.Expires = time.Unix(0, 0)
		c.MaxAge = -1
		http.SetCookie(rw, c)
	}
}

// NewCSRFToken returns a fresh random CSRF token.
func NewCSRFToken() (string, error) { return randomToken(32) }

// BearerToken extracts a token from the Authorization header, if present.
func BearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

// CookieValue returns a cookie's value, or "" when it is absent.
func CookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// CheckCSRF verifies the double-submit token: the value in the header must
// match the value in the cookie. Comparison is constant time.
func CheckCSRF(r *http.Request) bool {
	cookie := CookieValue(r, CookieCSRF)
	header := r.Header.Get(CSRFHeader)
	if cookie == "" || header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) == 1
}
