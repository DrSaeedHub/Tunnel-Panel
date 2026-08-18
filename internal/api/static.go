package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	webui "github.com/drs/gre-panel/web"
)

// indexFile is the single-page app entry point every client-side route falls
// back to.
const indexFile = "index.html"

// hashedAssetRe matches the content-hashed names the bundler emits, for example
// index-DxYz1234.js. Those names change whenever their content does, so they
// can be cached effectively forever; everything else must be revalidated.
var hashedAssetRe = regexp.MustCompile(`-[A-Za-z0-9_]{8,}\.[A-Za-z0-9]+$`)

// contentTypes pins the types that matter rather than trusting the host's
// /etc/mime.types, which is absent or wrong on minimal servers. Serving a
// module as text/plain breaks the app in a way that is tedious to diagnose.
var contentTypes = map[string]string{
	".css":         "text/css; charset=utf-8",
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".json":        "application/json; charset=utf-8",
	".map":         "application/json; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".svg":         "image/svg+xml",
	".txt":         "text/plain; charset=utf-8",
	".wasm":        "application/wasm",
	".webmanifest": "application/manifest+json",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
}

// StaticHandler serves the embedded frontend under the panel's base path.
type StaticHandler struct {
	files fs.FS

	basePath    string
	apiBasePath string
	version     string

	// index is the rendered index.html: the embedded file with the base path
	// injected. It is rendered once at startup because the prefix cannot change
	// while the process runs.
	index     []byte
	indexETag string

	// scriptHash is the CSP source expression for the injected bootstrap
	// script, as sha256-<base64>. The script has to be inline — it carries the
	// web path, which is only known at runtime — and a strict script-src would
	// otherwise block it, leaving the frontend with no idea where the API is.
	scriptHash string
}

// ScriptHash reports the CSP source expression that permits the injected
// bootstrap script, for the security-headers middleware to include in
// script-src.
func (h *StaticHandler) ScriptHash() string { return h.scriptHash }

// NewStaticHandler prepares the embedded assets for serving under basePath,
// which must begin and end with a slash. The version is the build serving the
// page, injected so the frontend can tell a page it is still showing from the
// build now answering it.
func NewStaticHandler(basePath, apiBasePath, version string) (*StaticHandler, error) {
	sub, err := fs.Sub(webui.Assets, "dist")
	if err != nil {
		return nil, fmt.Errorf("opening the embedded frontend: %w", err)
	}
	raw, err := fs.ReadFile(sub, indexFile)
	if err != nil {
		return nil, fmt.Errorf("reading the embedded %s: %w", indexFile, err)
	}

	h := &StaticHandler{files: sub, basePath: basePath, apiBasePath: apiBasePath, version: version}
	h.index, h.scriptHash = injectBasePath(raw, basePath, apiBasePath, version)
	sum := sha256.Sum256(h.index)
	h.indexETag = `"` + hex.EncodeToString(sum[:16]) + `"`
	return h, nil
}

// injectBasePath rewrites index.html so the frontend resolves its assets and
// its client-side routes against the configured web path (§5.2).
//
// A <base> tag does the work for asset URLs, which is why the bundle is built
// with relative asset paths; the injected global gives the router and the API
// client the same prefix without a second source of truth.
// It returns the rendered page and the CSP source expression for the inline
// script it injected, since script-src 'self' does not cover inline code.
func injectBasePath(raw []byte, basePath, apiBasePath, version string) ([]byte, string) {
	bootstrap, err := json.Marshal(map[string]string{
		"base_path":     basePath,
		"api_base_path": apiBasePath,
		// The build that served this page. An update replaces the binary and
		// restarts it, so a page whose version no longer matches the running
		// one is the old interface: the frontend uses this to know it must be
		// reloaded, and the ETag below changes with it so a cached index.html
		// is not what comes back.
		"version": version,
	})
	if err != nil {
		// The input is two strings from our own config; this cannot fail, but
		// falling back to an empty object beats serving a broken page.
		bootstrap = []byte(`{}`)
	}

	// The hash must cover exactly the bytes between the script tags, so build
	// the body once and use that same value for both the page and the hash.
	scriptBody := fmt.Sprintf("window.__GRE_PANEL__ = %s;", bootstrap)
	sum := sha256.Sum256([]byte(scriptBody))
	scriptHash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

	injected := fmt.Sprintf("\n    <base href=%q>\n    <script>%s</script>",
		basePath, scriptBody)

	// Insert immediately after <head ...>, so the base tag precedes every URL
	// it has to affect.
	lower := bytes.ToLower(raw)
	if idx := bytes.Index(lower, []byte("<head")); idx >= 0 {
		if end := bytes.IndexByte(lower[idx:], '>'); end >= 0 {
			at := idx + end + 1
			out := make([]byte, 0, len(raw)+len(injected))
			out = append(out, raw[:at]...)
			out = append(out, injected...)
			out = append(out, raw[at:]...)
			return out, scriptHash
		}
	}
	return append([]byte(injected), raw...), scriptHash
}

// ServeHTTP serves an embedded asset, falling back to index.html so client-side
// routes resolve (§20).
func (h *StaticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
			"That method is not allowed here.", "", nil)
		return
	}

	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" || name == "." {
		h.serveIndex(w, r)
		return
	}
	// path.Clean has already resolved any traversal, but a name that still
	// escapes is rejected rather than reinterpreted.
	if name == ".." || strings.HasPrefix(name, "../") {
		h.serveIndex(w, r)
		return
	}

	f, err := h.files.Open(name)
	if err != nil {
		// Not a file we ship: this is a client-side route, so serve the app.
		h.serveIndex(w, r)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		h.serveIndex(w, r)
		return
	}
	if name == indexFile {
		h.serveIndex(w, r)
		return
	}

	ext := strings.ToLower(path.Ext(name))
	contentType := contentTypes[ext]
	if contentType == "" {
		contentType = mime.TypeByExtension(ext)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	if hashedAssetRe.MatchString(name) {
		// The name changes with the content, so this can never go stale.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	if seeker, ok := f.(io.ReadSeeker); ok {
		// A zero modtime keeps ServeContent from emitting a misleading
		// Last-Modified: embedded files have no meaningful timestamp.
		http.ServeContent(w, r, name, time.Time{}, seeker)
		return
	}
	if _, err := io.Copy(w, f); err != nil {
		// The client went away mid-transfer; nothing useful is left to do.
		return
	}
}

// serveIndex writes the rendered index.html. It is never cached, so changing
// the web path or deploying a new bundle takes effect on the next load.
func (h *StaticHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("ETag", h.indexETag)
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, h.indexETag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	http.ServeContent(w, r, indexFile, time.Time{}, bytes.NewReader(h.index))
}
