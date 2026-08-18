// Package webui carries the built frontend, embedded into the binary so the
// panel ships as a single static file with no runtime dependencies (§20).
//
// The React sources live in _app/ beside dist/. The underscore is load-bearing:
// the Go tool ignores directories whose names begin with one, which keeps
// node_modules out of `go build ./...`. Some npm packages ship Go files of
// their own, and without that the Go build would depend on what npm installed.
// Only the build output is embedded.
package webui

import "embed"

// Assets holds the frontend build output. The all: prefix includes files whose
// names begin with a dot or an underscore, which Vite emits for some plugins
// and which the default embed rules would silently drop.
//
//go:embed all:dist
var Assets embed.FS
