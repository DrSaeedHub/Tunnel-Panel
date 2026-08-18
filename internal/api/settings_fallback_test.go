package api

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/settings"
)

// A page that reads a setting has to cope with not having it yet: the settings
// query is in flight on first paint, so `settingsQuery.data?.settings ?? {}` is
// genuinely empty for a frame or two and every read falls back. The dashboard
// colours its disk bars from metrics.disk_warn_pct and metrics.disk_critical_pct
// and fell back to 80 and 90 while the schema declared 85 and 95 — so a disk
// sitting at 82% painted itself amber on load and then corrected itself, and one
// at 96% stayed amber for that frame instead of going red.
//
// Nothing catches that. The fallback is only reached when the key is absent, so
// it is invisible to any test that supplies settings, and the two numbers live in
// different languages in different directories. This asserts the frontend's
// fallback for a settings key is the same number this package declares as that
// key's default, which is the only thing the fallback can honestly mean.

// The pages read a setting with a fallback through several small helpers, and
// the guard has to know all of them: numberSetting(settings, 'key', 1) on the
// dashboard, and number('key', 1) / text('key', 'x') / boolean('key', false) /
// setting('key', 1) in the create dialogs and the diagnostics panel. Matching
// only the first shape left the twelve busiest call sites unguarded.
var settingFallbackCalls = []*regexp.Regexp{
	// numberSetting(settings, 'some.key', 123)
	regexp.MustCompile(`numberSetting\(\s*[A-Za-z_$][\w$]*\s*,\s*['"]([^'"]+)['"]\s*,\s*([^,()]+?)\s*\)`),
	// number('some.key', 123) / text('some.key', 'x') / boolean('some.key', false)
	// / setting('some.key', 56)
	regexp.MustCompile(`\b(?:number|text|boolean|setting)\(\s*['"]([^'"]+)['"]\s*,\s*([^,()]+?)\s*\)`),
}

// settingKeyShape is what every key in the schema looks like. A first argument
// of this shape is being treated as a settings key, so it has to be one.
var settingKeyShape = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

// The forms spell their id fallbacks as named constants — NatMode.Masquerade
// rather than 10 — which is the right way round for anyone reading them. The
// guard resolves those names so it compares values rather than spellings, and
// so a constant pointing at the wrong id fails here too.
var (
	lookupTableDecl  = regexp.MustCompile(`export const (\w+) = \{([^}]*)\} as const`)
	lookupMemberDecl = regexp.MustCompile(`(\w+)\s*:\s*(-?\d+)`)
	// An identifier has to start with a letter or underscore. Allowing \w at
	// the front made this match the number 0.1, which was then looked up as a
	// constant, not found, and reported as a mismatch against itself.
	qualifiedName = regexp.MustCompile(`^[A-Za-z_]\w*\.[A-Za-z_]\w*$`)
)

// frontendConstants maps "NatMode.Masquerade" to 10, from the shared types the
// forms import.
func frontendConstants(t *testing.T) map[string]float64 {
	t.Helper()
	path := filepath.Join("..", "..", "web", "_app", "src", "lib", "types.ts")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	out := map[string]float64{}
	for _, table := range lookupTableDecl.FindAllStringSubmatch(string(body), -1) {
		for _, member := range lookupMemberDecl.FindAllStringSubmatch(table[2], -1) {
			value, err := strconv.ParseFloat(member[2], 64)
			if err != nil {
				continue
			}
			out[table[1]+"."+member[1]] = value
		}
	}
	if len(out) == 0 {
		t.Fatalf("no lookup constants were found in %s; the guard would silently stop resolving them", path)
	}
	return out
}

// webSourceFiles returns every TypeScript source file in the frontend.
func webSourceFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..", "..", "web", "_app", "src")
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatalf("no frontend sources under %s; this test would pass vacuously", root)
	}
	return out
}

func TestFrontendSettingFallbacksMatchTheDeclaredDefaults(t *testing.T) {
	defaults := map[string]any{}
	for _, def := range settings.Definitions() {
		defaults[def.Key] = def.Default
	}

	constants := frontendConstants(t)

	checked := 0
	for _, path := range webSourceFiles(t) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		for _, pattern := range settingFallbackCalls {
			for _, m := range pattern.FindAllStringSubmatch(string(body), -1) {
				key, literal := m[1], strings.TrimSpace(m[2])
				if !settingKeyShape.MatchString(key) {
					// Not a settings key at all — one of these helper names is
					// generic enough to be used for other things.
					continue
				}
				checked++

				declared, ok := defaults[key]
				if !ok {
					t.Errorf("%s falls back for %q, which has the shape of a settings key but is not one",
						filepath.Base(path), key)
					continue
				}
				if !sameLiteral(literal, declared, constants) {
					t.Errorf("%s falls back to [%s] for %q, but the declared default is [%v] (%T).\n"+
						"On first paint the settings query has not answered yet, so the fallback "+
						"is what an operator actually sees.",
						filepath.Base(path), literal, key, declared, declared)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no numberSetting(...) call sites were found; the pattern this guards has moved")
	}
	t.Logf("checked %d settings fallback(s) against the declared defaults", checked)
}

// sameLiteral reports whether a TypeScript literal is the same value as a
// declared default. The comparison is by kind: a numeric default has to be
// matched by a number, a string default by the same string whichever quotes
// the frontend used, and a boolean by the same boolean.
func sameLiteral(literal string, declared any, constants map[string]float64) bool {
	// A named constant stands for its value, so resolve it before comparing.
	if qualifiedName.MatchString(literal) {
		value, ok := constants[literal]
		if !ok {
			return false
		}
		literal = strconv.FormatFloat(value, 'f', -1, 64)
	}
	switch want := declared.(type) {
	case bool:
		return literal == strconv.FormatBool(want)
	case string:
		unquoted := strings.Trim(literal, `'"`)
		// Only a quoted literal can equal a string default; a bare identifier
		// is a constant this test cannot resolve, and guessing would be worse
		// than saying so.
		if unquoted == literal {
			return false
		}
		return unquoted == want
	default:
		got, err := strconv.ParseFloat(literal, 64)
		if err != nil {
			return false
		}
		n, err := numeric(declared)
		if err != nil {
			return false
		}
		return got == n
	}
}

// numeric reduces a declared default to a float, or reports that it is not a
// number at all.
func numeric(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	default:
		return 0, fmt.Errorf("%T is not numeric", v)
	}
}
