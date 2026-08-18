package api

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/diag"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/settings"
)

// The interface builds many of its labels by interpolating a value this backend
// produced into a translation key — `routes.protocol.${id}`,
// `audit.actions.${entry.action}`, `settings.enum.${key}.${option}` and around
// thirty others. i18next answers a key it does not have by echoing the key, or,
// where a defaultValue is supplied, by echoing the raw value. Neither errors,
// neither logs, and both look perfectly normal to every test that does not read
// the page. That is how a settings section came to be headed by the word
// "routes", and how six enum settings came to offer an operator the choices
// "gregorian" and "jalali" in a Farsi interface.
//
// A check on the frontend cannot close this: the set of values is decided here.
// So this walks the real backend constants — the lookup tables, the settings
// schema, the diagnostic verdicts — and asserts every value each of those keys
// can take has a translation in every locale. Adding a lookup row or an audit
// action without a label fails this test rather than reaching an operator as a
// raw identifier.

// localeFiles are the shipped translation bundles.
func localeFiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, locale := range []string{"en", "fa"} {
		path := filepath.Join("..", "..", "web", "_app", "src", "i18n", "locales", locale+".ts")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		// Line endings are the checkout's business: a Windows working tree holds
		// these with CRLF, and a search written for LF finds nothing there and
		// reports it as missing copy rather than as what it is.
		out[locale] = strings.ReplaceAll(string(body), "\r\n", "\n")
	}
	return out
}

// blockAt returns the body of a nested object, found by following the key path.
//
// It matches braces rather than indentation, and skips over anything inside a
// quoted string, because a translation may legitimately contain a brace — an
// interpolation placeholder is spelled {{count}}.
func blockAt(text string, path ...string) (string, bool) {
	current := text
	for _, name := range path {
		opening := regexp.MustCompile(`(?m)^[\t ]*` + regexp.QuoteMeta(name) + `:\s*\{`)
		where := opening.FindStringIndex(current)
		if where == nil {
			return "", false
		}
		body, ok := matchBrace(current[where[1]-1:])
		if !ok {
			return "", false
		}
		current = body
	}
	return current, true
}

// matchBrace returns what is between the leading '{' and the '}' closing it.
func matchBrace(text string) (string, bool) {
	depth := 0
	var quote rune
	escaped := false
	for i, r := range text {
		if escaped {
			// The character after a backslash is literal, whatever it is. Without
			// this an escaped quote closes the string it is inside, and every
			// brace after it is counted from the wrong state.
			escaped = false
			continue
		}
		switch {
		case quote != 0:
			switch r {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}
		case r == '\'' || r == '"' || r == '`':
			quote = r
		case r == '{':
			depth++
		case r == '}':
			depth--
			if depth == 0 {
				return text[1:i], true
			}
		}
	}
	return "", false
}

// hasLeaf reports whether an object body defines a non-empty string for a key.
//
// The three quote styles are tried separately because Go's regexp has no
// backreference to say "closed by the same quote it opened with". A key may
// also be a bare number — the forwarding lookups are keyed by identifier — so
// the name is matched with and without quotes around it.
func hasLeaf(block, name string) bool {
	// Not anchored to the start of a line: a short object is written on one
	// line here — `persistence: { Systemd: '…', Networkd: '…' }` — and anchoring
	// reported every entry but the first as missing. The boundary is instead the
	// start of the block or a separator, so `low` does not match inside
	// `yellow`.
	for _, key := range []string{regexp.QuoteMeta(name), `'` + regexp.QuoteMeta(name) + `'`,
		`"` + regexp.QuoteMeta(name) + `"`} {
		for _, quote := range []struct{ open, class string }{
			{`'`, `[^']`}, {`"`, `[^"]`}, {"`", "[^`]"},
		} {
			leaf := regexp.MustCompile(`(?:^|[{,\s])` + key + `\s*:\s*` + quote.open +
				`(` + quote.class + `*)`)
			if match := leaf.FindStringSubmatch(block); match != nil &&
				strings.TrimSpace(match[1]) != "" {
				return true
			}
		}
	}
	return false
}

// expectation is one translation key path the interface builds at runtime, and
// every value the backend can put in its final segment.
type expectation struct {
	// path is the fixed prefix, e.g. {"routes","protocol"}.
	path []string
	// values are the interpolated leaves, e.g. the lookup identifiers.
	values []string
	// why names the call site, so a failure says where the raw text appears.
	why string
	// open marks a block whose leaves are not fully determined by the backend,
	// so an entry the backend cannot produce is not reported as dead. Every
	// other block is closed: the backend decides the whole set, and a key
	// outside it is copy written against a value that does not exist.
	open bool
}

// leafKeys returns the keys defined directly in an object body, ignoring
// anything nested inside a child object.
func leafKeys(block string) []string {
	var out []string
	depth := 0
	var quote rune
	escaped := false
	start := 0
	for i, r := range block {
		if escaped {
			escaped = false
			continue
		}
		if quote != 0 {
			switch r {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"', '`':
			quote = r
		case '{':
			depth++
		case '}':
			depth--
		case ',', '\n':
			if depth == 0 {
				start = i + 1
			}
		case ':':
			if depth == 0 {
				name := strings.Trim(strings.TrimSpace(block[start:i]), `'"`)
				if name != "" && !strings.ContainsAny(name, " \t/*") {
					out = append(out, name)
				}
				start = i + 1
			}
		}
	}
	return out
}

// titlesOf returns the Title of every row of a lookup table, which is what the
// interface interpolates for the state-shaped keys.
func titlesOf(t *testing.T, table string) []string {
	t.Helper()
	declared, ok := model.LookupTableByName(table)
	if !ok {
		t.Fatalf("the lookup table %q does not exist", table)
	}
	var out []string
	for _, value := range declared.Values {
		out = append(out, value.Title)
	}
	return out
}

// idsOf returns the identifier of every row, which is what the interface
// interpolates for the routes.* keys — those render from the numeric id.
func idsOf(t *testing.T, table string) []string {
	t.Helper()
	declared, ok := model.LookupTableByName(table)
	if !ok {
		t.Fatalf("the lookup table %q does not exist", table)
	}
	var out []string
	for _, value := range declared.Values {
		out = append(out, fmt.Sprint(value.ID))
	}
	return out
}

func TestEveryBackendValueTheInterfaceRendersHasATranslation(t *testing.T) {
	files := localeFiles(t)

	var expectations []expectation

	// The settings schema: categories, and the choices of every enum setting.
	categories := map[string]bool{}
	var enumKeys []string
	for _, d := range settings.Definitions() {
		categories[d.Category] = true
		if d.Type == settings.KindEnum {
			enumKeys = append(enumKeys, d.Key)
			expectations = append(expectations, expectation{
				// The setting key itself contains dots, and i18next treats a dot
				// as a level, so the block nests by segment.
				path:   append([]string{"settings", "enum"}, strings.Split(d.Key, ".")...),
				values: append([]string(nil), d.Constraints.EnumValues...),
				why:    "the choices of the " + d.Key + " setting",
			})
		}
	}
	var categoryList []string
	for category := range categories {
		categoryList = append(categoryList, category)
	}
	sort.Strings(categoryList)
	expectations = append(expectations,
		expectation{path: []string{"settings", "category"}, values: categoryList,
			why: "the settings section titles"},
		expectation{path: []string{"settings", "categoryHelp"}, values: categoryList,
			why: "the settings section descriptions"},
	)

	// The lookup tables, in the two shapes the interface uses them: by title for
	// the state-like keys, and by identifier for the forwarding ones.
	expectations = append(expectations,
		expectation{path: []string{"monitor", "state"}, values: titlesOf(t, "MonitorState"),
			why: "the tunnel status pill"},
		expectation{path: []string{"monitor", "stateExplain"}, values: titlesOf(t, "MonitorState"),
			why: "the status pill's tooltip"},
		expectation{path: []string{"apply", "status"}, values: titlesOf(t, "ApplyStatus"),
			why: "the apply status badge"},
		expectation{path: []string{"reconcile", "status"}, values: titlesOf(t, "ReconcileStatus"),
			why: "the needs-attention card"},
		expectation{path: []string{"tunnel", "persistence"}, values: titlesOf(t, "PersistenceType"),
			why: "the tunnel row detail"},
		expectation{path: []string{"audit", "actions"}, values: titlesOf(t, "AuditAction"),
			why: "the audit history"},
		expectation{path: []string{"routes", "protocol"}, values: idsOf(t, "RouteProtocol"),
			why: "the forwarding rule protocol"},
		expectation{path: []string{"routes", "natMode"}, values: idsOf(t, "NatMode"),
			why: "the forwarding rule NAT mode"},
		expectation{path: []string{"routes", "loadBalance"}, values: idsOf(t, "LoadBalanceMode"),
			why: "the load balancing mode"},
	)

	// The diagnostic verdicts, which are stable strings rather than lookup rows.
	expectations = append(expectations,
		expectation{path: []string{"diagnostics", "analyze", "verdicts"}, values: []string{
			diag.VerdictInterfaceMissing, diag.VerdictInterfaceDown, diag.VerdictUnderlayUnreachable,
			diag.VerdictNoReturnTraffic, diag.VerdictKeyOrAddressing, diag.VerdictMtuProblem,
			diag.VerdictLocalFirewall, diag.VerdictHealthy,
		}, why: "the tunnel analyze verdict"},
		expectation{path: []string{"diagnostics", "analyze", "confidenceLevel"},
			values: []string{diag.ConfidenceHigh, diag.ConfidenceLow},
			why:    "the analyze confidence badge"},
		expectation{path: []string{"routeDiag", "verdict"}, values: []string{
			route.VerdictRuleMissing, route.VerdictForwardingDisabled, route.VerdictNoInboundTraffic,
			route.VerdictForwardBlocked, route.VerdictDestinationUnreachable, route.VerdictMtuProblem,
			route.VerdictRuleShadowed, route.VerdictTunnelDown, route.VerdictDisabled,
			route.VerdictHealthy,
		}, why: "the forwarding rule analyze verdict"},
	)

	var missing, dead []string
	for _, want := range expectations {
		expected := map[string]bool{}
		for _, value := range want.values {
			expected[value] = true
		}
		for locale, text := range files {
			block, ok := blockAt(text, want.path...)
			if !ok {
				missing = append(missing, fmt.Sprintf("%s: no %s block at all (%s)",
					locale, strings.Join(want.path, "."), want.why))
				continue
			}
			for _, value := range want.values {
				if !hasLeaf(block, value) {
					missing = append(missing, fmt.Sprintf("%s: %s.%s is untranslated, so %s renders the raw value",
						locale, strings.Join(want.path, "."), value, want.why))
				}
			}
			if want.open {
				continue
			}
			for _, key := range leafKeys(block) {
				if !expected[key] {
					dead = append(dead, fmt.Sprintf("%s: %s.%s is copy for a value %s never produces",
						locale, strings.Join(want.path, "."), key, want.why))
				}
			}
		}
	}
	sort.Strings(missing)
	sort.Strings(dead)
	if len(missing) > 0 {
		t.Errorf("the interface would render %d backend value(s) as raw text:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	// Dead copy is the same mistake seen from the other side: it means the
	// wording was written against a guess at what the backend emits rather than
	// against what it emits, and the guess is not checkable by reading either
	// side alone.
	if len(dead) > 0 {
		t.Errorf("%d translation(s) describe a value that cannot occur:\n  %s",
			len(dead), strings.Join(dead, "\n  "))
	}

	// A guard on the guard: if the schema ever stops declaring enum settings, or
	// the lookup tables come back empty, every loop above passes vacuously.
	if len(enumKeys) < 6 {
		t.Errorf("only %d enum settings were checked; the schema declares six", len(enumKeys))
	}
	if len(categoryList) < 10 {
		t.Errorf("only %d settings categories were checked", len(categoryList))
	}
}

// Dead copy in the settings block.
//
// The reverse check already exists for the diagnostic verdicts, where it found
// seven labels for verdicts the analyser cannot emit. The same question asked
// of the settings block finds the opposite shape of the same problem: copy
// written for a control that was never built. settings.resetAll is a label for
// a "Reset all settings" button that does not exist, and settings.unsavedTitle,
// unsavedBody, leave and stay are a whole unsaved-changes dialog that nothing
// ever opens.
//
// Only the direct string children of settings: are checked. The nested blocks —
// category, categoryHelp, enum and the rest — are reached through keys built at
// runtime from backend values, so a reference to them cannot be found by
// searching for the literal key, and the forward direction of this file already
// covers them.
func TestNoDeadCopyInTheSettingsBlock(t *testing.T) {
	locales := localeFiles(t)
	block, ok := blockAt(locales["en"], "settings")
	if !ok {
		t.Fatal("no settings block in en.ts")
	}

	sources := webSourceFiles(t)
	bodies := make(map[string]string, len(sources))
	for _, path := range sources {
		// The locale files themselves are where the copy is defined, so they
		// are not evidence that anything uses it.
		if strings.Contains(filepath.ToSlash(path), "/i18n/locales/") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		bodies[path] = string(body)
	}

	var dead []string
	for _, key := range directStringKeys(block) {
		// i18next picks a plural form itself: code asks for settings.dirty with
		// a count and i18next resolves settings.dirty_other. The suffixed key is
		// never named in source, and is in use whenever its base is.
		needle := "settings." + pluralBase(key)
		used := false
		for _, body := range bodies {
			if strings.Contains(body, needle) {
				used = true
				break
			}
		}
		if !used {
			dead = append(dead, needle)
		}
	}
	sort.Strings(dead)

	for _, key := range dead {
		t.Errorf("%s is translated in every locale and referenced by nothing.\n"+
			"Either the control it labels was never built, or it outlived one that was.", key)
	}
}

// directStringKeys returns the keys of a locale block whose values are plain
// strings, ignoring nested objects.
func directStringKeys(block string) []string {
	var out []string
	depth := 0
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		// Track nesting so only the top level of the block is considered.
		opens := strings.Count(trimmed, "{")
		closes := strings.Count(trimmed, "}")
		if depth == 0 {
			if key, isString := stringLeaf(trimmed); isString {
				out = append(out, key)
			}
		}
		depth += opens - closes
		if depth < 0 {
			depth = 0
		}
	}
	return out
}

// stringLeaf reports the key of a `name: 'value'` line, and whether it is one.
var leafLine = regexp.MustCompile(`^([A-Za-z_][\w]*):\s*['"\x60]`)

func stringLeaf(line string) (string, bool) {
	m := leafLine.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// pluralBase strips an i18next plural suffix, so settings.dirty_other is
// checked as settings.dirty. The suffixes are the CLDR categories i18next uses.
func pluralBase(key string) string {
	for _, suffix := range []string{"_zero", "_one", "_two", "_few", "_many", "_other"} {
		if strings.HasSuffix(key, suffix) {
			return strings.TrimSuffix(key, suffix)
		}
	}
	return key
}
