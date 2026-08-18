package api

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Iterating a list that arrived as null takes the whole page down. Three
// separate defects here were exactly that, and each was found by an operator
// or by driving the panel rather than by anything in a suite: "cpu": null blanked
// the dashboard's resource cards, "allowed_sources": null made every forwarding
// rule impossible to edit, and MtuResult left Steps nil so a path-MTU probe with
// nothing to report would have done the same.
//
// The server side is now handled at the response boundary. This is the other
// half, and it is what a suite can hold: no page should call .map, .filter,
// .length or .slice straight onto a field that an API type declares as a list,
// without a guard. The backend promises an array, but a browser holding an
// older bundle against a newer server -- the window an upgrade opens -- is
// exactly when these calls run.
//
// The list of field names comes from the TypeScript declarations themselves, so
// adding an array field to a response type extends this check automatically.

var (
	// `  addresses: TunnelAddress[]` and `  categories: string[]`.
	arrayFieldDecl = regexp.MustCompile(`(?m)^\s+([a-z_][A-Za-z0-9_]*)\??:\s*[A-Za-z0-9_<>| ]+\[\]`)
	// `.addresses.map(`, `.steps.length`, and the same through an optional chain.
	listUseTemplate = `\.%s\??\.(map|filter|length|slice|forEach|some|every|reduce|flatMap)\b`
)

// apiListFields returns every field name an API type declares as an array.
func apiListFields(t *testing.T) map[string]bool {
	t.Helper()
	path := filepath.Join("..", "..", "web", "_app", "src", "lib", "types.ts")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, m := range arrayFieldDecl.FindAllStringSubmatch(string(body), -1) {
		out[m[1]] = true
	}
	if len(out) < 20 {
		t.Fatalf("only %d array fields found in types.ts; the declaration shape has moved "+
			"and this check would pass vacuously", len(out))
	}
	return out
}

// Names that are lists in an API type but are also used for local state that is
// an array by construction. Each is here with a reason, so the next one is a
// decision rather than an oversight.
var localListNames = map[string]string{
	"destinations":    "DestinationsEditor takes the form's own array as a prop",
	"allowed_sources": "the form seeds this from the API and holds an array thereafter",
	"settings":        "the settings page keeps its own map of drafts",
	"categories":      "derived locally from the schema before rendering",
	"options":         "built inline for Select, never read from a response",
	"sides":           "SideSelector builds its own list from the lookup response",
	"columns":         "table definitions, declared in the component",
	"rows":            "table rows, built locally from whatever is being listed",
	"items":           "built locally by several components before rendering",
	"tabs":            "declared in the component",
	"values":          "built inline",
	"entries":         "built locally from Object.entries",
	"steps":           "the tunnel and route preview panels guard these; see below",
}

func TestNoPageIteratesAnApiListWithoutAGuard(t *testing.T) {
	fields := apiListFields(t)

	var offenders []string
	checked := 0
	for _, path := range webSourceFiles(t) {
		slashed := filepath.ToSlash(path)
		// Tests build their own fixtures, and the locale files hold no code.
		if strings.Contains(slashed, ".test.") || strings.Contains(slashed, "/i18n/locales/") ||
			strings.HasSuffix(slashed, "/lib/types.ts") {
			continue
		}
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(body)

		for field := range fields {
			if _, local := localListNames[field]; local {
				continue
			}
			pattern := regexp.MustCompile(regexp.QuoteMeta("") +
				strings.Replace(listUseTemplate, "%s", regexp.QuoteMeta(field), 1))
			for _, at := range pattern.FindAllStringIndex(text, -1) {
				checked++
				if guarded(text, at[0]) || localReceiver(text, at[0]) || isSpread(text, at[0]) {
					continue
				}
				offenders = append(offenders,
					filepath.Base(path)+": "+strings.TrimSpace(lineAround(text, at[0])))
			}
		}
	}
	sort.Strings(offenders)
	for _, offender := range offenders {
		t.Errorf("a list from an API response is iterated without a guard:\n    %s\n"+
			"    If the server ever sends null for it, this call takes the page down. "+
			"Write it as (x.field ?? []).map(...) or guard the list, not the element.", offender)
	}
	if checked == 0 {
		t.Fatal("no uses of any API list field were found at all; this check has stopped working")
	}
	t.Logf("checked %d use(s) of %d API list field(s)", checked, len(fields))
}

// guarded reports whether the use at this offset is defended, either by a
// `?? []` immediately before it or by an optional chain on the list itself.
func guarded(text string, at int) bool {
	// `(thing.field ?? []).map(` — the closing paren sits just before the dot.
	start := at - 64
	if start < 0 {
		start = 0
	}
	before := text[start:at]
	if strings.Contains(before, "?? []") || strings.Contains(before, "?? {}") {
		return true
	}
	// `thing.field?.map(` and `thing.field?.length` guard the list itself.
	return strings.HasPrefix(text[at:], ".") && strings.Contains(text[at:min(at+40, len(text))], "?.")
}

func lineAround(text string, at int) string {
	start := strings.LastIndexByte(text[:at], '\n') + 1
	end := strings.IndexByte(text[at:], '\n')
	if end < 0 {
		return text[start:]
	}
	return text[start : at+end]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// localReceiver reports whether the thing being iterated is the component's own
// state rather than a response. `form.addresses` is an array by construction —
// the form seeds it and holds it — so guarding it would imply a doubt that does
// not exist.
var localReceivers = map[string]bool{
	"form": true, "draft": true, "next": true, "current": true, "state": true,
}

func localReceiver(text string, at int) bool {
	start := at
	for start > 0 {
		c := text[start-1]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			start--
			continue
		}
		break
	}
	return localReceivers[text[start:at]]
}

// isSpread reports whether the dot this matched on belongs to a spread —
// `...interfaces.map(...)` reads as member access to a pattern that only looks
// at characters, but the receiver there is a local array, not a response field.
func isSpread(text string, at int) bool {
	return at >= 2 && text[at-2:at] == ".."
}
