package i18n

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// The functions whose first text argument is a catalog key, and where it is.
var keyArgument = map[string]int{"T": 1, "P": 0, "In": 1, "Errorf": 1, "N": 0}

// use is one place the source says a sentence.
type use struct {
	text     string
	position string
	// formatted reports that the sentence is given values to substitute, so its
	// placeholders are placeholders rather than text.
	formatted bool
	errorf    bool
}

// sourceUses reads every non-test Go file of the panel and returns each
// sentence it passes through this package, and every call it could not read a
// sentence from.
func sourceUses(t *testing.T) ([]use, []string) {
	t.Helper()
	root := filepath.Join("..", "..")
	var uses []use
	var unreadable []string
	for _, dir := range []string{"internal", filepath.Join("cmd", "gre-panel")} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			alias := importName(file)
			if alias == "" {
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != alias {
					return true
				}
				index, wanted := keyArgument[sel.Sel.Name]
				if !wanted {
					return true
				}
				where := fset.Position(call.Pos()).String()
				if len(call.Args) <= index {
					unreadable = append(unreadable, where+": no sentence")
					return true
				}
				text, ok := literal(call.Args[index])
				if !ok {
					unreadable = append(unreadable, where+": "+sel.Sel.Name+
						" needs a string literal, so the sentence can be found and translated")
					return true
				}
				uses = append(uses, use{
					text: text, position: where,
					formatted: len(call.Args) > index+1 || call.Ellipsis.IsValid(),
					errorf:    sel.Sel.Name == "Errorf",
				})
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("reading the source failed: %v", err)
		}
	}
	return uses, unreadable
}

// importName is what a file calls this package, or "" when it does not import it.
func importName(file *ast.File) string {
	for _, spec := range file.Imports {
		if path, _ := strconv.Unquote(spec.Path.Value); path == "github.com/drs/gre-panel/internal/i18n" {
			if spec.Name != nil {
				return spec.Name.Name
			}
			return "i18n"
		}
	}
	return ""
}

// literal reads a string literal, or literals joined with +.
func literal(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return literal(e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, ok := literal(e.X)
		if !ok {
			return "", false
		}
		right, ok := literal(e.Y)
		return left + right, ok
	}
	return "", false
}

// verbs returns the conversion verbs of an English format, one per argument.
func verbs(format string) []string {
	var out []string
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		j := i + 1
		for j < len(format) && strings.ContainsRune("+-# 0123456789.[]*", rune(format[j])) {
			j++
		}
		if j >= len(format) {
			break
		}
		if format[j] == '%' && j == i+1 {
			i = j
			continue
		}
		out = append(out, format[i:j+1])
		i = j
	}
	return out
}

// sample is a distinct value of the kind a verb takes.
func sample(verb string, i int) any {
	switch verb[len(verb)-1] {
	case 'd', 'b', 'o', 'x', 'X', 'c', 'U':
		return 9000 + i
	case 'f', 'F', 'e', 'E', 'g', 'G':
		return float64(9000 + i)
	case 't':
		return true
	case 'w':
		return errors.New("err" + strconv.Itoa(i))
	}
	return "val" + strconv.Itoa(i)
}

func sprint(format string, args []any, errorf bool) string {
	if errorf {
		return fmt.Errorf(format, args...).Error()
	}
	return fmt.Sprintf(format, args...)
}

func hasPersian(text string) bool {
	for _, r := range text {
		if unicode.Is(unicode.Arabic, r) {
			return true
		}
	}
	return false
}

// TestEverySentenceHasPersian is the contract of this package: every sentence
// the source says through it has Persian, the Persian takes the same values the
// English does and drops none of them, and no Persian is left behind after
// its English changed.
func TestEverySentenceHasPersian(t *testing.T) {
	uses, unreadable := sourceUses(t)
	for _, problem := range unreadable {
		t.Error(problem)
	}

	said := map[string]bool{}
	var missing []string
	for _, u := range uses {
		said[u.text] = true
		persian, ok := farsi[u.text]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s: %q", u.position, u.text))
			continue
		}
		if !hasPersian(persian) {
			t.Errorf("%s: the Persian for %q is not Persian: %q", u.position, u.text, persian)
		}
		if !u.formatted {
			continue
		}
		english := verbs(u.text)
		args := make([]any, len(english))
		for i, verb := range english {
			args[i] = sample(verb, i)
		}
		if out := sprint(u.text, args, u.errorf); strings.Contains(out, "%!") {
			t.Errorf("%s: the English does not format: %s", u.position, out)
			continue
		}
		out := sprint(persian, args, u.errorf)
		if strings.Contains(out, "%!") {
			t.Errorf("%s: the Persian for %q does not take the same values: %s", u.position, u.text, out)
			continue
		}
		for i, verb := range english {
			value := sprint(strings.Replace(verb, "w", "v", 1), []any{args[i]}, false)
			if strings.HasPrefix(verb, "%[") {
				continue
			}
			if !strings.Contains(out, value) {
				t.Errorf("%s: the Persian for %q drops value %d (%s): %s", u.position, u.text, i+1, verb, out)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d sentence(s) have no Persian. Add them to a catalog file in internal/i18n:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	var stale []string
	for english := range farsi {
		if !said[english] {
			stale = append(stale, fmt.Sprintf("%q", english))
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("%d Persian sentence(s) are no longer said anywhere; the English changed or was "+
			"removed:\n  %s", len(stale), strings.Join(stale, "\n  "))
	}
}

func TestTheLanguageComesFromTheRequestThenThePanel(t *testing.T) {
	defer SetPanelLanguage(func() string { return "" })
	register(map[string]string{"test: %d rule(s) on %s": "آزمون: %[2]s با %[1]d قانون"})
	defer delete(farsi, "test: %d rule(s) on %s")

	ctx := context.Background()
	if got := T(ctx, "test: %d rule(s) on %s", 2, "eth0"); got != "test: 2 rule(s) on eth0" {
		t.Errorf("with no language anywhere the English is said: %q", got)
	}
	SetPanelLanguage(func() string { return "fa-IR" })
	want := "آزمون: \u2068eth0\u2069 با 2 قانون"
	if got := T(ctx, "test: %d rule(s) on %s", 2, "eth0"); got != want {
		t.Errorf("the panel's language decides when the request names none: %q, want %q", got, want)
	}
	if got := T(WithLanguage(ctx, "en"), "test: %d rule(s) on %s", 2, "eth0"); got != "test: 2 rule(s) on eth0" {
		t.Errorf("the request's own language wins over the panel's: %q", got)
	}
	if got := T(ctx, "no Persian for this sentence: %d%%", 5); got != "no Persian for this sentence: 5%" {
		t.Errorf("a sentence with no Persian is said in English: %q", got)
	}
	if got := T(ctx, "80% full"); got != "80% full" {
		t.Errorf("a sentence with no values keeps a bare percent sign: %q", got)
	}

	inner := errors.New("inner")
	register(map[string]string{"test: wrapping %w": "آزمون: %w"})
	defer delete(farsi, "test: wrapping %w")
	if err := Errorf(ctx, "test: wrapping %w", inner); !errors.Is(err, inner) {
		t.Errorf("a translated error still wraps: %v", err)
	}
}

// A quoted value keeps its isolates outside the quotes. Wrapping the text
// before formatting made %q escape them into visible "⁨" text.
func TestAQuotedValueIsIsolatedOutsideItsQuotes(t *testing.T) {
	defer SetPanelLanguage(func() string { return "" })
	SetPanelLanguage(func() string { return Farsi })
	register(map[string]string{"test: rule %q": "آزمون: قانون %q"})
	defer delete(farsi, "test: rule %q")

	got := T(context.Background(), "test: rule %q", "web")
	if want := "آزمون: قانون ⁨\"web\"⁩"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := T(context.Background(), "test: rule %q", "وب"); got != "آزمون: قانون \"وب\"" {
		t.Errorf("a value with nothing Latin in it needs no isolates: %q", got)
	}
}
