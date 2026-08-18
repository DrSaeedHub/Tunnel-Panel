package api

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/settings"
)

// TestEverySettingIsReadBySomething is the guard for a whole class of defect:
// a setting that is stored, validated, described in confident prose on the
// Settings page, and read by nothing.
//
// Three were found this way. system.reconcile_interval_seconds named a cadence
// for a periodic reconcile that did not exist; system.auto_reapply_on_drift
// named a response to drift nothing was watching for; and
// tunnel.auto_mtu_from_underlay decided whether to measure the underlay, while
// the code measured it unconditionally. Each would pass any "change it, save
// it, reload it" check, because each really does persist. Persisting is not the
// property that matters.
//
// This is a coarse check — it asks whether the key appears anywhere outside its
// own definition — and coarse is the right shape here. It cannot prove a
// consumer uses a setting correctly, but it does prove one exists, and every
// one of the three defects above was the total absence of a reader.
func TestEverySettingIsReadBySomething(t *testing.T) {
	root := filepath.Join("..", "..")

	// Everything that could plausibly read a setting: the Go backend and the
	// TypeScript interface, minus the schema that declares them and the tests
	// that enumerate them.
	var sources []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "dist", "testdata", "Docs":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go", ".ts", ".tsx":
		default:
			return nil
		}
		name := filepath.Base(path)
		if strings.HasSuffix(name, "_test.go") || strings.Contains(name, ".test.") {
			return nil
		}
		// definition.go is where the keys are declared; finding a key there
		// proves only that it was declared.
		if filepath.ToSlash(path) == filepath.ToSlash(filepath.Join(root, "internal", "settings", "definition.go")) {
			return nil
		}
		sources = append(sources, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree failed: %v", err)
	}
	if len(sources) < 50 {
		t.Fatalf("only %d source files were scanned; the walk is not finding the tree", len(sources))
	}

	bodies := make([]string, 0, len(sources))
	for _, path := range sources {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		bodies = append(bodies, string(body))
	}

	var orphans []string
	for _, d := range settings.Definitions() {
		// Quoted, because that is how a consumer names a setting — settingBool("…")
		// in Go, settings['…'] in TypeScript. A bare substring search also matches
		// the key appearing in a comment, and a comment reads nothing: when this
		// check was first written it passed on a doc comment naming the very
		// setting whose reader had just been deleted.
		quoted := []string{`"` + d.Key + `"`, `'` + d.Key + `'`, "`" + d.Key + "`"}
		found := false
		for _, body := range bodies {
			for _, form := range quoted {
				if strings.Contains(body, form) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			orphans = append(orphans, d.Key)
		}
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d setting(s) are declared, stored and described, and read by nothing:\n  %s\n"+
			"A setting with no reader is not a setting. Either wire it to the behaviour it "+
			"describes, or remove it.", len(orphans), strings.Join(orphans, "\n  "))
	}
}
