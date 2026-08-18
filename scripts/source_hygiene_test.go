package scripts

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Two ways a Windows toolchain quietly writes a file the Linux build and the
// golden comparisons do not expect, checked together because they have one
// cause.
//
// A carriage return makes every byte-for-byte golden comparison fail with a
// diff whose two halves look identical, and puts a \r on the shebang line of
// scripts/install.sh, which bash answers with "set: pipefail: invalid option
// name". A byte-order mark is subtler — esbuild and vitest usually tolerate a
// leading one — but it is still a byte nobody asked for at the front of a
// source file, and one file having it when no other does is the kind of
// difference that costs an hour when something downstream does not tolerate it.
//
// .gitattributes pins the line endings for every clone, which is the real fix
// for the first. It cannot strip a BOM, so this covers both, and it covers the
// generated bundle too: web/dist/index.html was committed with carriage returns
// for five rebuilds before anyone noticed.

// textExtensions are the files whose bytes are read by something that cares.
var textExtensions = map[string]bool{
	".go": true, ".ts": true, ".tsx": true, ".js": true, ".mjs": true, ".css": true,
	".html": true, ".json": true, ".sh": true, ".md": true, ".yml": true, ".yaml": true,
	".service": true, ".netdev": true, ".network": true, ".nft": true, ".rules": true,
	".6rules": true, ".conf": true,
}

// skipDirs are not ours to police.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "dist/release": true,
}

func sourceFiles(t *testing.T) []string {
	t.Helper()
	root := filepath.Join("..")
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !textExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		// The proc fixtures are mode-120000 symlinks whose "content" is a link
		// target, and on a checkout with core.symlinks=false they are short text
		// files. Neither is a source file with line endings to police.
		if strings.Contains(filepath.ToSlash(path), "internal/rules/testdata/proc/") {
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree failed: %v", err)
	}
	if len(out) < 100 {
		t.Fatalf("only %d files were scanned; the walk is not finding the tree", len(out))
	}
	return out
}

func TestNoSourceFileHasAByteOrderMark(t *testing.T) {
	var found []string
	for _, path := range sourceFiles(t) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}) {
			found = append(found, filepath.ToSlash(path))
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("%d file(s) begin with a UTF-8 byte-order mark:\n  %s\n"+
			"On Windows this comes from Out-File or a bare > redirect, which default to "+
			"UTF-8 with a BOM. Rewrite with UTF8Encoding($false).",
			len(found), strings.Join(found, "\n  "))
	}
}

func TestNoSourceFileHasCarriageReturns(t *testing.T) {
	var found []string
	for _, path := range sourceFiles(t) {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if n := bytes.Count(body, []byte{'\r'}); n > 0 {
			found = append(found, filepath.ToSlash(path))
		}
	}
	sort.Strings(found)
	if len(found) > 0 {
		t.Errorf("%d file(s) contain carriage returns:\n  %s\n"+
			"The renderers emit LF and the goldens are compared byte for byte, so CRLF here "+
			"fails every golden with a diff whose halves look identical. .gitattributes pins "+
			"this for new clones; an existing worktree needs re-checking-out.",
			len(found), strings.Join(found, "\n  "))
	}
}
