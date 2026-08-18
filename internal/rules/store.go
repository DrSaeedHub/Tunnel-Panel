package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/persist"
)

// DefaultDir is where rendered rulesets live. It sits inside the data
// directory rather than in /etc, because these files are generated output owned
// by the panel and never something an operator edits — and because
// /etc/iptables belongs to the distribution's firewall persistence package,
// whose whole-system snapshots this subsystem replaces and must never write
// to (§6.3.3).
const DefaultDir = "/var/lib/gre-panel/rules"

// Payload file names. The persistence unit restores from exactly these files,
// so they are named once here rather than repeated at every call site.
const (
	NftFileName       = "gre-panel.nft"
	IptablesFileName  = "gre-panel.rules"
	Ip6tablesFileName = "gre-panel.6rules"
)

// FileMode is the permission mask for a rendered ruleset. It carries no
// secrets, and it lives in a directory that is already 0700.
const FileMode os.FileMode = 0o644

// OwnershipMarker identifies a file this panel wrote. Its presence is what
// makes overwriting one safe; its absence means the file belongs to whatever
// created it, and the panel refuses. It is the same marker the unit renderer
// uses, so "is this ours" has one answer across the whole panel.
const OwnershipMarker = persist.OwnershipMarker

// writeOwned writes a rendered payload atomically, refusing to overwrite a file
// the panel does not own (§6.3.2).
//
// Unlike the unit files, there is no takeover path: a foreign file at one of
// these paths is not something to adopt, it is a sign that the path is wrong.
func writeOwned(ctx context.Context, path, text string) error {
	owned, err := persist.IsPanelOwned(path)
	if err != nil {
		return err
	}
	if !owned {
		return fmt.Errorf("%w: %s", ErrNotPanelOwned, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	// Write to a sibling and rename, so a crash mid-write cannot leave the
	// restore unit reading half a ruleset at the next boot.
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(text), FileMode); err != nil {
		return fmt.Errorf("writing %s: %w", temp, err)
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return fmt.Errorf("installing %s: %w", path, err)
	}
	audit.TraceFrom(ctx).Add(audit.Operation{Kind: audit.KindFile, Detail: "write " + path})
	return nil
}

// header renders the comment block every generated ruleset carries, including
// the ownership marker. commentPrefix is "#" for both backends today, and is a
// parameter so a future backend with a different comment syntax cannot silently
// write a file the ownership check no longer recognises.
func header(lines ...string) string {
	var b strings.Builder
	b.WriteString(OwnershipMarker)
	b.WriteString("\n")
	b.WriteString("#\n")
	for _, line := range lines {
		if line == "" {
			b.WriteString("#\n")
			continue
		}
		b.WriteString("# ")
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
