package sourcelist

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/drs/gre-panel/internal/i18n"
)

//go:embed seed/*.txt
var seedFiles embed.FS

// builtIn is a list the panel ships with.
//
// The two operator ranges are here because they are the lists this panel is
// actually used with, and typing seven hundred ranges into a text box to get
// started is not a first run anybody should have. The private ranges are here
// because every allowlist wants them and they never change.
//
// The name and description are stored in English and marked for translation:
// a built-in list whose text is still this text is shown in the operator's
// language where lists are served, and one an operator has edited is shown
// as they wrote it.
type builtIn struct {
	name        string
	description string
	file        string
	inline      []string
}

var builtIns = []builtIn{
	{
		name:        i18n.N("Private IPs"),
		description: i18n.N("The ranges RFC 1918 and RFC 4193 reserve for private networks, plus loopback and link-local. Never routed on the internet, so allowing them only ever admits traffic from this machine or the networks it is on."),
		inline: []string{
			"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
			"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
			"::1/128", "fc00::/7", "fe80::/10",
		},
	},
	{
		name:        i18n.N("MCI"),
		description: i18n.N("Hamrah-e Aval (MCI), the Iranian mobile operator. Shipped with the panel and updated with it; edit it here to add a range the release does not have yet."),
		file:        "seed/mci.txt",
	},
	{
		name:        i18n.N("MTN"),
		description: i18n.N("Irancell (MTN), the Iranian mobile operator. Shipped with the panel and updated with it; edit it here to add a range the release does not have yet."),
		file:        "seed/mtn.txt",
	},
}

// Seed stores the built-in lists that are not already there.
//
// It runs on every start and is idempotent in the way that matters: a list an
// operator deleted stays deleted, and one they edited keeps their edits. Only
// a name that no live row answers to is created. That is what makes shipping a
// list different from imposing one.
func Seed(ctx context.Context, repo *Repo, log *slog.Logger) error {
	if repo == nil {
		return nil
	}
	// Seeding happens at start-up, with nobody to read its errors but the log,
	// so they are said in English whatever the panel's language is.
	ctx = i18n.WithLanguage(ctx, i18n.English)
	existing, err := repo.List(ctx)
	if err != nil {
		return err
	}
	present := map[string]bool{}
	for _, rec := range existing {
		present[strings.ToLower(rec.Name)] = true
	}

	for _, list := range builtIns {
		if present[strings.ToLower(list.name)] {
			continue
		}
		entries, err := list.entries()
		if err != nil {
			return err
		}
		rec, err := repo.Create(ctx, Input{
			Name: list.name, Description: list.description, Entries: entries,
		})
		if err != nil {
			return fmt.Errorf("seeding the %s source list: %w", list.name, err)
		}
		if err := repo.markBuiltIn(ctx, rec.SourceListID); err != nil {
			return err
		}
		if log != nil {
			log.Info("a built-in source list was created",
				"name", list.name, "ranges", len(rec.Entries))
		}
	}
	return nil
}

func (b builtIn) entries() ([]string, error) {
	if b.file == "" {
		return b.inline, nil
	}
	body, err := seedFiles.ReadFile(b.file)
	if err != nil {
		return nil, fmt.Errorf("reading the embedded %s: %w", b.file, err)
	}
	return strings.Split(strings.TrimSpace(string(body)), "\n"), nil
}

// markBuiltIn records that a list came from the panel rather than from an
// operator. It is only ever set by seeding.
func (r *Repo) markBuiltIn(ctx context.Context, id int64) error {
	if _, err := r.db.Write.ExecContext(ctx,
		`UPDATE SourceList SET IsBuiltIn = 1 WHERE SourceListID = ?`, id); err != nil {
		return fmt.Errorf("marking source list %d as built in: %w", id, err)
	}
	return nil
}
