package sourcelist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
)

// ErrNotFound is returned for a list that does not exist or has been deleted.
var ErrNotFound = errors.New("sourcelist: no such list")

// ErrNameTaken is returned when a live list already answers to that name.
var ErrNameTaken = errors.New("sourcelist: that name is already used")

// ErrInUse is returned when a list cannot be deleted because rules point at it.
var ErrInUse = errors.New("sourcelist: forwarding rules are using this list")

// Record is a list with its entries, which is how it is always read: a list
// without its addresses answers no question anybody asks.
type Record struct {
	model.SourceList
	Entries []model.SourceListEntry `json:"entries"`
	// UsedBy counts the live forwarding rules pointing at this list, so the
	// interface can say what a deletion would affect before it is attempted.
	UsedBy int `json:"used_by"`
}

// Prefixes returns the list's ranges in one address family.
func (r Record) Prefixes(family string) []string {
	out := make([]string, 0, len(r.Entries))
	for _, entry := range r.Entries {
		if familyOf(entry.AddressFamilyID) != family {
			continue
		}
		out = append(out, entry.Cidr)
	}
	return out
}

// Repo is the database view of the source lists.
type Repo struct{ db *db.DB }

// NewRepo returns a repository over the given database.
func NewRepo(database *db.DB) *Repo { return &Repo{db: database} }

const listColumns = `
	SourceListID, Name, Description, Slug, IsBuiltIn, CreatedDate, UpdatedDate, IsDeleted`

const entryColumns = `
	SourceListEntryID, SourceListID, Cidr, AddressFamilyID, Description,
	CreatedDate, UpdatedDate, IsDeleted`

// List returns every live list with its entries, by name.
func (r *Repo) List(ctx context.Context) ([]Record, error) {
	rows, err := r.db.Read.QueryContext(ctx,
		`SELECT `+listColumns+` FROM SourceList WHERE IsDeleted = 0 ORDER BY Name COLLATE NOCASE`)
	if err != nil {
		return nil, fmt.Errorf("reading the source lists: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rec, err := scanList(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("reading a source list row: %w", err)
		}
		out = append(out, Record{SourceList: rec})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	entries, err := r.allEntries(ctx)
	if err != nil {
		return nil, err
	}
	usage, err := r.usage(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Entries = entries[out[i].SourceListID]
		out[i].UsedBy = usage[out[i].SourceListID]
	}
	return out, nil
}

// ByID returns one list with its entries.
func (r *Repo) ByID(ctx context.Context, id int64) (Record, error) {
	row := r.db.Read.QueryRowContext(ctx,
		`SELECT `+listColumns+` FROM SourceList WHERE SourceListID = ? AND IsDeleted = 0`, id)
	list, err := scanList(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	if err != nil {
		return Record{}, fmt.Errorf("reading source list %d: %w", id, err)
	}

	entries, err := r.entriesFor(ctx, id)
	if err != nil {
		return Record{}, err
	}
	usage, err := r.usage(ctx)
	if err != nil {
		return Record{}, err
	}
	return Record{SourceList: list, Entries: entries, UsedBy: usage[id]}, nil
}

// Entries returns the ranges of several lists at once, keyed by list.
//
// It is the read the ruleset build makes, so it is one query rather than one
// per list: a rule may allow several lists, and a host may have many rules.
func (r *Repo) Entries(ctx context.Context, ids []int64) (map[int64][]model.SourceListEntry, error) {
	if len(ids) == 0 {
		return map[int64][]model.SourceListEntry{}, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+entryColumns+`
		FROM SourceListEntry WHERE IsDeleted = 0 AND SourceListID IN (`+
		strings.Join(placeholders, ", ")+`) ORDER BY SourceListID, SourceListEntryID`, args...)
	if err != nil {
		return nil, fmt.Errorf("reading source list entries: %w", err)
	}
	defer rows.Close()
	return groupEntries(rows)
}

func (r *Repo) entriesFor(ctx context.Context, id int64) ([]model.SourceListEntry, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+entryColumns+`
		FROM SourceListEntry WHERE SourceListID = ? AND IsDeleted = 0
		ORDER BY SourceListEntryID`, id)
	if err != nil {
		return nil, fmt.Errorf("reading the entries of source list %d: %w", id, err)
	}
	defer rows.Close()
	grouped, err := groupEntries(rows)
	if err != nil {
		return nil, err
	}
	return grouped[id], nil
}

func (r *Repo) allEntries(ctx context.Context) (map[int64][]model.SourceListEntry, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+entryColumns+`
		FROM SourceListEntry WHERE IsDeleted = 0 ORDER BY SourceListID, SourceListEntryID`)
	if err != nil {
		return nil, fmt.Errorf("reading source list entries: %w", err)
	}
	defer rows.Close()
	return groupEntries(rows)
}

// usage counts the live rules pointing at each list.
func (r *Repo) usage(ctx context.Context) (map[int64]int, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT l.SourceListID, COUNT(*)
		FROM RouteSourceList l
		JOIN RouteRule r ON r.RouteRuleID = l.RouteRuleID AND r.IsDeleted = 0
		WHERE l.IsDeleted = 0
		GROUP BY l.SourceListID`)
	if err != nil {
		return nil, fmt.Errorf("counting source list use: %w", err)
	}
	defer rows.Close()

	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		out[id] = count
	}
	return out, rows.Err()
}

// RuleIDs returns the live forwarding rules that allow a given list, which is
// what decides whose ruleset has to be rebuilt when the list changes.
func (r *Repo) RuleIDs(ctx context.Context, sourceListID int64) ([]int64, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT l.RouteRuleID FROM RouteSourceList l
		JOIN RouteRule r ON r.RouteRuleID = l.RouteRuleID AND r.IsDeleted = 0
		WHERE l.SourceListID = ? AND l.IsDeleted = 0`, sourceListID)
	if err != nil {
		return nil, fmt.Errorf("reading the rules using source list %d: %w", sourceListID, err)
	}
	defer rows.Close()

	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Input is a list as a request describes it.
type Input struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// Entries is the whole list, not an addition: saving replaces what was
	// there, the same way saving a forwarding rule replaces its destinations.
	Entries []string `json:"entries"`
}

// Create stores a new list and returns it.
func (r *Repo) Create(ctx context.Context, in Input) (Record, error) {
	if err := ValidateName(in.Name); err != nil {
		return Record{}, err
	}
	prefixes, _ := ParseEntries(strings.Join(in.Entries, "\n"))
	if len(prefixes) > MaxEntries {
		return Record{}, fmt.Errorf("a source list may hold at most %d ranges", MaxEntries)
	}

	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, fmt.Errorf("beginning the source list transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	name := strings.TrimSpace(in.Name)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO SourceList (Name, Description, Slug, IsBuiltIn, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, '', 0, ?, ?, 0)`, name, strings.TrimSpace(in.Description), now, now)
	if err != nil {
		return Record{}, storeError(err, name)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Record{}, fmt.Errorf("reading the new source list identifier: %w", err)
	}
	// The slug carries the identifier, so it can only be written once there is
	// one. It is never rewritten afterwards.
	if _, err := tx.ExecContext(ctx,
		`UPDATE SourceList SET Slug = ? WHERE SourceListID = ?`, Slugify(id, name), id); err != nil {
		return Record{}, fmt.Errorf("naming the source list's set: %w", err)
	}
	if err := replaceEntries(ctx, tx, id, prefixes, now); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("committing the source list: %w", err)
	}
	return r.ByID(ctx, id)
}

// Update replaces a list's name, note and entries.
func (r *Repo) Update(ctx context.Context, id int64, in Input) (Record, error) {
	if err := ValidateName(in.Name); err != nil {
		return Record{}, err
	}
	prefixes, _ := ParseEntries(strings.Join(in.Entries, "\n"))
	if len(prefixes) > MaxEntries {
		return Record{}, fmt.Errorf("a source list may hold at most %d ranges", MaxEntries)
	}

	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, fmt.Errorf("beginning the source list transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	name := strings.TrimSpace(in.Name)
	// The slug is deliberately not touched: renaming a list must not rename the
	// kernel set that installed rules are already pointing at.
	res, err := tx.ExecContext(ctx, `
		UPDATE SourceList SET Name = ?, Description = ?, UpdatedDate = ?
		WHERE SourceListID = ? AND IsDeleted = 0`,
		name, strings.TrimSpace(in.Description), now, id)
	if err != nil {
		return Record{}, storeError(err, name)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return Record{}, fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	if err := replaceEntries(ctx, tx, id, prefixes, now); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("committing source list %d: %w", id, err)
	}
	return r.ByID(ctx, id)
}

// Delete removes a list that nothing is using. A list a rule allows is refused
// rather than removed, because taking it away would silently widen that rule
// to every source on the internet.
func (r *Repo) Delete(ctx context.Context, id int64) error {
	users, err := r.RuleIDs(ctx, id)
	if err != nil {
		return err
	}
	if len(users) > 0 {
		return fmt.Errorf("%w: %d rule(s) allow it", ErrInUse, len(users))
	}

	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the source list transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	res, err := tx.ExecContext(ctx,
		`UPDATE SourceList SET IsDeleted = 1, UpdatedDate = ? WHERE SourceListID = ? AND IsDeleted = 0`,
		now, id)
	if err != nil {
		return fmt.Errorf("removing source list %d: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE SourceListEntry SET IsDeleted = 1, UpdatedDate = ? WHERE SourceListID = ? AND IsDeleted = 0`,
		now, id); err != nil {
		return fmt.Errorf("removing the entries of source list %d: %w", id, err)
	}
	return tx.Commit()
}

// replaceEntries rewrites a list's ranges. They are replaced rather than
// diffed for the same reason a rule's destinations are: they are read and
// written as a unit, and a diff here would be code that exists to save writes
// nobody is counting.
func replaceEntries(ctx context.Context, tx *sql.Tx, id int64,
	prefixes []netip.Prefix, now string) error {

	if _, err := tx.ExecContext(ctx,
		`UPDATE SourceListEntry SET IsDeleted = 1, UpdatedDate = ? WHERE SourceListID = ? AND IsDeleted = 0`,
		now, id); err != nil {
		return fmt.Errorf("replacing the entries of source list %d: %w", id, err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO SourceListEntry
			(SourceListID, Cidr, AddressFamilyID, Description, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, '', ?, ?, 0)`)
	if err != nil {
		return fmt.Errorf("preparing the source list entry insert: %w", err)
	}
	defer stmt.Close()

	for _, prefix := range prefixes {
		family := model.AddressFamilyIPv4
		if prefix.Addr().Is6() {
			family = model.AddressFamilyIPv6
		}
		if _, err := stmt.ExecContext(ctx, id, prefix.String(), family, now, now); err != nil {
			return fmt.Errorf("storing %s in source list %d: %w", prefix, id, err)
		}
	}
	return nil
}

func scanList(scan func(...any) error) (model.SourceList, error) {
	var list model.SourceList
	var isBuiltIn, isDeleted int64
	err := scan(&list.SourceListID, &list.Name, &list.Description, &list.Slug,
		&isBuiltIn, &list.CreatedDate, &list.UpdatedDate, &isDeleted)
	if err != nil {
		return list, err
	}
	list.IsBuiltIn = isBuiltIn != 0
	list.IsDeleted = isDeleted != 0
	return list, nil
}

func groupEntries(rows *sql.Rows) (map[int64][]model.SourceListEntry, error) {
	out := map[int64][]model.SourceListEntry{}
	for rows.Next() {
		var entry model.SourceListEntry
		var isDeleted int64
		if err := rows.Scan(&entry.SourceListEntryID, &entry.SourceListID, &entry.Cidr,
			&entry.AddressFamilyID, &entry.Description,
			&entry.CreatedDate, &entry.UpdatedDate, &isDeleted); err != nil {
			return nil, fmt.Errorf("reading a source list entry: %w", err)
		}
		entry.IsDeleted = isDeleted != 0
		out[entry.SourceListID] = append(out[entry.SourceListID], entry)
	}
	return out, rows.Err()
}

// storeError turns the unique-index violation into the one thing an operator
// can act on, rather than a constraint name.
func storeError(err error, name string) error {
	if strings.Contains(strings.ToLower(err.Error()), "unique") {
		return fmt.Errorf("%w: %q", ErrNameTaken, name)
	}
	return fmt.Errorf("storing the source list: %w", err)
}

func familyOf(id int64) string {
	if id == model.AddressFamilyIPv6 {
		return rules.FamilyIPv6
	}
	return rules.FamilyIPv4
}

// SortedIDs returns identifiers in a stable order, so a rendered ruleset does
// not change because a map iterated differently.
func SortedIDs(ids map[int64]bool) []int64 {
	out := make([]int64, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
