package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// ValidationError carries one message per rejected key. The API turns it into a
// 422 whose details map is exactly this map (§5.3).
type ValidationError struct {
	Errors map[string]string
}

func (e *ValidationError) Error() string {
	keys := make([]string, 0, len(e.Errors))
	for k := range e.Errors {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 1 {
		return fmt.Sprintf("%s: %s", keys[0], e.Errors[keys[0]])
	}
	return fmt.Sprintf("%d settings are invalid", len(keys))
}

// Store holds the effective value of every setting: the declared default,
// overridden by any row in AppSetting. Values are cached in memory and read
// under a read lock, so the hot paths never touch the database.
type Store struct {
	database *db.DB

	mu     sync.RWMutex
	values map[string]any

	listenerMu sync.Mutex
	listeners  []func(changed []string)
}

// New loads the store from the database. Settings with no stored row take their
// declared default, so a fresh installation is fully configured immediately.
func New(ctx context.Context, database *db.DB) (*Store, error) {
	s := &Store{database: database, values: map[string]any{}}
	if err := s.Reload(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload rebuilds the in-memory values from defaults plus stored overrides.
func (s *Store) Reload(ctx context.Context) error {
	values := make(map[string]any, len(definitions))
	for _, d := range definitions {
		values[d.Key] = d.Default
	}

	rows, err := s.database.Read.QueryContext(ctx, `SELECT SettingKey, ValueJson FROM AppSetting`)
	if err != nil {
		return fmt.Errorf("loading settings: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return fmt.Errorf("reading setting row: %w", err)
		}
		def, ok := Lookup(key)
		if !ok {
			// A key from a newer release, or one that has since been removed.
			// Ignoring it keeps a downgrade from failing to start; the row stays
			// so an upgrade picks it back up.
			continue
		}
		var decoded any
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			return fmt.Errorf("setting %s holds invalid JSON: %w", key, err)
		}
		v, err := def.Coerce(decoded)
		if err != nil {
			// A stored value that no longer satisfies its constraints must not
			// stop the panel from starting; fall back to the default.
			continue
		}
		values[key] = v
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading settings: %w", err)
	}

	s.mu.Lock()
	s.values = values
	s.mu.Unlock()
	return nil
}

// Subscribe registers a callback invoked with the changed keys after every
// successful update or reset. This is how the monitor and metrics supervisors
// reconfigure live workers without a process restart (§5.3).
func (s *Store) Subscribe(fn func(changed []string)) {
	if fn == nil {
		return
	}
	s.listenerMu.Lock()
	s.listeners = append(s.listeners, fn)
	s.listenerMu.Unlock()
}

func (s *Store) notify(changed []string) {
	if len(changed) == 0 {
		return
	}
	s.listenerMu.Lock()
	listeners := make([]func([]string), len(s.listeners))
	copy(listeners, s.listeners)
	s.listenerMu.Unlock()
	for _, fn := range listeners {
		fn(changed)
	}
}

// Get returns the effective value of a key.
func (s *Store) Get(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.values[key]
	return v, ok
}

// All returns every effective value, keyed by setting key.
func (s *Store) All() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]any, len(s.values))
	for k, v := range s.values {
		out[k] = v
	}
	return out
}

// SchemaEntry is one row of GET /settings/schema: the full metadata plus the
// current effective value, so the frontend needs a single request to render the
// settings screen.
type SchemaEntry struct {
	Definition
	Value any `json:"value"`
}

// Schema returns the metadata for every setting with its current value.
func (s *Store) Schema() []SchemaEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SchemaEntry, 0, len(definitions))
	for _, d := range definitions {
		out = append(out, SchemaEntry{Definition: d, Value: s.values[d.Key]})
	}
	return out
}

// Bool returns a boolean setting, or false if the key is not a boolean.
func (s *Store) Bool(key string) bool {
	v, _ := s.Get(key)
	b, _ := v.(bool)
	return b
}

// Int returns an integer setting. Missing or null yields 0; use IntPtr when the
// difference matters.
func (s *Store) Int(key string) int64 {
	v, _ := s.Get(key)
	i, _ := v.(int64)
	return i
}

// IntPtr returns an integer setting, or nil when it is null.
func (s *Store) IntPtr(key string) *int64 {
	v, ok := s.Get(key)
	if !ok || v == nil {
		return nil
	}
	i, ok := v.(int64)
	if !ok {
		return nil
	}
	return &i
}

// Float returns a float setting. Missing or null yields 0.
func (s *Store) Float(key string) float64 {
	v, _ := s.Get(key)
	f, _ := v.(float64)
	return f
}

// FloatPtr returns a float setting, or nil when it is null.
func (s *Store) FloatPtr(key string) *float64 {
	v, ok := s.Get(key)
	if !ok || v == nil {
		return nil
	}
	f, ok := v.(float64)
	if !ok {
		return nil
	}
	return &f
}

// String returns a string or enum setting.
func (s *Store) String(key string) string {
	v, _ := s.Get(key)
	str, _ := v.(string)
	return str
}

// StringSlice returns a JSON list setting as strings, skipping non-strings.
func (s *Store) StringSlice(key string) []string {
	v, _ := s.Get(key)
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if str, ok := item.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// StringMap returns a JSON object setting as string values, skipping non-strings.
func (s *Store) StringMap(key string) map[string]string {
	v, _ := s.Get(key)
	obj, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, item := range obj {
		if str, ok := item.(string); ok {
			out[k] = str
		}
	}
	return out
}

// Validate checks a batch of updates without applying them, returning one
// message per rejected key. Cross-key rules are checked against the values that
// would result, not against the values in force now.
func (s *Store) Validate(updates map[string]any) (map[string]any, *ValidationError) {
	errs := map[string]string{}
	coerced := make(map[string]any, len(updates))

	for key, raw := range updates {
		def, ok := Lookup(key)
		if !ok {
			errs[key] = "unknown setting"
			continue
		}
		v, err := def.Coerce(raw)
		if err != nil {
			errs[key] = err.Error()
			continue
		}
		coerced[key] = v
	}

	// Cross-key rules run against the merged result so that changing both sides
	// of a pair in one request is accepted.
	effective := s.All()
	for k, v := range coerced {
		effective[k] = v
	}
	for key, msg := range crossKeyErrors(effective) {
		if _, already := errs[key]; already {
			continue
		}
		// Only report a cross-key failure against a key the caller actually
		// touched; blaming an untouched key would be confusing.
		if _, touched := coerced[key]; touched {
			errs[key] = msg
		}
	}

	if len(errs) > 0 {
		return nil, &ValidationError{Errors: errs}
	}
	return coerced, nil
}

// crossKeyErrors holds the rules that involve more than one setting. Each
// message is attached to the key most likely to be the one the operator meant
// to change.
func crossKeyErrors(v map[string]any) map[string]string {
	errs := map[string]string{}
	num := func(key string) (float64, bool) {
		switch n := v[key].(type) {
		case int64:
			return float64(n), true
		case float64:
			return n, true
		}
		return 0, false
	}
	pair := func(lowKey, highKey, msg string) {
		lo, okLo := num(lowKey)
		hi, okHi := num(highKey)
		if okLo && okHi && lo > hi {
			errs[lowKey] = msg
			errs[highKey] = msg
		}
	}
	pair("monitor.degraded_loss_pct", "monitor.down_loss_pct",
		"the Degraded loss threshold must not exceed the Down loss threshold")
	pair("metrics.disk_warn_pct", "metrics.disk_critical_pct",
		"the disk warning threshold must not exceed the critical threshold")
	pair("diagnostics.mtu_probe_min", "diagnostics.mtu_probe_max",
		"the MTU probe lower bound must not exceed the upper bound")
	pair("diagnostics.manual_ping_count", "diagnostics.manual_ping_max_count",
		"the default ping count must not exceed the maximum ping count")
	return errs
}

// Update validates and applies a batch atomically: either every key is written
// or none is. It returns the keys that actually changed value.
func (s *Store) Update(ctx context.Context, updates map[string]any, userID *int64) ([]string, error) {
	coerced, verr := s.Validate(updates)
	if verr != nil {
		return nil, verr
	}

	now := model.NowUTC()
	tx, err := s.database.Write.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning settings transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	const stmt = `
		INSERT INTO AppSetting (SettingKey, ValueJson, UpdatedByUserID, UpdatedDate)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (SettingKey) DO UPDATE SET
			ValueJson       = excluded.ValueJson,
			UpdatedByUserID = excluded.UpdatedByUserID,
			UpdatedDate     = excluded.UpdatedDate`

	keys := make([]string, 0, len(coerced))
	for k := range coerced {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		encoded, err := json.Marshal(coerced[key])
		if err != nil {
			return nil, fmt.Errorf("encoding setting %s: %w", key, err)
		}
		if _, err := tx.ExecContext(ctx, stmt, key, string(encoded), userID, now); err != nil {
			return nil, fmt.Errorf("storing setting %s: %w", key, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing settings: %w", err)
	}

	changed := s.apply(coerced)
	s.notify(changed)
	return changed, nil
}

// Reset removes stored overrides so the affected settings fall back to their
// declared defaults. An empty key list resets every setting.
func (s *Store) Reset(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) == 0 {
		keys = Keys()
	}
	unknown := map[string]string{}
	for _, k := range keys {
		if _, ok := Lookup(k); !ok {
			unknown[k] = "unknown setting"
		}
	}
	if len(unknown) > 0 {
		return nil, &ValidationError{Errors: unknown}
	}

	tx, err := s.database.Write.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning settings transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for _, k := range keys {
		if _, err := tx.ExecContext(ctx, `DELETE FROM AppSetting WHERE SettingKey = ?`, k); err != nil {
			return nil, fmt.Errorf("resetting setting %s: %w", k, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing settings reset: %w", err)
	}

	defaults := make(map[string]any, len(keys))
	for _, k := range keys {
		def, _ := Lookup(k)
		defaults[k] = def.Default
	}
	changed := s.apply(defaults)
	s.notify(changed)
	return changed, nil
}

// apply writes the new values into the cache and reports which ones differ from
// what was there before.
func (s *Store) apply(values map[string]any) []string {
	changed := make([]string, 0, len(values))
	s.mu.Lock()
	for k, v := range values {
		if !sameValue(s.values[k], v) {
			changed = append(changed, k)
		}
		s.values[k] = v
	}
	s.mu.Unlock()
	sort.Strings(changed)
	return changed
}

// sameValue compares two setting values. JSON values are compared by their
// encoding, which is exact enough for change detection and avoids reflection.
func sameValue(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case int64:
		bv, ok := b.(int64)
		return ok && av == bv
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	}
	ea, errA := json.Marshal(a)
	eb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ea) == string(eb)
}
