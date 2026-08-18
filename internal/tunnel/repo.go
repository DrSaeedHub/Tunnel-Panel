package tunnel

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

// ErrNotFound is returned when no live tunnel or pool has that identifier.
var ErrNotFound = errors.New("tunnel: not found")

// Record is a tunnel row together with its addresses, which are always read and
// written as one unit because a tunnel without its addresses is not a usable
// description of anything.
type Record struct {
	model.Tunnel
	Addresses []model.TunnelAddress `json:"addresses"`
}

// tunnelColumns is the full column list, in the order rows are scanned. It is a
// single constant so the SELECT list and the scan can never drift apart.
const tunnelColumns = `
	TunnelID, TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName, DisplayName, TunnelNumber,
	LocalEndpoint, RemoteEndpoint, BindDevice,
	Ttl, Tos, Mtu, IKey, OKey,
	HasInputChecksum, HasOutputChecksum, HasInputSequence, HasOutputSequence,
	IsPathMtuDiscovery, IsIgnoreDf, FwMark, TxQueueLength,
	HopLimit, EncapLimit, TrafficClass, FlowLabel,
	AddressPoolID, IsEnabled, IsManaged, IsNameTemplated,
	ApplyStatusID, LastAppliedDate, LastApplyError, Note, TagsJson,
	MonitorIntervalSeconds, MonitorTimeoutSeconds, MonitorPacketSize, MonitorWindowSize,
	MonitorDegradedLossPercent, MonitorDownLossPercent, MonitorDegradedRttMs,
	MonitorStateChangeSamples, MonitorTarget, IsMonitorEnabled,
	CreatedDate, UpdatedDate, IsDeleted`

// Repo is the database view of tunnels, their addresses, and the address pools.
// It satisfies alloc.Repository directly and validate.Repository through
// ForValidation, which exists only because the two interfaces need the same
// method name to return different views of a pool.
type Repo struct {
	db *db.DB
}

// NewRepo returns a repository over the given database.
func NewRepo(database *db.DB) *Repo { return &Repo{db: database} }

// validationView adapts the repository to validate.Repository.
type validationView struct{ *Repo }

func (v validationView) PoolByID(ctx context.Context, id int64) (validate.Pool, error) {
	return v.Repo.ValidatePoolByID(ctx, id)
}

// ForValidation returns the repository as validation sees it.
func (r *Repo) ForValidation() validate.Repository { return validationView{r} }

// ---------------------------------------------------------------- reading

func scanTunnel(scan func(...any) error) (model.Tunnel, error) {
	var t model.Tunnel
	var (
		tunnelNumber, ikey, okey, fwMark, txQueueLength     sql.NullInt64
		hopLimit, encapLimit, addressPoolID                 sql.NullInt64
		displayName, bindDevice, trafficClass, flowLabel    sql.NullString
		lastAppliedDate, lastApplyError, note, tagsJson     sql.NullString
		monitorTarget                                       sql.NullString
		monitorInterval, monitorTimeout, monitorDegradedRtt sql.NullFloat64
		monitorDegradedLoss, monitorDownLoss                sql.NullFloat64
		monitorPacketSize, monitorWindowSize                sql.NullInt64
		monitorStateChangeSamples, isMonitorEnabled         sql.NullInt64

		hasInputChecksum, hasOutputChecksum   int64
		hasInputSequence, hasOutputSequence   int64
		isPathMtuDiscovery, isIgnoreDf        int64
		isEnabled, isManaged, isNameTemplated int64
		isDeleted                             int64
	)

	err := scan(
		&t.TunnelID, &t.TunnelTypeID, &t.TunnelSideID, &t.PersistenceTypeID, &t.InterfaceName, &displayName, &tunnelNumber,
		&t.LocalEndpoint, &t.RemoteEndpoint, &bindDevice,
		&t.Ttl, &t.Tos, &t.Mtu, &ikey, &okey,
		&hasInputChecksum, &hasOutputChecksum, &hasInputSequence, &hasOutputSequence,
		&isPathMtuDiscovery, &isIgnoreDf, &fwMark, &txQueueLength,
		&hopLimit, &encapLimit, &trafficClass, &flowLabel,
		&addressPoolID, &isEnabled, &isManaged, &isNameTemplated,
		&t.ApplyStatusID, &lastAppliedDate, &lastApplyError, &note, &tagsJson,
		&monitorInterval, &monitorTimeout, &monitorPacketSize, &monitorWindowSize,
		&monitorDegradedLoss, &monitorDownLoss, &monitorDegradedRtt,
		&monitorStateChangeSamples, &monitorTarget, &isMonitorEnabled,
		&t.CreatedDate, &t.UpdatedDate, &isDeleted,
	)
	if err != nil {
		return t, err
	}

	t.DisplayName = nullString(displayName)
	t.TunnelNumber = nullInt(tunnelNumber)
	t.BindDevice = nullString(bindDevice)
	t.IKey = nullInt(ikey)
	t.OKey = nullInt(okey)
	t.HasInputChecksum = hasInputChecksum != 0
	t.HasOutputChecksum = hasOutputChecksum != 0
	t.HasInputSequence = hasInputSequence != 0
	t.HasOutputSequence = hasOutputSequence != 0
	t.IsPathMtuDiscovery = isPathMtuDiscovery != 0
	t.IsIgnoreDf = isIgnoreDf != 0
	t.FwMark = nullInt(fwMark)
	t.TxQueueLength = nullInt(txQueueLength)
	t.HopLimit = nullInt(hopLimit)
	t.EncapLimit = nullInt(encapLimit)
	t.TrafficClass = nullString(trafficClass)
	t.FlowLabel = nullString(flowLabel)
	t.AddressPoolID = nullInt(addressPoolID)
	t.IsEnabled = isEnabled != 0
	t.IsManaged = isManaged != 0
	t.IsNameTemplated = isNameTemplated != 0
	t.LastAppliedDate = nullString(lastAppliedDate)
	t.LastApplyError = nullString(lastApplyError)
	t.Note = nullString(note)
	t.TagsJson = nullString(tagsJson)
	t.MonitorIntervalSeconds = nullFloat(monitorInterval)
	t.MonitorTimeoutSeconds = nullFloat(monitorTimeout)
	t.MonitorPacketSize = nullInt(monitorPacketSize)
	t.MonitorWindowSize = nullInt(monitorWindowSize)
	t.MonitorDegradedLossPercent = nullFloat(monitorDegradedLoss)
	t.MonitorDownLossPercent = nullFloat(monitorDownLoss)
	t.MonitorDegradedRttMs = nullFloat(monitorDegradedRtt)
	t.MonitorStateChangeSamples = nullInt(monitorStateChangeSamples)
	t.MonitorTarget = nullString(monitorTarget)
	if isMonitorEnabled.Valid {
		enabled := isMonitorEnabled.Int64 != 0
		t.IsMonitorEnabled = &enabled
	}
	t.IsDeleted = isDeleted != 0
	return t, nil
}

// List returns every live tunnel, oldest first, with its addresses.
func (r *Repo) List(ctx context.Context) ([]Record, error) {
	rows, err := r.db.Read.QueryContext(ctx,
		`SELECT `+tunnelColumns+` FROM Tunnel WHERE IsDeleted = 0 ORDER BY TunnelID`)
	if err != nil {
		return nil, fmt.Errorf("listing tunnels: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		t, err := scanTunnel(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("reading a tunnel row: %w", err)
		}
		out = append(out, Record{Tunnel: t})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing tunnels: %w", err)
	}

	addresses, err := r.allAddresses(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Addresses = addresses[out[i].TunnelID]
	}
	return out, nil
}

// ByID returns one live tunnel with its addresses.
func (r *Repo) ByID(ctx context.Context, id int64) (Record, error) {
	row := r.db.Read.QueryRowContext(ctx,
		`SELECT `+tunnelColumns+` FROM Tunnel WHERE TunnelID = ? AND IsDeleted = 0`, id)
	t, err := scanTunnel(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("%w: tunnel %d", ErrNotFound, id)
	}
	if err != nil {
		return Record{}, fmt.Errorf("reading tunnel %d: %w", id, err)
	}

	addresses, err := r.addressesFor(ctx, id)
	if err != nil {
		return Record{}, err
	}
	return Record{Tunnel: t, Addresses: addresses}, nil
}

// ByInterfaceName returns the live tunnel with that interface name.
func (r *Repo) ByInterfaceName(ctx context.Context, name string) (Record, error) {
	row := r.db.Read.QueryRowContext(ctx,
		`SELECT `+tunnelColumns+` FROM Tunnel WHERE InterfaceName = ? AND IsDeleted = 0`, name)
	t, err := scanTunnel(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("%w: tunnel %q", ErrNotFound, name)
	}
	if err != nil {
		return Record{}, fmt.Errorf("reading tunnel %q: %w", name, err)
	}
	addresses, err := r.addressesFor(ctx, t.TunnelID)
	if err != nil {
		return Record{}, err
	}
	return Record{Tunnel: t, Addresses: addresses}, nil
}

func (r *Repo) addressesFor(ctx context.Context, tunnelID int64) ([]model.TunnelAddress, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT TunnelAddressID, TunnelID, Address, PrefixLength, PeerAddress, AddressFamilyID,
		       IsPrimary, SortOrder, CreatedDate, UpdatedDate, IsDeleted
		FROM TunnelAddress WHERE TunnelID = ? AND IsDeleted = 0 ORDER BY SortOrder, TunnelAddressID`,
		tunnelID)
	if err != nil {
		return nil, fmt.Errorf("reading the addresses of tunnel %d: %w", tunnelID, err)
	}
	defer rows.Close()
	return scanAddresses(rows)
}

func (r *Repo) allAddresses(ctx context.Context) (map[int64][]model.TunnelAddress, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT TunnelAddressID, TunnelID, Address, PrefixLength, PeerAddress, AddressFamilyID,
		       IsPrimary, SortOrder, CreatedDate, UpdatedDate, IsDeleted
		FROM TunnelAddress WHERE IsDeleted = 0 ORDER BY TunnelID, SortOrder, TunnelAddressID`)
	if err != nil {
		return nil, fmt.Errorf("reading tunnel addresses: %w", err)
	}
	defer rows.Close()

	list, err := scanAddresses(rows)
	if err != nil {
		return nil, err
	}
	out := map[int64][]model.TunnelAddress{}
	for _, a := range list {
		out[a.TunnelID] = append(out[a.TunnelID], a)
	}
	return out, nil
}

func scanAddresses(rows *sql.Rows) ([]model.TunnelAddress, error) {
	out := []model.TunnelAddress{}
	for rows.Next() {
		var a model.TunnelAddress
		var peer sql.NullString
		var isPrimary, isDeleted int64
		if err := rows.Scan(&a.TunnelAddressID, &a.TunnelID, &a.Address, &a.PrefixLength, &peer,
			&a.AddressFamilyID, &isPrimary, &a.SortOrder, &a.CreatedDate, &a.UpdatedDate, &isDeleted); err != nil {
			return nil, fmt.Errorf("reading a tunnel address: %w", err)
		}
		a.PeerAddress = nullString(peer)
		a.IsPrimary = isPrimary != 0
		a.IsDeleted = isDeleted != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// ExistingTunnels satisfies validate.Repository.
func (r *Repo) ExistingTunnels(ctx context.Context) ([]validate.ExistingTunnel, error) {
	records, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]validate.ExistingTunnel, 0, len(records))
	for _, rec := range records {
		existing := validate.ExistingTunnel{
			TunnelID:       rec.TunnelID,
			InterfaceName:  rec.InterfaceName,
			LocalEndpoint:  rec.LocalEndpoint,
			RemoteEndpoint: rec.RemoteEndpoint,
			IKey:           rec.IKey,
			OKey:           rec.OKey,
		}
		for _, a := range rec.Addresses {
			existing.Addresses = append(existing.Addresses, validate.AddressInput{
				Address:      a.Address,
				PrefixLength: int(a.PrefixLength),
				PeerAddress:  derefString(a.PeerAddress),
				IsPrimary:    a.IsPrimary,
			})
		}
		out = append(out, existing)
	}
	return out, nil
}

// ---------------------------------------------------------------- writing

// Insert stores a new tunnel and its addresses in one transaction, so a tunnel
// is never half-recorded.
func (r *Repo) Insert(ctx context.Context, in validate.TunnelInput, isManaged, isNameTemplated bool) (int64, error) {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("beginning the tunnel transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	res, err := tx.ExecContext(ctx, `
		INSERT INTO Tunnel (
			TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName, DisplayName, TunnelNumber,
			LocalEndpoint, RemoteEndpoint, BindDevice,
			Ttl, Tos, Mtu, IKey, OKey,
			HasInputChecksum, HasOutputChecksum, HasInputSequence, HasOutputSequence,
			IsPathMtuDiscovery, IsIgnoreDf, FwMark, TxQueueLength,
			HopLimit, EncapLimit, TrafficClass, FlowLabel,
			AddressPoolID, IsEnabled, IsManaged, IsNameTemplated,
			MonitorIntervalSeconds, MonitorTimeoutSeconds, MonitorPacketSize, MonitorWindowSize,
			MonitorDegradedLossPercent, MonitorDownLossPercent, MonitorDegradedRttMs,
			MonitorStateChangeSamples,
			ApplyStatusID, CreatedDate, UpdatedDate, IsDeleted
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
		          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		in.TunnelTypeID, in.TunnelSideID, in.PersistenceTypeID, in.InterfaceName, emptyToNull(in.DisplayName), in.TunnelNumber,
		in.LocalEndpoint, in.RemoteEndpoint, emptyToNull(in.BindDevice),
		in.Ttl, in.Tos, in.Mtu, in.IKey, in.OKey,
		boolInt(in.HasInputChecksum), boolInt(in.HasOutputChecksum),
		boolInt(in.HasInputSequence), boolInt(in.HasOutputSequence),
		boolInt(in.IsPathMtuDiscovery), boolInt(in.IsIgnoreDf), in.FwMark, in.TxQueueLength,
		in.HopLimit, in.EncapLimit, emptyToNull(in.TrafficClass), emptyToNull(in.FlowLabel),
		in.AddressPoolID, boolInt(in.IsEnabled), boolInt(isManaged), boolInt(isNameTemplated),
		in.MonitorIntervalSeconds, in.MonitorTimeoutSeconds, in.MonitorPacketSize, in.MonitorWindowSize,
		in.MonitorDegradedLossPercent, in.MonitorDownLossPercent, in.MonitorDegradedRttMs,
		in.MonitorStateChangeSamples,
		model.ApplyStatusPending, now, now)
	if err != nil {
		return 0, fmt.Errorf("storing the tunnel: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("reading the new tunnel identifier: %w", err)
	}

	if err := insertAddresses(ctx, tx, id, in.Addresses, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing the tunnel: %w", err)
	}
	return id, nil
}

// Update rewrites a tunnel and replaces its addresses.
func (r *Repo) Update(ctx context.Context, id int64, in validate.TunnelInput, isNameTemplated bool) error {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the tunnel transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	res, err := tx.ExecContext(ctx, `
		UPDATE Tunnel SET
			TunnelTypeID = ?, TunnelSideID = ?, PersistenceTypeID = ?, InterfaceName = ?, DisplayName = ?, TunnelNumber = ?,
			LocalEndpoint = ?, RemoteEndpoint = ?, BindDevice = ?,
			Ttl = ?, Tos = ?, Mtu = ?, IKey = ?, OKey = ?,
			HasInputChecksum = ?, HasOutputChecksum = ?, HasInputSequence = ?, HasOutputSequence = ?,
			IsPathMtuDiscovery = ?, IsIgnoreDf = ?, FwMark = ?, TxQueueLength = ?,
			HopLimit = ?, EncapLimit = ?, TrafficClass = ?, FlowLabel = ?,
			AddressPoolID = ?, IsEnabled = ?, IsNameTemplated = ?,
			MonitorIntervalSeconds = ?, MonitorTimeoutSeconds = ?, MonitorPacketSize = ?,
			MonitorWindowSize = ?, MonitorDegradedLossPercent = ?, MonitorDownLossPercent = ?,
			MonitorDegradedRttMs = ?, MonitorStateChangeSamples = ?,
			UpdatedDate = ?
		WHERE TunnelID = ? AND IsDeleted = 0`,
		in.TunnelTypeID, in.TunnelSideID, in.PersistenceTypeID, in.InterfaceName, emptyToNull(in.DisplayName), in.TunnelNumber,
		in.LocalEndpoint, in.RemoteEndpoint, emptyToNull(in.BindDevice),
		in.Ttl, in.Tos, in.Mtu, in.IKey, in.OKey,
		boolInt(in.HasInputChecksum), boolInt(in.HasOutputChecksum),
		boolInt(in.HasInputSequence), boolInt(in.HasOutputSequence),
		boolInt(in.IsPathMtuDiscovery), boolInt(in.IsIgnoreDf), in.FwMark, in.TxQueueLength,
		in.HopLimit, in.EncapLimit, emptyToNull(in.TrafficClass), emptyToNull(in.FlowLabel),
		in.AddressPoolID, boolInt(in.IsEnabled), boolInt(isNameTemplated),
		in.MonitorIntervalSeconds, in.MonitorTimeoutSeconds, in.MonitorPacketSize,
		in.MonitorWindowSize, in.MonitorDegradedLossPercent, in.MonitorDownLossPercent,
		in.MonitorDegradedRttMs, in.MonitorStateChangeSamples,
		now, id)
	if err != nil {
		return fmt.Errorf("updating tunnel %d: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("%w: tunnel %d", ErrNotFound, id)
	}

	// Addresses are replaced wholesale rather than diffed: the request states the
	// complete desired set, and soft-deleting the old rows keeps the history.
	if _, err := tx.ExecContext(ctx,
		`UPDATE TunnelAddress SET IsDeleted = 1, UpdatedDate = ? WHERE TunnelID = ? AND IsDeleted = 0`,
		now, id); err != nil {
		return fmt.Errorf("clearing the addresses of tunnel %d: %w", id, err)
	}
	if err := insertAddresses(ctx, tx, id, in.Addresses, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing the tunnel: %w", err)
	}
	return nil
}

func insertAddresses(ctx context.Context, tx *sql.Tx, tunnelID int64, addresses []validate.AddressInput, now string) error {
	const stmt = `
		INSERT INTO TunnelAddress
			(TunnelID, Address, PrefixLength, PeerAddress, AddressFamilyID, IsPrimary, SortOrder,
			 CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`

	for i, addr := range addresses {
		family := model.AddressFamilyIPv4
		if strings.Contains(addr.Address, ":") {
			family = model.AddressFamilyIPv6
		}
		if _, err := tx.ExecContext(ctx, stmt, tunnelID, addr.Address, addr.PrefixLength,
			emptyToNull(addr.PeerAddress), family, boolInt(addr.IsPrimary || i == 0), i, now, now); err != nil {
			return fmt.Errorf("storing the address %s: %w", addr.Address, err)
		}
	}
	return nil
}

// SoftDelete marks a tunnel and its addresses deleted. Business rows are never
// hard-deleted (§6).
func (r *Repo) SoftDelete(ctx context.Context, id int64) error {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the delete transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	if _, err := tx.ExecContext(ctx,
		`UPDATE Tunnel SET IsDeleted = 1, IsEnabled = 0, UpdatedDate = ? WHERE TunnelID = ?`,
		now, id); err != nil {
		return fmt.Errorf("deleting tunnel %d: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE TunnelAddress SET IsDeleted = 1, UpdatedDate = ? WHERE TunnelID = ?`,
		now, id); err != nil {
		return fmt.Errorf("deleting the addresses of tunnel %d: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing the delete: %w", err)
	}
	return nil
}

// SetApplyStatus records the outcome of an apply. The error text is stored so
// the tunnel list can show why a tunnel is not working without re-running
// anything.
func (r *Repo) SetApplyStatus(ctx context.Context, id, statusID int64, applyErr error) error {
	now := model.NowUTC()
	var message any
	if applyErr != nil {
		message = applyErr.Error()
	}
	var applied any
	if statusID == model.ApplyStatusApplied {
		applied = now
	}
	_, err := r.db.Write.ExecContext(ctx, `
		UPDATE Tunnel SET
			ApplyStatusID = ?,
			LastApplyError = ?,
			LastAppliedDate = COALESCE(?, LastAppliedDate),
			UpdatedDate = ?
		WHERE TunnelID = ?`, statusID, message, applied, now, id)
	if err != nil {
		return fmt.Errorf("recording the apply status of tunnel %d: %w", id, err)
	}
	return nil
}

// SetEnabled records whether a tunnel should be up.
func (r *Repo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := r.db.Write.ExecContext(ctx,
		`UPDATE Tunnel SET IsEnabled = ?, UpdatedDate = ? WHERE TunnelID = ? AND IsDeleted = 0`,
		boolInt(enabled), model.NowUTC(), id)
	if err != nil {
		return fmt.Errorf("recording the enabled state of tunnel %d: %w", id, err)
	}
	return nil
}

// ---------------------------------------------------------------- pools

// Pools returns every live address pool, satisfying alloc.Repository.
func (r *Repo) Pools(ctx context.Context) ([]alloc.Pool, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT AddressPoolID, AddressPoolTitle, Cidr, PrefixLength, IsPublicRange, IsEnabled, Description
		FROM AddressPool WHERE IsDeleted = 0 ORDER BY AddressPoolID`)
	if err != nil {
		return nil, fmt.Errorf("listing address pools: %w", err)
	}
	defer rows.Close()

	var out []alloc.Pool
	for rows.Next() {
		var p alloc.Pool
		var isPublic, isEnabled int64
		if err := rows.Scan(&p.AddressPoolID, &p.Title, &p.Cidr, &p.PrefixLength,
			&isPublic, &isEnabled, &p.Description); err != nil {
			return nil, fmt.Errorf("reading an address pool: %w", err)
		}
		p.IsPublicRange = isPublic != 0
		p.IsEnabled = isEnabled != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// PoolByID returns one pool, satisfying alloc.Repository.
func (r *Repo) PoolByID(ctx context.Context, id int64) (alloc.Pool, error) {
	row := r.db.Read.QueryRowContext(ctx, `
		SELECT AddressPoolID, AddressPoolTitle, Cidr, PrefixLength, IsPublicRange, IsEnabled, Description
		FROM AddressPool WHERE AddressPoolID = ? AND IsDeleted = 0`, id)

	var p alloc.Pool
	var isPublic, isEnabled int64
	err := row.Scan(&p.AddressPoolID, &p.Title, &p.Cidr, &p.PrefixLength, &isPublic, &isEnabled, &p.Description)
	if errors.Is(err, sql.ErrNoRows) {
		return alloc.Pool{}, fmt.Errorf("%w: address pool %d", ErrNotFound, id)
	}
	if err != nil {
		return alloc.Pool{}, fmt.Errorf("reading address pool %d: %w", id, err)
	}
	p.IsPublicRange = isPublic != 0
	p.IsEnabled = isEnabled != 0
	return p, nil
}

// ValidatePoolByID adapts PoolByID to validate.Repository, which needs a
// narrower view.
func (r *Repo) ValidatePoolByID(ctx context.Context, id int64) (validate.Pool, error) {
	p, err := r.PoolByID(ctx, id)
	if err != nil {
		return validate.Pool{}, err
	}
	return validate.Pool{
		AddressPoolID: p.AddressPoolID, Title: p.Title, Cidr: p.Cidr,
		PrefixLength: p.PrefixLength, IsPublicRange: p.IsPublicRange, IsEnabled: p.IsEnabled,
	}, nil
}

// InsertPool creates an address pool.
func (r *Repo) InsertPool(ctx context.Context, p alloc.Pool) (int64, error) {
	now := model.NowUTC()
	res, err := r.db.Write.ExecContext(ctx, `
		INSERT INTO AddressPool
			(AddressPoolTitle, Cidr, PrefixLength, IsPublicRange, IsEnabled, Description,
			 CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		p.Title, p.Cidr, p.PrefixLength, boolInt(p.IsPublicRange), boolInt(p.IsEnabled),
		p.Description, now, now)
	if err != nil {
		return 0, fmt.Errorf("storing the address pool: %w", err)
	}
	return res.LastInsertId()
}

// UpdatePool rewrites an address pool.
func (r *Repo) UpdatePool(ctx context.Context, p alloc.Pool) error {
	res, err := r.db.Write.ExecContext(ctx, `
		UPDATE AddressPool SET
			AddressPoolTitle = ?, Cidr = ?, PrefixLength = ?, IsPublicRange = ?,
			IsEnabled = ?, Description = ?, UpdatedDate = ?
		WHERE AddressPoolID = ? AND IsDeleted = 0`,
		p.Title, p.Cidr, p.PrefixLength, boolInt(p.IsPublicRange), boolInt(p.IsEnabled),
		p.Description, model.NowUTC(), p.AddressPoolID)
	if err != nil {
		return fmt.Errorf("updating address pool %d: %w", p.AddressPoolID, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("%w: address pool %d", ErrNotFound, p.AddressPoolID)
	}
	return nil
}

// DeletePool soft-deletes an address pool. A pool still referenced by a live
// tunnel is refused, because deleting it would leave the tunnel pointing at
// nothing.
func (r *Repo) DeletePool(ctx context.Context, id int64) error {
	var count int
	if err := r.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM Tunnel WHERE AddressPoolID = ? AND IsDeleted = 0`, id).Scan(&count); err != nil {
		return fmt.Errorf("checking whether address pool %d is in use: %w", id, err)
	}
	if count > 0 {
		return fmt.Errorf("address pool %d is used by %d tunnel(s); change or remove those first", id, count)
	}

	res, err := r.db.Write.ExecContext(ctx,
		`UPDATE AddressPool SET IsDeleted = 1, UpdatedDate = ? WHERE AddressPoolID = ? AND IsDeleted = 0`,
		model.NowUTC(), id)
	if err != nil {
		return fmt.Errorf("deleting address pool %d: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("%w: address pool %d", ErrNotFound, id)
	}
	return nil
}

// UsedAddresses returns every address assigned to a live tunnel, satisfying
// alloc.Repository.
func (r *Repo) UsedAddresses(ctx context.Context) ([]string, error) {
	rows, err := r.db.Read.QueryContext(ctx, `
		SELECT a.Address FROM TunnelAddress a
		JOIN Tunnel t ON t.TunnelID = a.TunnelID AND t.IsDeleted = 0
		WHERE a.IsDeleted = 0
		UNION
		SELECT a.PeerAddress FROM TunnelAddress a
		JOIN Tunnel t ON t.TunnelID = a.TunnelID AND t.IsDeleted = 0
		WHERE a.IsDeleted = 0 AND a.PeerAddress IS NOT NULL`)
	if err != nil {
		return nil, fmt.Errorf("reading assigned addresses: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, fmt.Errorf("reading an assigned address: %w", err)
		}
		out = append(out, address)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- helpers

func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

func nullFloat(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	f := v.Float64
	return &f
}

func nullString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func emptyToNull(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// SetMonitorEnabled records the per-tunnel monitoring override. A nil value
// clears it, which returns the tunnel to inheriting the global setting — the
// nullable-means-inherit representation of §6.
func (r *Repo) SetMonitorEnabled(ctx context.Context, id int64, enabled *bool) error {
	var value any
	if enabled != nil {
		value = boolInt(*enabled)
	}
	res, err := r.db.Write.ExecContext(ctx,
		`UPDATE Tunnel SET IsMonitorEnabled = ?, UpdatedDate = ? WHERE TunnelID = ? AND IsDeleted = 0`,
		value, model.NowUTC(), id)
	if err != nil {
		return fmt.Errorf("recording the monitoring state of tunnel %d: %w", id, err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return fmt.Errorf("%w: tunnel %d", ErrNotFound, id)
	}
	return nil
}
