package db

// SchemaVersion is the structural version of the schema. Every table is created
// with CREATE TABLE IF NOT EXISTS and every index is guarded, so ordinary
// additive changes need no migration at all. This number exists for the changes
// that cannot be expressed idempotently (§6) and is recorded in SchemaVersion.
const SchemaVersion = 1

// entityDDL is every entity table and its indexes. Lookup tables are generated
// from model.LookupTables() in seed.go rather than repeated here, so a new
// lookup value only ever means editing internal/model.
//
// House schema style (§6): PascalCase singular table names, <TableName>ID
// primary keys, foreign keys carrying the name of the key they reference,
// Is/Has boolean prefixes with defaults, and CreatedDate / UpdatedDate /
// IsDeleted on every entity table. Dates are ISO-8601 UTC text.
var entityDDL = []string{
	`CREATE TABLE IF NOT EXISTS SchemaVersion (
		SchemaVersionID INTEGER PRIMARY KEY,
		Version         INTEGER NOT NULL,
		AppliedDate     TEXT    NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS AppUser (
		UserID           INTEGER PRIMARY KEY AUTOINCREMENT,
		Username         TEXT    NOT NULL,
		PasswordHash     TEXT    NOT NULL,
		IsActive         INTEGER NOT NULL DEFAULT 1,
		LastLoginDate    TEXT,
		FailedLoginCount INTEGER NOT NULL DEFAULT 0,
		LockedUntilDate  TEXT,
		TokenVersion     INTEGER NOT NULL DEFAULT 1,
		CreatedDate      TEXT    NOT NULL,
		UpdatedDate      TEXT    NOT NULL,
		IsDeleted        INTEGER NOT NULL DEFAULT 0
	)`,
	// Soft deletion means uniqueness has to be partial, or a deleted user would
	// permanently reserve their username.
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_AppUser_Username
		ON AppUser (Username) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS AddressPool (
		AddressPoolID    INTEGER PRIMARY KEY,
		AddressPoolTitle TEXT    NOT NULL,
		Cidr             TEXT    NOT NULL,
		PrefixLength     INTEGER NOT NULL,
		IsPublicRange    INTEGER NOT NULL DEFAULT 0,
		IsEnabled        INTEGER NOT NULL DEFAULT 1,
		Description      TEXT    NOT NULL DEFAULT '',
		CreatedDate      TEXT    NOT NULL,
		UpdatedDate      TEXT    NOT NULL,
		IsDeleted        INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS IX_AddressPool_Enabled
		ON AddressPool (IsEnabled, IsDeleted)`,

	`CREATE TABLE IF NOT EXISTS Tunnel (
		TunnelID          INTEGER PRIMARY KEY AUTOINCREMENT,
		TunnelTypeID      INTEGER NOT NULL,
		TunnelSideID      INTEGER NOT NULL,
		PersistenceTypeID INTEGER NOT NULL,
		InterfaceName     TEXT    NOT NULL,
		DisplayName       TEXT,
		TunnelNumber      INTEGER,
		LocalEndpoint     TEXT    NOT NULL,
		RemoteEndpoint    TEXT    NOT NULL,
		BindDevice        TEXT,

		Ttl  INTEGER NOT NULL DEFAULT 255,
		Tos  TEXT    NOT NULL DEFAULT 'inherit',
		Mtu  INTEGER NOT NULL DEFAULT 1472,
		IKey INTEGER,
		OKey INTEGER,

		HasInputChecksum   INTEGER NOT NULL DEFAULT 0,
		HasOutputChecksum  INTEGER NOT NULL DEFAULT 0,
		HasInputSequence   INTEGER NOT NULL DEFAULT 0,
		HasOutputSequence  INTEGER NOT NULL DEFAULT 0,
		IsPathMtuDiscovery INTEGER NOT NULL DEFAULT 0,
		IsIgnoreDf         INTEGER NOT NULL DEFAULT 0,

		FwMark        INTEGER,
		TxQueueLength INTEGER,

		HopLimit     INTEGER,
		EncapLimit   INTEGER,
		TrafficClass TEXT,
		FlowLabel    TEXT,

		AddressPoolID   INTEGER,
		IsEnabled       INTEGER NOT NULL DEFAULT 1,
		IsManaged       INTEGER NOT NULL DEFAULT 1,
		IsNameTemplated INTEGER NOT NULL DEFAULT 1,

		ApplyStatusID   INTEGER NOT NULL DEFAULT 10,
		LastAppliedDate TEXT,
		LastApplyError  TEXT,

		Note     TEXT,
		TagsJson TEXT,

		MonitorIntervalSeconds     REAL,
		MonitorTimeoutSeconds      REAL,
		MonitorPacketSize          INTEGER,
		MonitorWindowSize          INTEGER,
		MonitorDegradedLossPercent REAL,
		MonitorDownLossPercent     REAL,
		MonitorDegradedRttMs       REAL,
		MonitorStateChangeSamples  INTEGER,
		MonitorTarget              TEXT,
		IsMonitorEnabled           INTEGER,

		CreatedDate TEXT    NOT NULL,
		UpdatedDate TEXT    NOT NULL,
		IsDeleted   INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (TunnelTypeID)      REFERENCES TunnelType (TunnelTypeID),
		FOREIGN KEY (TunnelSideID)      REFERENCES TunnelSide (TunnelSideID),
		FOREIGN KEY (PersistenceTypeID) REFERENCES PersistenceType (PersistenceTypeID),
		FOREIGN KEY (ApplyStatusID)     REFERENCES ApplyStatus (ApplyStatusID),
		FOREIGN KEY (AddressPoolID)     REFERENCES AddressPool (AddressPoolID)
	)`,
	// Rows are soft-deleted, so interface name uniqueness must be a partial
	// unique index filtered on IsDeleted = 0 (§6). Without the filter, deleting
	// and recreating a tunnel with the same name would fail.
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_Tunnel_InterfaceName
		ON Tunnel (InterfaceName) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_Tunnel_Endpoints
		ON Tunnel (LocalEndpoint, RemoteEndpoint) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_Tunnel_Enabled
		ON Tunnel (IsEnabled, IsDeleted)`,

	`CREATE TABLE IF NOT EXISTS TunnelAddress (
		TunnelAddressID INTEGER PRIMARY KEY AUTOINCREMENT,
		TunnelID        INTEGER NOT NULL,
		Address         TEXT    NOT NULL,
		PrefixLength    INTEGER NOT NULL,
		PeerAddress     TEXT,
		AddressFamilyID INTEGER NOT NULL,
		IsPrimary       INTEGER NOT NULL DEFAULT 0,
		SortOrder       INTEGER NOT NULL DEFAULT 0,
		CreatedDate     TEXT    NOT NULL,
		UpdatedDate     TEXT    NOT NULL,
		IsDeleted       INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (TunnelID)        REFERENCES Tunnel (TunnelID),
		FOREIGN KEY (AddressFamilyID) REFERENCES AddressFamily (AddressFamilyID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_TunnelAddress_Tunnel
		ON TunnelAddress (TunnelID, SortOrder) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_TunnelAddress_Address
		ON TunnelAddress (Address) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS MonitorSample (
		MonitorSampleID INTEGER PRIMARY KEY AUTOINCREMENT,
		TunnelID        INTEGER NOT NULL,
		BucketStartDate TEXT    NOT NULL,
		SentCount       INTEGER NOT NULL DEFAULT 0,
		ReceivedCount   INTEGER NOT NULL DEFAULT 0,
		LossPercent     REAL    NOT NULL DEFAULT 0,
		RttMinMs        REAL,
		RttAvgMs        REAL,
		RttMaxMs        REAL,
		RttMdevMs       REAL,
		JitterMs        REAL,
		MonitorStateID  INTEGER NOT NULL,
		CreatedDate     TEXT    NOT NULL,
		UpdatedDate     TEXT    NOT NULL,
		IsDeleted       INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (TunnelID)       REFERENCES Tunnel (TunnelID),
		FOREIGN KEY (MonitorStateID) REFERENCES MonitorState (MonitorStateID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_MonitorSample_TunnelBucket
		ON MonitorSample (TunnelID, BucketStartDate)`,

	`CREATE TABLE IF NOT EXISTS MonitorEvent (
		MonitorEventID     INTEGER PRIMARY KEY AUTOINCREMENT,
		TunnelID           INTEGER NOT NULL,
		FromMonitorStateID INTEGER NOT NULL,
		ToMonitorStateID   INTEGER NOT NULL,
		Reason             TEXT    NOT NULL DEFAULT '',
		LossPercent        REAL,
		RttAvgMs           REAL,
		CreatedDate        TEXT    NOT NULL,

		FOREIGN KEY (TunnelID)           REFERENCES Tunnel (TunnelID),
		FOREIGN KEY (FromMonitorStateID) REFERENCES MonitorState (MonitorStateID),
		FOREIGN KEY (ToMonitorStateID)   REFERENCES MonitorState (MonitorStateID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_MonitorEvent_Tunnel
		ON MonitorEvent (TunnelID, CreatedDate)`,

	`CREATE TABLE IF NOT EXISTS DiagnosticRun (
		DiagnosticRunID  INTEGER PRIMARY KEY AUTOINCREMENT,
		TunnelID         INTEGER,
		DiagnosticTypeID INTEGER NOT NULL,
		ParamsJson       TEXT    NOT NULL DEFAULT '{}',
		ResultJson       TEXT,
		StartedDate      TEXT    NOT NULL,
		FinishedDate     TEXT,
		IsSuccess        INTEGER NOT NULL DEFAULT 0,
		CreatedDate      TEXT    NOT NULL,
		UpdatedDate      TEXT    NOT NULL,
		IsDeleted        INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (TunnelID)         REFERENCES Tunnel (TunnelID),
		FOREIGN KEY (DiagnosticTypeID) REFERENCES DiagnosticType (DiagnosticTypeID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_DiagnosticRun_Tunnel
		ON DiagnosticRun (TunnelID, StartedDate) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS InterfaceTrafficCounter (
		InterfaceTrafficCounterID INTEGER PRIMARY KEY AUTOINCREMENT,
		InterfaceName             TEXT    NOT NULL,
		InterfaceIndex            INTEGER NOT NULL DEFAULT 0,
		RxBytesTotal              INTEGER NOT NULL DEFAULT 0,
		TxBytesTotal              INTEGER NOT NULL DEFAULT 0,
		LastRawRxBytes            INTEGER NOT NULL DEFAULT 0,
		LastRawTxBytes            INTEGER NOT NULL DEFAULT 0,
		LastSeenDate              TEXT    NOT NULL,
		CreatedDate               TEXT    NOT NULL,
		UpdatedDate               TEXT    NOT NULL,
		IsDeleted                 INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_InterfaceTrafficCounter_Name
		ON InterfaceTrafficCounter (InterfaceName) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS RouteRule (
		RouteRuleID    INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleTitle TEXT    NOT NULL,
		Description    TEXT    NOT NULL DEFAULT '',

		RouteProtocolID INTEGER NOT NULL,
		AddressFamilyID INTEGER NOT NULL,

		BindAddress      TEXT    NOT NULL,
		BindPort         INTEGER NOT NULL,
		BindPortRangeEnd INTEGER,
		BindInterface    TEXT,

		DestinationAddress      TEXT    NOT NULL,
		DestinationPort         INTEGER NOT NULL,
		DestinationPortRangeEnd INTEGER,

		NatModeID         INTEGER NOT NULL DEFAULT 10,
		SnatAddress       TEXT,
		LoadBalanceModeID INTEGER NOT NULL DEFAULT 10,
		TunnelID          INTEGER,

		IsClampMssToPmtu         INTEGER NOT NULL DEFAULT 0,
		IsIncludeLocalOriginated INTEGER NOT NULL DEFAULT 0,
		IsLoggingEnabled         INTEGER NOT NULL DEFAULT 0,
		FwMark                   INTEGER,

		MaxConnectionsPerSource INTEGER,
		ConnectionRateLimit     INTEGER,

		IsEnabled       INTEGER NOT NULL DEFAULT 1,
		ApplyStatusID   INTEGER NOT NULL DEFAULT 10,
		LastAppliedDate TEXT,
		LastApplyError  TEXT,

		SortOrder INTEGER NOT NULL DEFAULT 0,
		TagsJson  TEXT,

		IsMonitorEnabled         INTEGER,
		MonitorModeID            INTEGER,
		MonitorIntervalSeconds   REAL,
		MonitorTimeoutSeconds    REAL,
		MonitorFailureThreshold  INTEGER,
		MonitorRecoveryThreshold INTEGER,

		CreatedDate TEXT    NOT NULL,
		UpdatedDate TEXT    NOT NULL,
		IsDeleted   INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (MonitorModeID)     REFERENCES RouteMonitorMode (RouteMonitorModeID),
		FOREIGN KEY (RouteProtocolID)   REFERENCES RouteProtocol (RouteProtocolID),
		FOREIGN KEY (AddressFamilyID)   REFERENCES AddressFamily (AddressFamilyID),
		FOREIGN KEY (NatModeID)         REFERENCES NatMode (NatModeID),
		FOREIGN KEY (LoadBalanceModeID) REFERENCES LoadBalanceMode (LoadBalanceModeID),
		FOREIGN KEY (ApplyStatusID)     REFERENCES ApplyStatus (ApplyStatusID),
		FOREIGN KEY (TunnelID)          REFERENCES Tunnel (TunnelID)
	)`,
	// The name an operator recognises a rule by has to be unique among live rows,
	// and partial for the same reason every other unique index here is: rows are
	// soft-deleted, so a deleted rule must not reserve its name forever.
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_RouteRule_Title
		ON RouteRule (RouteRuleTitle) WHERE IsDeleted = 0`,
	// Two live, enabled rules may not claim the same listener. The filter covers
	// both IsDeleted and IsEnabled: a disabled rule generates nothing, so it does
	// not hold the port, and refusing to store it would make disabling a rule to
	// build its replacement impossible. Range overlap cannot be expressed as an
	// index at all and is checked in validation instead.
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_RouteRule_Listener
		ON RouteRule (RouteProtocolID, BindAddress, BindPort) WHERE IsDeleted = 0 AND IsEnabled = 1`,
	`CREATE INDEX IF NOT EXISTS IX_RouteRule_Order
		ON RouteRule (SortOrder, RouteRuleID) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_RouteRule_Tunnel
		ON RouteRule (TunnelID) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_RouteRule_Enabled
		ON RouteRule (IsEnabled, IsDeleted)`,

	`CREATE TABLE IF NOT EXISTS RouteDestination (
		RouteDestinationID INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleID        INTEGER NOT NULL,
		Address            TEXT    NOT NULL,
		Port               INTEGER NOT NULL,
		PortRangeEnd       INTEGER,
		Weight             INTEGER NOT NULL DEFAULT 1,
		IsEnabled          INTEGER NOT NULL DEFAULT 1,
		SortOrder          INTEGER NOT NULL DEFAULT 0,

		IsMonitorEnabled         INTEGER,
		MonitorPort              INTEGER,
		MonitorIntervalSeconds   REAL,
		MonitorTimeoutSeconds    REAL,
		MonitorFailureThreshold  INTEGER,
		MonitorRecoveryThreshold INTEGER,
		IsSuppressed             INTEGER NOT NULL DEFAULT 0,

		CreatedDate        TEXT    NOT NULL,
		UpdatedDate        TEXT    NOT NULL,
		IsDeleted          INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (RouteRuleID) REFERENCES RouteRule (RouteRuleID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_RouteDestination_Rule
		ON RouteDestination (RouteRuleID, SortOrder) WHERE IsDeleted = 0`,

	// A named set of addresses an operator maintains once and points several
	// rules at. The alternative is retyping the same two hundred ranges into
	// every rule that needs them, and then editing every one of them when the
	// set changes.
	`CREATE TABLE IF NOT EXISTS SourceList (
		SourceListID INTEGER PRIMARY KEY AUTOINCREMENT,
		Name         TEXT    NOT NULL,
		Description  TEXT    NOT NULL DEFAULT '',
		-- Slug is the identifier the generated ruleset uses for this list's
		-- named set. It is derived from the name once, at creation, so
		-- renaming a list never renames a kernel object out from under a rule.
		Slug        TEXT    NOT NULL,
		-- IsBuiltIn marks the lists the panel ships with. They are ordinary
		-- rows an operator may edit or delete; the flag only says where they
		-- came from, so seeding never recreates one that was deleted.
		IsBuiltIn   INTEGER NOT NULL DEFAULT 0,
		CreatedDate TEXT    NOT NULL,
		UpdatedDate TEXT    NOT NULL,
		IsDeleted   INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_SourceList_Name
		ON SourceList (Name) WHERE IsDeleted = 0`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_SourceList_Slug
		ON SourceList (Slug) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS SourceListEntry (
		SourceListEntryID INTEGER PRIMARY KEY AUTOINCREMENT,
		SourceListID      INTEGER NOT NULL,
		-- Cidr is always stored masked and normalised, so two spellings of one
		-- range are one row and the unique index below can say so.
		Cidr            TEXT    NOT NULL,
		AddressFamilyID INTEGER NOT NULL,
		Description     TEXT    NOT NULL DEFAULT '',
		CreatedDate     TEXT    NOT NULL,
		UpdatedDate     TEXT    NOT NULL,
		IsDeleted       INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (SourceListID)    REFERENCES SourceList (SourceListID),
		FOREIGN KEY (AddressFamilyID) REFERENCES AddressFamily (AddressFamilyID)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_SourceListEntry_Range
		ON SourceListEntry (SourceListID, Cidr) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_SourceListEntry_List
		ON SourceListEntry (SourceListID) WHERE IsDeleted = 0`,

	// Which lists a forwarding rule allows. It is a table rather than a
	// column because a rule may allow several, and a list may be used by
	// several rules.
	`CREATE TABLE IF NOT EXISTS RouteSourceList (
		RouteSourceListID INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleID       INTEGER NOT NULL,
		SourceListID      INTEGER NOT NULL,
		SortOrder         INTEGER NOT NULL DEFAULT 0,
		CreatedDate       TEXT    NOT NULL,
		UpdatedDate       TEXT    NOT NULL,
		IsDeleted         INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (RouteRuleID)  REFERENCES RouteRule (RouteRuleID),
		FOREIGN KEY (SourceListID) REFERENCES SourceList (SourceListID)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_RouteSourceList_Pair
		ON RouteSourceList (RouteRuleID, SourceListID) WHERE IsDeleted = 0`,
	`CREATE INDEX IF NOT EXISTS IX_RouteSourceList_List
		ON RouteSourceList (SourceListID) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS RouteAllowedSource (
		RouteAllowedSourceID INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleID          INTEGER NOT NULL,
		Cidr                 TEXT    NOT NULL,
		Description          TEXT    NOT NULL DEFAULT '',
		CreatedDate          TEXT    NOT NULL,
		UpdatedDate          TEXT    NOT NULL,
		IsDeleted            INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (RouteRuleID) REFERENCES RouteRule (RouteRuleID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_RouteAllowedSource_Rule
		ON RouteAllowedSource (RouteRuleID) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS RouteTrafficCounter (
		RouteTrafficCounterID INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleID           INTEGER NOT NULL,
		RxBytesTotal          INTEGER NOT NULL DEFAULT 0,
		TxBytesTotal          INTEGER NOT NULL DEFAULT 0,
		RxPacketsTotal        INTEGER NOT NULL DEFAULT 0,
		TxPacketsTotal        INTEGER NOT NULL DEFAULT 0,
		LastRawRxBytes        INTEGER NOT NULL DEFAULT 0,
		LastRawTxBytes        INTEGER NOT NULL DEFAULT 0,
		LastRawRxPackets      INTEGER NOT NULL DEFAULT 0,
		LastRawTxPackets      INTEGER NOT NULL DEFAULT 0,
		LastSeenDate          TEXT    NOT NULL,
		CreatedDate           TEXT    NOT NULL,
		UpdatedDate           TEXT    NOT NULL,
		IsDeleted             INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (RouteRuleID) REFERENCES RouteRule (RouteRuleID)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_RouteTrafficCounter_Rule
		ON RouteTrafficCounter (RouteRuleID) WHERE IsDeleted = 0`,

	// One traffic limit. The limited thing is named by scope: a tunnel by its
	// id, a rule by its id, and a rule's destination by rule, address and port
	// — by address rather than by RouteDestinationID, because saving a rule
	// rewrites its destination rows and the limit has to survive that.
	//
	// The baseline columns are what the cumulative counters read when the
	// current window began; usage is the counter minus the baseline, so a
	// window rolls over by rebasing rather than by zeroing anything.
	`CREATE TABLE IF NOT EXISTS TrafficQuota (
		TrafficQuotaID    INTEGER PRIMARY KEY AUTOINCREMENT,
		ScopeTypeID       INTEGER NOT NULL,
		TunnelID          INTEGER,
		RouteRuleID       INTEGER,
		Address           TEXT,
		Port              INTEGER,

		LimitBytes        INTEGER NOT NULL,
		ModeID            INTEGER NOT NULL DEFAULT 10,
		PeriodID          INTEGER NOT NULL DEFAULT 40,
		DirectionID       INTEGER NOT NULL DEFAULT 10,

		BaselineRxBytes   INTEGER NOT NULL DEFAULT 0,
		BaselineTxBytes   INTEGER NOT NULL DEFAULT 0,
		PeriodStartDate   TEXT,
		QuotaDisabledDate TEXT,

		CreatedDate       TEXT    NOT NULL,
		UpdatedDate       TEXT    NOT NULL,
		IsDeleted         INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_TrafficQuota_Tunnel
		ON TrafficQuota (TunnelID) WHERE IsDeleted = 0 AND ScopeTypeID = 10`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_TrafficQuota_Rule
		ON TrafficQuota (RouteRuleID) WHERE IsDeleted = 0 AND ScopeTypeID = 20`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_TrafficQuota_Destination
		ON TrafficQuota (RouteRuleID, Address, Port) WHERE IsDeleted = 0 AND ScopeTypeID = 30`,

	// Cumulative per-destination traffic, folded from connection tracking the
	// way RouteTrafficCounter is folded from the rule counters. Keyed by rule,
	// address and port for the same reason the quota table is: destination
	// rows are rewritten on every save and a lifetime total has to survive it.
	`CREATE TABLE IF NOT EXISTS RouteDestinationTrafficCounter (
		RouteDestinationTrafficCounterID INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleID   INTEGER NOT NULL,
		Address       TEXT    NOT NULL,
		Port          INTEGER NOT NULL,
		RxBytesTotal  INTEGER NOT NULL DEFAULT 0,
		TxBytesTotal  INTEGER NOT NULL DEFAULT 0,
		LastSeenDate  TEXT    NOT NULL,
		CreatedDate   TEXT    NOT NULL,
		UpdatedDate   TEXT    NOT NULL,
		IsDeleted     INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (RouteRuleID) REFERENCES RouteRule (RouteRuleID)
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS UX_RouteDestinationTrafficCounter_Dest
		ON RouteDestinationTrafficCounter (RouteRuleID, Address, Port) WHERE IsDeleted = 0`,

	`CREATE TABLE IF NOT EXISTS RouteTrafficSample (
		RouteTrafficSampleID INTEGER PRIMARY KEY AUTOINCREMENT,
		RouteRuleID          INTEGER NOT NULL,
		BucketStartDate      TEXT    NOT NULL,
		RxBytes              INTEGER NOT NULL DEFAULT 0,
		TxBytes              INTEGER NOT NULL DEFAULT 0,
		RxPackets            INTEGER NOT NULL DEFAULT 0,
		TxPackets            INTEGER NOT NULL DEFAULT 0,
		ActiveConnections    INTEGER NOT NULL DEFAULT 0,
		NewConnections       INTEGER NOT NULL DEFAULT 0,
		CreatedDate          TEXT    NOT NULL,
		UpdatedDate          TEXT    NOT NULL,
		IsDeleted            INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (RouteRuleID) REFERENCES RouteRule (RouteRuleID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_RouteTrafficSample_RuleBucket
		ON RouteTrafficSample (RouteRuleID, BucketStartDate)`,

	// Where the panel listens. One row, always PanelAddressID = 1.
	//
	// This is deliberately not an AppSetting row. The settings store is a
	// declared schema rendered into a generated form, and a generated field
	// would let an operator save a port with no bind test, no protected-port
	// check and no restart — a value that looks saved and takes effect at the
	// next reboot as a panel nobody can reach. Changing this has a procedure,
	// so it has a table and an endpoint of its own.
	//
	// SeedBindPort and SeedWebPath hold what the environment file said at the
	// last start, which is how internal/address tells "the file was edited"
	// from "the file has always disagreed"; LastGoodBindPort is what the panel
	// falls back to when the configured port cannot be bound.
	`CREATE TABLE IF NOT EXISTS PanelAddress (
		PanelAddressID   INTEGER PRIMARY KEY,
		BindPort         INTEGER NOT NULL,
		WebPath          TEXT    NOT NULL DEFAULT '',
		LastGoodBindPort INTEGER,
		SeedBindPort     INTEGER,
		SeedWebPath      TEXT,
		UpdatedByUserID  INTEGER,
		CreatedDate      TEXT    NOT NULL,
		UpdatedDate      TEXT    NOT NULL,
		IsDeleted        INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (UpdatedByUserID) REFERENCES AppUser (UserID)
	)`,

	`CREATE TABLE IF NOT EXISTS AppSetting (
		SettingKey      TEXT PRIMARY KEY,
		ValueJson       TEXT NOT NULL,
		UpdatedByUserID INTEGER,
		UpdatedDate     TEXT NOT NULL,

		FOREIGN KEY (UpdatedByUserID) REFERENCES AppUser (UserID)
	)`,

	`CREATE TABLE IF NOT EXISTS AuditLog (
		AuditLogID     INTEGER PRIMARY KEY AUTOINCREMENT,
		AuditActionID  INTEGER NOT NULL,
		UserID         INTEGER,
		TargetType     TEXT    NOT NULL DEFAULT '',
		TargetID       TEXT    NOT NULL DEFAULT '',
		RequestJson    TEXT    NOT NULL DEFAULT '{}',
		OperationsJson TEXT    NOT NULL DEFAULT '[]',
		IsSuccess      INTEGER NOT NULL DEFAULT 1,
		ErrorMessage   TEXT,
		DurationMs     INTEGER NOT NULL DEFAULT 0,
		ClientIp       TEXT    NOT NULL DEFAULT '',
		CreatedDate    TEXT    NOT NULL,

		FOREIGN KEY (AuditActionID) REFERENCES AuditAction (AuditActionID),
		FOREIGN KEY (UserID)        REFERENCES AppUser (UserID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_AuditLog_Created
		ON AuditLog (CreatedDate)`,
	`CREATE INDEX IF NOT EXISTS IX_AuditLog_Action
		ON AuditLog (AuditActionID, CreatedDate)`,

	// BackupGrant is one live download link for the database file.
	//
	// The expiry is an absolute timestamp in the database rather than a timer in
	// the process, and that is the whole design: a timer dies with a restart, so
	// a link would either outlive its window or vanish inside it depending on
	// whether anything happened to bounce the service. Stored this way a restart
	// is not an event at all — the link is live if the clock says so, and the
	// sweeper that deletes expired rows is tidying, not enforcement.
	//
	// Only the SHA-256 of the token is kept. The row cannot be turned back into
	// a working link, which matters because the file this grants access to is
	// the database itself: whoever holds the token can read every password hash
	// in it.
	`CREATE TABLE IF NOT EXISTS BackupGrant (
		BackupGrantID   INTEGER PRIMARY KEY,
		TokenHash       TEXT    NOT NULL UNIQUE,
		ExpiresDate     TEXT    NOT NULL,
		CreatedByUserID INTEGER,
		DownloadCount   INTEGER NOT NULL DEFAULT 0,
		LastDownloadDate TEXT,
		CreatedDate     TEXT    NOT NULL,
		UpdatedDate     TEXT    NOT NULL,
		IsDeleted       INTEGER NOT NULL DEFAULT 0,

		FOREIGN KEY (CreatedByUserID) REFERENCES AppUser (UserID)
	)`,
	`CREATE INDEX IF NOT EXISTS IX_BackupGrant_Expires
		ON BackupGrant (ExpiresDate)`,
	`CREATE INDEX IF NOT EXISTS IX_AuditLog_User
		ON AuditLog (UserID, CreatedDate)`,
}
