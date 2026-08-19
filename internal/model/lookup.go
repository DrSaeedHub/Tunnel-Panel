// Package model holds the entity structs and the lookup identifier constants
// that the rest of the panel shares.
//
// The lookup identifiers in this file are the single source of truth for every
// categorical value in the system (§6). They are fixed integers spaced by ten so
// that new values can be inserted between existing ones in a later release
// without renumbering anything that is already stored in a customer database.
// internal/db derives both the DDL and the idempotent seeds from the tables
// declared here, so adding a value means editing this file only.
package model

// TunnelType identifiers.
const (
	TunnelTypeGRE       int64 = 10
	TunnelTypeGRETAP    int64 = 20
	TunnelTypeIP6GRE    int64 = 30
	TunnelTypeIP6GRETAP int64 = 40
)

// TunnelSide identifiers. A and B are the two ends of one tunnel; neither has a
// special role. GRE is a stateless encapsulation with no handshake and no
// session, so the vocabulary of protocols that negotiate one — client, server,
// and the pair of terms describing which end starts the exchange — is factually
// wrong here and appears nowhere in this codebase (§5.4).
const (
	TunnelSideA int64 = 10
	TunnelSideB int64 = 20
)

// PersistenceType identifiers.
const (
	PersistenceTypeSystemd  int64 = 10
	PersistenceTypeNetworkd int64 = 20
	PersistenceTypeRuntime  int64 = 30
)

// MonitorState identifiers.
const (
	MonitorStateUnknown  int64 = 10
	MonitorStateUp       int64 = 20
	MonitorStateDegraded int64 = 30
	MonitorStateDown     int64 = 40
	MonitorStateDisabled int64 = 50
)

// ApplyStatus identifiers.
const (
	ApplyStatusPending      int64 = 10
	ApplyStatusApplied      int64 = 20
	ApplyStatusFailed       int64 = 30
	ApplyStatusInconsistent int64 = 40
)

// ReconcileStatus identifiers.
const (
	ReconcileStatusInSync       int64 = 10
	ReconcileStatusDrifted      int64 = 20
	ReconcileStatusMissing      int64 = 30
	ReconcileStatusUnmanaged    int64 = 40
	ReconcileStatusInconsistent int64 = 50
)

// DiagnosticType identifiers.
const (
	DiagnosticTypePing       int64 = 10
	DiagnosticTypeMtuProbe   int64 = 20
	DiagnosticTypeTraceroute int64 = 30
	DiagnosticTypeAnalyze    int64 = 40
)

// AddressFamily identifiers.
const (
	AddressFamilyIPv4 int64 = 10
	AddressFamilyIPv6 int64 = 20
)

// RouteProtocol identifiers. Both generates the parallel rule set for each
// protocol rather than being a third protocol of its own.
const (
	RouteProtocolTCP  int64 = 10
	RouteProtocolUDP  int64 = 20
	RouteProtocolBoth int64 = 30
)

// NatMode identifiers. This is the most consequential choice on a forwarding
// rule: Masquerade and Snat rewrite the source address, so the destination sees
// this server rather than the client, while None preserves the client address
// and only works when the return path comes back through here.
const (
	NatModeMasquerade int64 = 10
	NatModeSnat       int64 = 20
	NatModeNone       int64 = 30
)

// RouteMonitorMode identifiers. Reporting is what a monitor does at minimum;
// failover is reporting plus taking the destination out of the rotation, which
// is a change to the installed ruleset the panel makes without being asked and
// so is never the default.
const (
	RouteMonitorModeReport   int64 = 10
	RouteMonitorModeFailover int64 = 20
)

// RouteMonitorModeName maps an identifier to the name the ruleset and the API
// use. An unknown identifier reports as reporting only, because that is the
// mode that changes nothing.
func RouteMonitorModeName(id int64) string {
	if id == RouteMonitorModeFailover {
		return "failover"
	}
	return "report"
}

// LoadBalanceMode identifiers. SourceHash keeps a given client on a given
// destination; RoundRobin does not.
const (
	LoadBalanceModeNone       int64 = 10
	LoadBalanceModeRoundRobin int64 = 20
	LoadBalanceModeSourceHash int64 = 30
	LoadBalanceModeWeighted   int64 = 40
)

// RuleBackendType identifiers: which netfilter interface actually carries the
// panel's forwarding rules on this host.
const (
	RuleBackendTypeNftables       int64 = 10
	RuleBackendTypeIptablesNft    int64 = 20
	RuleBackendTypeIptablesLegacy int64 = 30
)

// AuditAction identifiers.
const (
	AuditActionLogin          int64 = 10
	AuditActionLoginFailed    int64 = 20
	AuditActionLogout         int64 = 30
	AuditActionTunnelCreate   int64 = 40
	AuditActionTunnelUpdate   int64 = 50
	AuditActionTunnelDelete   int64 = 60
	AuditActionTunnelEnable   int64 = 70
	AuditActionTunnelDisable  int64 = 80
	AuditActionTunnelReapply  int64 = 90
	AuditActionTunnelAdopt    int64 = 100
	AuditActionSettingUpdate  int64 = 110
	AuditActionPasswordChange int64 = 120
	AuditActionPoolChange     int64 = 130
	AuditActionBackupImport   int64 = 140
	AuditActionRouteCreate    int64 = 150
	AuditActionRouteUpdate    int64 = 160
	AuditActionRouteDelete    int64 = 170
	AuditActionRouteEnable    int64 = 180
	AuditActionRouteDisable   int64 = 190
	AuditActionRouteReapply   int64 = 200
	// Where the panel serves, and a password put back by someone who could not
	// log in to change it. Both are recorded separately from the ordinary
	// actions above because both are things an operator will need to find
	// afterwards: one moved the panel, and the other is the only password
	// change that did not require knowing the old password.
	AuditActionPanelAddressChange int64 = 210
	AuditActionPasswordReset      int64 = 220
	AuditActionUsernameChange     int64 = 230
	// The database file itself leaving or replacing the panel. Separate from
	// BackupImport, which carries configuration only: a database download hands
	// over every password hash, and a database restore replaces every account
	// that exists. Both are the first thing anyone will look for afterwards.
	AuditActionDatabaseDownload int64 = 240
	AuditActionDatabaseRestore  int64 = 250
	// The panel replacing itself. Recorded before the installer starts, because
	// what happens next is this process being stopped: an entry written after
	// the fact may never be written at all, and "which version did we jump from,
	// and who asked for it" is the first question after a bad upgrade.
	AuditActionPanelUpdate int64 = 260
)

// tunnelTypeKinds maps a TunnelType identifier to the name the kernel and
// iproute2 use for it. These strings are the same values internal/link declares
// as KindGRE and friends; the two are asserted equal by a test rather than
// shared through an import, which would make this package depend on the system
// interaction layer.
var tunnelTypeKinds = map[int64]string{
	TunnelTypeGRE:       "gre",
	TunnelTypeGRETAP:    "gretap",
	TunnelTypeIP6GRE:    "ip6gre",
	TunnelTypeIP6GRETAP: "ip6gretap",
}

// TunnelTypeKind returns the kernel's name for a tunnel type, or "" when the
// identifier is not a declared type.
func TunnelTypeKind(id int64) string { return tunnelTypeKinds[id] }

// The forwarding vocabularies, mapped to the names internal/rules uses. They
// exist for the same reason tunnelTypeKinds does: the data model must not
// depend on the system interaction layer, and the two spellings are asserted
// equal by a test rather than shared through an import.
var (
	routeProtocolNames = map[int64]string{
		RouteProtocolTCP:  "tcp",
		RouteProtocolUDP:  "udp",
		RouteProtocolBoth: "both",
	}
	natModeNames = map[int64]string{
		NatModeMasquerade: "masquerade",
		NatModeSnat:       "snat",
		NatModeNone:       "none",
	}
	loadBalanceModeNames = map[int64]string{
		LoadBalanceModeNone:       "none",
		LoadBalanceModeRoundRobin: "round_robin",
		LoadBalanceModeSourceHash: "source_hash",
		LoadBalanceModeWeighted:   "weighted",
	}
	ruleBackendTypeNames = map[int64]string{
		RuleBackendTypeNftables:       "nftables",
		RuleBackendTypeIptablesNft:    "iptables_nft",
		RuleBackendTypeIptablesLegacy: "iptables_legacy",
	}
)

// RouteProtocolName returns the rule layer's name for a protocol, or "" when
// the identifier is not a declared one.
func RouteProtocolName(id int64) string { return routeProtocolNames[id] }

// NatModeName returns the rule layer's name for a NAT mode.
func NatModeName(id int64) string { return natModeNames[id] }

// LoadBalanceModeName returns the rule layer's name for a load balancing mode.
func LoadBalanceModeName(id int64) string { return loadBalanceModeNames[id] }

// RuleBackendTypeName returns the rule layer's name for a netfilter backend.
func RuleBackendTypeName(id int64) string { return ruleBackendTypeNames[id] }

// RuleBackendTypeForName is the reverse mapping, used to record which backend
// an installation is actually running.
func RuleBackendTypeForName(name string) (int64, bool) {
	for id, n := range ruleBackendTypeNames {
		if n == name {
			return id, true
		}
	}
	return 0, false
}

// TunnelTypeForKind is the reverse mapping, used when importing a tunnel that
// already exists on the system.
func TunnelTypeForKind(kind string) (int64, bool) {
	for id, name := range tunnelTypeKinds {
		if name == kind {
			return id, true
		}
	}
	return 0, false
}

// IsIPv6TunnelType reports whether a tunnel type carries its underlay over
// IPv6, which decides the endpoint address family and the encapsulation
// overhead.
func IsIPv6TunnelType(id int64) bool {
	return id == TunnelTypeIP6GRE || id == TunnelTypeIP6GRETAP
}

// SideSlot returns the canonical slot letter for a TunnelSide identifier.
// A and B are simply the two ends of one tunnel and neither has a special
// role (§5.4).
func SideSlot(id int64) string {
	switch id {
	case TunnelSideA:
		return "a"
	case TunnelSideB:
		return "b"
	}
	return ""
}

// OppositeSide returns the other end's TunnelSide identifier, which is what the
// pairing code flips (§14).
func OppositeSide(id int64) int64 {
	if id == TunnelSideA {
		return TunnelSideB
	}
	return TunnelSideA
}

// LookupValue is one seeded row of a lookup table.
type LookupValue struct {
	ID    int64
	Title string
}

// LookupTable describes a lookup table completely enough for internal/db to
// generate its DDL and its seeds without repeating any of this information.
type LookupTable struct {
	// Name is the PascalCase singular table name.
	Name string
	// Values are seeded on every startup with INSERT ... ON CONFLICT DO NOTHING,
	// so values added in a later release reach existing installations while rows
	// an operator has customised survive untouched.
	Values []LookupValue
}

// IDColumn returns the primary key column name, per the house naming rule.
func (t LookupTable) IDColumn() string { return t.Name + "ID" }

// TitleColumn returns the label column name, per the house naming rule.
func (t LookupTable) TitleColumn() string { return t.Name + "Title" }

// LookupTables returns every lookup table in a deterministic order. Foreign keys
// point at these tables, so they are created and seeded before entity tables.
func LookupTables() []LookupTable {
	return []LookupTable{
		{Name: "TunnelType", Values: []LookupValue{
			{TunnelTypeGRE, "GRE"},
			{TunnelTypeGRETAP, "GRETAP"},
			{TunnelTypeIP6GRE, "IP6GRE"},
			{TunnelTypeIP6GRETAP, "IP6GRETAP"},
		}},
		{Name: "TunnelSide", Values: []LookupValue{
			{TunnelSideA, "A"},
			{TunnelSideB, "B"},
		}},
		{Name: "PersistenceType", Values: []LookupValue{
			{PersistenceTypeSystemd, "Systemd"},
			{PersistenceTypeNetworkd, "Networkd"},
			{PersistenceTypeRuntime, "Runtime"},
		}},
		{Name: "MonitorState", Values: []LookupValue{
			{MonitorStateUnknown, "Unknown"},
			{MonitorStateUp, "Up"},
			{MonitorStateDegraded, "Degraded"},
			{MonitorStateDown, "Down"},
			{MonitorStateDisabled, "Disabled"},
		}},
		{Name: "ApplyStatus", Values: []LookupValue{
			{ApplyStatusPending, "Pending"},
			{ApplyStatusApplied, "Applied"},
			{ApplyStatusFailed, "Failed"},
			{ApplyStatusInconsistent, "Inconsistent"},
		}},
		{Name: "ReconcileStatus", Values: []LookupValue{
			{ReconcileStatusInSync, "InSync"},
			{ReconcileStatusDrifted, "Drifted"},
			{ReconcileStatusMissing, "Missing"},
			{ReconcileStatusUnmanaged, "Unmanaged"},
			{ReconcileStatusInconsistent, "Inconsistent"},
		}},
		{Name: "DiagnosticType", Values: []LookupValue{
			{DiagnosticTypePing, "Ping"},
			{DiagnosticTypeMtuProbe, "MtuProbe"},
			{DiagnosticTypeTraceroute, "Traceroute"},
			{DiagnosticTypeAnalyze, "Analyze"},
		}},
		{Name: "AddressFamily", Values: []LookupValue{
			{AddressFamilyIPv4, "IPv4"},
			{AddressFamilyIPv6, "IPv6"},
		}},
		{Name: "RouteProtocol", Values: []LookupValue{
			{RouteProtocolTCP, "TCP"},
			{RouteProtocolUDP, "UDP"},
			{RouteProtocolBoth, "Both"},
		}},
		{Name: "NatMode", Values: []LookupValue{
			{NatModeMasquerade, "Masquerade"},
			{NatModeSnat, "Snat"},
			{NatModeNone, "None"},
		}},
		{Name: "RouteMonitorMode", Values: []LookupValue{
			{RouteMonitorModeReport, "Report"},
			{RouteMonitorModeFailover, "Failover"},
		}},
		{Name: "LoadBalanceMode", Values: []LookupValue{
			{LoadBalanceModeNone, "None"},
			{LoadBalanceModeRoundRobin, "RoundRobin"},
			{LoadBalanceModeSourceHash, "SourceHash"},
			{LoadBalanceModeWeighted, "Weighted"},
		}},
		{Name: "RuleBackendType", Values: []LookupValue{
			{RuleBackendTypeNftables, "Nftables"},
			{RuleBackendTypeIptablesNft, "IptablesNft"},
			{RuleBackendTypeIptablesLegacy, "IptablesLegacy"},
		}},
		{Name: "AuditAction", Values: []LookupValue{
			{AuditActionLogin, "Login"},
			{AuditActionLoginFailed, "LoginFailed"},
			{AuditActionLogout, "Logout"},
			{AuditActionTunnelCreate, "TunnelCreate"},
			{AuditActionTunnelUpdate, "TunnelUpdate"},
			{AuditActionTunnelDelete, "TunnelDelete"},
			{AuditActionTunnelEnable, "TunnelEnable"},
			{AuditActionTunnelDisable, "TunnelDisable"},
			{AuditActionTunnelReapply, "TunnelReapply"},
			{AuditActionTunnelAdopt, "TunnelAdopt"},
			{AuditActionSettingUpdate, "SettingUpdate"},
			{AuditActionPasswordChange, "PasswordChange"},
			{AuditActionPoolChange, "PoolChange"},
			{AuditActionBackupImport, "BackupImport"},
			{AuditActionRouteCreate, "RouteCreate"},
			{AuditActionRouteUpdate, "RouteUpdate"},
			{AuditActionRouteDelete, "RouteDelete"},
			{AuditActionRouteEnable, "RouteEnable"},
			{AuditActionRouteDisable, "RouteDisable"},
			{AuditActionRouteReapply, "RouteReapply"},
			{AuditActionPanelAddressChange, "PanelAddressChange"},
			{AuditActionPasswordReset, "PasswordReset"},
			{AuditActionUsernameChange, "UsernameChange"},
			{AuditActionDatabaseDownload, "DatabaseDownload"},
			{AuditActionDatabaseRestore, "DatabaseRestore"},
			{AuditActionPanelUpdate, "PanelUpdate"},
		}},
	}
}

// LookupTableByName returns the declared lookup table with the given name.
// Settings of kind "lookup" reference lookup tables by name and are validated
// against the values declared here.
func LookupTableByName(name string) (LookupTable, bool) {
	for _, t := range LookupTables() {
		if t.Name == name {
			return t, true
		}
	}
	return LookupTable{}, false
}

// HasLookupValue reports whether id is a declared value of the named lookup table.
func HasLookupValue(table string, id int64) bool {
	t, ok := LookupTableByName(table)
	if !ok {
		return false
	}
	for _, v := range t.Values {
		if v.ID == id {
			return true
		}
	}
	return false
}
