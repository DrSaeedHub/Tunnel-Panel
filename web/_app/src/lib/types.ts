/**
 * TypeScript mirrors of the backend's JSON shapes.
 *
 * Every type here was read off the Go structs in `internal/`; nothing is
 * invented. Where the backend sends a pointer it is `| null` here, because the
 * difference between "unset" and "zero" is load-bearing throughout the panel —
 * a null monitoring override means inherit, not off.
 */

// ---------------------------------------------------------------- lookups

/** Fixed lookup identifiers, spaced by ten (internal/model/lookup.go). */
export const TunnelType = { GRE: 10, GRETAP: 20, IP6GRE: 30, IP6GRETAP: 40 } as const
export const TunnelSide = { A: 10, B: 20 } as const
export const PersistenceType = { Systemd: 10, Networkd: 20, Runtime: 30 } as const
export const MonitorState = {
  Unknown: 10,
  Up: 20,
  Degraded: 30,
  Down: 40,
  Disabled: 50,
} as const
export const ApplyStatus = {
  Pending: 10,
  Applied: 20,
  Failed: 30,
  Inconsistent: 40,
} as const
export const ReconcileStatus = {
  InSync: 10,
  Drifted: 20,
  Missing: 30,
  Unmanaged: 40,
  Inconsistent: 50,
} as const

export type MonitorStateId = (typeof MonitorState)[keyof typeof MonitorState]

// ---------------------------------------------------------------- auth

export interface User {
  user_id: number
  username: string
  is_active: boolean
  last_login_date: string | null
  created_date: string
}

export interface Session {
  user: User
  access_expires_at: string
  refresh_expires_at: string
  csrf_token: string
}

// ---------------------------------------------------------------- system

export interface BuildInfo {
  version: string
  commit: string
  date: string
}

export interface ComponentHealth {
  name: string
  status: string
  detail?: string
  data?: Record<string, unknown>
}

export interface HealthResponse {
  status: string
  version: string
  uptime_seconds: number
  setup_required: boolean
  components: ComponentHealth[]
  checked_at: string
}

export interface SystemInfo {
  build: BuildInfo
  runtime: {
    go_version: string
    os: string
    arch: string
    hostname: string
    pid: number
    uid: number
    is_root: boolean
    dev_mode: boolean
    uptime_seconds: number
  }
  paths: {
    data_dir: string
    database_path: string
    systemd_dir: string
    networkd_dir: string
    ip_bin: string
    systemctl_bin: string
  }
  serving: {
    bind_host: string
    bind_port: number
    web_path: string
    base_path: string
    api_base_path: string
  }
  kernel: { release: string; loaded_modules: Record<string, boolean> }
  started_at: string
}

export interface Capabilities {
  tunnel_types: {
    tunnel_type_id: number
    title: string
    supported: boolean
    link_manager: string
    note?: string
  }[]
  persistence: {
    persistence_type_id: number
    title: string
    available: boolean
    note?: string
  }[]
  link_managers: Record<string, unknown>
  tools: { name: string; path?: string; available: boolean }[]
  kernel: { release: string; loaded_modules: Record<string, boolean> }
  complete: boolean
}

// ---------------------------------------------------------------- settings

export type SettingKind = 'bool' | 'int' | 'float' | 'string' | 'enum' | 'json' | 'lookup'

/** One selectable value of a lookup-typed setting. */
export interface SettingOption {
  value: number
  label: string
}

export interface SettingConstraints {
  min?: number
  max?: number
  enum_values?: string[]
  lookup_table?: string
  /** Rows of `lookup_table`, resolved by the backend so a select can be built. */
  options?: SettingOption[]
  json_shape?: string
  pattern?: string
  nullable: boolean
}

export interface SettingSchemaEntry {
  key: string
  type: SettingKind
  category: string
  description: string
  default: unknown
  constraints: SettingConstraints
  restart_required: boolean
  unit?: string
  value: unknown
}

export interface SettingsSchemaResponse {
  settings: SettingSchemaEntry[]
  categories: string[]
}

export interface SettingsResponse {
  settings: Record<string, unknown>
}

// ---------------------------------------------------------------- tunnels

export interface TunnelAddress {
  tunnel_address_id: number
  tunnel_id: number
  address: string
  prefix_length: number
  peer_address: string | null
  address_family_id: number
  is_primary: boolean
  sort_order: number
  created_date: string
  updated_date: string
  is_deleted: boolean
}

export interface Tunnel {
  tunnel_id: number
  tunnel_type_id: number
  tunnel_side_id: number
  persistence_type_id: number
  interface_name: string
  display_name: string | null
  tunnel_number: number | null
  local_endpoint: string
  remote_endpoint: string
  bind_device: string | null

  ttl: number
  tos: string
  mtu: number
  ikey: number | null
  okey: number | null

  has_input_checksum: boolean
  has_output_checksum: boolean
  has_input_sequence: boolean
  has_output_sequence: boolean
  is_path_mtu_discovery: boolean
  is_ignore_df: boolean

  fwmark: number | null
  tx_queue_length: number | null
  hop_limit: number | null
  encap_limit: number | null
  traffic_class: string | null
  flow_label: string | null

  address_pool_id: number | null
  is_enabled: boolean
  is_managed: boolean
  is_name_templated: boolean

  apply_status_id: number
  last_applied_date: string | null
  last_apply_error: string | null

  note: string | null
  tags_json: string | null

  // Per-tunnel monitoring overrides; null means inherit from the global value.
  monitor_interval_seconds: number | null
  monitor_timeout_seconds: number | null
  monitor_packet_size: number | null
  monitor_window_size: number | null
  monitor_degraded_loss_percent: number | null
  monitor_down_loss_percent: number | null
  monitor_degraded_rtt_ms: number | null
  monitor_state_change_samples: number | null
  monitor_target: string | null
  is_monitor_enabled: boolean | null

  created_date: string
  updated_date: string
  is_deleted: boolean

  addresses: TunnelAddress[]
}

export interface ObservedLink {
  exists: boolean
  kind?: string
  index?: number
  mtu?: number
  oper_state?: string
  is_up: boolean
  is_lower_up: boolean
  flags?: string[]
  local_endpoint?: string
  remote_endpoint?: string
  addresses?: string[]
}

export interface TunnelResponse {
  tunnel: Tunnel
  observed: ObservedLink | null
}

export interface TunnelListResponse {
  tunnels: TunnelResponse[]
  total: number
  limit: number
  offset: number
}

export interface PlanStep {
  kind: string
  description: string
  interface?: string
  argv?: string[]
  path?: string
}

export interface PlannedFile {
  path: string
  content: string
  mode?: number
  action?: string
}

export interface ValidationWarning {
  code: string
  message: string
  field?: string
}

export interface Plan {
  operation: string
  interface: string
  tunnel_id?: number
  steps: PlanStep[]
  rollback: PlanStep[]
  files: PlannedFile[]
  requires_recreate: boolean
  recreate_reasons?: string[]
  warnings?: ValidationWarning[]
  verification?: string[]
}

export interface VerifyCheck {
  name: string
  ok: boolean
  detail?: string
  expected?: string
  actual?: string
  fatal: boolean
  skipped?: boolean
}

export interface VerifyReport {
  ok: boolean
  checks: VerifyCheck[]
  failures?: string[]
  oper_state?: string
}

export interface MtuTerm {
  label: string
  bytes: number
  detail?: string
}

export interface MtuAdvice {
  requested: number
  overhead: number
  underlay_mtu: number
  underlay_device?: string
  recommended: number
  matches: boolean
  breakdown: MtuTerm[]
}

export interface Diff {
  field: string
  from: string
  to: string
  in_place: boolean
  describe?: string
}

export interface Warning {
  code: string
  message: string
  field?: string
}

export interface CreateResponse {
  tunnel: Tunnel
  plan: Plan
  verification: VerifyReport
  warnings: Warning[]
}

export interface PreviewResponse {
  plan: Plan
  mtu: MtuAdvice
  warnings: Warning[]
  diffs?: Diff[]
  tunnel: Tunnel
}

export interface ActionResponse {
  action: string
  tunnel: Tunnel
  plan: Plan
  verification: VerifyReport
  warnings: Warning[]
}

export interface DeleteReport {
  tunnel_id: number
  interface: string
  plan: Plan
  interface_found: boolean
  files_removed: string[]
  files_absent: string[]
}

export interface SideRole {
  slot: string
  label: string
  endpoints: string
  address_in_subnet: string
  name_substitution: string
}

export interface SideInfo {
  summary: string
  sides: SideRole[]
  identical_on_both_ends: string[]
  tunnel_side_ids: Record<string, number>
}

export interface PairingCodeResponse {
  pairing_code: string
  summary: Record<string, unknown>
  note: string
}

export interface TunnelInput {
  tunnel_id?: number
  tunnel_type_id: number
  tunnel_side_id: number
  persistence_type_id: number
  interface_name: string
  display_name?: string
  tunnel_number: number | null
  local_endpoint: string
  remote_endpoint: string
  bind_device?: string
  ttl: number
  tos: string
  mtu: number
  ikey: number | null
  okey: number | null
  has_input_checksum: boolean
  has_output_checksum: boolean
  has_input_sequence: boolean
  has_output_sequence: boolean
  is_path_mtu_discovery: boolean
  is_ignore_df: boolean
  fwmark: number | null
  tx_queue_length: number | null
  hop_limit: number | null
  encap_limit: number | null
  traffic_class?: string
  flow_label?: string
  address_pool_id: number | null
  addresses: AddressInput[]
  is_enabled: boolean
  force?: boolean
}

export interface AddressInput {
  address: string
  prefix_length: number
  peer_address?: string
  is_primary: boolean
}

export interface FromPairingCodeResponse {
  tunnel: TunnelInput
  summary: Record<string, unknown>
  note: string
}

// ---------------------------------------------------------------- pools

export interface Pool {
  address_pool_id: number
  address_pool_title: string
  cidr: string
  prefix_length: number
  is_public_range: boolean
  is_enabled: boolean
  description: string
}

export interface PoolCapacity {
  address_pool_id: number
  scheme: string
  prefix_length: number
  capacity: number
  max_tunnel_number: number
  is_public_range: boolean
  error?: string
}

export interface PoolResponse extends Pool {
  capacity: PoolCapacity
  in_use: number
}

// ---------------------------------------------------------------- monitoring

export interface MonitorStats {
  sent: number
  received: number
  lost: number
  pending: number
  loss_percent: number
  rtt_min_ms: number | null
  rtt_avg_ms: number | null
  rtt_max_ms: number | null
  rtt_mdev_ms: number | null
  jitter_ms: number | null
  last_rtt_ms: number | null
  last_reply_at: string | null
  last_error?: string
}

export interface MonitorSnapshot {
  tunnel_id: number
  interface_name: string
  monitor_state_id: number
  state: string
  reason?: string
  stats: MonitorStats
  source?: string
  target?: string
  enabled: boolean
  since: string
  updated_at: string
}

export interface MonitorEvent {
  monitor_event_id: number
  tunnel_id: number
  from_monitor_state_id: number
  to_monitor_state_id: number
  from_state: string
  to_state: string
  reason: string
  loss_percent: number | null
  rtt_avg_ms: number | null
  created_date: string
}

export interface MonitorStatusResponse extends MonitorSnapshot {
  events: MonitorEvent[]
}

export interface MonitorSummaryResponse {
  tunnels: MonitorSnapshot[]
  total: number
  counts: Record<string, number>
  running: number
}

export interface MonitorHistoryPoint {
  bucket_start: string
  sent_count: number
  received_count: number
  loss_percent: number
  rtt_min_ms: number | null
  rtt_avg_ms: number | null
  rtt_max_ms: number | null
  jitter_ms: number | null
  worst_monitor_state_id: number
  worst_state: string
  samples: number
}

export interface MonitorHistoryResponse {
  tunnel_id: number
  points: MonitorHistoryPoint[]
  total: number
  resolution_seconds: number
}

// ---------------------------------------------------------------- metrics

export interface CpuUsage {
  name: string
  usage_percent: number
  user_percent: number
  system_percent: number
  iowait_percent: number
  steal_percent: number
  idle_percent: number
  nice_percent?: number
  irq_percent?: number
  softirq_percent?: number
}

export interface LoadAverage {
  one: number
  five: number
  fifteen: number
  running_entities: number
  total_entities: number
}

export interface Memory {
  total_bytes: number
  free_bytes: number
  available_bytes: number
  buffers_bytes: number
  cached_bytes: number
  used_bytes: number
  used_percent: number
  unavailable_bytes: number
  unavailable_percent: number
}

export interface Swap {
  configured: boolean
  total_bytes: number
  free_bytes: number
  used_bytes: number
  used_percent: number
}

export interface Disk {
  device: string
  mount_point: string
  fs_type: string
  options?: string
  is_pseudo: boolean
  total_bytes: number
  used_bytes: number
  available_bytes: number
  used_percent: number
  inodes_total: number
  inodes_used: number
  inodes_free: number
  inodes_used_percent: number
  error?: string
}

export interface InterfaceCounters {
  rx_bytes: number
  tx_bytes: number
  rx_packets: number
  tx_packets: number
  rx_errors: number
  tx_errors: number
  rx_dropped: number
  tx_dropped: number
}

export interface NetInterface {
  name: string
  index: number
  class: string
  is_loopback: boolean
  kind?: string
  mtu?: number
  oper_state?: string
  is_up: boolean
  flags?: string[]
  primary_address?: string
  addresses?: string[]
  counters: InterfaceCounters
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  rx_bytes_since_boot: number
  tx_bytes_since_boot: number
  rx_bytes_since_install: number
  tx_bytes_since_install: number
}

export interface NetworkTotals {
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  rx_bytes_since_boot: number
  tx_bytes_since_boot: number
  rx_bytes_since_install: number
  tx_bytes_since_install: number
}

/**
 * One forwarding rule's live relay traffic, multiplexed into the metrics
 * stream rather than carried on a second one.
 */
export interface RelayTraffic {
  route_rule_id: number
  title: string
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  /** The kernel's own counters, zeroed by every rebuild of the ruleset. */
  rx_bytes_since_boot: number
  tx_bytes_since_boot: number
  /** The panel's totals, folded across those resets. Never added to the above. */
  rx_bytes_since_creation: number
  tx_bytes_since_creation: number
  active_connections: number
  new_connections_per_second: number
}

export interface RelayTotals {
  routes: number
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  active_connections: number
}

export interface MetricsSnapshot {
  at: string
  cpu: CpuUsage[]
  load: LoadAverage
  memory: Memory
  swap: Swap
  disks: Disk[]
  network: { interfaces: NetInterface[]; totals: NetworkTotals }
  /** Absent on an instance with no forwarding rules, rather than empty. */
  routes?: RelayTraffic[]
  route_totals: RelayTotals
  interval_seconds: number
  errors?: string[]
}

export interface MetricsHistoryResponse {
  points: MetricsSnapshot[]
  total: number
}

// ---------------------------------------------------------------- diagnostics

export interface DiagnosticRun {
  diagnostic_run_id: number
  tunnel_id: number | null
  diagnostic_type_id: number
  type: string
  params: unknown
  result?: unknown
  started_date: string
  finished_date?: string
  is_success: boolean
  running: boolean
}

export interface PingPacket {
  sequence: number
  success: boolean
  rtt_ms?: number
  size?: number
  from?: string
  kind?: string
  error?: string
  at: string
}

export interface PingSummary {
  sent: number
  received: number
  loss_percent: number
  rtt_min_ms: number | null
  rtt_avg_ms: number | null
  rtt_max_ms: number | null
  rtt_mdev_ms: number | null
  jitter_ms: number | null
  reported_mtu?: number
  too_large_to_send?: boolean
  answered_by?: string[]
  packets?: PingPacket[]
}

export interface PingResult {
  cancelled: boolean
  source: string
  target: string
  summary: PingSummary
}

export interface Evidence {
  name: string
  detail: string
  data?: unknown
}

export interface AnalyzeResult {
  verdict: string
  confidence: string
  summary: string
  suggested_fix?: string[]
  evidence: Evidence[]
  checked_at: string
}

export interface MtuStep {
  packet_size: number
  fits: boolean
  detail?: string
  reported_mtu?: number
}

export interface MtuResult {
  source: string
  target: string
  path: string
  discovered_path_mtu: number
  reported_path_mtu?: number
  recommended_tunnel_mtu: number
  current_tunnel_mtu: number
  overhead: number
  matches: boolean
  steps: MtuStep[]
  detail: string
  applied: boolean
}

export interface MtuProbeResponse {
  result: MtuResult
  run?: DiagnosticRun
  apply?: { method: string; path: string; body: Record<string, unknown> }
}

export interface Hop {
  ttl: number
  addresses?: string[]
  rtts_ms?: number[]
  reached: boolean
  timeout: boolean
  detail?: string
}

export interface TracerouteResult {
  source: string
  target: string
  path: string
  hops: Hop[]
  reached: boolean
  detail: string
}

export interface CountersResponse {
  interface_name: string
  counters: InterfaceCounters
  deltas: InterfaceCounters
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  interval_seconds: number
  sampled_at: string
}

// ---------------------------------------------------------------- reconcile

export interface FieldDiff {
  field: string
  expected: string
  observed: string
}

export interface ReconcileItem {
  tunnel_id?: number
  interface_name: string
  reconcile_status_id: number
  status: string
  detail: string
  diffs?: FieldDiff[]
  observed?: Record<string, unknown>
  legacy?: Record<string, unknown>
  actions: string[]
  is_ignored: boolean
}

/** One line of the forwarding half of the reconcile report. */
export interface ReconcileRouteItem {
  route_rule_id?: number
  title: string
  reconcile_status_id: number
  status: string
  detail: string
  diffs?: FieldDiff[]
  actions: string[]
  /** How many rules the panel intends for this row, and how many exist. */
  expected_rules: number
  installed_rules: number
  /** Foreign rules claiming this one's traffic. Reported, never removed. */
  shadows?: ForeignRule[]
}

/** What the forwarding half observed about the host rather than one rule. */
export interface ReconcileRouteFindings {
  backend: string
  readable: boolean
  detail?: string
  enabled_rules: number
  ip_forwarding_enabled: boolean
  ip_forwarding_expected: boolean
  ip_forwarding_panel_managed: boolean
  missing_jumps?: string[]
  foreign_readable: boolean
  foreign_managers?: string[]
  foreign_shadows?: (ForeignRule & { shadows_route_rule_ids: number[] })[]
  notes?: string[]
}

export interface ReconcileReport {
  checked_at: string
  items: ReconcileItem[]
  counts: Record<string, number>
  routes: ReconcileRouteItem[]
  route_counts: Record<string, number>
  route_findings: ReconcileRouteFindings
}

// ---------------------------------------------------------------- audit

export interface AuditEntry {
  audit_log_id: number
  audit_action_id: number
  action: string
  user_id: number | null
  username?: string
  target_type: string
  target_id: string
  request: unknown
  operations: unknown
  is_success: boolean
  error_message?: string
  duration_ms: number
  client_ip: string
  created_date: string
}

export interface AuditResponse {
  entries: AuditEntry[]
  total: number
  limit: number
  offset: number
  actions: string[]
}

// ---------------------------------------------------------------- interfaces

export interface HostInterface {
  name: string
  index: number
  mtu: number
  kind?: string
  oper_state?: string
  flags?: string[]
  is_up: boolean
  is_lower_up: boolean
  is_running?: boolean
  addresses?: { address: string; prefix_length: number; family: string }[]
  class: string
}

export interface InterfacesResponse {
  interfaces: HostInterface[]
  total: number
}

export interface Route {
  destination: string
  gateway?: string
  device: string
  is_default: boolean
  protocol?: string
}

export interface RoutesResponse {
  routes: Route[]
  total: number
  default_route_devices: string[]
}

// ---------------------------------------------------------------- backup

export interface BackupImportAction {
  kind: string
  target: string
  action: string
  detail?: string
  error?: string
}

export interface BackupImportResponse {
  actions: BackupImportAction[]
  dry_run?: boolean
  applied?: boolean
}

// ---------------------------------------------------------------- forwarding
//
// The port forwarding subsystem. `Route` above is a kernel routing-table entry
// from `/system/routes` and is a different thing entirely; a forwarding rule is
// a `RouteRule` here as it is in the database.

/** Fixed lookup identifiers for forwarding (internal/model/lookup.go). */
export const RouteProtocol = { TCP: 10, UDP: 20, Both: 30 } as const
export const NatMode = { Masquerade: 10, Snat: 20, None: 30 } as const
export const LoadBalanceMode = { None: 10, RoundRobin: 20, SourceHash: 30, Weighted: 40 } as const
export const AddressFamily = { IPv4: 10, IPv6: 20 } as const

/**
 * A rule's state as the panel reports it.
 *
 * `impaired` is the one that matters: the rules are installed exactly as
 * intended and the tunnel they relay over is down, so the rule is neither
 * healthy nor broken and must not be presented as either.
 */
export type RouteHealthState =
  | 'disabled'
  | 'pending'
  | 'healthy'
  | 'impaired'
  | 'failed'
  | 'inconsistent'

export interface RouteDestination {
  route_destination_id: number
  route_rule_id: number
  address: string
  port: number
  port_range_end: number | null
  weight: number
  is_enabled: boolean
  sort_order: number
  created_date: string
  updated_date: string
  is_deleted: boolean
}

export interface RouteAllowedSource {
  route_allowed_source_id: number
  route_rule_id: number
  cidr: string
  description: string
  created_date: string
  updated_date: string
  is_deleted: boolean
}

export interface RouteRule {
  route_rule_id: number
  route_rule_title: string
  description: string

  route_protocol_id: number
  address_family_id: number

  bind_address: string
  bind_port: number
  bind_port_range_end: number | null
  bind_interface: string | null

  destination_address: string
  destination_port: number
  destination_port_range_end: number | null

  nat_mode_id: number
  snat_address: string | null
  load_balance_mode_id: number

  tunnel_id: number | null

  is_clamp_mss_to_pmtu: boolean
  is_include_local_originated: boolean
  is_logging_enabled: boolean
  fwmark: number | null

  max_connections_per_source: number | null
  connection_rate_limit: number | null

  is_enabled: boolean
  apply_status_id: number
  last_applied_date: string | null
  last_apply_error: string | null

  sort_order: number
  tags_json: string | null

  created_date: string
  updated_date: string
  is_deleted: boolean

  destinations: RouteDestination[]
  allowed_sources: RouteAllowedSource[]
}

/** The health of the tunnel a rule relays over, when it has one. */
export interface RouteTunnelHealth {
  tunnel_id: number
  interface_name: string
  is_enabled: boolean
  /** The kernel's UP and LOWER_UP flags, never the operational state. */
  is_up: boolean
  monitor_state?: string
  peer_address?: string
  addresses?: string[]
}

export interface RouteHealth {
  route_rule_id: number
  state: RouteHealthState
  detail: string
  /** Whether the rule's rules are in the kernel now. */
  installed: boolean
  tunnel?: RouteTunnelHealth
}

/**
 * One rule's live accounting.
 *
 * The two sets of byte figures are never added together. The since-boot ones
 * are the kernel's own counters, zeroed by every rebuild of the ruleset; the
 * since-creation ones are the panel's, folded across those resets.
 */
export interface RouteTraffic {
  route_rule_id: number
  title: string
  at: string
  interval_seconds: number

  rx_bytes_per_second: number
  tx_bytes_per_second: number
  rx_packets_per_second: number
  tx_packets_per_second: number

  rx_bytes_since_boot: number
  tx_bytes_since_boot: number
  rx_packets_since_boot: number
  tx_packets_since_boot: number

  rx_bytes_since_creation: number
  tx_bytes_since_creation: number
  rx_packets_since_creation: number
  tx_packets_since_creation: number

  active_connections: number
  new_connections_per_second: number

  reset_detected: boolean
}

/** One entry of the in-memory ring buffer, for the sparklines. */
export interface RouteTrafficPoint {
  at: string
  interval_seconds: number
  rx_bytes: number
  tx_bytes: number
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  active_connections: number
}

/** One stored aggregate bucket, holding what moved in that interval. */
export interface RouteTrafficSample {
  route_rule_id: number
  bucket_start_date: string
  rx_bytes: number
  tx_bytes: number
  rx_packets: number
  tx_packets: number
  active_connections: number
  new_connections: number
}

export interface RouteTrafficSummary {
  routes: number
  rx_bytes_per_second: number
  tx_bytes_per_second: number
  rx_bytes_since_creation: number
  tx_bytes_since_creation: number
  active_connections: number
  at: string
}

export interface RouteResponse {
  route: RouteRule
  health: RouteHealth
  traffic?: RouteTraffic
}

export interface RouteListResponse {
  routes: RouteResponse[]
  total: number
  limit: number
  offset: number
  /** Explains the two sets of byte figures wherever they are returned. */
  note: string
}

export interface RulePayloadPart {
  kind: string
  path: string
  text: string
  argv: string[]
}

export interface RulePayload {
  backend: string
  parts: RulePayloadPart[]
  assertions?: { description: string; check: string[]; install: string[] }[]
}

export interface RoutePlanStep {
  kind: string
  description: string
  argv?: string[]
  path?: string
  content?: string
  unit?: string
  payload?: RulePayload
  tolerate?: boolean
}

export interface RoutePlannedFile {
  kind: string
  path: string
  content: string
}

export interface RoutePlan {
  operation: string
  route_rule_id?: number
  title?: string
  backend: string
  steps: RoutePlanStep[]
  rollback: RoutePlanStep[]
  files: RoutePlannedFile[]
  affected_route_rule_ids?: number[]
  warnings?: ValidationWarning[]
  verification?: string[]
}

export interface RouteVerifyReport {
  ok: boolean
  checks: VerifyCheck[]
  failures?: string[]
  backend?: string
  rule_count: number
}

export interface RouteResultResponse {
  route: RouteRule
  plan: RoutePlan
  verification: RouteVerifyReport
  warnings: Warning[]
}

export interface RouteActionResponse {
  action: string
  route: RouteRule
  plan: RoutePlan
  verification: RouteVerifyReport
  warnings: Warning[]
}

export interface RoutePreviewResponse {
  plan: RoutePlan
  route: RouteRule
  /** The exact ruleset that would be submitted, rendered for reading. */
  payload: string
  warnings: Warning[]
  note: string
}

export interface RouteDeleteReport {
  route_rule_id: number
  title: string
  plan: RoutePlan
  verification: RouteVerifyReport
  /** The panel turned forwarding on and this was the last rule. An offer only. */
  forwarding_can_be_reverted: boolean
  note?: string
}

export interface RouteDuplicateResponse {
  route: RouteRule
  plan: RoutePlan
  verification: RouteVerifyReport
  warnings: Warning[]
  note: string
}

/** One live connection through a relay, as connection tracking sees it. */
export interface RouteFlow {
  protocol: string
  source_address: string
  source_port: number
  bind_address: string
  bind_port: number
  destination_address: string
  destination_port: number
  /** Empty for UDP, which has no transport state to report. */
  state?: string
  age_seconds?: number
  timeout_seconds?: number
  tx_bytes: number
  rx_bytes: number
  tx_packets: number
  rx_packets: number
  mark?: number
}

export interface RouteConnectionList {
  route_rule_id: number
  reader: string
  /** False means the table could not be read — not that nobody is using it. */
  available: boolean
  detail?: string
  connections: RouteFlow[]
  total: number
  by_source?: Record<string, number>
  new_per_second: number
  checked_at: string
}

export interface RouteCounterReport {
  route_rule_id: number
  rx_bytes_since_boot: number
  tx_bytes_since_boot: number
  rx_packets_since_boot: number
  tx_packets_since_boot: number
  rx_bytes_since_creation: number
  tx_bytes_since_creation: number
  /** Whether the rule has matched anything since the ruleset was last built. */
  hit: boolean
  source: string
  note: string
  checked_at: string
}

export interface RouteReachabilityResult {
  address: string
  port: number
  protocol: string
  /** True only when something answered. */
  reachable: boolean
  /** False means the probe proves nothing either way, which UDP silence does. */
  conclusive: boolean
  latency_ms?: number
  detail: string
  error?: string
  checked_at: string
}

export interface RouteAnalyzeResult {
  route_rule_id: number
  title: string
  verdict: string
  confidence: string
  summary: string
  suggested_fix?: string[]
  evidence: Evidence[]
  checked_at: string
}

export interface ForwardingStatus {
  ipv4_forwarding: boolean
  ipv6_forwarding: boolean
  panel_managed: boolean
  sysctl_path: string
  previous_values?: Record<string, string>
  can_revert: boolean
  conntrack_count: number
  conntrack_max: number
  conntrack_usage_percent: number
  backend?: string
  namespace?: string
  warnings?: ValidationWarning[]
}

export interface ForeignRule {
  table: string
  chain: string
  text: string
  protocol?: string
  address?: string
  port?: number
  port_end?: number
  manager?: string
}

export interface ForwardingResponse {
  forwarding: ForwardingStatus
  warnings: Warning[]
  backend: Record<string, unknown>
  foreign: {
    readable: boolean
    detail?: string
    managers?: string[]
    rules?: ForeignRule[]
    total?: number
  }
}

/** A forwarding rule that relays over a tunnel, for the tunnel detail page. */
export interface DependentRoute {
  route_rule_id: number
  title: string
  protocol: string
  bind: string
  destination: string
  is_enabled: boolean
}

export interface TunnelRoutesResponse {
  tunnel_id: number
  interface: string
  /** What a new rule's destination is prefilled with. */
  peer_address: string
  routes: DependentRoute[]
  total: number
  note: string
}

/**
 * The create/update body.
 *
 * Every field is optional: on create what is absent takes its default from the
 * `routes.*` settings, and on update what is absent keeps the value the rule
 * already has.
 */
export interface RouteInput {
  route_rule_id?: number
  route_rule_title?: string
  description?: string
  route_protocol_id?: number
  address_family_id?: number
  bind_address?: string
  bind_port?: number
  bind_port_range_end?: number
  bind_interface?: string
  destination_address?: string
  destination_port?: number
  destination_port_range_end?: number
  nat_mode_id?: number
  snat_address?: string
  load_balance_mode_id?: number
  tunnel_id?: number | null
  is_clamp_mss_to_pmtu?: boolean
  is_include_local_originated?: boolean
  is_logging_enabled?: boolean
  fwmark?: number | null
  max_connections_per_source?: number | null
  connection_rate_limit?: number | null
  is_enabled?: boolean
  sort_order?: number
  destinations?: RouteDestinationInput[]
  allowed_sources?: RouteAllowedSourceInput[]
  force?: boolean
}

export interface RouteDestinationInput {
  route_destination_id?: number
  address: string
  port: number
  port_range_end?: number
  weight?: number
  is_enabled: boolean
  sort_order?: number
}

export interface RouteAllowedSourceInput {
  route_allowed_source_id?: number
  cidr: string
  description?: string
}

/**
 * Where the panel serves itself: GET /system/address.
 *
 * `web_path` is always present and may be the empty string, which means the
 * panel is served at the root. It is deliberately not optional — an absent
 * field and an empty one would be indistinguishable to a caller, and this is a
 * configuration with a meaning rather than a value that might be missing.
 */
export interface PanelAddress {
  bind_host: string
  port: number
  web_path: string
  base_path: string
  url: string
  sources: { port: string; web_path: string }
  /** Present only when the configured port could not be bound. */
  fallback?: {
    wanted_port: number
    serving_port: number
    reason: string
    at: string
  }
  can_apply: boolean
  cannot_apply_why?: string
  protected_ports: { port: number; reason: string; process?: string }[]
  env_file: {
    path: string
    port: number
    web_path: string
    disagrees: boolean
  }
}

/**
 * The answer to POST /system/address, which arrives before the restart it
 * describes. Everything the operator needs in order to find the panel again is
 * in here, because the connection that carried it is about to close.
 */
export interface PanelAddressChange {
  url: string
  previous_url: string
  port: number
  web_path: string
  health_url: string
  restarting: boolean
  /** False when the change moves the cookie path, so signing in again is expected. */
  session_survives: boolean
  detail: string
}
