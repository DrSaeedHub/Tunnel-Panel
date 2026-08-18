import { useMemo, useState } from 'react'
import { Link, useOutletContext, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  ChevronDown,
  Download,
  Loader2,
  MoreHorizontal,
  Plus,
  RefreshCw,
  Search,
  Trash2,
} from 'lucide-react'

import { api } from '@/lib/api'
import {
  ApplyStatus,
  MonitorState,
  PersistenceType,
  TunnelSide,
  type MonitorSnapshot,
  type Tunnel,
  type TunnelInput,
  type TunnelListResponse,
  type TunnelResponse,
} from '@/lib/types'
import { formatMs, formatPercent } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useTunnelActions } from '@/hooks/useTunnelActions'
import type { useMonitorSummary } from '@/hooks/useMonitorSummary'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Checkbox, Input, Select } from '@/components/ui/form'
import { Badge, EmptyState, ErrorState, Skeleton } from '@/components/ui/feedback'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/overlay'
import { ApplyStatusBadge, StatusPill, monitorStateKey } from '@/components/ui/status'
import { Technical } from '@/components/ui/technical'
import { cn } from '@/lib/utils'
import { TunnelFormDialog } from '@/components/tunnels/TunnelFormDialog'
import { DeleteTunnelDialog } from '@/components/tunnels/DeleteTunnelDialog'
import { ImportPairingCodeDialog, PairingCodeDialog } from '@/components/tunnels/PairingDialogs'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

type MonitorContext = ReturnType<typeof useMonitorSummary>
type SortKey = 'name' | 'status' | 'type' | 'side'

export default function TunnelsPage() {
  const { t } = useTranslation()
  const monitor = useOutletContext<MonitorContext>()
  const actions = useTunnelActions()

  // Filters, sort and expansion live in the URL, so a view is shareable and
  // survives a reload — an operator can send a colleague "the down ones".
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const statusFilter = params.get('status') ?? ''
  const typeFilter = params.get('type') ?? ''
  const sideFilter = params.get('side') ?? ''
  const applyFilter = params.get('apply') ?? ''
  const sortKey = (params.get('sort') as SortKey) ?? 'name'
  const expandedId = params.get('expanded')

  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [formOpen, setFormOpen] = useState(params.get('create') === '1')
  const [editing, setEditing] = useState<Tunnel | null>(null)
  const [prefill, setPrefill] = useState<TunnelInput | null>(null)
  const [deleting, setDeleting] = useState<Tunnel | null>(null)
  const [pairingFor, setPairingFor] = useState<number | null>(null)
  const [importOpen, setImportOpen] = useState(false)

  useDocumentTitle(t('tunnels.title'))

  const listQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 10_000,
  })

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const rows = useMemo(() => {
    const entries = listQuery.data?.tunnels ?? []
    const needle = search.trim().toLowerCase()

    const filtered = entries.filter((entry) => {
      const tunnel = entry.tunnel
      const snapshot = monitor.byTunnel.get(tunnel.tunnel_id)

      if (needle) {
        const haystack = [
          tunnel.interface_name,
          tunnel.display_name ?? '',
          tunnel.local_endpoint,
          tunnel.remote_endpoint,
          ...(tunnel.addresses ?? []).map((address) => address.address),
          ...(tunnel.addresses ?? []).map((address) => address.peer_address ?? ''),
        ]
          .join(' ')
          .toLowerCase()
        if (!haystack.includes(needle)) return false
      }

      if (statusFilter && monitorStateKey(snapshot?.monitor_state_id ?? MonitorState.Unknown) !== statusFilter) {
        return false
      }
      if (typeFilter && String(tunnel.tunnel_type_id) !== typeFilter) return false
      if (sideFilter && String(tunnel.tunnel_side_id) !== sideFilter) return false
      if (applyFilter === 'inconsistent' && tunnel.apply_status_id !== ApplyStatus.Inconsistent) return false

      return true
    })

    return [...filtered].sort((a, b) => {
      if (sortKey === 'status') {
        const left = monitor.byTunnel.get(a.tunnel.tunnel_id)?.monitor_state_id ?? MonitorState.Unknown
        const right = monitor.byTunnel.get(b.tunnel.tunnel_id)?.monitor_state_id ?? MonitorState.Unknown
        // Worst first: Down before Degraded before Up.
        return right - left
      }
      if (sortKey === 'type') return a.tunnel.tunnel_type_id - b.tunnel.tunnel_type_id
      if (sortKey === 'side') return a.tunnel.tunnel_side_id - b.tunnel.tunnel_side_id
      const left = a.tunnel.display_name || a.tunnel.interface_name
      const right = b.tunnel.display_name || b.tunnel.interface_name
      return left.localeCompare(right)
    })
  }, [listQuery.data, monitor.byTunnel, search, statusFilter, typeFilter, sideFilter, applyFilter, sortKey])

  const total = listQuery.data?.total ?? 0
  const filtersActive = Boolean(search || statusFilter || typeFilter || sideFilter || applyFilter)

  const toggleSelected = (id: number) =>
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const openCreate = () => {
    setEditing(null)
    setPrefill(null)
    setFormOpen(true)
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-0 flex-1 sm:max-w-xs">
          <Search
            className="pointer-events-none absolute top-1/2 size-4 -translate-y-1/2 text-muted-foreground [inset-inline-start:0.625rem]"
            aria-hidden="true"
          />
          <Input
            data-shortcut="search"
            value={search}
            onChange={(event) => setParam('q', event.target.value)}
            placeholder={t('tunnels.search')}
            aria-label={t('tunnels.search')}
            className="rounded-full [padding-inline-start:2.25rem]"
          />
        </div>

        <Select
          value={statusFilter}
          onValueChange={(value) => setParam('status', value === 'all' ? '' : value)}
          aria-label={t('tunnels.filter.status')}
          className="w-auto min-w-32"
          options={[
            { value: 'all', label: t('tunnels.filter.all') },
            ...(['Up', 'Degraded', 'Down', 'Unknown', 'Disabled'] as const).map((key) => ({
              value: key,
              label: t(`monitor.state.${key}`),
            })),
          ]}
        />

        <Select
          value={sideFilter}
          onValueChange={(value) => setParam('side', value === 'all' ? '' : value)}
          aria-label={t('tunnels.filter.side')}
          className="w-auto min-w-24"
          options={[
            { value: 'all', label: t('tunnels.filter.all') },
            { value: String(TunnelSide.A), label: t('tunnel.side.a') },
            { value: String(TunnelSide.B), label: t('tunnel.side.b') },
          ]}
        />

        {filtersActive ? (
          <Button variant="ghost" size="sm" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
            {t('actions.clearFilters')}
          </Button>
        ) : null}

        <div className="ms-auto flex items-center gap-2">
          <Button variant="secondary" onClick={() => setImportOpen(true)}>
            <Download className="size-4" aria-hidden="true" />
            <span className="hidden sm:inline">{t('actions.importFromPairingCode')}</span>
          </Button>
          <Button variant="primary" onClick={openCreate} data-shortcut="create">
            <Plus className="size-4" aria-hidden="true" />
            {t('actions.createTunnel')}
          </Button>
        </div>
      </div>

      {selected.size ? (
        <BulkBar
          count={selected.size}
          onClear={() => setSelected(new Set())}
          onAction={async (action) => {
            const chosen = rows.filter((row) => selected.has(row.tunnel.tunnel_id))
            for (const row of chosen) {
              await actions.run(row.tunnel.tunnel_id, action, row.tunnel.interface_name)
            }
            setSelected(new Set())
          }}
        />
      ) : null}

      {listQuery.isLoading ? (
        <TableSkeleton />
      ) : listQuery.error ? (
        <ErrorState error={listQuery.error} onRetry={() => void listQuery.refetch()} />
      ) : !total ? (
        <Card>
          <CardContent>
            <EmptyState
              illustration="empty-tunnels"
              title={t('tunnels.emptyTitle')}
              body={t('tunnels.emptyBody')}
              action={
                <div className="flex flex-wrap justify-center gap-2">
                  <Button variant="primary" onClick={openCreate}>
                    <Plus className="size-4" aria-hidden="true" />
                    {t('actions.createTunnel')}
                  </Button>
                  <Button variant="secondary" onClick={() => setImportOpen(true)}>
                    <Download className="size-4" aria-hidden="true" />
                    {t('actions.importFromPairingCode')}
                  </Button>
                </div>
              }
            />
          </CardContent>
        </Card>
      ) : !rows.length ? (
        <Card>
          <CardContent>
            <EmptyState
              illustration="empty-search"
              title={t('tunnels.noMatchTitle')}
              body={t('tunnels.noMatchBody')}
              action={
                <Button variant="secondary" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
                  {t('actions.clearFilters')}
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : (
        <>
          {filtersActive ? (
            <p className="text-xs text-muted-foreground">
              {t('tunnels.filter.applied', { count: rows.length, total })}
            </p>
          ) : null}

          <Card className="overflow-hidden">
            <table className="w-full border-collapse text-sm">
              <caption className="sr-only">{t('tunnels.title')}</caption>
              <thead className="display hidden border-b border-border bg-surface-sunken/70 text-2xs font-semibold text-muted-foreground md:table-header-group">
                <tr>
                  <th scope="col" className="w-8 p-2" />
                  <SortableHeader label={t('tunnels.columns.status')} sortKey="status" active={sortKey} onSort={setParam} />
                  <SortableHeader label={t('tunnels.columns.name')} sortKey="name" active={sortKey} onSort={setParam} />
                  <th scope="col" className="p-2 text-start font-medium">
                    {t('tunnels.columns.endpoints')}
                  </th>
                  <th scope="col" className="p-2 text-start font-medium">
                    {t('tunnels.columns.addresses')}
                  </th>
                  <th scope="col" className="p-2 text-start font-medium">
                    {t('tunnels.columns.health')}
                  </th>
                  <th scope="col" className="w-10 p-2">
                    <span className="sr-only">{t('tunnels.columns.actions')}</span>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows.map((row) => (
                  <TunnelRow
                    key={row.tunnel.tunnel_id}
                    entry={row}
                    snapshot={monitor.byTunnel.get(row.tunnel.tunnel_id)}
                    selected={selected.has(row.tunnel.tunnel_id)}
                    onSelect={() => toggleSelected(row.tunnel.tunnel_id)}
                    expanded={expandedId === String(row.tunnel.tunnel_id)}
                    onToggleExpand={() =>
                      setParam('expanded', expandedId === String(row.tunnel.tunnel_id) ? '' : String(row.tunnel.tunnel_id))
                    }
                    busy={actions.pending === row.tunnel.tunnel_id}
                    onAction={(action) => void actions.run(row.tunnel.tunnel_id, action, row.tunnel.interface_name)}
                    onEdit={() => {
                      setEditing(row.tunnel)
                      setPrefill(null)
                      setFormOpen(true)
                    }}
                    onDelete={() => setDeleting(row.tunnel)}
                    onPairingCode={() => setPairingFor(row.tunnel.tunnel_id)}
                  />
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}

      <TunnelFormDialog
        open={formOpen}
        onOpenChange={(open) => {
          setFormOpen(open)
          if (!open) {
            setEditing(null)
            setPrefill(null)
            setParam('create', '')
          }
        }}
        tunnel={editing ?? undefined}
        initial={prefill ?? undefined}
        onCreated={(created) => setPairingFor(created.tunnel_id)}
      />

      {deleting ? (
        <DeleteTunnelDialog
          tunnel={deleting}
          open={Boolean(deleting)}
          onOpenChange={(open) => !open && setDeleting(null)}
        />
      ) : null}

      {pairingFor ? (
        <PairingCodeDialog
          tunnelId={pairingFor}
          open={Boolean(pairingFor)}
          onOpenChange={(open) => !open && setPairingFor(null)}
        />
      ) : null}

      <ImportPairingCodeDialog
        open={importOpen}
        onOpenChange={setImportOpen}
        onDecoded={(input) => {
          setEditing(null)
          setPrefill(input)
          setFormOpen(true)
        }}
      />
    </div>
  )
}

function SortableHeader({
  label,
  sortKey,
  active,
  onSort,
}: {
  label: string
  sortKey: SortKey
  active: SortKey
  onSort: (key: string, value: string) => void
}) {
  const { t } = useTranslation()
  const isActive = active === sortKey
  return (
    <th scope="col" className="p-2 text-start font-medium" aria-sort={isActive ? 'ascending' : 'none'}>
      <button
        type="button"
        onClick={() => onSort('sort', sortKey)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        <span className="sr-only">{isActive ? t('a11y.sortAscending') : t('a11y.sortNone')}</span>
        {isActive ? <ChevronDown className="size-3" aria-hidden="true" /> : null}
      </button>
    </th>
  )
}

function TunnelRow({
  entry,
  snapshot,
  selected,
  onSelect,
  expanded,
  onToggleExpand,
  busy,
  onAction,
  onEdit,
  onDelete,
  onPairingCode,
}: {
  entry: TunnelResponse
  snapshot?: MonitorSnapshot
  selected: boolean
  onSelect: () => void
  expanded: boolean
  onToggleExpand: () => void
  busy: boolean
  onAction: (action: 'up' | 'down' | 'restart' | 'reapply') => void
  onEdit: () => void
  onDelete: () => void
  onPairingCode: () => void
}) {
  const { t } = useTranslation()
  const { digits } = usePreferences()
  const tunnel = entry.tunnel
  const stats = snapshot?.stats

  const loss = stats ? formatPercent(stats.loss_percent, digits, 0) : null
  const latency = formatMs(stats?.rtt_avg_ms ?? null, digits)

  return (
    <>
      <tr
        className={cn(
          'align-middle transition-colors hover:bg-muted/50',
          // A single highlight when the state changes, never a looping pulse
          // on a steady state.
          busy && 'animate-pulse-once',
        )}
      >
        <td className="px-2 py-[var(--row-padding-block)]">
          <Checkbox
            checked={selected}
            onCheckedChange={onSelect}
            aria-label={t('a11y.selectRow', { name: tunnel.interface_name })}
          />
        </td>
        <td className="px-2 py-[var(--row-padding-block)]">
          <div className="flex flex-col items-start gap-1">
            <StatusPill
              stateId={snapshot?.monitor_state_id ?? MonitorState.Unknown}
              reason={snapshot?.reason}
              size="sm"
            />
            <ApplyStatusBadge statusId={tunnel.apply_status_id} />
          </div>
        </td>
        <td className="px-2 py-[var(--row-padding-block)]">
          <Link
            to={`/tunnels/${tunnel.tunnel_id}`}
            className="font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {tunnel.display_name ? tunnel.display_name : <Technical>{tunnel.interface_name}</Technical>}
          </Link>
          {tunnel.display_name ? <Technical className="block text-xs text-muted-foreground">{tunnel.interface_name}</Technical> : null}
          <div className="mt-0.5 flex flex-wrap items-center gap-1">
            <Badge>{tunnel.tunnel_side_id === TunnelSide.A ? t('tunnel.side.a') : t('tunnel.side.b')}</Badge>
            {!tunnel.is_enabled ? <Badge tone="neutral">{t('states.disabled')}</Badge> : null}
          </div>
        </td>
        <td className="hidden px-2 py-[var(--row-padding-block)] md:table-cell">
          <Technical className="block text-xs">{tunnel.local_endpoint}</Technical>
          <Technical className="block text-xs text-muted-foreground">{tunnel.remote_endpoint}</Technical>
        </td>
        <td className="hidden px-2 py-[var(--row-padding-block)] lg:table-cell">
          {(tunnel.addresses ?? []).map((address) => (
            <Technical key={address.tunnel_address_id} className="block text-xs">
              {`${address.address}/${address.prefix_length}`}
            </Technical>
          ))}
        </td>
        <td className="hidden px-2 py-[var(--row-padding-block)] sm:table-cell">
          {stats ? (
            <div className="text-xs">
              <span className="tabular">{loss}</span>
              {latency ? <span className="tabular text-muted-foreground"> · {latency}</span> : null}
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">{t('monitor.noData')}</span>
          )}
        </td>
        <td className="px-2 py-[var(--row-padding-block)] text-end">
          <div className="flex items-center justify-end gap-1">
            {busy ? <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden="true" /> : null}
            <Button variant="ghost" size="iconSm" onClick={onToggleExpand} aria-expanded={expanded}
              aria-label={expanded ? t('tunnels.rowCollapse') : t('tunnels.rowExpand')}>
              <ChevronDown
                className={cn('size-4 transition-transform duration-250', expanded && 'rotate-180')}
                aria-hidden="true"
              />
            </Button>
            <RowMenu
              tunnel={tunnel}
              busy={busy}
              onAction={onAction}
              onEdit={onEdit}
              onDelete={onDelete}
              onPairingCode={onPairingCode}
            />
          </div>
        </td>
      </tr>

      {expanded ? (
        <tr className="bg-surface-sunken">
          <td colSpan={7} className="p-3">
            <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
              <Detail label={t('tunnel.fields.mtu')} value={String(tunnel.mtu)} />
              <Detail label={t('tunnel.fields.ttl')} value={String(tunnel.ttl)} />
              <Detail label={t('tunnel.fields.key')} value={tunnel.ikey === null ? '—' : String(tunnel.ikey)} />
              <Detail label={t('tunnel.fields.tos')} value={tunnel.tos} />
              <Detail
                label={t('tunnel.fields.persistence')}
                value={t(`tunnel.persistence.${persistenceKey(tunnel.persistence_type_id)}`)}
                plain
              />
              <Detail
                label={t('tunnel.fields.checksum')}
                value={`${tunnel.has_input_checksum ? 'in' : '—'} / ${tunnel.has_output_checksum ? 'out' : '—'}`}
              />
              <Detail
                label={t('tunnel.fields.sequence')}
                value={`${tunnel.has_input_sequence ? 'in' : '—'} / ${tunnel.has_output_sequence ? 'out' : '—'}`}
              />
              <Detail
                label={t('tunnel.fields.pmtudisc')}
                value={tunnel.is_path_mtu_discovery ? t('states.on') : t('states.off')}
                plain
              />
              {entry.observed ? (
                <Detail
                  label={t('tunnels.columns.status')}
                  value={entry.observed.exists ? (entry.observed.oper_state ?? '—') : t('reconcile.status.Missing')}
                />
              ) : null}
              {tunnel.last_apply_error ? (
                <div className="sm:col-span-2 lg:col-span-4">
                  <dt className="text-muted-foreground">{t('apply.lastError')}</dt>
                  <dd className="text-danger">{tunnel.last_apply_error}</dd>
                </div>
              ) : null}
            </dl>
          </td>
        </tr>
      ) : null}
    </>
  )
}

function Detail({ label, value, plain }: { label: string; value: string; plain?: boolean }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{plain ? value : <Technical className="text-xs">{value}</Technical>}</dd>
    </div>
  )
}

function persistenceKey(id: number): string {
  if (id === PersistenceType.Systemd) return 'Systemd'
  if (id === PersistenceType.Networkd) return 'Networkd'
  return 'Runtime'
}

function RowMenu({
  tunnel,
  busy,
  onAction,
  onEdit,
  onDelete,
  onPairingCode,
}: {
  tunnel: Tunnel
  busy: boolean
  onAction: (action: 'up' | 'down' | 'restart' | 'reapply') => void
  onEdit: () => void
  onDelete: () => void
  onPairingCode: () => void
}) {
  const { t } = useTranslation()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="iconSm" disabled={busy} aria-label={t('actions.more')}>
          <MoreHorizontal className="size-4" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuItem asChild>
          <Link to={`/tunnels/${tunnel.tunnel_id}`}>{t('actions.viewDetails')}</Link>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onEdit}>{t('actions.edit')}</DropdownMenuItem>
        <DropdownMenuSeparator />
        {tunnel.is_enabled ? (
          <DropdownMenuItem onSelect={() => onAction('down')}>{t('actions.disable')}</DropdownMenuItem>
        ) : (
          <DropdownMenuItem onSelect={() => onAction('up')}>{t('actions.enable')}</DropdownMenuItem>
        )}
        <DropdownMenuItem onSelect={() => onAction('restart')}>
          <RefreshCw className="size-4" aria-hidden="true" />
          {t('actions.restart')}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => onAction('reapply')}>{t('actions.reapply')}</DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={onPairingCode}>{t('actions.copyPairingCode')}</DropdownMenuItem>
        <DropdownMenuSeparator />
        {/* Destructive, and visibly not the same kind of thing as disable. */}
        <DropdownMenuItem tone="danger" onSelect={onDelete}>
          <Trash2 className="size-4" aria-hidden="true" />
          {t('actions.delete')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function BulkBar({
  count,
  onClear,
  onAction,
}: {
  count: number
  onClear: () => void
  onAction: (action: 'up' | 'down') => void | Promise<void>
}) {
  const { t } = useTranslation()
  return (
    // Selection speaks in the ink voice: a command bar, not another card.
    <div className="flex flex-wrap items-center gap-2 rounded-full bg-ink px-4 py-2 text-ink-foreground shadow-slab">
      <span className="text-xs font-medium">{t('tunnels.selected', { count })}</span>
      <div className="ms-auto flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="ghost"
          className="text-ink-foreground hover:bg-ink-foreground/15"
          onClick={() => void onAction('up')}
        >
          {t('tunnels.bulk.enable')}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="text-ink-foreground hover:bg-ink-foreground/15"
          onClick={() => void onAction('down')}
        >
          {t('tunnels.bulk.disable')}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="text-ink-foreground/70 hover:bg-ink-foreground/15 hover:text-ink-foreground"
          onClick={onClear}
        >
          {t('actions.clear')}
        </Button>
      </div>
    </div>
  )
}

function TableSkeleton() {
  return (
    <Card className="overflow-hidden">
      <div className="divide-y divide-border">
        {Array.from({ length: 5 }).map((_, index) => (
          <div key={index} className="flex items-center gap-3 p-3">
            <Skeleton className="size-4 shrink-0" />
            <Skeleton className="h-6 w-20 shrink-0 rounded-full" />
            <Skeleton className="h-4 w-28" />
            <Skeleton className="hidden h-4 w-32 md:block" />
            <Skeleton className="hidden h-4 w-24 lg:block" />
            <Skeleton className="ms-auto size-7 shrink-0" />
          </div>
        ))}
      </div>
    </Card>
  )
}
