import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  GripVertical,
  Loader2,
  MoreHorizontal,
  Plus,
  RefreshCw,
  Search,
  Shuffle,
  Trash2,
  Waypoints,
} from 'lucide-react'

import { api } from '@/lib/api'
import {
  LoadBalanceMode,
  NatMode,
  RouteProtocol,
  type RelayTraffic,
  type ForwardingResponse,
  type RouteListResponse,
  type RouteResponse,
  type RouteRule,
  type TunnelListResponse,
} from '@/lib/types'
import { formatCount, formatThroughput, formatVolume } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useMetrics } from '@/hooks/useMetrics'
import { useRouteActions } from '@/hooks/useRouteActions'
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
  Tooltip,
} from '@/components/ui/overlay'
import { ApplyStatusBadge, RouteStatusPill } from '@/components/ui/status'
import { Technical, TechnicalBlock } from '@/components/ui/technical'
import { StaleWrapper } from '@/components/layout/LiveIndicator'
import { cn } from '@/lib/utils'
import { RouteFlow, endpointLabel } from '@/components/routes/RouteFlow'
import { RouteFormDialog } from '@/components/routes/RouteFormDialog'
import { DeleteRouteDialog } from '@/components/routes/DeleteRouteDialog'
import { BulkRouteDialog, type BulkAction } from '@/components/routes/BulkRouteDialog'
import { ForwardingBanner } from '@/components/routes/ForwardingBanner'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

/** `order` is the emission order, which is the only one drag applies to. */
type SortKey = 'order' | 'name' | 'status' | 'rate'

export default function RoutesPage() {
  const { t } = useTranslation()
  const actions = useRouteActions()
  const { units, digits, language } = usePreferences()

  // Filters, sort and expansion live in the URL, so a view is shareable and
  // survives a reload.
  const [params, setParams] = useSearchParams()
  const search = params.get('q') ?? ''
  const protocolFilter = params.get('protocol') ?? ''
  const statusFilter = params.get('status') ?? ''
  const natFilter = params.get('nat') ?? ''
  const tunnelFilter = params.get('tunnel') ?? ''
  const sortKey = (params.get('sort') as SortKey) ?? 'order'
  const expandedId = params.get('expanded')

  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [formOpen, setFormOpen] = useState(params.get('create') === '1')
  const [editing, setEditing] = useState<RouteRule | null>(null)
  const [deleting, setDeleting] = useState<RouteRule | null>(null)
  const [bulk, setBulk] = useState<BulkAction | null>(null)
  const [dragging, setDragging] = useState<number | null>(null)
  const [dragOver, setDragOver] = useState<number | null>(null)

  useDocumentTitle(t('routes.title'))

  const listQuery = useQuery({
    queryKey: ['routes', 'list'],
    queryFn: () => api.get<RouteListResponse>('/routes'),
    staleTime: 10_000,
  })

  // Live relay figures ride the metrics stream, which is where §5.4 puts them
  // rather than on a stream of their own.
  const metrics = useMetrics(true)
  const trafficById = useMemo(() => {
    const map = new Map<number, RelayTraffic>()
    for (const entry of metrics.latest?.routes ?? []) map.set(entry.route_rule_id, entry)
    return map
  }, [metrics.latest])

  // For the tunnel filter, and to name the tunnel a rule relays over.
  const tunnelsQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 60_000,
  })
  const tunnelNames = useMemo(() => {
    const map = new Map<number, string>()
    for (const entry of tunnelsQuery.data?.tunnels ?? []) {
      map.set(entry.tunnel.tunnel_id, entry.tunnel.interface_name)
    }
    return map
  }, [tunnelsQuery.data])

  const forwardingQuery = useQuery({
    queryKey: ['forwarding'],
    queryFn: () => api.get<ForwardingResponse>('/system/forwarding'),
    staleTime: 30_000,
  })

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  // A stable identity: `?? []` produces a new array on every render, which
  // would make the filtering memo below recompute each time.
  const entries = useMemo(() => listQuery.data?.routes ?? [], [listQuery.data])
  const total = listQuery.data?.total ?? 0

  const rows = useMemo(() => {
    const needle = search.trim().toLowerCase()

    const filtered = entries.filter((entry) => {
      const rule = entry.route

      if (needle) {
        const haystack = [
          rule.route_rule_title,
          rule.description,
          rule.bind_address,
          String(rule.bind_port),
          rule.bind_port_range_end ? String(rule.bind_port_range_end) : '',
          rule.destination_address,
          String(rule.destination_port),
          ...(rule.destinations ?? []).map((d) => `${d.address} ${d.port}`),
        ]
          .join(' ')
          .toLowerCase()
        if (!haystack.includes(needle)) return false
      }

      if (protocolFilter && String(rule.route_protocol_id) !== protocolFilter) return false
      if (statusFilter && entry.health.state !== statusFilter) return false
      if (natFilter && String(rule.nat_mode_id) !== natFilter) return false
      if (tunnelFilter === 'none' && rule.tunnel_id !== null) return false
      if (tunnelFilter && tunnelFilter !== 'none' && String(rule.tunnel_id ?? '') !== tunnelFilter) {
        return false
      }
      return true
    })

    return [...filtered].sort((a, b) => {
      if (sortKey === 'name') return a.route.route_rule_title.localeCompare(b.route.route_rule_title)
      if (sortKey === 'status') return HEALTH_RANK[a.health.state] - HEALTH_RANK[b.health.state]
      if (sortKey === 'rate') {
        const left = trafficById.get(a.route.route_rule_id)
        const right = trafficById.get(b.route.route_rule_id)
        return rateOf(right) - rateOf(left)
      }
      // Emission order, which is what the backend applies and what first-match
      // resolution follows.
      if (a.route.sort_order !== b.route.sort_order) return a.route.sort_order - b.route.sort_order
      return a.route.route_rule_id - b.route.route_rule_id
    })
  }, [entries, search, protocolFilter, statusFilter, natFilter, tunnelFilter, sortKey, trafficById])

  const filtersActive = Boolean(search || protocolFilter || statusFilter || natFilter || tunnelFilter)
  // Dragging rewrites the emission order of the whole list, so it is only
  // offered when the list on screen is that order in full. Reordering a
  // filtered or differently sorted view would move rules the operator cannot
  // see.
  const canReorder = sortKey === 'order' && !filtersActive && rows.length > 1

  const toggleSelected = (id: number) =>
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  const openCreate = () => {
    setEditing(null)
    setFormOpen(true)
  }

  const move = async (from: number, to: number) => {
    if (from === to || to < 0 || to >= rows.length) return
    const ids = rows.map((row) => row.route.route_rule_id)
    const [moved] = ids.splice(from, 1)
    ids.splice(to, 0, moved)
    await actions.reorder(ids)
  }

  const rate = (traffic: RelayTraffic | undefined) => ({
    rx: formatThroughput(traffic?.rx_bytes_per_second ?? 0, units).text,
    tx: formatThroughput(traffic?.tx_bytes_per_second ?? 0, units).text,
  })

  return (
    <div className="space-y-4">
      <ForwardingBanner
        forwarding={forwardingQuery.data}
        enabledRules={entries.filter((entry) => entry.route.is_enabled).length}
        onChanged={() => void forwardingQuery.refetch()}
      />

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
            placeholder={t('routes.search')}
            aria-label={t('routes.search')}
            className="rounded-full [padding-inline-start:2.25rem]"
          />
        </div>

        <Select
          value={protocolFilter}
          onValueChange={(value) => setParam('protocol', value === 'all' ? '' : value)}
          aria-label={t('routes.filter.protocol')}
          className="w-auto min-w-28"
          options={[
            { value: 'all', label: t('routes.filter.all') },
            ...Object.values(RouteProtocol).map((id) => ({
              value: String(id),
              label: t(`routes.protocol.${id}`),
            })),
          ]}
        />

        <Select
          value={statusFilter}
          onValueChange={(value) => setParam('status', value === 'all' ? '' : value)}
          aria-label={t('routes.filter.status')}
          className="w-auto min-w-32"
          options={[
            { value: 'all', label: t('routes.filter.all') },
            ...(['healthy', 'impaired', 'failed', 'inconsistent', 'pending', 'disabled'] as const).map(
              (state) => ({ value: state, label: t(`routes.state.${state}`) }),
            ),
          ]}
        />

        <Select
          value={natFilter}
          onValueChange={(value) => setParam('nat', value === 'all' ? '' : value)}
          aria-label={t('routes.filter.natMode')}
          className="hidden w-auto min-w-32 sm:flex"
          options={[
            { value: 'all', label: t('routes.filter.all') },
            ...Object.values(NatMode).map((id) => ({
              value: String(id),
              label: t(`routes.natMode.${id}`),
            })),
          ]}
        />

        {tunnelNames.size ? (
          <Select
            value={tunnelFilter}
            onValueChange={(value) => setParam('tunnel', value === 'all' ? '' : value)}
            aria-label={t('routes.filter.tunnel')}
            className="hidden w-auto min-w-32 lg:flex"
            options={[
              { value: 'all', label: t('routes.filter.all') },
              { value: 'none', label: t('routes.filter.noTunnel') },
              ...[...tunnelNames].map(([id, name]) => ({ value: String(id), label: name })),
            ]}
          />
        ) : null}

        {filtersActive ? (
          <Button variant="ghost" size="sm" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
            {t('actions.clearFilters')}
          </Button>
        ) : null}

        <div className="ms-auto flex items-center gap-2">
          <Button
            variant="secondary"
            loading={actions.bulkPending}
            onClick={() => void actions.applyAll()}
            title={t('routes.applyAll')}
          >
            <RefreshCw className="size-4" aria-hidden="true" />
            <span className="hidden sm:inline">{t('actions.applyAll')}</span>
          </Button>
          <Button variant="primary" onClick={openCreate} data-shortcut="create">
            <Plus className="size-4" aria-hidden="true" />
            {t('actions.createRoute')}
          </Button>
        </div>
      </div>

      {selected.size ? (
        <BulkBar
          count={selected.size}
          onClear={() => setSelected(new Set())}
          onAction={(action) => setBulk(action)}
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
              icon={<Waypoints className="size-5" aria-hidden="true" />}
              title={t('routes.emptyTitle')}
              body={t('routes.emptyBody')}
              action={
                <Button variant="primary" onClick={openCreate}>
                  <Plus className="size-4" aria-hidden="true" />
                  {t('actions.createRoute')}
                </Button>
              }
            />
          </CardContent>
        </Card>
      ) : !rows.length ? (
        <Card>
          <CardContent>
            <EmptyState
              title={t('routes.noMatchTitle')}
              body={t('routes.noMatchBody')}
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
          <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            {filtersActive ? <p>{t('routes.filter.applied', { count: rows.length, total })}</p> : null}
            {/* First-match-wins is user-visible behaviour, so the consequence
                is stated on the page rather than left for the operator to
                discover from a rule that never matches. */}
            {rows.length > 1 ? (
              <p className="flex items-center gap-1.5">
                <Shuffle className="size-3.5" aria-hidden="true" />
                <span className="font-medium text-foreground">{t('routes.order.title')}</span>
                <span>{t('routes.order.body')}</span>
              </p>
            ) : null}
          </div>

          <StaleWrapper stale={metrics.stream.stale}>
            <Card className="overflow-hidden">
              <table className="w-full border-collapse text-sm">
                <caption className="sr-only">{t('routes.title')}</caption>
                <thead className="display hidden border-b border-border bg-surface-sunken/70 text-2xs font-semibold text-muted-foreground md:table-header-group">
                  <tr>
                    <th scope="col" className="w-8 p-2" />
                    <th scope="col" className="w-8 p-2">
                      <span className="sr-only">{t('routes.columns.order')}</span>
                    </th>
                    <SortableHeader label={t('routes.columns.status')} sortKey="status" active={sortKey} onSort={setParam} />
                    <SortableHeader label={t('routes.columns.name')} sortKey="name" active={sortKey} onSort={setParam} />
                    <th scope="col" className="p-2 text-start font-medium">
                      {t('routes.columns.flow')}
                    </th>
                    <SortableHeader label={t('routes.columns.rate')} sortKey="rate" active={sortKey} onSort={setParam} />
                    <th scope="col" className="hidden p-2 text-start font-medium lg:table-cell">
                      {t('routes.columns.volume')}
                    </th>
                    <th scope="col" className="hidden p-2 text-start font-medium xl:table-cell">
                      {t('routes.columns.connections')}
                    </th>
                    <th scope="col" className="w-10 p-2">
                      <span className="sr-only">{t('routes.columns.actions')}</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {rows.map((row, index) => (
                    <RouteRow
                      key={row.route.route_rule_id}
                      entry={row}
                      index={index}
                      count={rows.length}
                      traffic={trafficById.get(row.route.route_rule_id)}
                      tunnelName={row.route.tunnel_id ? tunnelNames.get(row.route.tunnel_id) : undefined}
                      selected={selected.has(row.route.route_rule_id)}
                      onSelect={() => toggleSelected(row.route.route_rule_id)}
                      expanded={expandedId === String(row.route.route_rule_id)}
                      onToggleExpand={() =>
                        setParam(
                          'expanded',
                          expandedId === String(row.route.route_rule_id)
                            ? ''
                            : String(row.route.route_rule_id),
                        )
                      }
                      busy={actions.pending === row.route.route_rule_id || actions.bulkPending}
                      canReorder={canReorder}
                      dragging={dragging === index}
                      dragOver={dragOver === index}
                      onDragStart={() => setDragging(index)}
                      onDragEnter={() => setDragOver(index)}
                      onDragEnd={() => {
                        if (dragging !== null && dragOver !== null) void move(dragging, dragOver)
                        setDragging(null)
                        setDragOver(null)
                      }}
                      onMove={(delta) => void move(index, index + delta)}
                      onAction={(action) =>
                        void actions.run(row.route.route_rule_id, action, row.route.route_rule_title)
                      }
                      onEdit={() => {
                        setEditing(row.route)
                        setFormOpen(true)
                      }}
                      onDuplicate={() =>
                        void actions.duplicate(row.route.route_rule_id, row.route.route_rule_title)
                      }
                      onDelete={() => setDeleting(row.route)}
                      rate={rate}
                      formatVolumeText={(bytes) => formatVolume(bytes, units).text}
                      formatCountText={(value) => formatCount(value, digits, language)}
                    />
                  ))}
                </tbody>
              </table>
            </Card>
          </StaleWrapper>
        </>
      )}

      <RouteFormDialog
        open={formOpen}
        onOpenChange={(open) => {
          setFormOpen(open)
          if (!open) {
            setEditing(null)
            setParam('create', '')
          }
        }}
        route={editing ?? undefined}
      />

      {deleting ? (
        <DeleteRouteDialog
          route={deleting}
          open={Boolean(deleting)}
          onOpenChange={(open) => !open && setDeleting(null)}
        />
      ) : null}

      {bulk ? (
        <BulkRouteDialog
          action={bulk}
          routes={rows.filter((row) => selected.has(row.route.route_rule_id)).map((row) => row.route)}
          open={Boolean(bulk)}
          onOpenChange={(open) => !open && setBulk(null)}
          onDone={() => {
            setBulk(null)
            setSelected(new Set())
          }}
        />
      ) : null}
    </div>
  )
}

/** Worst first, so sorting by status surfaces what needs attention. */
const HEALTH_RANK: Record<string, number> = {
  inconsistent: 0,
  failed: 1,
  impaired: 2,
  pending: 3,
  healthy: 4,
  disabled: 5,
}

function rateOf(traffic: RelayTraffic | undefined): number {
  if (!traffic) return 0
  return traffic.rx_bytes_per_second + traffic.tx_bytes_per_second
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
        onClick={() => onSort('sort', isActive ? 'order' : sortKey)}
        className="inline-flex items-center gap-1 hover:text-foreground"
      >
        {label}
        <span className="sr-only">{isActive ? t('a11y.sortAscending') : t('a11y.sortNone')}</span>
        {isActive ? <ChevronDown className="size-3" aria-hidden="true" /> : null}
      </button>
    </th>
  )
}

function RouteRow({
  entry,
  index,
  count,
  traffic,
  tunnelName,
  selected,
  onSelect,
  expanded,
  onToggleExpand,
  busy,
  canReorder,
  dragging,
  dragOver,
  onDragStart,
  onDragEnter,
  onDragEnd,
  onMove,
  onAction,
  onEdit,
  onDuplicate,
  onDelete,
  rate,
  formatVolumeText,
  formatCountText,
}: {
  entry: RouteResponse
  index: number
  count: number
  traffic?: RelayTraffic
  tunnelName?: string
  selected: boolean
  onSelect: () => void
  expanded: boolean
  onToggleExpand: () => void
  busy: boolean
  canReorder: boolean
  dragging: boolean
  dragOver: boolean
  onDragStart: () => void
  onDragEnter: () => void
  onDragEnd: () => void
  onMove: (delta: number) => void
  onAction: (action: 'enable' | 'disable' | 'reapply') => void
  onEdit: () => void
  onDuplicate: () => void
  onDelete: () => void
  rate: (traffic: RelayTraffic | undefined) => { rx: string; tx: string }
  formatVolumeText: (bytes: number) => string
  formatCountText: (value: number) => string
}) {
  const { t } = useTranslation()
  const rule = entry.route
  const { rx, tx } = rate(traffic)

  const bind = endpointLabel(
    isAnyAddress(rule.bind_address) ? t('routes.anyAddress') : rule.bind_address,
    rule.bind_port,
    rule.bind_port_range_end,
  )
  const primary = rule.destinations[0]
  const destination = primary
    ? endpointLabel(primary.address, primary.port, primary.port_range_end)
    : endpointLabel(rule.destination_address, rule.destination_port, rule.destination_port_range_end)
  const extra = Math.max(0, (rule.destinations ?? []).length - 1)

  return (
    <>
      <tr
        draggable={canReorder}
        onDragStart={canReorder ? onDragStart : undefined}
        onDragEnter={canReorder ? onDragEnter : undefined}
        onDragOver={canReorder ? (event) => event.preventDefault() : undefined}
        onDragEnd={canReorder ? onDragEnd : undefined}
        onDrop={canReorder ? (event) => event.preventDefault() : undefined}
        className={cn(
          'align-middle transition-colors hover:bg-muted/50',
          busy && 'animate-pulse-once',
          dragging && 'opacity-50',
          dragOver && !dragging && 'border-t-2 border-t-accent',
        )}
      >
        <td className="px-2 py-[var(--row-padding-block)]">
          <Checkbox
            checked={selected}
            onCheckedChange={onSelect}
            aria-label={t('a11y.selectRow', { name: rule.route_rule_title })}
          />
        </td>

        <td className="px-2 py-[var(--row-padding-block)]">
          {/* Drag is a pointer affordance; the two buttons behind the menu are
              the keyboard one, because a list whose order is behaviour must be
              reorderable without a mouse. */}
          {canReorder ? (
            <Tooltip content={`${t('routes.order.dragHandle')} · ${t('routes.order.position', { position: index + 1, total: count })}`}>
              <span className="flex cursor-grab items-center justify-center text-muted-foreground active:cursor-grabbing">
                <GripVertical className="size-4" aria-hidden="true" />
                <span className="sr-only">
                  {t('routes.order.position', { position: index + 1, total: count })}
                </span>
              </span>
            </Tooltip>
          ) : (
            <span className="tabular block text-center text-2xs text-muted-foreground">{index + 1}</span>
          )}
        </td>

        <td className="px-2 py-[var(--row-padding-block)]">
          <div className="flex flex-col items-start gap-1">
            <RouteStatusPill state={entry.health.state} detail={entry.health.detail} size="sm" />
            <ApplyStatusBadge statusId={rule.apply_status_id} />
          </div>
        </td>

        <td className="px-2 py-[var(--row-padding-block)]">
          <Link
            to={`/routes/${rule.route_rule_id}`}
            className="font-medium hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {rule.route_rule_title}
          </Link>
          <div className="mt-0.5 flex flex-wrap items-center gap-1">
            <Badge>{t(`routes.protocol.${rule.route_protocol_id}`)}</Badge>
            {tunnelName ? (
              <Badge tone="neutral">
                <Technical className="text-2xs">{tunnelName}</Technical>
              </Badge>
            ) : null}
            {index === 0 && count > 1 ? <Badge tone="neutral">{t('routes.order.hint')}</Badge> : null}
          </div>
        </td>

        <td className="px-2 py-[var(--row-padding-block)]">
          <RouteFlow
            bind={bind}
            destination={destination}
            destinationNote={extra ? t('routes.moreDestinations', { count: extra }) : undefined}
          />
        </td>

        <td className="px-2 py-[var(--row-padding-block)]">
          <div className="flex flex-col text-2xs">
            <span className="tabular flex items-center gap-1">
              <ArrowDown className="size-3 text-ok" aria-hidden="true" />
              {rx}
            </span>
            <span className="tabular flex items-center gap-1 text-muted-foreground">
              <ArrowUp className="size-3 text-accent" aria-hidden="true" />
              {tx}
            </span>
          </div>
        </td>

        <td className="hidden px-2 py-[var(--row-padding-block)] lg:table-cell">
          <Tooltip content={t('routeDetail.traffic.basisNote')}>
            <span className="tabular text-2xs">
              {formatVolumeText(
                (traffic?.rx_bytes_since_creation ?? 0) + (traffic?.tx_bytes_since_creation ?? 0),
              )}
            </span>
          </Tooltip>
        </td>

        <td className="hidden px-2 py-[var(--row-padding-block)] xl:table-cell">
          <span className="tabular text-2xs">{formatCountText(traffic?.active_connections ?? 0)}</span>
        </td>

        <td className="px-2 py-[var(--row-padding-block)] text-end">
          <div className="flex items-center justify-end gap-1">
            {busy ? <Loader2 className="size-4 animate-spin text-muted-foreground" aria-hidden="true" /> : null}
            <Button
              variant="ghost"
              size="iconSm"
              onClick={onToggleExpand}
              aria-expanded={expanded}
              aria-label={expanded ? t('routes.rowCollapse') : t('routes.rowExpand')}
            >
              <ChevronDown
                className={cn('size-4 transition-transform duration-250', expanded && 'rotate-180')}
                aria-hidden="true"
              />
            </Button>
            <RowMenu
              rule={rule}
              busy={busy}
              canReorder={canReorder}
              first={index === 0}
              last={index === count - 1}
              onMove={onMove}
              onAction={onAction}
              onEdit={onEdit}
              onDuplicate={onDuplicate}
              onDelete={onDelete}
            />
          </div>
        </td>
      </tr>

      {expanded ? (
        <tr className="bg-surface-sunken">
          <td colSpan={9} className="p-3">
            <RouteExpansion entry={entry} tunnelName={tunnelName} />
          </td>
        </tr>
      ) : null}
    </>
  )
}

/** The full parameter set and the rules the panel generates from it. */
function RouteExpansion({ entry, tunnelName }: { entry: RouteResponse; tunnelName?: string }) {
  const { t } = useTranslation()
  const rule = entry.route

  const previewQuery = useQuery({
    queryKey: ['routes', rule.route_rule_id, 'preview'],
    queryFn: () =>
      api.post<{ payload: string }>('/routes/preview', { route_rule_id: rule.route_rule_id }),
    staleTime: 30_000,
    retry: false,
  })

  return (
    <div className="space-y-3">
      <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
        <Detail label={t('routeForm.fields.protocol')} value={t(`routes.protocol.${rule.route_protocol_id}`)} plain />
        <Detail label={t('routeForm.sectionNat')} value={t(`routes.natMode.${rule.nat_mode_id}`)} plain />
        {rule.nat_mode_id === NatMode.Snat && rule.snat_address ? (
          <Detail label={t('routeForm.fields.snatAddress')} value={rule.snat_address} />
        ) : null}
        {rule.load_balance_mode_id !== LoadBalanceMode.None ? (
          <Detail
            label={t('routeForm.fields.loadBalance')}
            value={t(`routes.loadBalance.${rule.load_balance_mode_id}`)}
            plain
          />
        ) : null}
        {tunnelName ? <Detail label={t('routeForm.destination.pickTunnel')} value={tunnelName} /> : null}
        {rule.bind_interface ? (
          <Detail label={t('routeForm.fields.bindInterface')} value={rule.bind_interface} />
        ) : null}
        <Detail
          label={t('routeForm.fields.clampMss')}
          value={rule.is_clamp_mss_to_pmtu ? t('states.on') : t('states.off')}
          plain
        />
        <Detail
          label={t('routeForm.fields.includeLocalOriginated')}
          value={rule.is_include_local_originated ? t('states.on') : t('states.off')}
          plain
        />
        <Detail
          label={t('routeForm.fields.logging')}
          value={rule.is_logging_enabled ? t('states.on') : t('states.off')}
          plain
        />
        {rule.fwmark !== null ? (
          <Detail label={t('routeForm.fields.fwmark')} value={`0x${rule.fwmark.toString(16)}`} />
        ) : null}
        {rule.max_connections_per_source !== null ? (
          <Detail
            label={t('routeForm.fields.maxConnectionsPerSource')}
            value={String(rule.max_connections_per_source)}
          />
        ) : null}
        {rule.connection_rate_limit !== null ? (
          <Detail
            label={t('routeForm.fields.connectionRateLimit')}
            value={String(rule.connection_rate_limit)}
          />
        ) : null}

        {(rule.destinations ?? []).length > 1 ? (
          <div className="sm:col-span-2 lg:col-span-4">
            <dt className="text-muted-foreground">{t('routeForm.fields.destinations')}</dt>
            <dd className="mt-0.5 flex flex-wrap gap-2">
              {(rule.destinations ?? []).map((destination) => (
                <Badge
                  key={destination.route_destination_id}
                  // A destination taken out of rotation is deliberate, not a
                  // fault, so it dims rather than turning a warning colour.
                  className={cn(!destination.is_enabled && 'opacity-50 line-through')}
                >
                  <Technical className="text-2xs">
                    {endpointLabel(destination.address, destination.port, destination.port_range_end)}
                  </Technical>
                  {rule.load_balance_mode_id === LoadBalanceMode.Weighted
                    ? ` · ${t('routeForm.fields.weight')} ${destination.weight}`
                    : ''}
                </Badge>
              ))}
            </dd>
          </div>
        ) : null}

        {rule.allowed_sources.length ? (
          <div className="sm:col-span-2 lg:col-span-4">
            <dt className="text-muted-foreground">{t('routeForm.fields.allowedSources')}</dt>
            <dd className="mt-0.5 flex flex-wrap gap-2">
              {rule.allowed_sources.map((source) => (
                <Badge key={source.route_allowed_source_id}>
                  <Technical className="text-2xs">{source.cidr}</Technical>
                </Badge>
              ))}
            </dd>
          </div>
        ) : null}

        {rule.last_apply_error ? (
          <div className="sm:col-span-2 lg:col-span-4">
            <dt className="text-muted-foreground">{t('apply.lastError')}</dt>
            <dd className="text-danger">{rule.last_apply_error}</dd>
          </div>
        ) : null}
      </dl>

      <div>
        <p className="mb-1.5 text-xs font-medium">{t('routeDetail.rules.intended')}</p>
        {previewQuery.isLoading ? (
          <Skeleton className="h-24" />
        ) : previewQuery.error ? (
          <ErrorState error={previewQuery.error} onRetry={() => void previewQuery.refetch()} compact />
        ) : previewQuery.data?.payload ? (
          <TechnicalBlock copyable className="max-h-48">
            {previewQuery.data.payload}
          </TechnicalBlock>
        ) : null}
      </div>
    </div>
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

function RowMenu({
  rule,
  busy,
  canReorder,
  first,
  last,
  onMove,
  onAction,
  onEdit,
  onDuplicate,
  onDelete,
}: {
  rule: RouteRule
  busy: boolean
  canReorder: boolean
  first: boolean
  last: boolean
  onMove: (delta: number) => void
  onAction: (action: 'enable' | 'disable' | 'reapply') => void
  onEdit: () => void
  onDuplicate: () => void
  onDelete: () => void
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
          <Link to={`/routes/${rule.route_rule_id}`}>{t('actions.viewDetails')}</Link>
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onEdit}>{t('actions.edit')}</DropdownMenuItem>
        <DropdownMenuItem onSelect={onDuplicate}>{t('actions.duplicate')}</DropdownMenuItem>
        <DropdownMenuSeparator />
        {rule.is_enabled ? (
          <DropdownMenuItem onSelect={() => onAction('disable')}>{t('actions.disable')}</DropdownMenuItem>
        ) : (
          <DropdownMenuItem onSelect={() => onAction('enable')}>{t('actions.enable')}</DropdownMenuItem>
        )}
        <DropdownMenuItem onSelect={() => onAction('reapply')}>
          <RefreshCw className="size-4" aria-hidden="true" />
          {t('actions.reapply')}
        </DropdownMenuItem>
        {canReorder ? (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem disabled={first} onSelect={() => onMove(-1)}>
              <ArrowUp className="size-4" aria-hidden="true" />
              {t('routes.order.moveUp')}
            </DropdownMenuItem>
            <DropdownMenuItem disabled={last} onSelect={() => onMove(1)}>
              <ArrowDown className="size-4" aria-hidden="true" />
              {t('routes.order.moveDown')}
            </DropdownMenuItem>
          </>
        ) : null}
        <DropdownMenuSeparator />
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
  onAction: (action: BulkAction) => void
}) {
  const { t } = useTranslation()
  return (
    // Selection speaks in the ink voice: a command bar, not another card.
    <div className="flex flex-wrap items-center gap-2 rounded-full bg-ink px-4 py-2 text-ink-foreground shadow-slab">
      <span className="text-xs font-medium">{t('routes.selected', { count })}</span>
      <div className="ms-auto flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="ghost"
          className="text-ink-foreground hover:bg-ink-foreground/15"
          onClick={() => onAction('enable')}
        >
          {t('routes.bulk.enable')}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          className="text-ink-foreground hover:bg-ink-foreground/15"
          onClick={() => onAction('disable')}
        >
          {t('routes.bulk.disable')}
        </Button>
        <Button size="sm" variant="danger" onClick={() => onAction('delete')}>
          {t('routes.bulk.delete')}
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

/** 0.0.0.0 and :: mean every local address; the literal is not worth showing. */
export function isAnyAddress(address: string): boolean {
  const trimmed = address.trim()
  return trimmed === '' || trimmed === '0.0.0.0' || trimmed === '::'
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
            <Skeleton className="hidden h-4 w-40 md:block" />
            <Skeleton className="hidden h-4 w-20 lg:block" />
            <Skeleton className="ms-auto size-7 shrink-0" />
          </div>
        ))}
      </div>
    </Card>
  )
}
