import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowDown, ArrowLeft, ArrowUp, Pencil, RefreshCw, Trash2 } from 'lucide-react'

import { api } from '@/lib/api'
import {
  NatMode,
  type AuditResponse,
  type RelayTraffic,
  type RouteResponse,
  type RouteTrafficPoint,
  type RouteTrafficSample,
} from '@/lib/types'
import {
  formatCount,
  formatDateTime,
  formatThroughput,
  formatVolume,
  tunnelLabel,
} from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useMetrics } from '@/hooks/useMetrics'
import { useRouteActions } from '@/hooks/useRouteActions'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState, ErrorState, Skeleton } from '@/components/ui/feedback'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/disclosure'
import { ApplyStatusBadge, RouteStatusPill } from '@/components/ui/status'
import { Technical, TunnelName } from '@/components/ui/technical'
import { StaleWrapper } from '@/components/layout/LiveIndicator'
import { RouteFlow, endpointLabel } from '@/components/routes/RouteFlow'
import { RouteFormDialog } from '@/components/routes/RouteFormDialog'
import { DeleteRouteDialog } from '@/components/routes/DeleteRouteDialog'
import { RouteTrafficChart } from '@/components/routes/RouteTrafficChart'
import { RouteConnectionsPanel } from '@/components/routes/RouteConnectionsPanel'
import { RouteDestinationsPanel } from '@/components/routes/RouteDestinationsPanel'
import { RouteDiagnosticsPanel } from '@/components/routes/RouteDiagnosticsPanel'
import { RouteRulesPanel } from '@/components/routes/RouteRulesPanel'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'
import { isAnyAddress } from './RoutesPage'

type Range = 'live' | 'hour' | 'day' | 'week' | 'month'

const RANGE_HOURS: Record<Exclude<Range, 'live'>, number> = {
  hour: 1,
  day: 24,
  week: 24 * 7,
  month: 24 * 30,
}

export default function RouteDetailPage() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const routeRuleId = Number(id)

  const [params, setParams] = useSearchParams()
  const range = (params.get('range') as Range) ?? 'live'
  const tab = params.get('tab') ?? 'overview'

  const [editing, setEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)

  const actions = useRouteActions()
  const { calendar, digits, language, units } = usePreferences()

  const routeQuery = useQuery({
    queryKey: ['routes', routeRuleId],
    queryFn: () => api.get<RouteResponse>(`/routes/${routeRuleId}`),
    enabled: Number.isFinite(routeRuleId),
    staleTime: 10_000,
  })

  // The live figures come from the metrics stream the whole panel shares.
  const metrics = useMetrics(true)
  const live: RelayTraffic | undefined = useMemo(
    () => metrics.latest?.routes?.find((entry) => entry.route_rule_id === routeRuleId),
    [metrics.latest, routeRuleId],
  )

  const trafficQuery = useQuery({
    queryKey: ['routes', routeRuleId, 'traffic'],
    queryFn: () =>
      api.get<{ points: RouteTrafficPoint[] }>(`/routes/${routeRuleId}/traffic`, {
        query: { points: 300 },
      }),
    enabled: Number.isFinite(routeRuleId) && range === 'live',
    refetchInterval: range === 'live' ? 5000 : false,
  })

  const historyQuery = useQuery({
    queryKey: ['routes', routeRuleId, 'history', range],
    queryFn: () =>
      api.get<{ samples: RouteTrafficSample[] }>(`/routes/${routeRuleId}/traffic/history`, {
        query: { hours: range === 'live' ? 1 : RANGE_HOURS[range as Exclude<Range, 'live'>] },
      }),
    enabled: Number.isFinite(routeRuleId) && range !== 'live',
    refetchInterval: 60_000,
  })

  const auditQuery = useQuery({
    queryKey: ['audit', 'route', routeRuleId],
    queryFn: () =>
      api.get<AuditResponse>('/audit', {
        query: { target_type: 'RouteRule', limit: 50 },
      }),
    enabled: Number.isFinite(routeRuleId) && tab === 'audit',
  })

  const route = routeQuery.data?.route
  const health = routeQuery.data?.health

  // Named for the rule once it is known, and for the page until then, so the
  // loading, error and not-found states do not keep the previous page's title.
  useDocumentTitle(route ? route.route_rule_title : t('routes.title'))

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  if (routeQuery.isLoading) return <DetailSkeleton />
  if (routeQuery.error) {
    return <ErrorState error={routeQuery.error} onRetry={() => void routeQuery.refetch()} />
  }
  if (!route || !health) return <EmptyState title={t('errors.notFound')} />

  const busy = actions.pending === routeRuleId
  const primary = route.destinations[0]
  const bind = endpointLabel(
    isAnyAddress(route.bind_address) ? t('routes.anyAddress') : route.bind_address,
    route.bind_port,
    route.bind_port_range_end,
  )
  const destination = primary
    ? endpointLabel(primary.address, primary.port, primary.port_range_end)
    : endpointLabel(route.destination_address, route.destination_port, route.destination_port_range_end)
  // The heading names the first destination and counts the rest; the panel
  // below is where each of them is actually accounted for.
  const extraDestinations = Math.max(0, (route.destinations?.length ?? 0) - 1)

  const rate = (value: number) => formatThroughput(value, units).text
  const volume = (value: number) => formatVolume(value, units).text

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Button asChild variant="ghost" size="sm" className="mb-1 -ms-2">
            <Link to="/routes">
              <ArrowLeft className="icon-directional size-4" aria-hidden="true" />
              {t('nav.routes')}
            </Link>
          </Button>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="display text-2xl font-bold tracking-tight">{route.route_rule_title}</h2>
            <RouteStatusPill state={health.state} detail={health.detail} />
            <ApplyStatusBadge statusId={route.apply_status_id} />
          </div>
          <div className="mt-1">
            <RouteFlow
              bind={bind}
              destination={destination}
              destinationNote={
                extraDestinations
                  ? t('routes.moreDestinations', { count: extraDestinations })
                  : undefined
              }
            />
          </div>
          {route.description ? (
            <p className="mt-1 text-xs text-muted-foreground">{route.description}</p>
          ) : null}
        </div>

        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" size="sm" onClick={() => setEditing(true)}>
            <Pencil className="size-4" aria-hidden="true" />
            {t('actions.edit')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            loading={busy}
            onClick={() => void actions.run(routeRuleId, 'reapply', route.route_rule_title)}
          >
            <RefreshCw className="size-4" aria-hidden="true" />
            {t('actions.reapply')}
          </Button>
          <Button
            variant="secondary"
            size="sm"
            loading={busy}
            onClick={() =>
              void actions.run(
                routeRuleId,
                route.is_enabled ? 'disable' : 'enable',
                route.route_rule_title,
              )
            }
          >
            {route.is_enabled ? t('actions.disable') : t('actions.enable')}
          </Button>
          <Button variant="dangerOutline" size="sm" onClick={() => setDeleting(true)}>
            <Trash2 className="size-4" aria-hidden="true" />
            {t('actions.delete')}
          </Button>
        </div>
      </div>

      {/* Impaired is the state that needs explaining: the rules are right and
          the path is not, and the banner names the tunnel rather than leaving
          the operator to work out which one. */}
      {health.state === 'impaired' && health.tunnel ? (
        <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-muted p-3 text-xs">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
          <span>
            {t('routeDetail.impairedBanner', { tunnel: tunnelLabel(health.tunnel) })}{' '}
            <Link to={`/tunnels/${health.tunnel.tunnel_id}`} className="underline">
              <TunnelName tunnel={health.tunnel} />
            </Link>
          </span>
        </p>
      ) : null}

      <StaleWrapper stale={metrics.stream.stale}>
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <Stat
            label={`${t('routeDetail.traffic.in')} · ${t('routeDetail.traffic.rate')}`}
            value={rate(live?.rx_bytes_per_second ?? 0)}
            Icon={ArrowDown}
            tone="ok"
          />
          <Stat
            label={`${t('routeDetail.traffic.out')} · ${t('routeDetail.traffic.rate')}`}
            value={rate(live?.tx_bytes_per_second ?? 0)}
            Icon={ArrowUp}
            tone="accent"
          />
          <Stat
            label={t('routeDetail.traffic.connections')}
            value={formatCount(live?.active_connections ?? 0, digits, language)}
            hint={`${t('routeDetail.traffic.newPerSecond')}: ${(live?.new_connections_per_second ?? 0).toFixed(1)}`}
          />
          <Stat
            label={t('routeDetail.traffic.sinceCreation')}
            value={volume(
              (live?.rx_bytes_since_creation ?? 0) + (live?.tx_bytes_since_creation ?? 0),
            )}
            hint={t('routeDetail.traffic.basisNote')}
          />
        </div>
      </StaleWrapper>

      <Tabs value={tab} onValueChange={(value) => setParam('tab', value === 'overview' ? '' : value)}>
        <TabsList>
          <TabsTrigger value="overview">{t('routeDetail.tabs.overview')}</TabsTrigger>
          <TabsTrigger value="connections">{t('routeDetail.tabs.connections')}</TabsTrigger>
          <TabsTrigger value="diagnostics">{t('routeDetail.tabs.diagnostics')}</TabsTrigger>
          <TabsTrigger value="rules">{t('routeDetail.tabs.rules')}</TabsTrigger>
          <TabsTrigger value="audit">{t('routeDetail.tabs.audit')}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <Card>
            <CardHeader>
              <CardTitle>{t('routeDetail.traffic.title')}</CardTitle>
              <div className="inline-flex rounded-full border border-border/60 bg-surface-sunken p-0.5 text-2xs">
                {(['live', 'hour', 'day', 'week', 'month'] as const).map((option) => (
                  <button
                    key={option}
                    type="button"
                    aria-pressed={range === option}
                    onClick={() => setParam('range', option === 'live' ? '' : option)}
                    className={
                      range === option
                        ? 'rounded-full bg-ink px-2.5 py-1 font-medium text-ink-foreground shadow-sm'
                        : 'rounded-full px-2.5 py-1 text-muted-foreground hover:text-foreground'
                    }
                  >
                    {t(`routeDetail.range.${option}`)}
                  </button>
                ))}
              </div>
            </CardHeader>
            <CardContent>
              {live?.rx_bytes_since_boot === 0 && live?.tx_bytes_since_boot === 0 ? null : null}
              <RouteTrafficChart
                live={range === 'live'}
                points={trafficQuery.data?.points ?? []}
                samples={historyQuery.data?.samples ?? []}
              />
              <p className="mt-3 text-2xs text-muted-foreground">{t('routeDetail.traffic.basisNote')}</p>
            </CardContent>
          </Card>

          <div className="mt-4">
            <RouteDestinationsPanel route={route} live={live} />
          </div>

          <Card className="mt-4">
            <CardHeader>
              <CardTitle>{t('routes.columns.flow')}</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
                <Detail label={t('routeForm.fields.protocol')} value={t(`routes.protocol.${route.route_protocol_id}`)} plain />
                <Detail label={t('routeForm.sectionNat')} value={t(`routes.natMode.${route.nat_mode_id}`)} plain />
                {route.nat_mode_id === NatMode.Snat && route.snat_address ? (
                  <Detail label={t('routeForm.fields.snatAddress')} value={route.snat_address} />
                ) : null}
                <Detail label={t('routeForm.fields.bindAddress')} value={route.bind_address || '0.0.0.0'} />
                <Detail
                  label={t('routeForm.fields.clampMss')}
                  value={route.is_clamp_mss_to_pmtu ? t('states.on') : t('states.off')}
                  plain
                />
                <Detail
                  label={t('routeForm.fields.includeLocalOriginated')}
                  value={route.is_include_local_originated ? t('states.on') : t('states.off')}
                  plain
                />
                {route.last_applied_date ? (
                  <Detail
                    label={t('apply.lastApplied')}
                    value={formatDateTime(route.last_applied_date, { locale: language, calendar, digits })}
                    plain
                  />
                ) : null}
              </dl>
              {route.last_apply_error ? (
                <p className="mt-3 rounded-md border border-danger/30 bg-danger-muted p-3 text-xs text-danger">
                  {route.last_apply_error}
                </p>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="connections">
          <RouteConnectionsPanel routeRuleId={routeRuleId} />
        </TabsContent>

        <TabsContent value="diagnostics">
          <RouteDiagnosticsPanel route={route} />
        </TabsContent>

        <TabsContent value="rules">
          <RouteRulesPanel routeRuleId={routeRuleId} />
        </TabsContent>

        <TabsContent value="audit">
          <Card>
            <CardHeader>
              <CardTitle>{t('routeDetail.audit.title')}</CardTitle>
            </CardHeader>
            <CardContent>
              {auditQuery.isLoading ? (
                <Skeleton className="h-24" />
              ) : auditQuery.error ? (
                <ErrorState error={auditQuery.error} onRetry={() => void auditQuery.refetch()} compact />
              ) : !auditQuery.data?.entries.length ? (
                <EmptyState illustration="empty-log" title={t('routeDetail.audit.empty')} />
              ) : (
                <ul className="divide-y divide-border text-xs">
                  {auditQuery.data.entries
                    .filter((entry) => entry.target_id === route.route_rule_title)
                    .map((entry) => (
                      <li key={entry.audit_log_id} className="flex flex-wrap items-baseline gap-2 py-2">
                        <span className={entry.is_success ? '' : 'text-danger'}>{entry.action}</span>
                        <span className="text-muted-foreground">
                          {formatDateTime(entry.created_date, { locale: language, calendar, digits })}
                        </span>
                        {entry.username ? (
                          <span className="text-muted-foreground">{entry.username}</span>
                        ) : null}
                        <Technical className="ms-auto text-2xs text-muted-foreground">
                          {entry.client_ip}
                        </Technical>
                        {entry.error_message ? (
                          <span className="w-full text-danger">{entry.error_message}</span>
                        ) : null}
                      </li>
                    ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <RouteFormDialog
        open={editing}
        onOpenChange={setEditing}
        route={route}
      />

      {deleting ? (
        <DeleteRouteDialog
          route={route}
          open={deleting}
          onOpenChange={(open) => {
            setDeleting(open)
            if (!open) navigate('/routes')
          }}
        />
      ) : null}
    </div>
  )
}

function Stat({
  label,
  value,
  hint,
  Icon,
  tone,
}: {
  label: string
  value: string
  hint?: string
  Icon?: typeof ArrowDown
  tone?: 'ok' | 'accent'
}) {
  return (
    <Card>
      <CardContent>
        <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
          {Icon ? (
            <Icon
              className={tone === 'ok' ? 'size-3.5 text-ok' : 'size-3.5 text-accent'}
              aria-hidden="true"
            />
          ) : null}
          {label}
        </p>
        <p className="tabular mt-0.5 text-xl font-semibold">{value}</p>
        {hint ? <p className="mt-0.5 line-clamp-2 text-2xs text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
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

function DetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-64" />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-20" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  )
}
