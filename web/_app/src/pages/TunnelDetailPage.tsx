import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Pencil, RefreshCw, Trash2 } from 'lucide-react'

import { api } from '@/lib/api'
import {
  MonitorState,
  PersistenceType,
  TunnelSide,
  type AuditResponse,
  type MonitorHistoryResponse,
  type MonitorStatusResponse,
  type TunnelResponse,
} from '@/lib/types'
import { formatDateTime, formatMs, formatPercent, formatRelative } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useTunnelActions } from '@/hooks/useTunnelActions'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge, EmptyState, ErrorState, Skeleton } from '@/components/ui/feedback'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/disclosure'
import { ApplyStatusBadge, StatusDot, StatusPill } from '@/components/ui/status'
import { Technical } from '@/components/ui/technical'
import { SwitchField } from '@/components/ui/form'
import { HealthChart } from '@/components/tunnels/HealthChart'
import { DiagnosticRuns, DiagnosticsPanel } from '@/components/tunnels/DiagnosticsPanel'
import { TunnelFormDialog } from '@/components/tunnels/TunnelFormDialog'
import { DeleteTunnelDialog } from '@/components/tunnels/DeleteTunnelDialog'
import { PairingCodeDialog } from '@/components/tunnels/PairingDialogs'
import { TunnelRoutesCard } from '@/components/routes/TunnelRoutesCard'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

type Range = 'live' | 'hour' | 'day' | 'week' | 'month'

const RANGE_SECONDS: Record<Range, number> = {
  live: 15 * 60,
  hour: 60 * 60,
  day: 24 * 60 * 60,
  week: 7 * 24 * 60 * 60,
  month: 30 * 24 * 60 * 60,
}

export default function TunnelDetailPage() {
  const { t } = useTranslation()
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const tunnelId = Number(id)

  const [params, setParams] = useSearchParams()
  const range = (params.get('range') as Range) ?? 'hour'
  const tab = params.get('tab') ?? 'overview'

  const [editing, setEditing] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [pairing, setPairing] = useState(false)

  const actions = useTunnelActions()
  const { calendar, digits, language } = usePreferences()

  const tunnelQuery = useQuery({
    queryKey: ['tunnels', tunnelId],
    queryFn: () => api.get<TunnelResponse>(`/tunnels/${tunnelId}`),
    enabled: Number.isFinite(tunnelId),
    staleTime: 10_000,
  })

  const statusQuery = useQuery({
    queryKey: ['tunnels', tunnelId, 'status'],
    queryFn: () => api.get<MonitorStatusResponse>(`/tunnels/${tunnelId}/status`),
    enabled: Number.isFinite(tunnelId),
    // The live range refreshes quickly; the longer ones do not need to.
    refetchInterval: range === 'live' ? 2000 : 15000,
  })

  const historyQuery = useQuery({
    queryKey: ['tunnels', tunnelId, 'history', range],
    queryFn: () =>
      api.get<MonitorHistoryResponse>(`/tunnels/${tunnelId}/history`, {
        query: {
          from: new Date(Date.now() - RANGE_SECONDS[range] * 1000).toISOString(),
          limit: 500,
        },
      }),
    enabled: Number.isFinite(tunnelId),
    refetchInterval: range === 'live' ? 5000 : 60000,
  })

  const tunnel = tunnelQuery.data?.tunnel

  // Named for the tunnel once it is known, and for the page until then. The
  // effect this replaces only ever set a title when the tunnel loaded, so the
  // loading, error and not-found states all kept the previous page's title.
  useDocumentTitle(tunnel ? tunnel.display_name || tunnel.interface_name : t('tunnels.title'))

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  if (tunnelQuery.isLoading) return <DetailSkeleton />
  if (tunnelQuery.error) {
    return <ErrorState error={tunnelQuery.error} onRetry={() => void tunnelQuery.refetch()} />
  }
  if (!tunnel) return <EmptyState title={t('errors.notFound')} />

  const status = statusQuery.data
  const busy = actions.pending === tunnelId

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <Button asChild variant="ghost" size="sm" className="mb-1 -ms-2">
            <Link to="/tunnels">
              <ArrowLeft className="icon-directional size-4" aria-hidden="true" />
              {t('nav.tunnels')}
            </Link>
          </Button>
          <div className="flex flex-wrap items-center gap-2.5">
            <h2 className="text-2xl font-semibold tracking-tight">
              {tunnel.display_name ? tunnel.display_name : <Technical copyable>{tunnel.interface_name}</Technical>}
            </h2>
            <StatusPill
              stateId={status?.monitor_state_id ?? MonitorState.Unknown}
              reason={status?.reason}
            />
            <ApplyStatusBadge statusId={tunnel.apply_status_id} />
            <Badge>{tunnel.tunnel_side_id === TunnelSide.A ? t('tunnel.side.a') : t('tunnel.side.b')}</Badge>
          </div>
          {tunnel.display_name ? (
            <p className="mt-0.5">
              <Technical copyable className="text-xs text-muted-foreground">{tunnel.interface_name}</Technical>
            </p>
          ) : null}
          <p className="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
            <Technical>{tunnel.local_endpoint}</Technical>
            <span aria-hidden="true">↔</span>
            <Technical>{tunnel.remote_endpoint}</Technical>
          </p>
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
            onClick={() => void actions.run(tunnelId, 'restart', tunnel.interface_name)}
          >
            <RefreshCw className="size-4" aria-hidden="true" />
            {t('actions.restart')}
          </Button>
          <Button variant="secondary" size="sm" onClick={() => setPairing(true)}>
            {t('actions.copyPairingCode')}
          </Button>
          <Button variant="dangerOutline" size="sm" onClick={() => setDeleting(true)}>
            <Trash2 className="size-4" aria-hidden="true" />
            {t('actions.delete')}
          </Button>
        </div>
      </div>

      {tunnel.last_apply_error ? (
        <div className="rounded-md border border-danger/30 bg-danger-muted p-3 text-xs" role="alert">
          <p className="font-medium text-danger">{t('apply.lastError')}</p>
          <p className="mt-1">{tunnel.last_apply_error}</p>
        </div>
      ) : null}

      <Tabs value={tab} onValueChange={(value) => setParam('tab', value)}>
        <TabsList>
          <TabsTrigger value="overview">{t('tunnelDetail.overview')}</TabsTrigger>
          <TabsTrigger value="diagnostics">{t('tunnelDetail.diagnostics')}</TabsTrigger>
          <TabsTrigger value="configuration">{t('tunnelDetail.configuration')}</TabsTrigger>
          <TabsTrigger value="audit">{t('tunnelDetail.audit')}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle>{t('tunnelDetail.charts')}</CardTitle>
                <div className="inline-flex flex-wrap rounded-full border border-border/60 bg-surface-sunken p-0.5 text-2xs">
                  {(['live', 'hour', 'day', 'week', 'month'] as Range[]).map((option) => (
                    <button
                      key={option}
                      type="button"
                      onClick={() => setParam('range', option)}
                      aria-pressed={range === option}
                      className={
                        range === option
                          ? 'rounded-full bg-ink px-2.5 py-1 font-medium text-ink-foreground shadow-sm'
                          : 'rounded-full px-2.5 py-1 text-muted-foreground hover:text-foreground'
                      }
                    >
                      {t(`tunnelDetail.range.${option}`)}
                    </button>
                  ))}
                </div>
              </CardHeader>
              <CardContent>
                {historyQuery.isLoading ? (
                  <Skeleton className="h-64" />
                ) : historyQuery.error ? (
                  <ErrorState error={historyQuery.error} onRetry={() => void historyQuery.refetch()} compact />
                ) : (
                  <HealthChart points={historyQuery.data?.points ?? []} events={status?.events ?? []} />
                )}
              </CardContent>
            </Card>

            <div className="space-y-4">
              <Card>
                <CardHeader>
                  {/*
                    A section title, not the state. This hardcoded the key
                    `monitor.state.Up`, so the card announced "Up" above the
                    evidence that a tunnel was down — 100% loss, nothing
                    received, every event a transition to Down.

                    The live state belongs to the status pill in the header,
                    which has the colour, the icon and the text that §3 requires
                    of an indicator. A bare word as a card title has none of
                    them and would be read as a second, contradicting one.
                  */}
                  <CardTitle>{t('monitor.title')}</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {status ? (
                    <>
                      {/* The two figures an operator came for, in the
                          instrument voice; the rest of the tape below. */}
                      <div className="grid grid-cols-2 gap-3">
                        <div className="rounded-lg bg-surface-sunken/70 p-3">
                          <p className="text-2xs text-muted-foreground">{t('monitor.latency')}</p>
                          <p className="readout mt-1 text-2xl">{formatMs(status.stats.rtt_avg_ms, digits) ?? '—'}</p>
                        </div>
                        <div className="rounded-lg bg-surface-sunken/70 p-3">
                          <p className="text-2xs text-muted-foreground">{t('monitor.loss')}</p>
                          <p className="readout mt-1 text-2xl">{formatPercent(status.stats.loss_percent, digits)}</p>
                        </div>
                      </div>
                      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                        <Figure label={t('monitor.jitter')} value={formatMs(status.stats.jitter_ms, digits) ?? '—'} />
                        <Figure label={t('monitor.sent')} value={String(status.stats.sent)} />
                        <Figure label={t('monitor.received')} value={String(status.stats.received)} />
                        <Figure label={t('monitor.lost')} value={String(status.stats.lost)} />
                        {status.target ? <Figure label={t('monitor.target')} value={status.target} /> : null}
                        {status.stats.last_reply_at ? (
                          <Figure
                            label={t('monitor.lastReply')}
                            value={formatRelative(status.stats.last_reply_at, language)}
                            plain
                          />
                        ) : null}
                      </dl>

                      <SwitchField
                        label={t('monitor.enableMonitoring')}
                        checked={status.enabled}
                        onCheckedChange={(value) =>
                          void actions.setMonitoring(tunnelId, value, tunnel.interface_name)
                        }
                      />
                    </>
                  ) : (
                    <Skeleton className="h-24" />
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>{t('tunnelDetail.events')}</CardTitle>
                </CardHeader>
                <CardContent>
                  {!status?.events?.length ? (
                    <p className="text-xs text-muted-foreground">{t('tunnelDetail.eventLog.empty')}</p>
                  ) : (
                    // A long history scrolls inside its card instead of
                    // stretching the page: the log is a tape, not the layout.
                    <ol className="max-h-80 space-y-2.5 overflow-y-auto pe-1 scrollbar-thin">
                      {(status.events ?? []).map((event) => (
                        <li key={event.monitor_event_id} className="flex gap-2 text-xs">
                          <StatusDot stateId={event.to_monitor_state_id} className="mt-0.5" />
                          <div className="min-w-0">
                            <p>
                              {t('tunnelDetail.eventLog.from', { state: event.from_state })}{' '}
                              {t('tunnelDetail.eventLog.to', { state: event.to_state })}
                            </p>
                            <p className="text-2xs text-muted-foreground">{event.reason}</p>
                            <p className="text-2xs text-muted-foreground">
                              {formatDateTime(event.created_date, { locale: language, calendar, digits })}
                            </p>
                          </div>
                        </li>
                      ))}
                    </ol>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>

          {/* What depends on this tunnel. An operator about to restart it
              should see what crosses it without going to look (§10). */}
          <TunnelRoutesCard tunnelId={tunnelId} />
        </TabsContent>

        <TabsContent value="diagnostics" className="space-y-4">
          <DiagnosticsPanel tunnel={tunnel} />
          <Card>
            <CardHeader>
              <CardTitle>{t('diagnostics.runs.title')}</CardTitle>
            </CardHeader>
            <CardContent>
              <DiagnosticRuns tunnelId={tunnelId} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="configuration">
          <ConfigurationView entry={tunnelQuery.data} onEdit={() => setEditing(true)} />
        </TabsContent>

        <TabsContent value="audit">
          <TunnelAudit interfaceName={tunnel.interface_name} />
        </TabsContent>
      </Tabs>

      <TunnelFormDialog open={editing} onOpenChange={setEditing} tunnel={tunnel} />
      <DeleteTunnelDialog
        tunnel={tunnel}
        open={deleting}
        onOpenChange={setDeleting}
        onDeleted={() => navigate('/tunnels')}
      />
      <PairingCodeDialog tunnelId={tunnelId} open={pairing} onOpenChange={setPairing} />
    </div>
  )
}

function ConfigurationView({ entry, onEdit }: { entry?: TunnelResponse; onEdit: () => void }) {
  const { t } = useTranslation()
  if (!entry) return null
  const { tunnel, observed } = entry

  const rows: [string, React.ReactNode][] = [
    [t('tunnel.fields.interfaceName'), <Technical key="n" copyable>{tunnel.interface_name}</Technical>],
    [t('tunnel.fields.localEndpoint'), <Technical key="l" copyable>{tunnel.local_endpoint}</Technical>],
    [t('tunnel.fields.remoteEndpoint'), <Technical key="r" copyable>{tunnel.remote_endpoint}</Technical>],
    [t('tunnel.fields.mtu'), <Technical key="m">{String(tunnel.mtu)}</Technical>],
    [t('tunnel.fields.ttl'), <Technical key="t">{String(tunnel.ttl)}</Technical>],
    [t('tunnel.fields.tos'), <Technical key="tos">{tunnel.tos}</Technical>],
    [t('tunnel.fields.ikey'), <Technical key="ik">{tunnel.ikey === null ? '—' : String(tunnel.ikey)}</Technical>],
    [t('tunnel.fields.okey'), <Technical key="ok">{tunnel.okey === null ? '—' : String(tunnel.okey)}</Technical>],
    [
      t('tunnel.fields.persistence'),
      t(
        `tunnel.persistence.${
          tunnel.persistence_type_id === PersistenceType.Systemd
            ? 'Systemd'
            : tunnel.persistence_type_id === PersistenceType.Networkd
              ? 'Networkd'
              : 'Runtime'
        }`,
      ),
    ],
    [
      t('tunnel.fields.addresses'),
      <span key="a" className="space-y-0.5">
        {(tunnel.addresses ?? []).map((address) => (
          <Technical key={address.tunnel_address_id} className="block" copyable>
            {`${address.address}/${address.prefix_length}`}
          </Technical>
        ))}
      </span>,
    ],
    [t('tunnel.fields.bindDevice'), tunnel.bind_device ? <Technical key="b">{tunnel.bind_device}</Technical> : '—'],
  ]

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>{t('tunnelDetail.configuration')}</CardTitle>
          <Button variant="secondary" size="sm" onClick={onEdit}>
            <Pencil className="size-4" aria-hidden="true" />
            {t('actions.edit')}
          </Button>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-3">
            {rows.map(([label, value]) => (
              <div key={label}>
                <dt className="text-muted-foreground">{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>

      {observed?.exists ? (
        <Card>
          <CardHeader>
            <CardTitle>{t('reconcile.observed')}</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid gap-x-6 gap-y-2 text-xs sm:grid-cols-3">
              <div>
                <dt className="text-muted-foreground">{t('tunnel.fields.mtu')}</dt>
                <dd>
                  <Technical>{String(observed.mtu ?? '—')}</Technical>
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t('tunnel.fields.operState')}</dt>
                <dd>
                  <Technical>{observed.oper_state ?? '—'}</Technical>
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t('tunnel.fields.flags')}</dt>
                <dd>
                  <Technical>{(observed.flags ?? []).join(',')}</Technical>
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      ) : null}
    </div>
  )
}

function TunnelAudit({ interfaceName }: { interfaceName: string }) {
  const { t } = useTranslation()
  const { calendar, digits, language } = usePreferences()

  const auditQuery = useQuery({
    queryKey: ['audit', 'tunnel', interfaceName],
    queryFn: () =>
      api.get<AuditResponse>('/audit', {
        query: { target_type: 'Tunnel', target_id: interfaceName, limit: 25 },
      }),
    staleTime: 30_000,
  })

  if (auditQuery.isLoading) return <Skeleton className="h-32" />
  if (auditQuery.error) return <ErrorState error={auditQuery.error} onRetry={() => void auditQuery.refetch()} />

  const entries = auditQuery.data?.entries ?? []
  if (!entries.length) return <EmptyState title={t('audit.empty')} />

  return (
    <Card className="overflow-hidden">
      <ul className="divide-y divide-border">
        {entries.map((entry) => (
          <li key={entry.audit_log_id} className="flex flex-wrap items-baseline justify-between gap-2 p-3 text-xs">
            <span className="flex items-center gap-2">
              <Badge tone={entry.is_success ? 'ok' : 'danger'}>
                {entry.is_success ? t('audit.success') : t('audit.failure')}
              </Badge>
              {t(`audit.actions.${entry.action}`, entry.action)}
              {entry.username ? <span className="text-muted-foreground">· {entry.username}</span> : null}
            </span>
            <span className="text-2xs text-muted-foreground">
              {formatDateTime(entry.created_date, { locale: language, calendar, digits })}
            </span>
          </li>
        ))}
      </ul>
    </Card>
  )
}

function Figure({ label, value, plain }: { label: string; value: string; plain?: boolean }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{plain ? value : <Technical className="text-xs font-medium">{value}</Technical>}</dd>
    </div>
  )
}

function DetailSkeleton() {
  return (
    <div className="space-y-4">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-10 w-72" />
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-80 lg:col-span-2" />
        <div className="space-y-4">
          <Skeleton className="h-40" />
          <Skeleton className="h-36" />
        </div>
      </div>
    </div>
  )
}
