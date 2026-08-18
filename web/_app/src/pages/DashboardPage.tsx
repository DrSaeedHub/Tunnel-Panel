import { useMemo } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { ArrowUpCircle, Network, Plus, RefreshCw } from 'lucide-react'

import { api } from '@/lib/api'
import { cn } from '@/lib/utils'
import type { SettingsResponse, SystemInfo, TunnelListResponse } from '@/lib/types'
import { formatCount, formatDuration } from '@/lib/format'
import { useMetrics, series } from '@/hooks/useMetrics'
import type { useMonitorSummary } from '@/hooks/useMonitorSummary'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useUpdate } from '@/providers/UpdateProvider'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Badge, EmptyState, ErrorState, Skeleton } from '@/components/ui/feedback'
import { Technical } from '@/components/ui/technical'
import { StaleWrapper } from '@/components/layout/LiveIndicator'
import { AttentionCard } from '@/components/dashboard/AttentionCard'
import { CpuCard, DiskCard, MemoryCard, SwapCard } from '@/components/dashboard/ResourceCards'
import { TrafficCard } from '@/components/dashboard/TrafficCard'
import { RoutesStrip } from '@/components/dashboard/RoutesStrip'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

type MonitorContext = ReturnType<typeof useMonitorSummary>

export default function DashboardPage() {
  const { t } = useTranslation()
  const monitor = useOutletContext<MonitorContext>()
  const metrics = useMetrics(true)

  useDocumentTitle(t('dashboard.title'))

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<SettingsResponse>('/settings'),
    staleTime: 60_000,
  })

  const tunnelsQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 15_000,
  })

  const settings = settingsQuery.data?.settings ?? {}
  // These fallbacks are reached on first paint, before the settings query has
  // answered, so they have to be the schema's own defaults: anything else paints
  // a disk the wrong colour for a frame and then corrects itself.
  const warnPercent = numberSetting(settings, 'metrics.disk_warn_pct', 85)
  const criticalPercent = numberSetting(settings, 'metrics.disk_critical_pct', 95)
  const hideLoopback = settings['metrics.hide_loopback'] !== false

  // Interface name to tunnel identifier, so a tunnel row in the traffic
  // breakdown navigates to the tunnel it belongs to.
  const tunnelsByInterface = useMemo(() => {
    const map = new Map<string, number>()
    for (const entry of tunnelsQuery.data?.tunnels ?? []) {
      map.set(entry.tunnel.interface_name, entry.tunnel.tunnel_id)
    }
    return map
  }, [tunnelsQuery.data])

  if (metrics.error && !metrics.latest) {
    return <ErrorState error={metrics.error} onRetry={metrics.refetch} />
  }

  return (
    <div className="space-y-4 sm:space-y-5">
      {/* Absent unless something actually disagrees, so it means something
          when it appears. The machine itself always leads. */}
      <AttentionCard />

      {metrics.isLoading || !metrics.latest ? (
        <ResourceSkeleton />
      ) : (
        <StaleWrapper stale={metrics.stream.stale}>
          <div className="grid gap-4 sm:grid-cols-2 sm:gap-5 xl:grid-cols-4">
            <CpuCard
              snapshot={metrics.latest}
              // `cpu?.[0]`, not `cpu[0]?.`: the optional chain has to guard the
              // list itself, not only the element. The first reading after a
              // restart carries no CPU utilisation, because utilisation is a
              // delta and there is nothing to subtract from yet, and this threw
              // on it and took the whole resource grid down with it.
              history={series(metrics.history, (point) => point.cpu?.[0]?.usage_percent ?? 0)}
            />
            <MemoryCard
              snapshot={metrics.latest}
              history={series(metrics.history, (point) => point.memory.used_percent)}
            />
            <SwapCard snapshot={metrics.latest} />
            <DiskCard
              snapshot={metrics.latest}
              warnPercent={warnPercent}
              criticalPercent={criticalPercent}
            />
          </div>

          <div className="mt-4 sm:mt-5">
            <TrafficCard
              snapshot={metrics.latest}
              history={metrics.history}
              tunnelsByInterface={tunnelsByInterface}
              hideLoopbackByDefault={hideLoopback}
            />
          </div>
        </StaleWrapper>
      )}

      {/* The fleet counts live in the header's health chip; a server with no
          tunnels at all still gets the invitation, after the machine itself. */}
      <NoTunnelsInvite monitor={monitor} tunnels={tunnelsQuery.data} />

      {/* Relaying is the other half of what this server does. */}
      <RoutesStrip snapshot={metrics.latest} />

      <SystemStrip />
    </div>
  )
}

function numberSetting(settings: Record<string, unknown>, key: string, fallback: number): number {
  const value = settings[key]
  return typeof value === 'number' ? value : fallback
}

/** The invitation to create the first tunnel; absent once any tunnel exists. */
function NoTunnelsInvite({ monitor, tunnels }: { monitor: MonitorContext; tunnels?: TunnelListResponse }) {
  const { t } = useTranslation()
  const total = tunnels?.total ?? monitor.counts.total

  if (monitor.isLoading || total > 0) return null

  return (
    <Card>
      <CardContent>
        <EmptyState
          icon={<Network className="size-5" aria-hidden="true" />}
          title={t('dashboard.tunnels.emptyTitle')}
          body={t('dashboard.tunnels.emptyBody')}
          action={
            <Button asChild variant="primary">
              <Link to="/tunnels?create=1">
                <Plus className="size-4" aria-hidden="true" />
                {t('actions.createTunnel')}
              </Link>
            </Button>
          }
        />
      </CardContent>
    </Card>
  )
}

/** Hostname, distribution, kernel, uptime and panel version. */
function SystemStrip() {
  const { t } = useTranslation()
  const { digits, language } = usePreferences()

  const infoQuery = useQuery({
    queryKey: ['system', 'info'],
    queryFn: () => api.get<SystemInfo>('/system/info'),
    staleTime: 300_000,
  })

  if (infoQuery.isLoading) return <Skeleton className="h-12" />
  if (!infoQuery.data) return null

  const info = infoQuery.data
  const items: [string, React.ReactNode][] = [
    [t('dashboard.system.hostname'), <Technical key="host">{info.runtime.hostname}</Technical>],
    [t('dashboard.system.kernel'), <Technical key="kernel">{info.kernel.release}</Technical>],
    [t('dashboard.system.architecture'), <Technical key="arch">{info.runtime.arch}</Technical>],
    [
      t('dashboard.system.uptime'),
      formatDuration(info.runtime.uptime_seconds, digits, {
        day: t('units.day'),
        hour: t('units.hour'),
        minute: t('units.minute'),
        second: t('units.second'),
      }),
    ],
    [t('dashboard.system.version'), <PanelVersion key="version" version={info.build.version} />],
  ]

  // The machine's identity plate: a quiet strip on the plate itself rather
  // than another card competing with the instruments above it.
  return (
    <div className="flex flex-wrap gap-x-8 gap-y-2 border-t border-border/60 px-1 pt-4 text-xs">
      {items.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className="text-2xs text-muted-foreground">{label}</dt>
          <dd className="truncate font-medium">{value}</dd>
        </div>
      ))}
      <span className="sr-only">{formatCount(info.runtime.pid, digits, language)}</span>
    </div>
  )
}

/**
 * The version, and what to do about it.
 *
 * The build stamp is where an operator already looks to answer "what is this
 * running", so it is where the answer to "is there anything newer" belongs, and
 * the button that closes the gap belongs beside both. Everything behind it —
 * the check, the notice, the dialog — lives in the shell, so this stays a
 * button and the state does not restart when the operator leaves the page.
 */
function PanelVersion({ version }: { version: string }) {
  const { t } = useTranslation()
  const { status, open, applying } = useUpdate()

  const available = Boolean(status?.update_available)

  return (
    <span className="flex flex-wrap items-center gap-1.5">
      <Technical>{version}</Technical>
      {applying ? (
        <Badge tone="accent">{t('update.badge.applying')}</Badge>
      ) : (
        // One button in both states, opening the same dialog: an operator who
        // wants to know whether anything is newer looks in the same place as
        // one who has been told that something is, and the dialog is where
        // checking again, the release notes and the install all live.
        <Button
          variant={available ? 'primary' : 'ghost'}
          size="sm"
          className={cn('h-6 px-2.5 text-2xs', !available && 'px-2 text-muted-foreground')}
          onClick={open}
        >
          {available ? (
            <ArrowUpCircle className="size-3" aria-hidden="true" />
          ) : (
            <RefreshCw className="size-3" aria-hidden="true" />
          )}
          {available
            ? t('update.actions.updateTo', { version: status?.latest.version ?? '' })
            : t('update.badge.upToDate')}
        </Button>
      )}
    </span>
  )
}
/** Skeletons shaped like the cards they stand in for. */
function ResourceSkeleton() {
  return (
    <div className="space-y-4 sm:space-y-5">
      <div className="grid gap-4 sm:grid-cols-2 sm:gap-5 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Card key={index}>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-5 w-12" />
              </div>
              <Skeleton className="h-1.5" />
              <Skeleton className="h-7" />
              <div className="grid grid-cols-3 gap-2">
                <Skeleton className="h-6" />
                <Skeleton className="h-6" />
                <Skeleton className="h-6" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      <Skeleton className="h-48" />
    </div>
  )
}
