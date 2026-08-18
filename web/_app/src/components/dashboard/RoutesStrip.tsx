import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowDownUp, CheckCircle2, Plus, Waypoints } from 'lucide-react'

import { api } from '@/lib/api'
import type { MetricsSnapshot, RouteListResponse } from '@/lib/types'
import { formatCount, formatThroughput } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Button } from '../ui/button'
import { Card, CardContent } from '../ui/card'
import { EmptyState } from '../ui/feedback'
import { cn } from '@/lib/utils'

/**
 * The forwarding summary, beside the tunnel one.
 *
 * Each figure is a filtered link into the routes page, so "2 impaired" is one
 * click from the two rules that are impaired rather than a number to go hunting
 * for — the same construction the tunnel strip uses, for the same reason.
 */
export function RoutesStrip({ snapshot }: { snapshot: MetricsSnapshot | null }) {
  const { t } = useTranslation()
  const { digits, language, units } = usePreferences()

  const routesQuery = useQuery({
    queryKey: ['routes', 'list'],
    queryFn: () => api.get<RouteListResponse>('/routes'),
    staleTime: 15_000,
  })

  const entries = routesQuery.data?.routes ?? []
  const total = routesQuery.data?.total ?? 0

  if (routesQuery.isLoading) return null

  if (total === 0) {
    return (
      <Card>
        <CardContent>
          <EmptyState
            icon={<Waypoints className="size-5" aria-hidden="true" />}
            title={t('routesSummary.emptyTitle')}
            body={t('routesSummary.emptyBody')}
            action={
              <Button asChild variant="primary">
                <Link to="/routes?create=1">
                  <Plus className="size-4" aria-hidden="true" />
                  {t('actions.createRoute')}
                </Link>
              </Button>
            }
          />
        </CardContent>
      </Card>
    )
  }

  const enabled = entries.filter((entry) => entry.route.is_enabled).length
  const impaired = entries.filter(
    (entry) =>
      entry.health.state === 'impaired' ||
      entry.health.state === 'failed' ||
      entry.health.state === 'inconsistent',
  ).length

  const totals = snapshot?.route_totals
  const throughput = formatThroughput(
    (totals?.rx_bytes_per_second ?? 0) + (totals?.tx_bytes_per_second ?? 0),
    units,
  ).text

  const number = (value: number) => formatCount(value, digits, language)

  const cells = [
    { key: 'total', label: t('routesSummary.total'), value: number(total), to: '/routes', tone: 'neutral' as const },
    {
      key: 'enabled',
      label: t('routesSummary.enabled'),
      value: number(enabled),
      to: '/routes?status=healthy',
      tone: 'ok' as const,
      Icon: CheckCircle2,
    },
    {
      key: 'impaired',
      label: t('routesSummary.impaired'),
      value: number(impaired),
      to: '/routes?status=impaired',
      tone: impaired > 0 ? ('warn' as const) : ('neutral' as const),
      Icon: AlertTriangle,
    },
    {
      key: 'throughput',
      label: t('routesSummary.throughput'),
      value: throughput,
      to: '/routes?sort=rate',
      tone: 'neutral' as const,
      Icon: ArrowDownUp,
    },
    {
      key: 'connections',
      label: t('routesSummary.connections'),
      value: number(totals?.active_connections ?? 0),
      to: '/routes',
      tone: 'neutral' as const,
    },
  ]

  // The first two figures share a row with the title; the live pair below get
  // the larger readouts — an uneven board, weighted by what changes.
  const [totalCell, enabledCell, impairedCell, throughputCell, connectionsCell] = cells

  return (
    <Card className="flex h-full flex-col">
      <CardContent className="flex h-full flex-col gap-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="display text-sm font-semibold">{t('routesSummary.title')}</p>
          <div className="flex gap-1.5">
            {[totalCell, enabledCell, impairedCell].map(({ key, label, value, to, tone, Icon }) => (
              <Link
                key={key}
                to={to}
                className={cn(
                  'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  tone === 'ok' && 'bg-ok-muted text-ok hover:bg-ok-muted/70',
                  tone === 'warn' && 'bg-warn-muted text-warn hover:bg-warn-muted/70',
                  tone === 'neutral' && 'bg-muted text-muted-foreground hover:bg-muted/70',
                )}
              >
                {Icon ? <Icon className="size-3.5" aria-hidden="true" /> : null}
                {label}
                <span className="tabular font-semibold">{value}</span>
              </Link>
            ))}
          </div>
        </div>

        <div className="grid flex-1 grid-cols-2 gap-3">
          {[throughputCell, connectionsCell].map(({ key, label, value, to }) => (
            <Link
              key={key}
              to={to}
              className="flex flex-col justify-end gap-1 rounded-lg bg-surface-sunken/70 p-3.5 transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <span className="text-xs text-muted-foreground">{label}</span>
              <span className="readout text-2xl sm:text-[1.75rem]">{value}</span>
            </Link>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
