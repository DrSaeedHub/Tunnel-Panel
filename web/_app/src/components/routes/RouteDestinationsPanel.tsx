import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Loader2, Radio } from 'lucide-react'

import { api } from '@/lib/api'
import {
  LoadBalanceMode,
  RouteProtocol,
  type RouteConnectionList,
  type RouteDestination,
  type RouteDestinationLoad,
  type RelayTraffic,
  type RouteDestinationHealth,
  type RouteDestinationHealthResponse,
  type RouteReachabilityResult,
  type RouteRule,
} from '@/lib/types'
import {
  formatMs,
  formatPercent,
  formatThroughput,
  formatVolume,
  type UnitPreferences,
} from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { describeError } from '../ui/feedback'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, Meter, Skeleton } from '../ui/feedback'
import { Technical } from '../ui/technical'
import { endpointLabel } from './RouteFlow'

/**
 * Where a rule sends traffic, one line per destination.
 *
 * A relay with two destinations is the case the rest of the page cannot
 * describe: every figure above it is a total, and a total is exactly what hides
 * a destination taking nothing. So each destination gets its own line, and each
 * line answers three separate questions — what the rule says about it, where
 * the traffic is actually going, and whether it answers at all.
 *
 * The share is read from connection tracking and not from the ruleset, because
 * the ruleset only says what was intended. It counts the connections open now,
 * which is why a quiet relay shows no share rather than an even one: nothing
 * has been distributed yet.
 */
export function RouteDestinationsPanel({
  route,
  live: ruleTraffic,
}: {
  route: RouteRule
  /** The rule's own live figures, which the destinations are checked against. */
  live?: RelayTraffic
}) {
  const { t } = useTranslation()
  const { digits, units } = usePreferences()

  // The same query the connections tab uses, so opening both costs one read of
  // a table that is expensive to read on a busy host.
  const query = useQuery({
    queryKey: ['routes', route.route_rule_id, 'connections'],
    queryFn: () => api.get<RouteConnectionList>(`/routes/${route.route_rule_id}/connections`),
    refetchInterval: 10_000,
  })

  // What the monitor has found, which is a different question from what the
  // traffic shows: a destination with no connections may be dead or may
  // simply be next in the rotation.
  const healthQuery = useQuery({
    queryKey: ['routes', route.route_rule_id, 'destinations', 'health'],
    queryFn: () =>
      api.get<RouteDestinationHealthResponse>(
        `/routes/${route.route_rule_id}/destinations/health`,
      ),
    refetchInterval: 10_000,
  })
  const healthByAddress = useMemo(() => {
    const map = new Map<string, RouteDestinationHealth>()
    for (const entry of healthQuery.data?.destinations ?? []) {
      map.set(`${entry.address}:${entry.port}`, entry)
    }
    return map
  }, [healthQuery.data])

  const rows = useMemo(
    () => joinDestinations(route, query.data?.by_destination ?? []),
    [route, query.data],
  )

  const live = query.data?.available ?? false
  // Two separate things can be missing. The table may be unreadable, in which
  // case there are no connections either; or it may be readable while the
  // kernel counts no bytes on them, which is the default on most kernels and
  // is why a busy relay can show thousands of connections and no volume.
  const counting = query.data?.byte_accounting ?? false
  const rateSeconds = query.data?.rate_interval_seconds ?? 0
  const totalConnections = rows.reduce((sum, row) => sum + row.connections, 0)

  // What the destinations account for, against what the rule's own counters
  // say crossed it. The two do not have to agree: a connection that opened
  // and closed between two readings of the table moved bytes that no
  // destination can be credited with. Printing the shortfall is the only
  // honest way to show a figure that is a floor.
  const measured =
    rows.reduce((sum, row) => sum + row.rxRate + row.txRate, 0) || 0
  const ruleRate =
    (ruleTraffic?.rx_bytes_per_second ?? 0) + (ruleTraffic?.tx_bytes_per_second ?? 0)
  const unattributed = ruleRate > 0 && measured < ruleRate * 0.9
  const mode = route.load_balance_mode_id
  // Two destinations in the rotation are distributed across whatever the mode
  // says, including when it says nothing: the ruleset falls back to round robin
  // rather than sending everything to the first, so the panel does too.
  const balanced = rows.filter((row) => row.enabled && row.configured).length > 1

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>{t('routeDetail.destinations.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {t('routeDetail.destinations.count', { count: rows.length })}
            {balanced && mode !== LoadBalanceMode.None
              ? ` · ${t(`routes.loadBalance.${mode}`)}`
              : ''}
          </p>
        </div>
      </CardHeader>
      <CardContent>
        {balanced ? (
          <p className="mb-3 text-xs text-muted-foreground">
            {t(`routeDetail.destinations.mode.${mode}`)}
          </p>
        ) : null}

        {query.isLoading ? (
          <Skeleton className="h-24" />
        ) : (
          <>
            {!live ? (
              <p className="mb-3 flex items-start gap-2 rounded-md border border-warn/40 bg-warn-muted p-3 text-2xs">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
                {t('routeDetail.destinations.unknownShare')}
              </p>
            ) : null}

            <ul className="divide-y divide-border">
              {rows.map((row, index) => (
                <DestinationRow
                  key={`${row.address}:${row.port}:${index}`}
                  row={row}
                  index={index}
                  route={route}
                  live={live}
                  health={healthByAddress.get(`${row.address}:${row.port}`)}
                  counting={counting}
                  rated={rateSeconds > 0}
                  balanced={balanced}
                  totalConnections={totalConnections}
                  digits={digits}
                  units={units}
                />
              ))}
            </ul>

            {live && !counting ? <CountingOffNotice /> : null}

            {live && counting ? (
              <div className="mt-3 space-y-1">
                {unattributed ? (
                  <p className="text-2xs text-muted-foreground">
                    {t('routeDetail.destinations.unattributed', {
                      measured: formatThroughput(measured, units).text,
                      total: formatThroughput(ruleRate, units).text,
                    })}
                  </p>
                ) : null}
                <p className="text-2xs text-muted-foreground">
                  {t('routeDetail.destinations.snapshotNote')}
                </p>
              </div>
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * The kernel is tracking the connections without counting the bytes on them.
 *
 * That is the default on most kernels, and it is one parameter away from not
 * being. The panel sets it the same way it sets forwarding -- recorded in its
 * own sysctl file, so it survives a reboot and can be put back -- which is why
 * this offers a button rather than a command to paste into a shell.
 */
function CountingOffNotice() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [busy, setBusy] = useState(false)

  const enable = async () => {
    setBusy(true)
    try {
      await api.post('/system/forwarding/enable', {})
      toast({ tone: 'success', title: t('routeDetail.destinations.countingOnDone') })
      await queryClient.invalidateQueries({ queryKey: ['routes'] })
    } catch (error) {
      toast({
        tone: 'error',
        title: t('routeDetail.destinations.countingOn'),
        description: describeError(error, t).message,
      })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mt-3 rounded-md border border-warn/40 bg-warn-muted p-3">
      <p className="flex items-start gap-2 text-2xs">
        <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
        {t('routeDetail.destinations.noByteAccounting')}
      </p>
      <Button variant="secondary" size="sm" className="mt-2" loading={busy} onClick={() => void enable()}>
        {t('routeDetail.destinations.countingOn')}
      </Button>
    </div>
  )
}

/** One destination: what the rule says, what the kernel shows, and a probe. */
function DestinationRow({
  row,
  index,
  route,
  live,
  health,
  counting,
  rated,
  balanced,
  totalConnections,
  digits,
  units,
}: {
  row: DestinationRowModel
  index: number
  route: RouteRule
  live: boolean
  /** The monitor's verdict, when this rule is monitored at all. */
  health?: RouteDestinationHealth
  /** Whether the kernel is counting bytes, without which volume is not zero — it is unknown. */
  counting: boolean
  /** Whether there have been two readings to measure a rate between. */
  rated: boolean
  balanced: boolean
  totalConnections: number
  digits: 'latin' | 'persian'
  units: UnitPreferences
}) {
  const { t } = useTranslation()
  const probe = useDestinationProbe(route, row.address, row.port)

  const share = totalConnections > 0 ? (row.connections / totalConnections) * 100 : 0
  const expected = expectedShare(route, row, balanced)
  // A destination in the rotation carrying nothing while the others carry
  // something is the failure this panel exists to make visible.
  const idle = live && row.enabled && row.configured && totalConnections > 0 && row.connections === 0

  return (
    <li className="py-3 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="neutral">{t('routeDetail.destinations.order', { index: index + 1 })}</Badge>
        <Technical className="text-sm font-medium">
          {endpointLabel(row.address, row.port, row.portRangeEnd)}
        </Technical>
        {/* The monitor's verdict leads the badges: it is the one that says
            whether anything is listening, rather than whether anything
            happens to be connected. */}
        {health && health.state !== 'Disabled' ? (
          <Badge
            tone={health.state === 'Up' ? 'ok' : health.state === 'Down' ? 'danger' : 'neutral'}
          >
            {t(`monitor.state.${health.state}`)}
          </Badge>
        ) : null}
        {health?.is_suppressed ? (
          <Badge tone="warn">{t('routeDetail.destinations.outOfRotation')}</Badge>
        ) : null}
        {!row.enabled ? <Badge tone="neutral">{t('routeDetail.destinations.disabled')}</Badge> : null}
        {!row.configured ? (
          <Badge tone="warn">{t('routeDetail.destinations.unconfigured')}</Badge>
        ) : null}
        {idle && health?.state !== 'Up' ? (
          <Badge tone="warn">{t('routeDetail.destinations.idle')}</Badge>
        ) : null}
        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="ms-auto"
          disabled={probe.busy}
          onClick={() => void probe.run()}
        >
          {probe.busy ? (
            <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
          ) : (
            <Radio className="size-3.5" aria-hidden="true" />
          )}
          {probe.busy ? t('routeDetail.destinations.testing') : t('routeDetail.destinations.test')}
        </Button>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-muted-foreground">
        {row.weight !== null ? (
          <span>{t('routeDetail.destinations.weight', { weight: row.weight })}</span>
        ) : null}
        {expected !== null ? (
          <span>
            {t('routeDetail.destinations.expected', { percent: formatPercent(expected, digits, 0) })}
          </span>
        ) : null}
        {live ? (
          <span className="tabular text-foreground">
            {t('routeDetail.destinations.connections', { count: row.connections })}
          </span>
        ) : null}
        {live && counting && rated ? (
          <span className="tabular text-foreground">
            {`↓ ${formatThroughput(row.rxRate, units).text} · ↑ ${formatThroughput(row.txRate, units).text}`}
          </span>
        ) : null}
        {live && counting ? (
          <span className="tabular">
            {`↓ ${formatVolume(row.rxBytes, units).text} · ↑ ${formatVolume(row.txBytes, units).text}`}
          </span>
        ) : null}
      </div>

      {/* A destination out of the rotation is not competing for a share, so it
          gets no bar: an empty track beside "out of the rotation" reads as a
          destination that is being starved rather than one that was switched
          off. */}
      {live && balanced && row.enabled ? (
        <div className="mt-1.5 flex items-center gap-2">
          <Meter
            value={share}
            tone={idle ? 'warn' : 'accent'}
            label={t('routeDetail.destinations.shareLabel', {
              address: endpointLabel(row.address, row.port, row.portRangeEnd),
            })}
          />
          <span className="tabular w-12 shrink-0 text-end text-2xs text-muted-foreground">
            {formatPercent(share, digits, 0)}
          </span>
        </div>
      ) : null}

      {/* The probe's answer goes on its own line rather than beside the button:
          a refusal explains itself in a sentence, and a sentence squeezed into
          a row of badges is where the layout breaks. */}
      {probe.result ? (
        <p
          role="status"
          className={
            probe.result.reachable
              ? 'mt-1.5 flex items-start gap-1 text-2xs text-ok'
              : probe.result.conclusive
                ? 'mt-1.5 flex items-start gap-1 text-2xs text-danger'
                : 'mt-1.5 flex items-start gap-1 text-2xs text-muted-foreground'
          }
        >
          {probe.result.reachable ? (
            <Check className="mt-0.5 size-3 shrink-0" aria-hidden="true" />
          ) : null}
          {probe.result.reachable
            ? t('routeDetail.destinations.reachable', {
                latency: formatMs(probe.result.latency_ms ?? 0, digits) ?? '',
              })
            : probe.result.detail}
        </p>
      ) : null}

      {/* The probe's own words when it failed, which is the difference
          between a refused connection and a timeout. */}
      {health && health.state === 'Down' && health.detail ? (
        <p className="mt-1.5 text-2xs text-danger">
          {health.is_suppressed
            ? t('routeDetail.destinations.downAndOut', { detail: health.detail })
            : t('routeDetail.destinations.down', { detail: health.detail })}
        </p>
      ) : null}

      {idle && !health ? (
        <p className="mt-1.5 text-2xs text-warn">{t('routeDetail.destinations.idleHint')}</p>
      ) : null}
      {!row.configured ? (
        <p className="mt-1.5 text-2xs text-muted-foreground">
          {t('routeDetail.destinations.unconfiguredHint')}
        </p>
      ) : null}
    </li>
  )
}

/**
 * The reachability probe, run from this server against one destination.
 *
 * It is the same read of the network the create form offers before a rule
 * exists, asked again of a rule that does: a destination that stopped answering
 * looks identical to one that is simply idle until something knocks on it.
 */
function useDestinationProbe(route: RouteRule, address: string, port: number) {
  const [result, setResult] = useState<RouteReachabilityResult | null>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    setResult(null)
    try {
      setResult(
        await api.post<RouteReachabilityResult>('/routes/diagnostics/test', {
          address,
          port,
          protocol: route.route_protocol_id === RouteProtocol.UDP ? 'udp' : 'tcp',
        }),
      )
    } catch {
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  return { result, busy, run }
}

interface DestinationRowModel {
  address: string
  port: number
  portRangeEnd: number | null
  /** Null unless the rule is weighted, where a weight is what it distributes by. */
  weight: number | null
  enabled: boolean
  /** False for a destination conntrack still shows but the rule no longer has. */
  configured: boolean
  connections: number
  rxBytes: number
  txBytes: number
  rxRate: number
  txRate: number
}

/**
 * The rule's destinations joined to what conntrack shows for each.
 *
 * Both directions matter. A configured destination with no live entry is the
 * one an operator needs to see; a live entry with no configured destination is
 * what the table holds for a while after a destination is edited away, and
 * dropping it would leave connections unaccounted for.
 */
export function joinDestinations(
  route: RouteRule,
  load: RouteDestinationLoad[],
): DestinationRowModel[] {
  const weighted = route.load_balance_mode_id === LoadBalanceMode.Weighted
  const configured: RouteDestination[] = route.destinations?.length
    ? [...route.destinations].sort((a, b) => a.sort_order - b.sort_order)
    : []

  const byKey = new Map(load.map((entry) => [`${entry.address}:${entry.port}`, entry]))
  const rows: DestinationRowModel[] = []

  const take = (address: string, port: number) => {
    const entry = byKey.get(`${address}:${port}`)
    byKey.delete(`${address}:${port}`)
    return entry
  }

  if (configured.length) {
    for (const destination of configured) {
      const entry = take(destination.address, destination.port)
      rows.push({
        address: destination.address,
        port: destination.port,
        portRangeEnd: destination.port_range_end,
        weight: weighted ? destination.weight : null,
        enabled: destination.is_enabled,
        configured: true,
        connections: entry?.connections ?? 0,
        rxBytes: entry?.rx_bytes ?? 0,
        txBytes: entry?.tx_bytes ?? 0,
        rxRate: entry?.rx_bytes_per_second ?? 0,
        txRate: entry?.tx_bytes_per_second ?? 0,
      })
    }
  } else {
    // A rule stored before destinations became rows of their own still carries
    // the pair on the rule itself, and that pair is the destination.
    const entry = take(route.destination_address, route.destination_port)
    rows.push({
      address: route.destination_address,
      port: route.destination_port,
      portRangeEnd: route.destination_port_range_end,
      weight: null,
      enabled: true,
      configured: true,
      connections: entry?.connections ?? 0,
      rxBytes: entry?.rx_bytes ?? 0,
      txBytes: entry?.tx_bytes ?? 0,
      rxRate: entry?.rx_bytes_per_second ?? 0,
      txRate: entry?.tx_bytes_per_second ?? 0,
    })
  }

  for (const entry of byKey.values()) {
    rows.push({
      address: entry.address,
      port: entry.port,
      portRangeEnd: null,
      weight: null,
      enabled: true,
      configured: false,
      connections: entry.connections,
      rxBytes: entry.rx_bytes,
      txBytes: entry.tx_bytes,
      rxRate: entry.rx_bytes_per_second,
      txRate: entry.tx_bytes_per_second,
    })
  }

  return rows
}

/**
 * The share the rule intends for a destination, where it intends one.
 *
 * Round robin and weighted both distribute by rotation, so the intended share
 * is arithmetic. Source hash distributes by client, so its intended share
 * depends on who is connecting and there is no honest number to print.
 */
function expectedShare(
  route: RouteRule,
  row: DestinationRowModel,
  balanced: boolean,
): number | null {
  if (!balanced || !row.enabled || !row.configured) return null
  const inRotation = (route.destinations ?? []).filter((entry) => entry.is_enabled)
  if (inRotation.length < 2) return null

  // None is round robin here for the same reason it is in the ruleset.
  if (
    route.load_balance_mode_id === LoadBalanceMode.RoundRobin ||
    route.load_balance_mode_id === LoadBalanceMode.None
  ) {
    return 100 / inRotation.length
  }
  if (route.load_balance_mode_id === LoadBalanceMode.Weighted) {
    const total = inRotation.reduce((sum, entry) => sum + Math.max(1, entry.weight), 0)
    if (total <= 0) return null
    return (Math.max(1, row.weight ?? 1) / total) * 100
  }
  return null
}
