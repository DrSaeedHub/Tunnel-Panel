import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { ArrowDown, ArrowUp, ChevronDown, Gauge, Info } from 'lucide-react'

import type { MetricsSnapshot, NetInterface, RelayTraffic } from '@/lib/types'
import { formatThroughput, formatVolume } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../ui/disclosure'
import { Sparkline } from '../ui/sparkline'
import { Technical } from '../ui/technical'
import { Tooltip } from '../ui/overlay'

/**
 * Which cumulative figure is on screen.
 *
 * Kernel counters reset whenever an interface is recreated, which happens
 * routinely because restarting a tunnel rebuilds its link. The backend keeps
 * both figures, and they are never blended: the operator is always told which
 * one they are looking at.
 */
type VolumeBasis = 'boot' | 'install'
type SortKey = 'rate' | 'volume' | 'name'

const GROUP_ORDER = ['physical', 'tunnel', 'other', 'loopback'] as const
type Group = (typeof GROUP_ORDER)[number]

function groupOf(iface: NetInterface): Group {
  if (iface.is_loopback || iface.class === 'loopback') return 'loopback'
  if (iface.class === 'tunnel') return 'tunnel'
  if (iface.class === 'physical') return 'physical'
  return 'other'
}

export function TrafficCard({
  snapshot,
  history,
  tunnelsByInterface,
  hideLoopbackByDefault,
}: {
  snapshot: MetricsSnapshot
  history: MetricsSnapshot[]
  /** Lets a tunnel row link to the tunnel it belongs to. */
  tunnelsByInterface: Map<string, number>
  hideLoopbackByDefault: boolean
}) {
  const { t } = useTranslation()
  const { units } = usePreferences()

  const [expanded, setExpanded] = useState(false)
  const [basis, setBasis] = useState<VolumeBasis>('boot')
  const [showLoopback, setShowLoopback] = useState(!hideLoopbackByDefault)
  const [sortKey, setSortKey] = useState<SortKey>('rate')

  const totals = snapshot.network.totals
  const rxSeries = useMemo(() => history.map((point) => point.network.totals.rx_bytes_per_second), [history])
  const txSeries = useMemo(() => history.map((point) => point.network.totals.tx_bytes_per_second), [history])

  const volumeRx = basis === 'boot' ? totals.rx_bytes_since_boot : totals.rx_bytes_since_install
  const volumeTx = basis === 'boot' ? totals.tx_bytes_since_boot : totals.tx_bytes_since_install

  const grouped = useMemo(() => {
    const visible = (snapshot.network.interfaces ?? []).filter(
      (iface) => showLoopback || groupOf(iface) !== 'loopback',
    )
    const sorted = [...visible].sort((a, b) => {
      if (sortKey === 'name') return a.name.localeCompare(b.name)
      if (sortKey === 'volume') {
        const left = basis === 'boot' ? a.rx_bytes_since_boot + a.tx_bytes_since_boot : a.rx_bytes_since_install + a.tx_bytes_since_install
        const right = basis === 'boot' ? b.rx_bytes_since_boot + b.tx_bytes_since_boot : b.rx_bytes_since_install + b.tx_bytes_since_install
        return right - left
      }
      return (
        b.rx_bytes_per_second + b.tx_bytes_per_second - (a.rx_bytes_per_second + a.tx_bytes_per_second)
      )
    })

    const groups = new Map<Group, NetInterface[]>()
    for (const iface of sorted) {
      const group = groupOf(iface)
      groups.set(group, [...(groups.get(group) ?? []), iface])
    }
    return groups
  }, [snapshot.network.interfaces, showLoopback, sortKey, basis])

  const historyFor = (name: string) =>
    history.map((point) => {
      const iface = point.network.interfaces.find((entry) => entry.name === name)
      return iface ? iface.rx_bytes_per_second + iface.tx_bytes_per_second : 0
    })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Gauge className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('dashboard.traffic.title')}
        </CardTitle>
        <BasisSwitch basis={basis} onChange={setBasis} />
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <TotalsBlock
            title={t('dashboard.traffic.throughput')}
            down={formatThroughput(totals.rx_bytes_per_second, units).text}
            up={formatThroughput(totals.tx_bytes_per_second, units).text}
            downSeries={rxSeries}
            upSeries={txSeries}
          />
          <TotalsBlock
            title={t('dashboard.traffic.volume')}
            down={formatVolume(volumeRx, units).text}
            up={formatVolume(volumeTx, units).text}
            caption={
              basis === 'boot' ? t('dashboard.traffic.sinceBoot') : t('dashboard.traffic.sinceInstall')
            }
            captionHint={
              basis === 'boot'
                ? t('dashboard.traffic.sinceBootHint')
                : t('dashboard.traffic.sinceInstallHint')
            }
          />
        </div>

        <Collapsible open={expanded} onOpenChange={setExpanded}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CollapsibleTrigger className="group flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
              <ChevronDown
                className="size-3.5 transition-transform duration-250 group-data-[state=open]:rotate-180"
                aria-hidden="true"
              />
              {expanded ? t('dashboard.traffic.hideBreakdown') : t('dashboard.traffic.showBreakdown')}
            </CollapsibleTrigger>

            {expanded ? (
              <div className="flex items-center gap-2 text-2xs">
                <label className="flex items-center gap-1 text-muted-foreground">
                  {t('dashboard.traffic.sortBy')}
                  <select
                    value={sortKey}
                    onChange={(event) => setSortKey(event.target.value as SortKey)}
                    className="rounded border border-border bg-surface px-1.5 py-0.5 text-2xs"
                  >
                    <option value="rate">{t('dashboard.traffic.sortByRate')}</option>
                    <option value="volume">{t('dashboard.traffic.sortByVolume')}</option>
                    <option value="name">{t('dashboard.traffic.sortByName')}</option>
                  </select>
                </label>
                <button
                  type="button"
                  onClick={() => setShowLoopback((v) => !v)}
                  className="text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
                >
                  {showLoopback ? t('dashboard.traffic.hideLoopback') : t('dashboard.traffic.showLoopback')}
                </button>
              </div>
            ) : null}
          </div>

          <CollapsibleContent className="pt-3">
            {grouped.size ? (
              <div className="space-y-4">
                {GROUP_ORDER.filter((group) => grouped.has(group)).map((group) => (
                  <section key={group}>
                    <h4 className="display mb-1.5 px-1 text-2xs font-semibold text-muted-foreground">
                      {t(`dashboard.traffic.group.${group}`)}
                    </h4>
                    <ul className="space-y-1">
                      {(grouped.get(group) ?? []).map((iface) => (
                        <InterfaceRow
                          key={iface.name}
                          iface={iface}
                          basis={basis}
                          history={historyFor(iface.name)}
                          tunnelId={tunnelsByInterface.get(iface.name)}
                        />
                      ))}
                    </ul>
                  </section>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">{t('dashboard.traffic.noInterfaces')}</p>
            )}

            {/* Relayed traffic is accounted for rather than left unexplained:
                without this section a busy relay shows as unattributed volume
                on the physical interfaces it entered and left by. */}
            {snapshot.routes?.length ? (
              <section className="mt-4">
                <h4 className="display mb-1.5 px-1 text-2xs font-semibold text-muted-foreground">
                  {t('routesSummary.relayed')}
                </h4>
                <ul className="space-y-1">
                  {[...snapshot.routes]
                    .sort(
                      (a, b) =>
                        b.rx_bytes_per_second +
                        b.tx_bytes_per_second -
                        (a.rx_bytes_per_second + a.tx_bytes_per_second),
                    )
                    .map((relay) => (
                      <RelayRow key={relay.route_rule_id} relay={relay} basis={basis} />
                    ))}
                </ul>
                <p className="mt-1.5 text-2xs text-muted-foreground">{t('routesSummary.relayedNote')}</p>
              </section>
            ) : null}
          </CollapsibleContent>
        </Collapsible>
      </CardContent>
    </Card>
  )
}

/**
 * One forwarding rule in the traffic breakdown.
 *
 * It follows the interface rows deliberately: an interface is where bytes
 * physically moved, a rule is why they moved, and both are true of the same
 * bytes.
 */
function RelayRow({ relay, basis }: { relay: RelayTraffic; basis: VolumeBasis }) {
  const { units } = usePreferences()
  const volume =
    basis === 'boot'
      ? relay.rx_bytes_since_boot + relay.tx_bytes_since_boot
      : relay.rx_bytes_since_creation + relay.tx_bytes_since_creation

  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-full bg-surface-sunken/70 px-4 py-2 text-xs">
      <Link
        to={`/routes/${relay.route_rule_id}`}
        className="min-w-0 flex-1 truncate font-medium hover:underline"
      >
        {relay.title}
      </Link>
      <span className="tabular flex items-center gap-1 text-2xs">
        <ArrowDown className="size-3 text-ok" aria-hidden="true" />
        {formatThroughput(relay.rx_bytes_per_second, units).text}
      </span>
      <span className="tabular flex items-center gap-1 text-2xs">
        <ArrowUp className="size-3 text-accent" aria-hidden="true" />
        {formatThroughput(relay.tx_bytes_per_second, units).text}
      </span>
      <span className="tabular text-2xs text-muted-foreground">{formatVolume(volume, units).text}</span>
    </li>
  )
}

function BasisSwitch({ basis, onChange }: { basis: VolumeBasis; onChange: (value: VolumeBasis) => void }) {
  const { t } = useTranslation()
  return (
    <div className="inline-flex rounded-full border border-border/60 bg-surface-sunken p-0.5 text-2xs" role="group">
      {(
        [
          ['boot', 'dashboard.traffic.sinceBoot'],
          ['install', 'dashboard.traffic.sinceInstall'],
        ] as const
      ).map(([value, labelKey]) => (
        <button
          key={value}
          type="button"
          onClick={() => onChange(value)}
          aria-pressed={basis === value}
          className={cn(
            'rounded-full px-2.5 py-1 font-medium transition-colors',
            basis === value ? 'bg-ink text-ink-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {t(labelKey)}
        </button>
      ))}
    </div>
  )
}

function TotalsBlock({
  title,
  down,
  up,
  downSeries,
  upSeries,
  caption,
  captionHint,
}: {
  title: string
  down: string
  up: string
  downSeries?: number[]
  upSeries?: number[]
  caption?: string
  captionHint?: string
}) {
  const { t } = useTranslation()
  return (
    <div className="rounded-lg bg-surface-sunken/70 p-3.5">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">{title}</p>
        {caption ? (
          <span className="flex items-center gap-1 text-2xs text-muted-foreground">
            {caption}
            {captionHint ? (
              <Tooltip content={captionHint}>
                <button type="button" aria-label={captionHint} className="hover:text-foreground">
                  <Info className="size-3" aria-hidden="true" />
                </button>
              </Tooltip>
            ) : null}
          </span>
        ) : null}
      </div>
      <div className="mt-2 grid grid-cols-2 gap-3">
        <div>
          <p className="flex items-center gap-1 text-2xs text-muted-foreground">
            <ArrowDown className="size-3" aria-hidden="true" />
            {t('dashboard.traffic.down')}
          </p>
          <p className="readout text-xl">{down}</p>
          {downSeries ? <Sparkline values={downSeries} tone="accent" height={20} /> : null}
        </div>
        <div>
          <p className="flex items-center gap-1 text-2xs text-muted-foreground">
            <ArrowUp className="size-3" aria-hidden="true" />
            {t('dashboard.traffic.up')}
          </p>
          <p className="readout text-xl">{up}</p>
          {upSeries ? <Sparkline values={upSeries} tone="ok" height={20} /> : null}
        </div>
      </div>
    </div>
  )
}

function InterfaceRow({
  iface,
  basis,
  history,
  tunnelId,
}: {
  iface: NetInterface
  basis: VolumeBasis
  history: number[]
  tunnelId?: number
}) {
  const { units } = usePreferences()

  const volume =
    basis === 'boot'
      ? iface.rx_bytes_since_boot + iface.tx_bytes_since_boot
      : iface.rx_bytes_since_install + iface.tx_bytes_since_install

  const body = (
    <>
      <div className="flex min-w-0 flex-1 items-center gap-2">
        <span
          className={cn(
            'size-1.5 shrink-0 rounded-full',
            iface.is_up ? 'bg-ok' : 'bg-muted-foreground',
          )}
          aria-hidden="true"
        />
        <div className="min-w-0">
          <Technical className="block truncate text-xs">{iface.name}</Technical>
          {iface.primary_address ? (
            <Technical className="block truncate text-2xs text-muted-foreground">
              {iface.primary_address}
            </Technical>
          ) : null}
        </div>
      </div>

      <div className="hidden w-24 shrink-0 sm:block">
        <Sparkline values={history} tone="accent" height={16} />
      </div>

      <div className="shrink-0 text-end">
        <p className="tabular text-2xs">
          ↓ {formatThroughput(iface.rx_bytes_per_second, units).text}
        </p>
        <p className="tabular text-2xs text-muted-foreground">
          ↑ {formatThroughput(iface.tx_bytes_per_second, units).text}
        </p>
      </div>

      <div className="hidden w-24 shrink-0 text-end sm:block">
        <p className="tabular text-2xs">{formatVolume(volume, units).text}</p>
      </div>
    </>
  )

  return (
    <li>
      {tunnelId ? (
        <Link
          to={`/tunnels/${tunnelId}`}
          className="flex items-center gap-3 rounded-full bg-surface-sunken/70 px-4 py-[var(--row-padding-block)] transition-colors hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {body}
        </Link>
      ) : (
        <div className="flex items-center gap-3 rounded-full bg-surface-sunken/70 px-4 py-[var(--row-padding-block)]">{body}</div>
      )}
    </li>
  )
}
