import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Area,
  CartesianGrid,
  ComposedChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from 'recharts'

import type { RouteTrafficPoint, RouteTrafficSample } from '@/lib/types'
import { formatThroughput, formatTime, formatVolume } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Button } from '../ui/button'
import { EmptyState } from '../ui/feedback'
import { Technical } from '../ui/technical'

/**
 * Relayed traffic in and out, over time.
 *
 * In and out share one axis and are stacked mirror-image — in above the line,
 * out below — because the question is whether the two directions match, and
 * two separate charts turn an observation into a comparison.
 *
 * Under RTL the whole chart mirrors: the value axis moves to the right and the
 * time axis reverses, so time still runs from the past towards the present in
 * the reading direction.
 */
export function RouteTrafficChart({
  points,
  samples,
  live,
}: {
  /** The in-memory ring buffer, for the live range. */
  points: RouteTrafficPoint[]
  /** Stored aggregate buckets, for the longer ranges. */
  samples: RouteTrafficSample[]
  live: boolean
}) {
  const { t } = useTranslation()
  const { dir, digits, calendar, language, units } = usePreferences()
  const [showTable, setShowTable] = useState(false)

  const rtl = dir === 'rtl'

  const data = useMemo(() => {
    if (live) {
      return points.map((point) => ({
        at: point.at,
        rx: point.rx_bytes_per_second,
        // Out is drawn below the axis so the two directions are comparable at a
        // glance; the sign is presentation and never reaches a figure.
        tx: -point.tx_bytes_per_second,
        rxRaw: point.rx_bytes_per_second,
        txRaw: point.tx_bytes_per_second,
        connections: point.active_connections,
      }))
    }
    return samples.map((sample) => {
      const seconds = Math.max(1, sample.rx_bytes + sample.tx_bytes > 0 ? 60 : 60)
      return {
        at: sample.bucket_start_date,
        rx: sample.rx_bytes / seconds,
        tx: -(sample.tx_bytes / seconds),
        rxRaw: sample.rx_bytes / seconds,
        txRaw: sample.tx_bytes / seconds,
        connections: sample.active_connections,
      }
    })
  }, [live, points, samples])

  const summary = useMemo(() => {
    const rx = data.reduce((total, point) => total + point.rxRaw, 0) / Math.max(1, data.length)
    const tx = data.reduce((total, point) => total + point.txRaw, 0) / Math.max(1, data.length)
    return { rx, tx }
  }, [data])

  if (!data.length) {
    return <EmptyState title={t('routeDetail.traffic.noData')} />
  }

  const timeLabel = (iso: string) => formatTime(iso, { locale: language, calendar, digits })
  const rate = (value: number) => formatThroughput(Math.abs(value), units).text

  return (
    <div className="space-y-3">
      {/* The chart is never the only way to obtain a value. */}
      <p className="sr-only" role="status">
        {t('routeDetail.traffic.accessibleSummary', {
          rx: rate(summary.rx),
          tx: rate(summary.tx),
          points: data.length,
        })}
      </p>

      <div className="h-64 w-full" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 4, left: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
            <XAxis
              dataKey="at"
              tickFormatter={timeLabel}
              reversed={rtl}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              stroke="hsl(var(--border))"
              minTickGap={32}
            />
            <YAxis
              orientation={rtl ? 'right' : 'left'}
              tickFormatter={(value: number) => rate(value)}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              stroke="hsl(var(--border))"
              width={64}
            />
            <RechartsTooltip content={<ChartTooltip timeLabel={timeLabel} />} wrapperStyle={{ outline: 'none' }} />
            <Area
              type="monotone"
              dataKey="rx"
              stroke="hsl(var(--ok))"
              fill="hsl(var(--ok))"
              fillOpacity={0.2}
              strokeWidth={1.5}
              isAnimationActive={false}
              name={t('routeDetail.traffic.in')}
            />
            <Area
              type="monotone"
              dataKey="tx"
              stroke="hsl(var(--accent))"
              fill="hsl(var(--accent))"
              fillOpacity={0.2}
              strokeWidth={1.5}
              isAnimationActive={false}
              name={t('routeDetail.traffic.out')}
            />
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center gap-4 text-2xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-4 rounded bg-ok/40" aria-hidden="true" />
          {t('routeDetail.traffic.in')}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-4 rounded bg-accent/40" aria-hidden="true" />
          {t('routeDetail.traffic.out')}
        </span>
        <Button variant="ghost" size="sm" className="ms-auto" onClick={() => setShowTable((v) => !v)}>
          {showTable ? t('actions.showLess') : t('a11y.dataTable')}
        </Button>
      </div>

      {showTable ? (
        <div className="max-h-64 overflow-auto rounded-md border border-border scrollbar-thin">
          <table className="w-full text-2xs">
            <caption className="sr-only">{t('routeDetail.traffic.title')}</caption>
            <thead className="sticky top-0 bg-surface-sunken">
              <tr>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('routeDetail.traffic.time')}
                </th>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('routeDetail.traffic.in')}
                </th>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('routeDetail.traffic.out')}
                </th>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('routeDetail.traffic.connections')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data.map((point) => (
                <tr key={point.at}>
                  <td className="p-2">{timeLabel(point.at)}</td>
                  <td className="tabular p-2">{rate(point.rxRaw)}</td>
                  <td className="tabular p-2">{rate(point.txRaw)}</td>
                  <td className="tabular p-2">{point.connections}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {!live && samples.length ? (
        <p className="text-2xs text-muted-foreground">
          {formatVolume(
            samples.reduce((total, sample) => total + sample.rx_bytes + sample.tx_bytes, 0),
            units,
          ).text}
        </p>
      ) : null}
    </div>
  )
}

interface TooltipPayload {
  payload?: { at: string; rxRaw: number; txRaw: number; connections: number }
}

function ChartTooltip({
  active,
  payload,
  timeLabel,
}: {
  active?: boolean
  payload?: TooltipPayload[]
  timeLabel: (iso: string) => string
}) {
  const { t } = useTranslation()
  const { units } = usePreferences()

  if (!active || !payload?.length) return null
  const point = payload[0]?.payload
  if (!point) return null

  return (
    <div className="rounded-md border border-border bg-surface-raised px-2.5 py-2 text-2xs shadow-lg">
      <p className="font-medium">{timeLabel(point.at)}</p>
      <dl className="mt-1 space-y-0.5">
        <Row label={t('routeDetail.traffic.in')} value={formatThroughput(point.rxRaw, units).text} />
        <Row label={t('routeDetail.traffic.out')} value={formatThroughput(point.txRaw, units).text} />
        <Row label={t('routeDetail.traffic.connections')} value={String(point.connections)} />
      </dl>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd>
        <Technical className="text-2xs">{value}</Technical>
      </dd>
    </div>
  )
}
