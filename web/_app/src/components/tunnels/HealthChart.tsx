import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from 'recharts'

import type { MonitorEvent, MonitorHistoryPoint } from '@/lib/types'
import { formatMs, formatPercent, formatTime } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Button } from '../ui/button'
import { EmptyState } from '../ui/feedback'
import { Technical } from '../ui/technical'

/**
 * Latency and packet loss over time.
 *
 * Loss reads as a filled area beneath the latency line, because the question an
 * operator asks is "was the tunnel losing packets while latency spiked", and
 * two separate charts make that a comparison rather than an observation. State
 * transitions are annotated on the timeline for the same reason.
 *
 * Under RTL the whole chart mirrors: the value axis moves to the right, the
 * time axis reverses, and the tooltip anchors on the correct side.
 */
export function HealthChart({
  points,
  events,
}: {
  points: MonitorHistoryPoint[]
  events: MonitorEvent[]
}) {
  const { t } = useTranslation()
  const { dir, digits, calendar, language } = usePreferences()
  const [showTable, setShowTable] = useState(false)

  const rtl = dir === 'rtl'

  const data = useMemo(
    () =>
      points.map((point) => ({
        at: point.bucket_start,
        latency: point.rtt_avg_ms ?? null,
        loss: point.loss_percent,
        min: point.rtt_min_ms ?? null,
        max: point.rtt_max_ms ?? null,
        jitter: point.jitter_ms ?? null,
        state: point.worst_state,
      })),
    [points],
  )

  const summary = useMemo(() => {
    const latencies = points.map((p) => p.rtt_avg_ms).filter((v): v is number => v !== null)
    const avg = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : null
    const loss = points.length ? points.reduce((a, b) => a + b.loss_percent, 0) / points.length : 0
    return { avg, loss }
  }, [points])

  if (!points.length) {
    return <EmptyState title={t('tunnelDetail.chart.noData')} />
  }

  const timeLabel = (iso: string) => formatTime(iso, { locale: language, calendar, digits })

  return (
    <div className="space-y-3">
      {/* Charts are never the only way to obtain a value: this states the
          headline figures in words, and the table below carries every point. */}
      <p className="sr-only" role="status">
        {t('tunnelDetail.chart.accessibleSummary', {
          avg: formatMs(summary.avg, digits) ?? '—',
          loss: formatPercent(summary.loss, digits),
          points: points.length,
        })}
      </p>

      <div className="h-64 w-full" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={data} margin={{ top: 8, right: 8, bottom: 4, left: 8 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
            <XAxis
              dataKey="at"
              tickFormatter={timeLabel}
              // Under RTL time still runs from the past to the present, but the
              // axis is read from the right, so the data order is reversed.
              reversed={rtl}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              stroke="hsl(var(--border))"
              minTickGap={32}
            />
            <YAxis
              yAxisId="latency"
              orientation={rtl ? 'right' : 'left'}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              stroke="hsl(var(--border))"
              width={44}
            />
            <YAxis
              yAxisId="loss"
              orientation={rtl ? 'left' : 'right'}
              domain={[0, 100]}
              tick={{ fontSize: 10, fill: 'hsl(var(--muted-foreground))' }}
              stroke="hsl(var(--border))"
              width={36}
            />
            <RechartsTooltip
              content={<ChartTooltip timeLabel={timeLabel} />}
              wrapperStyle={{ outline: 'none' }}
              position={rtl ? undefined : undefined}
            />
            <Area
              yAxisId="loss"
              type="monotone"
              dataKey="loss"
              stroke="hsl(var(--danger))"
              fill="hsl(var(--danger))"
              fillOpacity={0.18}
              strokeWidth={1}
              isAnimationActive={false}
              name={t('tunnelDetail.chart.lossPercent')}
            />
            <Line
              yAxisId="latency"
              type="monotone"
              dataKey="latency"
              stroke="hsl(var(--accent))"
              strokeWidth={1.75}
              dot={false}
              connectNulls={false}
              // Interpolating between updates rather than redrawing abruptly.
              isAnimationActive
              animationDuration={250}
              name={t('tunnelDetail.chart.latencyMs')}
            />
            {events.slice(0, 12).map((event) => (
              <ReferenceLine
                key={event.monitor_event_id}
                yAxisId="latency"
                x={event.created_date}
                stroke="hsl(var(--warn))"
                strokeDasharray="2 2"
                strokeWidth={1}
              />
            ))}
          </ComposedChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center gap-4 text-2xs text-muted-foreground">
        <span className="flex items-center gap-1.5">
          <span className="h-0.5 w-4 rounded bg-accent" aria-hidden="true" />
          {t('tunnelDetail.chart.latency')}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-4 rounded bg-danger/30" aria-hidden="true" />
          {t('tunnelDetail.chart.loss')}
        </span>
        <Button variant="ghost" size="sm" className="ms-auto" onClick={() => setShowTable((v) => !v)}>
          {showTable ? t('actions.showLess') : t('a11y.dataTable')}
        </Button>
      </div>

      {showTable ? (
        <div className="max-h-64 overflow-auto rounded-md border border-border scrollbar-thin">
          <table className="w-full text-2xs">
            <caption className="sr-only">{t('tunnelDetail.chart.tableSummary')}</caption>
            <thead className="sticky top-0 bg-surface-sunken">
              <tr>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('tunnelDetail.chart.time')}
                </th>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('tunnelDetail.chart.latency')}
                </th>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('tunnelDetail.chart.loss')}
                </th>
                <th scope="col" className="p-2 text-start font-medium">
                  {t('monitor.jitter')}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {points.map((point) => (
                <tr key={point.bucket_start}>
                  <td className="p-2">{timeLabel(point.bucket_start)}</td>
                  <td className="tabular p-2">{formatMs(point.rtt_avg_ms, digits) ?? '—'}</td>
                  <td className="tabular p-2">{formatPercent(point.loss_percent, digits)}</td>
                  <td className="tabular p-2">{formatMs(point.jitter_ms, digits) ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  )
}

interface TooltipPayload {
  payload?: { at: string; latency: number | null; loss: number; min: number | null; max: number | null }
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
  const { digits } = usePreferences()

  if (!active || !payload?.length) return null
  const point = payload[0]?.payload
  if (!point) return null

  return (
    <div className="rounded-md border border-border bg-surface-raised px-2.5 py-2 text-2xs shadow-lg">
      <p className="font-medium">{timeLabel(point.at)}</p>
      <dl className="mt-1 space-y-0.5">
        <Row label={t('tunnelDetail.chart.latency')} value={formatMs(point.latency, digits) ?? '—'} />
        <Row label={t('tunnelDetail.chart.loss')} value={formatPercent(point.loss, digits)} />
        {point.min !== null ? <Row label={t('monitor.rttMin')} value={formatMs(point.min, digits) ?? '—'} /> : null}
        {point.max !== null ? <Row label={t('monitor.rttMax')} value={formatMs(point.max, digits) ?? '—'} /> : null}
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
