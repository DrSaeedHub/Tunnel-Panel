import { useCallback, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'

import { api } from '@/lib/api'
import { useEventStream, type StreamState } from '@/lib/sse'
import type { MetricsHistoryResponse, MetricsSnapshot } from '@/lib/types'

/** How many readings the sparklines keep. Enough for a trend, not a chart. */
const HISTORY_LIMIT = 60

export interface MetricsState {
  latest: MetricsSnapshot | null
  history: MetricsSnapshot[]
  stream: StreamState
  isLoading: boolean
  error: unknown
  refetch: () => void
}

/**
 * This server's live metrics.
 *
 * Seeded from the history endpoint so the sparklines have a shape immediately
 * rather than drawing themselves one point at a time, then kept current by the
 * stream. When the stream drops, `stream.stale` goes true and the cards dim —
 * the figures stay on screen, but they stop claiming to be current.
 */
export function useMetrics(enabled = true): MetricsState {
  const [live, setLive] = useState<MetricsSnapshot[]>([])
  const seeded = useRef(false)

  const historyQuery = useQuery({
    queryKey: ['metrics', 'history'],
    queryFn: () => api.get<MetricsHistoryResponse>('/system/metrics/history', { query: { limit: HISTORY_LIMIT } }),
    enabled,
    staleTime: 60_000,
  })

  // A snapshot too, so a panel opened before the first stream frame is not
  // empty for a whole sampling interval.
  const snapshotQuery = useQuery({
    queryKey: ['metrics', 'latest'],
    queryFn: () => api.get<MetricsSnapshot>('/system/metrics'),
    enabled,
    staleTime: 5_000,
  })

  const append = useCallback((snapshot: MetricsSnapshot) => {
    setLive((current) => {
      const next = [...current, snapshot]
      return next.length > HISTORY_LIMIT ? next.slice(next.length - HISTORY_LIMIT) : next
    })
  }, [])

  const stream = useEventStream<MetricsSnapshot>('/system/metrics/stream', {
    enabled,
    events: { metrics: append },
  })

  const history = useMemo(() => {
    const stored = historyQuery.data?.points ?? []
    if (!seeded.current && stored.length) seeded.current = true

    // The stream repeats the newest stored reading when it opens, so entries
    // are keyed by their timestamp to keep the series from doubling up.
    const byTime = new Map<string, MetricsSnapshot>()
    for (const point of stored) byTime.set(point.at, point)
    if (snapshotQuery.data) byTime.set(snapshotQuery.data.at, snapshotQuery.data)
    for (const point of live) byTime.set(point.at, point)

    const merged = [...byTime.values()].sort((a, b) => a.at.localeCompare(b.at))
    return merged.length > HISTORY_LIMIT ? merged.slice(merged.length - HISTORY_LIMIT) : merged
  }, [historyQuery.data, snapshotQuery.data, live])

  const latest = history.length ? history[history.length - 1] : null

  return {
    latest,
    history,
    stream,
    isLoading: snapshotQuery.isLoading && historyQuery.isLoading && !latest,
    error: snapshotQuery.error ?? historyQuery.error,
    refetch: () => {
      void snapshotQuery.refetch()
      void historyQuery.refetch()
    },
  }
}

/** Pulls one series out of the history, for a sparkline. */
export function series(history: MetricsSnapshot[], pick: (snapshot: MetricsSnapshot) => number): number[] {
  return history.map(pick).filter((value) => Number.isFinite(value))
}
