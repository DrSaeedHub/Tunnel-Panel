import { useCallback, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from '@/lib/api'
import { useEventStream, type StreamState } from '@/lib/sse'
import { MonitorState, type MonitorSnapshot, type MonitorSummaryResponse } from '@/lib/types'

export interface MonitorSummary {
  byTunnel: Map<number, MonitorSnapshot>
  counts: { up: number; degraded: number; down: number; unknown: number; disabled: number; total: number }
  stream: StreamState
  isLoading: boolean
  error: unknown
  refetch: () => void
}

/**
 * Every tunnel's monitoring state, seeded from the summary endpoint and then
 * kept current by the live stream.
 *
 * One subscription serves the whole app: the header, the dashboard strip and
 * the tunnel list all read from here, so an operator with fifty tunnels opens
 * one stream rather than fifty.
 */
export function useMonitorSummary(enabled = true): MonitorSummary {
  const queryClient = useQueryClient()
  const [live, setLive] = useState<Map<number, MonitorSnapshot>>(new Map())

  const query = useQuery({
    queryKey: ['monitor', 'summary'],
    queryFn: () => api.get<MonitorSummaryResponse>('/monitor/summary'),
    enabled,
    staleTime: 10_000,
  })

  const applySnapshot = useCallback((snapshot: MonitorSnapshot) => {
    setLive((current) => {
      const next = new Map(current)
      next.set(snapshot.tunnel_id, snapshot)
      return next
    })
  }, [])

  const stream = useEventStream<MonitorSnapshot | MonitorSummaryResponse>('/monitor/stream', {
    enabled,
    events: {
      // The stream opens with a full summary, then sends one tunnel at a time.
      summary: (data) => {
        const summary = data as MonitorSummaryResponse
        if (!Array.isArray(summary.tunnels)) return
        setLive(new Map((summary.tunnels ?? []).map((s) => [s.tunnel_id, s])))
        queryClient.setQueryData(['monitor', 'summary'], summary)
      },
      tunnel: (data) => applySnapshot(data as MonitorSnapshot),
    },
  })

  const byTunnel = useMemo(() => {
    const merged = new Map<number, MonitorSnapshot>()
    for (const snapshot of query.data?.tunnels ?? []) merged.set(snapshot.tunnel_id, snapshot)
    for (const [id, snapshot] of live) merged.set(id, snapshot)
    return merged
  }, [query.data, live])

  const counts = useMemo(() => {
    const tally = { up: 0, degraded: 0, down: 0, unknown: 0, disabled: 0, total: 0 }
    for (const snapshot of byTunnel.values()) {
      tally.total += 1
      switch (snapshot.monitor_state_id) {
        case MonitorState.Up:
          tally.up += 1
          break
        case MonitorState.Degraded:
          tally.degraded += 1
          break
        case MonitorState.Down:
          tally.down += 1
          break
        case MonitorState.Disabled:
          tally.disabled += 1
          break
        default:
          tally.unknown += 1
      }
    }
    return tally
  }, [byTunnel])

  return {
    byTunnel,
    counts,
    stream,
    isLoading: query.isLoading,
    error: query.error,
    refetch: () => void query.refetch(),
  }
}
