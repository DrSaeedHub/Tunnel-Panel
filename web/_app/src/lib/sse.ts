import { useEffect, useRef, useState } from 'react'
import { apiUrl } from './bootstrap'

export type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'closed'

export interface StreamState {
  status: StreamStatus
  /** When the last event arrived, so a view can say how old its figures are. */
  lastEventAt: number | null
  /** True once the connection has dropped and the data on screen is no longer live. */
  stale: boolean
}

interface Options<T> {
  /** Named events to listen for, mapped to their handlers. */
  events: Record<string, (data: T) => void>
  /** Disable the stream entirely, for example while logged out. */
  enabled?: boolean
}

const MIN_RETRY_MS = 1000
const MAX_RETRY_MS = 30000

/**
 * Subscribes to a server-sent event stream with reconnection.
 *
 * The returned state is what the live-connection indicator renders. The rule
 * this exists to enforce is that a dropped stream must never leave the last
 * figures on screen looking current: `stale` goes true the moment the
 * connection is lost, and the views dim their numbers accordingly.
 */
export function useEventStream<T = unknown>(path: string, options: Options<T>): StreamState {
  const { enabled = true } = options
  const [state, setState] = useState<StreamState>({
    status: enabled ? 'connecting' : 'closed',
    lastEventAt: null,
    stale: false,
  })

  // Handlers change on every render; keeping them in a ref means the stream is
  // not torn down and rebuilt each time.
  const handlers = useRef(options.events)
  handlers.current = options.events

  useEffect(() => {
    if (!enabled) {
      setState({ status: 'closed', lastEventAt: null, stale: false })
      return
    }

    let source: EventSource | null = null
    let retryTimer: number | undefined
    let retryDelay = MIN_RETRY_MS
    let disposed = false

    const connect = () => {
      if (disposed) return
      source = new EventSource(apiUrl(path), { withCredentials: true })

      source.onopen = () => {
        retryDelay = MIN_RETRY_MS
        setState((prev) => ({ ...prev, status: 'live', stale: false }))
      }

      source.onerror = () => {
        source?.close()
        source = null
        if (disposed) return
        // Everything on screen was measured before the drop, so it is no
        // longer live and must not be presented as though it were.
        setState((prev) => ({ ...prev, status: 'reconnecting', stale: true }))
        retryTimer = window.setTimeout(connect, retryDelay)
        retryDelay = Math.min(retryDelay * 2, MAX_RETRY_MS)
      }

      for (const [name, handler] of Object.entries(handlers.current)) {
        source.addEventListener(name, (event) => {
          const message = event as MessageEvent<string>
          setState((prev) => ({
            status: 'live',
            lastEventAt: Date.now(),
            stale: false,
            ...(prev.status === 'live' ? {} : {}),
          }))
          try {
            handler(JSON.parse(message.data) as T)
          } catch {
            // A malformed frame is dropped rather than killing the stream.
          }
        })
      }
    }

    connect()

    return () => {
      disposed = true
      if (retryTimer) window.clearTimeout(retryTimer)
      source?.close()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, enabled])

  return state
}
