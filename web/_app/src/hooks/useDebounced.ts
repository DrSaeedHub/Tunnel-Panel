import { useEffect, useState } from 'react'

/**
 * A value that settles before it is used.
 *
 * The forwarding form previews its ruleset from the backend as the operator
 * types, and every keystroke in a port field would otherwise be a round trip
 * that plans and renders a whole netfilter payload. Waiting for the typing to
 * pause turns that into one request per edit.
 */
export function useDebounced<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value)

  useEffect(() => {
    const timer = window.setTimeout(() => setSettled(value), delayMs)
    return () => window.clearTimeout(timer)
  }, [value, delayMs])

  return settled
}
