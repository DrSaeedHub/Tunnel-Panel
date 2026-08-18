import { ArrowRight } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { cn } from '@/lib/utils'
import { Technical } from '../ui/technical'

/**
 * `bind → destination`, rendered as a direction rather than as two addresses
 * with a character between them.
 *
 * Two rules make this component necessary rather than a convenience.
 *
 * The arrow is directional: it means "traffic moves this way", and reading
 * order carries that meaning. Under RTL the whole indicator mirrors — the bind
 * address sits on the right, the destination on the left, and the arrowhead
 * points left — so an operator reading Farsi reads the flow in their own
 * direction. That comes from `flex-row-reverse` under `rtl:` on the container
 * plus `icon-directional` on the glyph, not from swapping the two values, so
 * the DOM order stays source-then-destination for a screen reader.
 *
 * The addresses themselves are Latin technical values and never mirror: each
 * goes through `Technical`, which isolates it from the surrounding direction so
 * `203.0.113.10:2044` does not render with its parts transposed inside Farsi
 * text.
 */
export function RouteFlow({
  bind,
  destination,
  className,
  size = 'md',
  /** A second line under the destination, for a load-balanced set. */
  destinationNote,
}: {
  bind: string
  destination: string
  className?: string
  size?: 'sm' | 'md'
  destinationNote?: string
}) {
  const { t } = useTranslation()
  const text = size === 'sm' ? 'text-2xs' : 'text-xs'

  return (
    <span
      className={cn('inline-flex flex-wrap items-center gap-1.5 rtl:flex-row-reverse', className)}
      data-testid="route-flow"
      // One label for assistive technology, in the operator's own language and
      // reading order, so the arrow needs no announcement of its own.
      aria-label={t('routes.flowLabel', { bind, destination })}
    >
      <Technical className={text}>{bind}</Technical>
      <ArrowRight
        className={cn('icon-directional shrink-0 text-muted-foreground', size === 'sm' ? 'size-3' : 'size-3.5')}
        aria-hidden="true"
        data-testid="route-flow-arrow"
      />
      <span className="inline-flex flex-col">
        <Technical className={text}>{destination}</Technical>
        {destinationNote ? (
          <span className="text-2xs text-muted-foreground">{destinationNote}</span>
        ) : null}
      </span>
    </span>
  )
}

/** `address:port`, or `address:start-end` for a range. */
export function endpointLabel(address: string, port: number, rangeEnd?: number | null): string {
  const ports = rangeEnd && rangeEnd > port ? `${port}-${rangeEnd}` : String(port)
  return `${address}:${ports}`
}
