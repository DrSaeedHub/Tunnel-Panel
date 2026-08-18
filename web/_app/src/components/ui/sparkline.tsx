import { useId } from 'react'

import { cn } from '@/lib/utils'

/**
 * A compact trend line.
 *
 * Drawn as a plain SVG path rather than through the chart library: it appears
 * on every resource card and every tunnel row, and pulling the charting bundle
 * in for a shape this simple would cost more than it is worth.
 *
 * It is decorative by design — every value it plots is also shown as a number
 * beside it, so a screen reader loses nothing by skipping it.
 */
export function Sparkline({
  values,
  className,
  tone = 'accent',
  /** Fixes the vertical scale, for series like loss where 0–100 is meaningful. */
  max,
  height = 28,
  filled = true,
}: {
  values: number[]
  className?: string
  tone?: 'accent' | 'ok' | 'warn' | 'danger' | 'muted'
  max?: number
  height?: number
  filled?: boolean
}) {
  const gradientId = useId()
  const width = 100

  if (!values.length) {
    // No measurements is an absence, so the space is hatched rather than blank.
    return <div className={cn('hatch-soft h-7 rounded-sm', className)} aria-hidden="true" />
  }

  const top = max ?? Math.max(...values, 0.0001)
  const bottom = Math.min(...values, 0)
  const span = top - bottom || 1

  const step = values.length > 1 ? width / (values.length - 1) : width
  const points = values.map((value, index) => {
    const x = index * step
    const y = height - ((value - bottom) / span) * height
    return [x, Number.isFinite(y) ? y : height] as const
  })

  const line = points.map(([x, y], index) => `${index === 0 ? 'M' : 'L'}${x.toFixed(2)},${y.toFixed(2)}`).join(' ')
  const area = `${line} L${width},${height} L0,${height} Z`

  const stroke = {
    accent: 'stroke-accent',
    ok: 'stroke-ok',
    warn: 'stroke-warn',
    danger: 'stroke-danger',
    muted: 'stroke-muted-foreground',
  }[tone]

  const fill = {
    accent: 'text-accent',
    ok: 'text-ok',
    warn: 'text-warn',
    danger: 'text-danger',
    muted: 'text-muted-foreground',
  }[tone]

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      className={cn('h-7 w-full overflow-visible', className)}
      aria-hidden="true"
      focusable="false"
    >
      {filled ? (
        <>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="currentColor" stopOpacity="0.28" />
              <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={area} fill={`url(#${gradientId})`} className={fill} />
        </>
      ) : null}
      <path
        d={line}
        fill="none"
        className={stroke}
        strokeWidth={1.5}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
