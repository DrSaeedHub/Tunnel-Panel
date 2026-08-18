import { cn } from '@/lib/utils'

/**
 * One card, one spacing scale, one radius — so the dashboard, the tunnel list
 * and settings read as one product rather than three.
 *
 * Cards lean on light: a soft ambient shadow and a half-strength hairline by
 * day, a hairline alone by night. `ink` inverts the card into the page's one
 * instrument slab — use it once per page, for the figure that matters most.
 */
export function Card({
  className,
  ink,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & { ink?: boolean }) {
  return <div className={cn(ink ? 'ink-slab' : 'card-surface', className)} {...props} />
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex flex-wrap items-start justify-between gap-2 border-b border-border p-[var(--card-padding)]', className)}
      {...props}
    />
  )
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h3 className={cn('display text-sm font-semibold leading-tight', className)} {...props} />
}

export function CardDescription({ className, ...props }: React.HTMLAttributes<HTMLParagraphElement>) {
  return <p className={cn('text-xs text-muted-foreground', className)} {...props} />
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-[var(--card-padding)]', className)} {...props} />
}

export function CardFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex flex-wrap items-center gap-2 border-t border-border p-[var(--card-padding)]', className)}
      {...props}
    />
  )
}
