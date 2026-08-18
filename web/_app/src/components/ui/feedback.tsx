import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApiError, NetworkError } from '@/lib/api'
import { cn } from '@/lib/utils'
import { Button } from './button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from './disclosure'
import { TechnicalBlock } from './technical'

export function Badge({
  className,
  tone = 'neutral',
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & {
  tone?: 'neutral' | 'accent' | 'ok' | 'warn' | 'danger'
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-2xs font-medium',
        tone === 'neutral' && 'bg-muted text-muted-foreground',
        tone === 'accent' && 'bg-accent-muted text-accent',
        tone === 'ok' && 'bg-ok-muted text-ok',
        tone === 'warn' && 'bg-warn-muted text-warn',
        tone === 'danger' && 'bg-danger-muted text-danger',
        className,
      )}
      {...props}
    />
  )
}

/** A skeleton shaped like the content it stands in for, never a spinner. */
export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('skeleton h-4 w-full', className)} aria-hidden="true" {...props} />
}

export function SkeletonText({ lines = 3, className }: { lines?: number; className?: string }) {
  return (
    <div className={cn('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton key={index} className={index === lines - 1 ? 'w-2/3' : 'w-full'} />
      ))}
    </div>
  )
}

export function EmptyState({
  icon,
  title,
  body,
  action,
  className,
}: {
  icon?: React.ReactNode
  title: string
  body?: string
  action?: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 px-6 py-12 text-center', className)}>
      {/* Emptiness is drawn, not just greyed: the disc wears the drafting hatch. */}
      <div className="hatch rounded-full border border-border/60 p-3.5 text-muted-foreground">
        {icon ?? <Inbox className="size-5" aria-hidden="true" />}
      </div>
      <div className="space-y-1">
        <p className="text-sm font-medium">{title}</p>
        {body ? <p className="mx-auto max-w-md text-xs text-muted-foreground">{body}</p> : null}
      </div>
      {action}
    </div>
  )
}

/**
 * The one place an error is rendered.
 *
 * The operator sees the backend's own message, which is written for them, and
 * the machine-readable parts stay one disclosure away. Never a stack trace,
 * never a bare "something went wrong".
 */
export function ErrorState({
  error,
  onRetry,
  className,
  compact,
}: {
  error: unknown
  onRetry?: () => void
  className?: string
  compact?: boolean
}) {
  const { t } = useTranslation()
  const { message, code, field, details } = describeError(error, t)

  return (
    <div
      className={cn(
        'rounded-lg border border-danger/30 bg-danger-muted/40 p-4',
        compact && 'p-3',
        className,
      )}
      role="alert"
    >
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden="true" />
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-sm font-medium">{message}</p>

          {code || details ? (
            <Collapsible>
              <CollapsibleTrigger className="text-xs text-muted-foreground underline-offset-2 hover:underline">
                {t('errors.technicalDetails')}
              </CollapsibleTrigger>
              <CollapsibleContent className="pt-2">
                <dl className="space-y-1 text-xs">
                  {code ? (
                    <div className="flex gap-2">
                      <dt className="text-muted-foreground">{t('errors.code')}</dt>
                      <dd className="technical">{code}</dd>
                    </div>
                  ) : null}
                  {field ? (
                    <div className="flex gap-2">
                      <dt className="text-muted-foreground">{t('errors.field')}</dt>
                      <dd className="technical">{field}</dd>
                    </div>
                  ) : null}
                </dl>
                {details ? <TechnicalBlock className="mt-2 max-h-48">{details}</TechnicalBlock> : null}
              </CollapsibleContent>
            </Collapsible>
          ) : null}

          {onRetry ? (
            <Button size="sm" variant="secondary" onClick={onRetry}>
              <RefreshCw className="size-3.5" aria-hidden="true" />
              {t('errors.retry')}
            </Button>
          ) : null}
        </div>
      </div>
    </div>
  )
}

/** Turns any thrown value into the four things the error card renders. */
export function describeError(
  error: unknown,
  t: (key: string, options?: Record<string, unknown>) => string,
): { message: string; code: string; field: string; details: string } {
  if (error instanceof NetworkError) {
    return { message: t('errors.network'), code: 'NETWORK', field: '', details: '' }
  }
  if (error instanceof ApiError) {
    const details = Object.keys(error.details).length ? JSON.stringify(error.details, null, 2) : ''
    return { message: error.message || fallbackMessage(error, t), code: error.code, field: error.field, details }
  }
  if (error instanceof Error) {
    return { message: error.message || t('errors.title'), code: '', field: '', details: '' }
  }
  return { message: t('errors.title'), code: '', field: '', details: '' }
}

function fallbackMessage(error: ApiError, t: (key: string) => string): string {
  switch (error.code) {
    case 'NOT_FOUND':
      return t('errors.notFound')
    case 'SERVICE_UNAVAILABLE':
      return t('errors.unavailable')
    case 'FORBIDDEN':
      return t('errors.forbidden')
    case 'VALIDATION_FAILED':
      return t('errors.validation')
    case 'CONFLICT':
      return t('errors.conflict')
    case 'INTERNAL_ERROR':
      return t('errors.internal')
    default:
      return t('errors.title')
  }
}

/** A thin progress bar, used for utilisation rather than for indeterminate waits. */
export function Meter({
  value,
  tone = 'accent',
  className,
  label,
}: {
  value: number
  tone?: 'accent' | 'ok' | 'warn' | 'danger'
  className?: string
  label?: string
}) {
  const clamped = Math.max(0, Math.min(100, value))
  return (
    <div
      className={cn('h-1.5 w-full overflow-hidden rounded-full bg-muted', className)}
      role="meter"
      aria-valuenow={Math.round(clamped)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label={label}
    >
      <div
        className={cn(
          'h-full rounded-full transition-[width] duration-250',
          tone === 'accent' && 'bg-accent',
          tone === 'ok' && 'bg-ok',
          tone === 'warn' && 'bg-warn',
          tone === 'danger' && 'bg-danger',
        )}
        style={{ inlineSize: `${clamped}%` }}
      />
    </div>
  )
}
