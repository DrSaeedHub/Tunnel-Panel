import { useTranslation } from 'react-i18next'
import { Radio, RefreshCw, WifiOff } from 'lucide-react'

import type { StreamState } from '@/lib/sse'
import { formatRelative } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { cn } from '@/lib/utils'
import { Tooltip } from '../ui/overlay'

/**
 * Whether what is on screen is live.
 *
 * The rule this enforces is that stale data is never presented as current. When
 * the stream drops, this turns amber and says so, and the views that read from
 * it dim their figures. It never silently keeps showing the last value as
 * though nothing happened.
 */
export function LiveIndicator({ stream }: { stream: StreamState }) {
  const { t } = useTranslation()
  const { language } = usePreferences()

  const when = stream.lastEventAt
    ? formatRelative(new Date(stream.lastEventAt).toISOString(), language)
    : ''

  const presentation = {
    live: {
      tone: 'ok' as const,
      Icon: Radio,
      label: t('states.live'),
      tooltip: t('states.liveHint'),
    },
    connecting: {
      tone: 'muted' as const,
      Icon: RefreshCw,
      label: t('states.connecting'),
      tooltip: t('states.connectingHint'),
    },
    reconnecting: {
      tone: 'warn' as const,
      Icon: RefreshCw,
      label: t('states.reconnecting'),
      tooltip: t('states.staleHint', { when }),
    },
    closed: {
      tone: 'muted' as const,
      Icon: WifiOff,
      label: t('states.stale'),
      tooltip: t('states.staleHint', { when }),
    },
  }[stream.status]

  const { Icon } = presentation

  return (
    <Tooltip content={presentation.tooltip}>
      <span
        className={cn(
          'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-2xs font-medium',
          presentation.tone === 'ok' && 'bg-ok-muted text-ok',
          presentation.tone === 'warn' && 'bg-warn-muted text-warn',
          presentation.tone === 'muted' && 'bg-muted text-muted-foreground',
        )}
        role="status"
        aria-live="polite"
      >
        <Icon
          className={cn('size-3', stream.status === 'reconnecting' && 'animate-spin')}
          aria-hidden="true"
        />
        <span className="hidden md:inline">{presentation.label}</span>
      </span>
    </Tooltip>
  )
}

/**
 * Wraps a figure that came from a live stream, dimming it when the stream has
 * dropped so the number never looks current when it is not.
 */
export function StaleWrapper({
  stale,
  children,
  className,
}: {
  stale: boolean
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn(stale && 'opacity-60 transition-opacity duration-250', className)} aria-stale={stale ? 'true' : undefined}>
      {children}
    </div>
  )
}
