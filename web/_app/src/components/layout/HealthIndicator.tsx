import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, CircleSlash, XCircle } from 'lucide-react'

import { api } from '@/lib/api'
import { ApplyStatus, type TunnelListResponse } from '@/lib/types'
import { usePreferences } from '@/providers/PreferencesProvider'
import { formatCount } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Tooltip } from '../ui/overlay'

interface Counts {
  up: number
  degraded: number
  down: number
  unknown: number
  disabled: number
  total: number
}

/**
 * The global health summary, always visible.
 *
 * It answers "is anything wrong on this server" without navigating, and it
 * links straight to the tunnels that are wrong. A tunnel in the Inconsistent
 * apply state escalates past every monitoring state, because that one means a
 * previous change half-applied and a human has to look.
 */
export function HealthIndicator({ counts }: { counts: Counts }) {
  const { t } = useTranslation()
  const { digits, language } = usePreferences()

  // Apply state is not part of the monitoring stream, so it is read separately.
  const tunnelsQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 15_000,
  })

  const inconsistent =
    (tunnelsQuery.data?.tunnels ?? []).filter((entry) => entry.tunnel.apply_status_id === ApplyStatus.Inconsistent)
      .length ?? 0

  const number = (value: number) => formatCount(value, digits, language)

  if (inconsistent > 0) {
    return (
      <Indicator
        to="/tunnels?apply=inconsistent"
        tone="danger"
        icon={<AlertTriangle className="size-3.5" aria-hidden="true" />}
        label={t('health.needsAttention', { count: inconsistent })}
        tooltip={t('apply.inconsistentWarning')}
      />
    )
  }

  if (counts.total === 0) {
    return (
      <Indicator
        to="/tunnels"
        tone="muted"
        icon={<CircleSlash className="size-3.5" aria-hidden="true" />}
        label={t('health.nothingMonitored')}
      />
    )
  }

  if (counts.down > 0) {
    return (
      <Indicator
        to="/tunnels?status=Down"
        tone="danger"
        icon={<XCircle className="size-3.5" aria-hidden="true" />}
        label={t('health.indicator', { up: number(counts.up), degraded: number(counts.down) })}
        tooltip={t('monitor.stateExplain.Down')}
      />
    )
  }

  if (counts.degraded > 0) {
    return (
      <Indicator
        to="/tunnels?status=Degraded"
        tone="warn"
        icon={<AlertTriangle className="size-3.5" aria-hidden="true" />}
        label={t('health.indicator', { up: number(counts.up), degraded: number(counts.degraded) })}
        tooltip={t('monitor.stateExplain.Degraded')}
      />
    )
  }

  return (
    <Indicator
      to="/tunnels"
      tone="ok"
      icon={<CheckCircle2 className="size-3.5" aria-hidden="true" />}
      label={t('health.allUp', { count: counts.up })}
    />
  )
}

function Indicator({
  to,
  tone,
  icon,
  label,
  tooltip,
}: {
  to: string
  tone: 'ok' | 'warn' | 'danger' | 'muted'
  icon: React.ReactNode
  label: string
  tooltip?: string
}) {
  const content = (
    <Link
      to={to}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-2xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring sm:text-xs',
        tone === 'ok' && 'bg-ok-muted text-ok hover:bg-ok-muted/70',
        tone === 'warn' && 'bg-warn-muted text-warn hover:bg-warn-muted/70',
        tone === 'danger' && 'bg-danger-muted text-danger hover:bg-danger-muted/70',
        tone === 'muted' && 'hatch-soft bg-muted/40 text-muted-foreground hover:bg-muted/70',
      )}
    >
      {icon}
      <span className="hidden sm:inline">{label}</span>
    </Link>
  )
  return tooltip ? <Tooltip content={tooltip}>{content}</Tooltip> : content
}
