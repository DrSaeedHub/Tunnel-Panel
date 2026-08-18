import {
  AlertTriangle,
  CheckCircle2,
  CircleDashed,
  CircleSlash,
  HelpCircle,
  XCircle,
} from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { ApplyStatus, MonitorState, type RouteHealthState } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Tooltip } from './overlay'

type Tone = 'ok' | 'warn' | 'danger' | 'neutral' | 'muted'

const MONITOR_PRESENTATION: Record<number, { key: string; tone: Tone; Icon: typeof CheckCircle2 }> = {
  [MonitorState.Up]: { key: 'Up', tone: 'ok', Icon: CheckCircle2 },
  [MonitorState.Degraded]: { key: 'Degraded', tone: 'warn', Icon: AlertTriangle },
  [MonitorState.Down]: { key: 'Down', tone: 'danger', Icon: XCircle },
  [MonitorState.Unknown]: { key: 'Unknown', tone: 'neutral', Icon: HelpCircle },
  [MonitorState.Disabled]: { key: 'Disabled', tone: 'muted', Icon: CircleSlash },
}

const TONE_CLASSES: Record<Tone, string> = {
  ok: 'border-transparent bg-ok-muted text-ok',
  warn: 'border-transparent bg-warn-muted text-warn',
  danger: 'border-transparent bg-danger-muted text-danger',
  neutral: 'border-transparent bg-muted text-muted-foreground',
  // Not-monitored is an absence, so it wears the drafting hatch.
  muted: 'border-border/60 bg-transparent text-muted-foreground hatch-soft',
}

/**
 * A tunnel's monitoring state.
 *
 * Colour, icon and text together, always. An operator with a colour-vision
 * deficiency, or one glancing at a dimmed screen across the room, gets the same
 * answer as everyone else — and this is the single most repeated indicator in
 * the panel, so it is the one that matters most.
 */
export function StatusPill({
  stateId,
  reason,
  size = 'md',
  className,
}: {
  stateId: number
  reason?: string
  size?: 'sm' | 'md'
  className?: string
}) {
  const { t } = useTranslation()
  const presentation = MONITOR_PRESENTATION[stateId] ?? MONITOR_PRESENTATION[MonitorState.Unknown]
  const { Icon } = presentation
  const label = t(`monitor.state.${presentation.key}`)
  const explanation = reason || t(`monitor.stateExplain.${presentation.key}`)

  const pill = (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-medium',
        size === 'sm' ? 'px-2 py-0.5 text-2xs' : 'px-2.5 py-1 text-xs',
        TONE_CLASSES[presentation.tone],
        className,
      )}
    >
      <Icon className={size === 'sm' ? 'size-3' : 'size-3.5'} aria-hidden="true" />
      {label}
    </span>
  )

  return explanation ? <Tooltip content={explanation}>{pill}</Tooltip> : pill
}

const APPLY_PRESENTATION: Record<number, { key: string; tone: Tone; Icon: typeof CheckCircle2 }> = {
  [ApplyStatus.Pending]: { key: 'Pending', tone: 'neutral', Icon: CircleDashed },
  [ApplyStatus.Applied]: { key: 'Applied', tone: 'ok', Icon: CheckCircle2 },
  [ApplyStatus.Failed]: { key: 'Failed', tone: 'danger', Icon: XCircle },
  [ApplyStatus.Inconsistent]: { key: 'Inconsistent', tone: 'danger', Icon: AlertTriangle },
}

/**
 * The apply state, which is separate from health: a tunnel can be Up and still
 * Inconsistent, meaning a previous change half-applied and needs a human.
 */
export function ApplyStatusBadge({ statusId, className }: { statusId: number; className?: string }) {
  const { t } = useTranslation()
  const presentation = APPLY_PRESENTATION[statusId]
  // Applied is the expected state and carries no information worth the space.
  if (!presentation || statusId === ApplyStatus.Applied) return null
  const { Icon } = presentation

  return (
    <Tooltip
      content={statusId === ApplyStatus.Inconsistent ? t('apply.inconsistentWarning') : undefined}
    >
      <span
        className={cn(
          'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-2xs font-medium',
          TONE_CLASSES[presentation.tone],
          className,
        )}
      >
        <Icon className="size-3" aria-hidden="true" />
        {t(`apply.status.${presentation.key}`)}
      </span>
    </Tooltip>
  )
}

/** The small dot form, for dense rows where the pill would not fit. */
export function StatusDot({ stateId, className }: { stateId: number; className?: string }) {
  const { t } = useTranslation()
  const presentation = MONITOR_PRESENTATION[stateId] ?? MONITOR_PRESENTATION[MonitorState.Unknown]
  const { Icon } = presentation
  const label = t(`monitor.state.${presentation.key}`)
  return (
    <span className={cn('inline-flex items-center gap-1', className)} title={label}>
      <Icon
        className={cn(
          'size-3.5',
          presentation.tone === 'ok' && 'text-ok',
          presentation.tone === 'warn' && 'text-warn',
          presentation.tone === 'danger' && 'text-danger',
          (presentation.tone === 'neutral' || presentation.tone === 'muted') && 'text-muted-foreground',
        )}
        aria-hidden="true"
      />
      <span className="sr-only">{label}</span>
    </span>
  )
}

export function monitorStateKey(stateId: number): string {
  return (MONITOR_PRESENTATION[stateId] ?? MONITOR_PRESENTATION[MonitorState.Unknown]).key
}

const ROUTE_PRESENTATION: Record<RouteHealthState, { tone: Tone; Icon: typeof CheckCircle2 }> = {
  healthy: { tone: 'ok', Icon: CheckCircle2 },
  // Impaired is warn, not danger: the rules are installed exactly as intended
  // and the path they relay over is what is broken. Colouring it as a failure
  // would send an operator to edit a rule with nothing wrong with it.
  impaired: { tone: 'warn', Icon: AlertTriangle },
  failed: { tone: 'danger', Icon: XCircle },
  inconsistent: { tone: 'danger', Icon: AlertTriangle },
  pending: { tone: 'neutral', Icon: CircleDashed },
  disabled: { tone: 'muted', Icon: CircleSlash },
}

/**
 * A forwarding rule's state.
 *
 * Same construction as the tunnel pill — colour, icon and text together — over
 * the rule vocabulary rather than the monitoring one. The detail the backend
 * returns is the tooltip, because "impaired" alone does not say which tunnel
 * went down.
 */
export function RouteStatusPill({
  state,
  detail,
  size = 'md',
  className,
}: {
  state: RouteHealthState
  detail?: string
  size?: 'sm' | 'md'
  className?: string
}) {
  const { t } = useTranslation()
  const presentation = ROUTE_PRESENTATION[state] ?? ROUTE_PRESENTATION.pending
  const { Icon } = presentation
  const label = t(`routes.state.${state}`)

  const pill = (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-medium',
        size === 'sm' ? 'px-2 py-0.5 text-2xs' : 'px-2.5 py-1 text-xs',
        TONE_CLASSES[presentation.tone],
        className,
      )}
    >
      <Icon className={size === 'sm' ? 'size-3' : 'size-3.5'} aria-hidden="true" />
      {label}
    </span>
  )

  return detail ? <Tooltip content={detail}>{pill}</Tooltip> : pill
}
