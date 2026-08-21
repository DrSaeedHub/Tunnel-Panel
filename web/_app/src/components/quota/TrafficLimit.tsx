import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Gauge, OctagonX, Pencil } from 'lucide-react'

import { api } from '@/lib/api'
import { TrafficLimitMode, TrafficPeriod, type QuotaStatus, type QuotaStatuses } from '@/lib/types'
import { formatVolume } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Badge, describeError } from '../ui/feedback'
import { Field, Select, TechnicalInput } from '../ui/form'
import { Popover, PopoverContent, PopoverTrigger } from '../ui/overlay'
import { cn } from '@/lib/utils'

/**
 * Traffic limits, shown and edited in one place: beside the usage they limit.
 *
 * A limit is a promise about a number, so it lives next to the number rather
 * than in a form two pages away. The row is one line — a bar, the figure, and
 * a pencil — and everything else is behind the pencil, which is what keeps a
 * page with ten limited things on it from reading like a spreadsheet.
 *
 * The two modes are the two answers to "and then what": warn leaves the
 * traffic alone and turns the row red; enforce stops the tunnel, rule or
 * destination until the window rolls over, the usage is reset, or the limit
 * is removed.
 */

/** Names one limited thing for the API. */
export type QuotaSubject =
  | { scope: 'tunnel'; tunnel_id: number }
  | { scope: 'rule'; route_rule_id: number }
  | { scope: 'destination'; route_rule_id: number; address: string; port: number }

/** Every limit's standing, polled once and joined by the pages that show it. */
export function useQuotaStatuses(enabled = true) {
  return useQuery({
    queryKey: ['quota'],
    queryFn: () => api.get<QuotaStatuses>('/quota'),
    staleTime: 15_000,
    refetchInterval: 30_000,
    enabled,
  })
}

export function tunnelQuota(statuses: QuotaStatuses | undefined, tunnelId: number) {
  return statuses?.tunnels?.[String(tunnelId)]
}

export function ruleQuota(statuses: QuotaStatuses | undefined, ruleId: number) {
  return statuses?.rules?.[String(ruleId)]
}

export function destinationQuota(
  statuses: QuotaStatuses | undefined,
  ruleId: number,
  address: string,
  port: number,
) {
  return statuses?.destinations?.[String(ruleId)]?.[`${address}:${port}`]
}

/**
 * The badge for list rows: nothing at all until a limit is actually reached,
 * because a list is not the place to advertise settings.
 */
export function QuotaBadge({ status }: { status?: QuotaStatus }) {
  const { t } = useTranslation()
  if (!status?.exhausted) return null
  if (status.stopped) {
    return (
      <Badge tone="danger">
        <OctagonX className="size-3" aria-hidden="true" />
        {t('quota.stopped')}
      </Badge>
    )
  }
  return (
    <Badge tone="warn">
      <AlertTriangle className="size-3" aria-hidden="true" />
      {t('quota.overLimit')}
    </Badge>
  )
}

/**
 * The one-line control: bar, figure, badge, pencil. Without a limit it is a
 * single quiet button.
 */
export function QuotaRow({
  subject,
  status,
  compact,
}: {
  subject: QuotaSubject
  status?: QuotaStatus
  /** Smaller everything, for a line inside a list row. */
  compact?: boolean
}) {
  const { t } = useTranslation()
  const { units } = usePreferences()
  const [open, setOpen] = useState(false)

  const editor = (
    <QuotaEditor subject={subject} status={status} onDone={() => setOpen(false)} />
  )

  if (!status) {
    return (
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button variant="ghost" size="sm" className={cn('text-muted-foreground', compact && 'h-6 px-1.5 text-2xs')}>
            <Gauge className={compact ? 'size-3' : 'size-3.5'} aria-hidden="true" />
            {t('quota.set')}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-72">{editor}</PopoverContent>
      </Popover>
    )
  }

  const fraction = status.limit_bytes > 0 ? Math.min(1, status.used_bytes / status.limit_bytes) : 0
  const tone =
    status.exhausted ? 'bg-danger' : fraction >= 0.8 ? 'bg-warn' : 'bg-accent'

  return (
    <div className={cn('flex flex-wrap items-center gap-2', compact ? 'text-2xs' : 'text-xs')}>
      <div
        className={cn('h-1.5 overflow-hidden rounded-full bg-muted', compact ? 'w-16' : 'w-24')}
        role="progressbar"
        aria-valuenow={Math.round(fraction * 100)}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={t('quota.title')}
      >
        <div className={cn('h-full rounded-full', tone)} style={{ width: `${fraction * 100}%` }} />
      </div>
      <span className="tabular text-muted-foreground">
        {t('quota.used', {
          used: formatVolume(status.used_bytes, units).text,
          limit: formatVolume(status.limit_bytes, units).text,
        })}
        {' · '}
        {t(`quota.period.${status.period_id}`)}
      </span>
      <QuotaBadge status={status} />
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            variant="ghost"
            size={compact ? 'sm' : 'iconSm'}
            className={compact ? 'h-6 w-6 p-0' : undefined}
            aria-label={t('quota.edit')}
            title={t('quota.edit')}
          >
            <Pencil className="size-3" aria-hidden="true" />
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-72">{editor}</PopoverContent>
      </Popover>
    </div>
  )
}

const GB = 1_000_000_000
const TB = 1_000_000_000_000

/** The editor behind the pencil: amount, window, and what happens at the end. */
function QuotaEditor({
  subject,
  status,
  onDone,
}: {
  subject: QuotaSubject
  status?: QuotaStatus
  onDone: () => void
}) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [unit, setUnit] = useState(() =>
    status && status.limit_bytes >= TB && status.limit_bytes % TB === 0 ? TB : GB,
  )
  const [amount, setAmount] = useState(() =>
    status ? String(Math.round((status.limit_bytes / unit) * 100) / 100) : '',
  )
  const [periodId, setPeriodId] = useState(status?.period_id ?? TrafficPeriod.Monthly)
  const [modeId, setModeId] = useState(status?.mode_id ?? TrafficLimitMode.Warn)

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['quota'] })
  const fail = (error: unknown) =>
    toast({ tone: 'error', title: t('quota.title'), description: describeError(error, t).message })

  const save = useMutation({
    mutationFn: (limitBytes: number) =>
      api.put('/quota', { ...subject, limit_bytes: limitBytes, mode_id: modeId, period_id: periodId }),
    onSuccess: async (_result, limitBytes) => {
      toast({ tone: 'success', title: limitBytes > 0 ? t('quota.saved') : t('quota.removed') })
      await invalidate()
      onDone()
    },
    onError: fail,
  })

  const reset = useMutation({
    mutationFn: () => api.post('/quota/reset', { ...subject }),
    onSuccess: async () => {
      toast({ tone: 'success', title: t('quota.resetDone') })
      await invalidate()
      onDone()
    },
    onError: fail,
  })

  const parsed = Number(amount)
  const valid = amount.trim() !== '' && Number.isFinite(parsed) && parsed > 0

  return (
    <div className="space-y-3">
      <p className="text-xs font-medium">{t('quota.title')}</p>
      <p className="text-2xs text-muted-foreground">{t('quota.hint')}</p>

      <div className="flex gap-2">
        <div className="flex-1">
          <Field label={t('quota.limit')}>
            {(props) => (
              <TechnicalInput
                {...props}
                inputMode="decimal"
                value={amount}
                onChange={(event) => setAmount(event.target.value)}
                placeholder="100"
              />
            )}
          </Field>
        </div>
        <div className="w-20 self-end">
          <Select
            value={String(unit)}
            onValueChange={(value) => setUnit(Number(value))}
            aria-label={t('quota.unit')}
            options={[
              { value: String(GB), label: 'GB' },
              { value: String(TB), label: 'TB' },
            ]}
          />
        </div>
      </div>

      <Field label={t('quota.window')}>
        {(props) => (
          <Select
            id={props.id}
            value={String(periodId)}
            onValueChange={(value) => setPeriodId(Number(value))}
            options={[
              { value: String(TrafficPeriod.Monthly), label: t('quota.period.40') },
              { value: String(TrafficPeriod.Weekly), label: t('quota.period.30') },
              { value: String(TrafficPeriod.Daily), label: t('quota.period.20') },
              { value: String(TrafficPeriod.Total), label: t('quota.period.10') },
            ]}
          />
        )}
      </Field>

      <Field label={t('quota.onReached')} description={t(`quota.modeHint.${modeId}`)}>
        {(props) => (
          <Select
            id={props.id}
            value={String(modeId)}
            onValueChange={(value) => setModeId(Number(value))}
            options={[
              { value: String(TrafficLimitMode.Warn), label: t('quota.mode.10') },
              { value: String(TrafficLimitMode.Enforce), label: t('quota.mode.20') },
            ]}
          />
        )}
      </Field>

      <div className="flex flex-wrap items-center gap-2">
        <Button
          variant="primary"
          size="sm"
          disabled={!valid}
          loading={save.isPending && save.variables !== 0}
          onClick={() => save.mutate(Math.round(parsed * unit))}
        >
          {t('actions.save')}
        </Button>
        {status ? (
          <>
            <Button variant="secondary" size="sm" loading={reset.isPending} onClick={() => reset.mutate()}>
              {t('quota.reset')}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              loading={save.isPending && save.variables === 0}
              onClick={() => save.mutate(0)}
            >
              {t('quota.remove')}
            </Button>
          </>
        ) : null}
      </div>
    </div>
  )
}
