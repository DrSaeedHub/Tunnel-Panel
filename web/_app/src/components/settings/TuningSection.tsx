import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Gauge, Pencil, RotateCcw, ShieldCheck, Undo2, X } from 'lucide-react'

import { api } from '@/lib/api'
import type { TuningReading, TuningReport } from '@/lib/types'
import { formatCount } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, ErrorState, Skeleton, describeError } from '../ui/feedback'
import { Select, TechnicalInput } from '../ui/form'
import { Technical } from '../ui/technical'
import { cn } from '@/lib/utils'

/**
 * The kernel parameters a relay's speed and stability depend on.
 *
 * A stock kernel is sized for a machine that serves a handful of connections,
 * and a relay is not that machine. Every parameter here is shown with what this
 * kernel holds now, what this host should be setting it to — computed from its
 * memory, its cores and the connections its rules are actually carrying — and
 * an explanation of what going wrong looks like, because a list of kernel names
 * is not something anybody can act on.
 *
 * Every one of them is also editable. The recommendation is the panel's opinion
 * about a host it can only measure from the outside, and an operator who knows
 * something it does not — a machine shared with another service, a link whose
 * real limit is somewhere else — needs the field rather than the opinion. The
 * one-click tuning stays for everyone else.
 */
export function TuningSection() {
  const { t } = useTranslation()
  const { digits, language } = usePreferences()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const query = useQuery({
    queryKey: ['system', 'tuning'],
    queryFn: () => api.get<TuningReport>('/system/tuning'),
    staleTime: 30_000,
  })
  const report = query.data

  /**
   * Only the parameters somebody has actually touched.
   *
   * The alternative — holding a value for every row and sending the lot — would
   * make opening the page and pressing save a way to freeze seventeen kernel
   * parameters at whatever they happened to be, which is not what anyone means
   * by saving a form they did not edit.
   */
  const [draft, setDraft] = useState<Record<string, string>>({})
  const edited = Object.keys(draft)

  const errors = useMemo(() => {
    const found: Record<string, string> = {}
    for (const reading of report?.readings ?? []) {
      const value = draft[reading.key]
      if (value === undefined) continue
      const problem = checkValue(reading, value, t)
      if (problem) found[reading.key] = problem
    }
    return found
  }, [draft, report, t])

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['system', 'tuning'] })

  const apply = useMutation({
    mutationFn: () => api.post<{ applied: number }>('/system/tuning/apply', {}),
    onSuccess: async (result) => {
      setDraft({})
      toast({ tone: 'success', title: t('tuning.applied', { count: result.applied ?? 0 }) })
      await invalidate()
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('tuning.apply'), description: describeError(error, t).message }),
  })

  const save = useMutation({
    mutationFn: (values: Record<string, string>) =>
      api.post<{ applied: number }>('/system/tuning/set', { values }),
    onSuccess: async (result, values) => {
      setDraft((current) => {
        const rest = { ...current }
        for (const key of Object.keys(values)) delete rest[key]
        return rest
      })
      toast({ tone: 'success', title: t('tuning.edit.saved', { count: result.applied ?? 0 }) })
      await invalidate()
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('tuning.edit.save'), description: describeError(error, t).message }),
  })

  const release = useMutation({
    mutationFn: (key: string) => api.post('/system/tuning/set', { values: { [key]: '' } }),
    onSuccess: async () => {
      toast({ tone: 'success', title: t('tuning.edit.released') })
      await invalidate()
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('tuning.edit.release'), description: describeError(error, t).message }),
  })

  const safety = (report?.readings ?? []).filter((r) => r.group === 'safety')
  const throughput = (report?.readings ?? []).filter((r) => r.group === 'throughput')

  const rowProps = {
    draft,
    errors,
    onChange: (key: string, value: string) => setDraft((current) => ({ ...current, [key]: value })),
    onRevert: (key: string) =>
      setDraft((current) => {
        const rest = { ...current }
        delete rest[key]
        return rest
      }),
    onRelease: (key: string) => release.mutate(key),
    releasing: release.isPending ? (release.variables as string) : undefined,
  }

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>{t('tuning.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('tuning.intro')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {report?.panel_managed ? (
            <RevertButton onDone={invalidate} />
          ) : null}
          <Button
            variant="primary"
            size="sm"
            loading={apply.isPending}
            disabled={!report || report.pending === 0}
            onClick={() => apply.mutate()}
          >
            <Gauge className="size-4" aria-hidden="true" />
            {report?.pending
              ? t('tuning.applyCount', { count: report.pending })
              : t('tuning.upToDate')}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {query.isLoading ? (
          <Skeleton className="h-40" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
        ) : !report ? null : (
          <>
            {/* What the recommendations were computed from. A number with no
                stated basis is a number from somebody else's machine. */}
            <p className="text-2xs text-muted-foreground">
              {t('tuning.basis', {
                memory: formatCount(report.facts.MemoryMB, digits, language),
                cores: formatCount(report.facts.Cores, digits, language),
                connections: formatCount(report.facts.LiveConnections, digits, language),
              })}
            </p>

            <Group
              icon={<ShieldCheck className="size-4 text-ok" aria-hidden="true" />}
              title={t('tuning.group.safety')}
              body={t('tuning.group.safetyBody')}
              readings={safety}
              {...rowProps}
            />
            <Group
              icon={<Gauge className="size-4 text-accent" aria-hidden="true" />}
              title={t('tuning.group.throughput')}
              body={t('tuning.group.throughputBody')}
              readings={throughput}
              {...rowProps}
            />

            <p className="text-2xs text-muted-foreground">
              {t('tuning.file')} <Technical className="text-2xs">{report.sysctl_path}</Technical>
            </p>
          </>
        )}
      </CardContent>

      {/* The save bar appears only once something has been edited, and stays in
          view while the page is scrolled: the field being changed and the button
          that commits it are usually a long way apart on a list this long. */}
      {edited.length > 0 ? (
        <div className="sticky bottom-0 z-10 flex flex-wrap items-center gap-2 border-t border-border bg-surface-raised/95 px-4 py-3 backdrop-blur sm:px-5">
          <Pencil className="size-4 text-accent" aria-hidden="true" />
          <p className="text-xs">{t('tuning.edit.unsaved')}</p>
          <div className="ms-auto flex flex-wrap gap-2">
            <Button variant="ghost" size="sm" onClick={() => setDraft({})}>
              {t('tuning.edit.discard')}
            </Button>
            <Button
              variant="primary"
              size="sm"
              loading={save.isPending}
              disabled={Object.keys(errors).length > 0}
              onClick={() => save.mutate(draft)}
            >
              {t('tuning.edit.saveCount', { count: edited.length })}
            </Button>
          </div>
        </div>
      ) : null}
    </Card>
  )
}

function RevertButton({ onDone }: { onDone: () => Promise<unknown> }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const revert = useMutation({
    mutationFn: () => api.post('/system/tuning/revert', {}),
    onSuccess: async () => {
      toast({ tone: 'success', title: t('tuning.reverted') })
      await onDone()
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('tuning.revert'), description: describeError(error, t).message }),
  })
  return (
    <Button variant="secondary" size="sm" loading={revert.isPending} onClick={() => revert.mutate()}>
      <RotateCcw className="size-4" aria-hidden="true" />
      {t('tuning.revert')}
    </Button>
  )
}

type RowActions = {
  draft: Record<string, string>
  errors: Record<string, string>
  onChange: (key: string, value: string) => void
  onRevert: (key: string) => void
  onRelease: (key: string) => void
  releasing?: string
}

function Group({
  icon,
  title,
  body,
  readings,
  ...actions
}: {
  icon: React.ReactNode
  title: string
  body: string
  readings: TuningReading[]
} & RowActions) {
  if (!readings.length) return null
  return (
    <section>
      <h4 className="flex items-center gap-2 text-xs font-medium">
        {icon}
        {title}
      </h4>
      <p className="mt-0.5 text-2xs text-muted-foreground">{body}</p>
      <ul className="mt-2 divide-y divide-border">
        {readings.map((reading) => (
          <Row key={reading.key} reading={reading} {...actions} />
        ))}
      </ul>
    </section>
  )
}

/**
 * One parameter: what it is called in plain language, what it does, the field
 * that sets it, and the two values that tell you whether you should.
 *
 * The field starts from what the panel has been asked to keep, falling back to
 * what the kernel holds — so opening the page and saving without touching
 * anything sets nothing to a surprise. The kernel's own name for the parameter
 * is shown small and last: it is what an operator needs in order to search for
 * it or set it by hand, and it is not what tells them whether they should.
 */
function Row({
  reading,
  draft,
  errors,
  onChange,
  onRevert,
  onRelease,
  releasing,
}: { reading: TuningReading } & RowActions) {
  const { t } = useTranslation()

  const pending = draft[reading.key]
  const value = pending ?? reading.desired ?? ''
  const shown = value || reading.current
  const problem = errors[reading.key]
  const isEdited = pending !== undefined

  return (
    <li className="py-3">
      <div className="flex flex-wrap items-baseline gap-2">
        <p className="text-xs font-medium">{reading.title}</p>
        {!reading.available ? (
          <Badge tone="neutral">{t('tuning.absent')}</Badge>
        ) : reading.drifted ? (
          <Badge tone="warn">
            <AlertTriangle className="size-3" aria-hidden="true" />
            {t('tuning.edit.drifted')}
          </Badge>
        ) : reading.custom ? (
          <Badge tone="accent">{t('tuning.edit.yours')}</Badge>
        ) : reading.matches ? (
          <Badge tone="ok">
            <Check className="size-3" aria-hidden="true" />
            {t('tuning.set')}
          </Badge>
        ) : (
          <Badge tone="warn">
            <AlertTriangle className="size-3" aria-hidden="true" />
            {t('tuning.pending')}
          </Badge>
        )}
        {isEdited ? (
          <Button variant="ghost" size="sm" onClick={() => onRevert(reading.key)}>
            <Undo2 className="size-3" aria-hidden="true" />
            {t('tuning.edit.discard')}
          </Button>
        ) : null}
      </div>

      <p className="mt-1 text-2xs leading-relaxed text-muted-foreground">{reading.explain}</p>

      {reading.available ? (
        <div className="mt-2 flex flex-wrap items-start gap-2">
          <div className="w-full max-w-xs">
            <ValueField
              reading={reading}
              value={shown}
              edited={isEdited}
              invalid={Boolean(problem)}
              onChange={(next) => onChange(reading.key, next)}
            />
            {problem ? (
              <p className="mt-1 text-2xs text-danger">{problem}</p>
            ) : hint(reading, t) ? (
              <p className="mt-1 text-2xs text-muted-foreground">{hint(reading, t)}</p>
            ) : null}
          </div>

          <div className="flex flex-wrap gap-1.5">
            {reading.recommended && !equalValues(shown, reading.recommended) ? (
              <Button variant="ghost" size="sm" onClick={() => onChange(reading.key, reading.recommended)}>
                {t('tuning.edit.useRecommended')}
                <Technical className="text-2xs text-ok">{reading.recommended}</Technical>
              </Button>
            ) : null}
            {reading.desired ? (
              <Button
                variant="ghost"
                size="sm"
                loading={releasing === reading.key}
                onClick={() => onRelease(reading.key)}
              >
                <X className="size-3" aria-hidden="true" />
                {t('tuning.edit.release')}
              </Button>
            ) : null}
          </div>
        </div>
      ) : (
        <p className="mt-1.5 text-2xs text-muted-foreground">{t('tuning.absentHint')}</p>
      )}

      <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs">
        {reading.available ? (
          <span className="text-muted-foreground">
            {t('tuning.now')}{' '}
            <Technical className={cn('text-2xs', !reading.matches && 'text-foreground')}>
              {reading.current}
            </Technical>
          </span>
        ) : null}
        {reading.recommended ? (
          <span className="text-muted-foreground">
            {t('tuning.recommended')}{' '}
            <Technical className="text-2xs text-ok">{reading.recommended}</Technical>
          </span>
        ) : null}
        {reading.drifted ? (
          <span className="text-warn">
            {t('tuning.edit.driftedHint', { value: reading.desired, current: reading.current })}
          </span>
        ) : null}
        <Technical className="ms-auto text-2xs text-muted-foreground/70">{reading.key}</Technical>
      </div>
    </li>
  )
}

/**
 * The control the value's shape asks for.
 *
 * A queueing discipline the panel has never heard of is still one this kernel
 * might have, so those get a list of suggestions attached to a field rather
 * than a list that is the only way to answer.
 */
function ValueField({
  reading,
  value,
  edited,
  invalid,
  onChange,
}: {
  reading: TuningReading
  value: string
  edited: boolean
  invalid: boolean
  onChange: (value: string) => void
}) {
  const { t } = useTranslation()
  const ring = cn(
    edited && !invalid && 'border-accent',
    invalid && 'border-danger focus-visible:ring-danger/40',
  )

  if (reading.kind === 'choice' && reading.choices?.length && !reading.open) {
    return (
      <Select
        value={value}
        onValueChange={onChange}
        aria-label={reading.title}
        className={ring}
        options={reading.choices.map((choice) => ({
          value: choice.value,
          label: choice.value,
          description: choice.detail,
        }))}
      />
    )
  }

  const listId = reading.choices?.length ? `tuning-${reading.key}` : undefined
  return (
    <>
      <TechnicalInput
        value={value}
        list={listId}
        inputMode={reading.kind === 'number' ? 'numeric' : 'text'}
        aria-label={reading.title}
        aria-invalid={invalid || undefined}
        className={ring}
        placeholder={reading.recommended || t('tuning.edit.value')}
        onChange={(event) => onChange(event.target.value)}
      />
      {listId ? (
        <datalist id={listId}>
          {reading.choices?.map((choice) => (
            <option key={choice.value} value={choice.value}>
              {choice.detail}
            </option>
          ))}
        </datalist>
      ) : null}
    </>
  )
}

/** What this field will accept, said before it is typed rather than after. */
function hint(reading: TuningReading, t: TFunction): string {
  const parts: string[] = []
  if (reading.unit) parts.push(reading.unit)
  if (reading.kind === 'numbers' && reading.fields) {
    parts.push(t('tuning.edit.fields', { count: reading.fields }))
  }
  if (reading.min && reading.max) {
    parts.push(t('tuning.edit.range', { min: reading.min, max: reading.max }))
  }
  if (reading.open) parts.push(t('tuning.edit.custom'))
  return parts.join(' · ')
}

/**
 * The same check the panel makes before it writes anything, made here as well.
 *
 * Not because the server's answer cannot be trusted — it is the one that counts
 * — but because a field that says what is wrong with it as you type is a
 * different thing to use than one that waits for a round trip to tell you.
 */
function checkValue(
  reading: TuningReading,
  value: string,
  t: TFunction,
): string | undefined {
  const trimmed = value.trim()
  // An empty field is how the row asks the panel to stop keeping the parameter,
  // which is a legitimate answer rather than an unfinished one.
  if (!trimmed) return undefined

  const outOfRange = (n: number) => {
    if (reading.min && n < reading.min) return true
    if (reading.max && n > reading.max) return true
    return false
  }

  if (reading.kind === 'number') {
    if (!/^-?\d+$/.test(trimmed)) return t('tuning.edit.value')
    if (outOfRange(Number(trimmed))) {
      return t('tuning.edit.range', { min: reading.min, max: reading.max })
    }
    return undefined
  }

  if (reading.kind === 'numbers') {
    const fields = trimmed.split(/\s+/)
    if (reading.fields && fields.length !== reading.fields) {
      return t('tuning.edit.fields', { count: reading.fields })
    }
    for (const field of fields) {
      if (!/^-?\d+$/.test(field)) return t('tuning.edit.value')
      if (outOfRange(Number(field))) {
        return t('tuning.edit.range', { min: reading.min, max: reading.max })
      }
    }
    return undefined
  }

  if (reading.kind === 'choice' && !reading.open && reading.choices?.length) {
    if (!reading.choices.some((choice) => choice.value === trimmed)) {
      return t('tuning.edit.value')
    }
  }
  return undefined
}

/** Whitespace is not a difference: the kernel prints tabs where a file writes spaces. */
function equalValues(a: string, b: string): boolean {
  return a.trim().split(/\s+/).join(' ') === b.trim().split(/\s+/).join(' ')
}
