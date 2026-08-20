import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Gauge, RotateCcw, ShieldCheck } from 'lucide-react'

import { api } from '@/lib/api'
import type { TuningReading, TuningReport } from '@/lib/types'
import { formatCount } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, ErrorState, Skeleton, describeError } from '../ui/feedback'
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

  const apply = useMutation({
    mutationFn: () => api.post<{ applied: number }>('/system/tuning/apply', {}),
    onSuccess: async (result) => {
      toast({ tone: 'success', title: t('tuning.applied', { count: result.applied ?? 0 }) })
      await queryClient.invalidateQueries({ queryKey: ['system', 'tuning'] })
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('tuning.apply'), description: describeError(error, t).message }),
  })

  const revert = useMutation({
    mutationFn: () => api.post('/system/tuning/revert', {}),
    onSuccess: async () => {
      toast({ tone: 'success', title: t('tuning.reverted') })
      await queryClient.invalidateQueries({ queryKey: ['system', 'tuning'] })
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('tuning.revert'), description: describeError(error, t).message }),
  })

  const report = query.data
  const safety = (report?.readings ?? []).filter((r) => r.group === 'safety')
  const throughput = (report?.readings ?? []).filter((r) => r.group === 'throughput')

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>{t('tuning.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('tuning.intro')}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          {report?.panel_managed ? (
            <Button variant="secondary" size="sm" loading={revert.isPending} onClick={() => revert.mutate()}>
              <RotateCcw className="size-4" aria-hidden="true" />
              {t('tuning.revert')}
            </Button>
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
            />
            <Group
              icon={<Gauge className="size-4 text-accent" aria-hidden="true" />}
              title={t('tuning.group.throughput')}
              body={t('tuning.group.throughputBody')}
              readings={throughput}
            />

            <p className="text-2xs text-muted-foreground">
              {t('tuning.file')} <Technical className="text-2xs">{report.sysctl_path}</Technical>
            </p>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function Group({
  icon,
  title,
  body,
  readings,
}: {
  icon: React.ReactNode
  title: string
  body: string
  readings: TuningReading[]
}) {
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
          <Row key={reading.key} reading={reading} />
        ))}
      </ul>
    </section>
  )
}

/**
 * One parameter: what it is called in plain language, what it does, and the two
 * numbers that matter.
 *
 * The kernel's own name for it is shown too, but small and last: it is what an
 * operator needs to search for or to set by hand, and it is not what tells them
 * whether they should.
 */
function Row({ reading }: { reading: TuningReading }) {
  const { t } = useTranslation()

  return (
    <li className="py-3">
      <div className="flex flex-wrap items-baseline gap-2">
        <p className="text-xs font-medium">{reading.title}</p>
        {!reading.available ? (
          <Badge tone="neutral">{t('tuning.absent')}</Badge>
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
      </div>

      <p className="mt-1 text-2xs leading-relaxed text-muted-foreground">{reading.explain}</p>

      <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs">
        {reading.available ? (
          <span className="text-muted-foreground">
            {t('tuning.now')}{' '}
            <Technical className={cn('text-2xs', !reading.matches && 'text-foreground')}>
              {reading.current}
            </Technical>
          </span>
        ) : (
          <span className="text-muted-foreground">{t('tuning.absentHint')}</span>
        )}
        {reading.recommended && !reading.matches ? (
          <span className="text-muted-foreground">
            {t('tuning.recommended')}{' '}
            <Technical className="text-2xs text-ok">{reading.recommended}</Technical>
          </span>
        ) : null}
        <Technical className="ms-auto text-2xs text-muted-foreground/70">{reading.key}</Technical>
      </div>
    </li>
  )
}
