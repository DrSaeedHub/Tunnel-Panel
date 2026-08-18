import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, XCircle } from 'lucide-react'

import { api } from '@/lib/api'
import type { ReconcileReport, RouteCounterReport, RoutePreviewResponse } from '@/lib/types'
import { formatCount, formatVolume } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, ErrorState, Skeleton } from '../ui/feedback'
import { Technical, TechnicalBlock } from '../ui/technical'

/**
 * What the panel intends, beside what the kernel actually holds.
 *
 * The intended side is the backend's own rendering — the exact bytes an apply
 * would submit — rather than a reconstruction. The installed side is the
 * reconcile classification for this rule: whether the kernel holds it, how many
 * rules it holds, and, when something is missing, which part. Putting the two
 * together is what makes drift visible without an operator having to read a
 * ruleset and compare it by eye.
 */
export function RouteRulesPanel({ routeRuleId }: { routeRuleId: number }) {
  const { t } = useTranslation()
  const { digits, language, units } = usePreferences()

  const previewQuery = useQuery({
    queryKey: ['routes', routeRuleId, 'preview'],
    queryFn: () => api.post<RoutePreviewResponse>('/routes/preview', { route_rule_id: routeRuleId }),
    staleTime: 30_000,
    retry: false,
  })

  const reconcileQuery = useQuery({
    queryKey: ['reconcile'],
    queryFn: () => api.get<ReconcileReport>('/reconcile'),
    staleTime: 15_000,
  })

  const countersQuery = useQuery({
    queryKey: ['routes', routeRuleId, 'counters'],
    queryFn: () => api.get<RouteCounterReport>(`/routes/${routeRuleId}/counters`),
    refetchInterval: 15_000,
  })

  const item = reconcileQuery.data?.routes.find((entry) => entry.route_rule_id === routeRuleId)
  const counters = countersQuery.data

  const inSync = item?.status === 'InSync'
  const missing = item?.status === 'Missing'

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>{t('routeDetail.rules.title')}</CardTitle>
          {item ? (
            <p className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
              {inSync ? (
                <CheckCircle2 className="size-3.5 text-ok" aria-hidden="true" />
              ) : missing ? (
                <XCircle className="size-3.5 text-danger" aria-hidden="true" />
              ) : (
                <AlertTriangle className="size-3.5 text-warn" aria-hidden="true" />
              )}
              {inSync
                ? t('routeDetail.rules.inSync')
                : missing
                  ? t('routeDetail.rules.notInstalled')
                  : t('routeDetail.rules.drifted')}
            </p>
          ) : null}
        </div>
        {item ? (
          // The count the kernel holds, on its own. The backend's expected
          // figure counts distinct match criteria rather than lines — one
          // criterion can be satisfied by more than one rendered rule — so
          // showing it as a denominator would read as "more than expected"
          // on a ruleset that is exactly right. The status carries the verdict.
          <Badge tone={inSync ? 'ok' : missing ? 'danger' : 'warn'}>
            {t('routeDetail.rules.installedCount', {
              count: item.installed_rules,
              formatted: formatCount(item.installed_rules, digits, language),
            })}
          </Badge>
        ) : null}
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Counters first: whether the rule is being reached at all is the
            question an operator asks before reading the rule text. */}
        {counters ? (
          <div className="rounded-md border border-border bg-surface-sunken p-3">
            <p className="flex flex-wrap items-baseline gap-2 text-xs">
              <span className="font-medium">{t('routeDetail.rules.counters')}</span>
              <Technical className="text-xs">
                {`${formatVolume(counters.rx_bytes_since_boot, units).text} / ${formatVolume(counters.tx_bytes_since_boot, units).text}`}
              </Technical>
              {!counters.hit ? <Badge tone="warn">{t('routeDetail.rules.neverHit')}</Badge> : null}
            </p>
            <p className="mt-1 text-2xs text-muted-foreground">
              {t('routeDetail.rules.counterSource', { source: counters.source })}
            </p>
            {/* The two figures are different measurements, and the backend's own
                sentence saying so travels with them. */}
            <p className="mt-1 text-2xs text-muted-foreground">{counters.note}</p>
          </div>
        ) : null}

        {item?.diffs?.length ? (
          <div className="rounded-md border border-warn/40 bg-warn-muted p-3">
            <p className="text-xs font-medium">{t('routeDetail.rules.installed')}</p>
            <ul className="mt-1 space-y-0.5 text-2xs">
              {(item.diffs ?? []).map((diff) => (
                <li key={diff.field} className="flex flex-wrap items-center gap-1.5">
                  <Badge>{diff.field}</Badge>
                  <span className="text-muted-foreground">{diff.expected}</span>
                  <span aria-hidden="true">·</span>
                  <span>{diff.observed}</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {item?.shadows?.length ? (
          <div className="rounded-md border border-warn/40 bg-warn-muted p-3">
            <p className="flex items-center gap-2 text-xs font-medium">
              <AlertTriangle className="size-3.5 text-warn" aria-hidden="true" />
              {t('routeDiag.verdict.RULE_SHADOWED')}
            </p>
            <ul className="mt-1 space-y-1 text-2xs">
              {(item.shadows ?? []).map((shadow) => (
                <li key={`${shadow.chain}-${shadow.text}`}>
                  {shadow.manager ? <Badge>{shadow.manager}</Badge> : null}{' '}
                  <Technical className="text-2xs">{shadow.text}</Technical>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        <section>
          <h4 className="mb-1.5 text-xs font-medium">{t('routeDetail.rules.intended')}</h4>
          {previewQuery.isLoading ? (
            <Skeleton className="h-32" />
          ) : previewQuery.error ? (
            <ErrorState error={previewQuery.error} onRetry={() => void previewQuery.refetch()} compact />
          ) : previewQuery.data?.payload ? (
            <TechnicalBlock copyable>{previewQuery.data.payload}</TechnicalBlock>
          ) : null}
        </section>
      </CardContent>
    </Card>
  )
}
