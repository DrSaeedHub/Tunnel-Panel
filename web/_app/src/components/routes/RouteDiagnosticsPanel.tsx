import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, HelpCircle, Stethoscope, Wifi, XCircle } from 'lucide-react'

import { api } from '@/lib/api'
import type { RouteAnalyzeResult, RouteReachabilityResult, RouteRule } from '@/lib/types'
import { formatDateTime, formatMs } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { describeError } from '../ui/feedback'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge } from '../ui/feedback'
import { DisclosurePanel } from '../ui/disclosure'
import { Technical, TechnicalBlock } from '../ui/technical'
import { cn } from '@/lib/utils'

/** Which verdicts read as a fault, and how strongly. */
const VERDICT_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  HEALTHY: 'ok',
  RULE_DISABLED: 'neutral',
  NO_INBOUND_TRAFFIC: 'neutral',
  MTU_PROBLEM: 'warn',
  TUNNEL_DOWN: 'warn',
  RULE_SHADOWED: 'warn',
  RULE_MISSING: 'danger',
  FORWARDING_DISABLED: 'danger',
  FORWARD_BLOCKED: 'danger',
  DESTINATION_UNREACHABLE: 'danger',
}

/**
 * The reachability test and the analysis, side by side.
 *
 * The analysis is the one that matters: it returns a specific verdict with the
 * evidence it rests on, rather than a status word an operator has to interpret.
 * Every piece of evidence the backend gathered is shown, including the ones
 * that did not decide the verdict, because what was ruled out is as useful as
 * what was found.
 */
export function RouteDiagnosticsPanel({ route }: { route: RouteRule }) {
  const { t } = useTranslation()
  const { calendar, digits, language } = usePreferences()
  const [analysis, setAnalysis] = useState<RouteAnalyzeResult | null>(null)
  const [probe, setProbe] = useState<RouteReachabilityResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const analyzeMutation = useMutation({
    mutationFn: () =>
      api.post<RouteAnalyzeResult>(`/routes/${route.route_rule_id}/diagnostics/analyze`, {}),
    onSuccess: (result) => {
      setAnalysis(result)
      setError(null)
    },
    onError: (cause) => setError(describeError(cause, t).message),
  })

  const testMutation = useMutation({
    mutationFn: () => api.post<RouteReachabilityResult>(`/routes/${route.route_rule_id}/diagnostics/test`, {}),
    onSuccess: (result) => {
      setProbe(result)
      setError(null)
    },
    onError: (cause) => setError(describeError(cause, t).message),
  })

  const tone = analysis ? (VERDICT_TONE[analysis.verdict] ?? 'neutral') : 'neutral'
  const VerdictIcon =
    tone === 'ok' ? CheckCircle2 : tone === 'danger' ? XCircle : tone === 'warn' ? AlertTriangle : HelpCircle

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('routeDiag.title')}</CardTitle>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            size="sm"
            loading={testMutation.isPending}
            onClick={() => testMutation.mutate()}
          >
            <Wifi className="size-4" aria-hidden="true" />
            {testMutation.isPending ? t('routeDiag.testing') : t('routeDiag.test')}
          </Button>
          <Button
            variant="primary"
            size="sm"
            loading={analyzeMutation.isPending}
            onClick={() => analyzeMutation.mutate()}
          >
            <Stethoscope className="size-4" aria-hidden="true" />
            {analyzeMutation.isPending ? t('routeDiag.analyzing') : t('routeDiag.analyze')}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {error ? (
          <p className="rounded-md border border-danger/30 bg-danger-muted px-3 py-2 text-xs text-danger" role="alert">
            {error}
          </p>
        ) : null}

        {probe ? (
          <div
            className={cn(
              'rounded-md border p-3',
              probe.reachable
                ? 'border-ok/30 bg-ok-muted'
                : probe.conclusive
                  ? 'border-danger/30 bg-danger-muted'
                  : 'border-border bg-surface-sunken',
            )}
          >
            <p className="flex flex-wrap items-center gap-2 text-xs font-medium">
              {probe.reachable ? (
                <CheckCircle2 className="size-3.5 text-ok" aria-hidden="true" />
              ) : probe.conclusive ? (
                <XCircle className="size-3.5 text-danger" aria-hidden="true" />
              ) : (
                <HelpCircle className="size-3.5 text-muted-foreground" aria-hidden="true" />
              )}
              <Technical className="text-xs">{`${probe.address}:${probe.port}/${probe.protocol}`}</Technical>
              {probe.latency_ms ? (
                <Badge tone="ok">{formatMs(probe.latency_ms, digits) ?? ''}</Badge>
              ) : null}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">{probe.detail}</p>
          </div>
        ) : null}

        {analysis ? (
          <div className="space-y-3">
            <div
              className={cn(
                'rounded-md border p-3',
                tone === 'ok' && 'border-ok/30 bg-ok-muted',
                tone === 'warn' && 'border-warn/40 bg-warn-muted',
                tone === 'danger' && 'border-danger/30 bg-danger-muted',
                tone === 'neutral' && 'border-border bg-surface-sunken',
              )}
            >
              <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                <VerdictIcon
                  className={cn(
                    'size-4',
                    tone === 'ok' && 'text-ok',
                    tone === 'warn' && 'text-warn',
                    tone === 'danger' && 'text-danger',
                    tone === 'neutral' && 'text-muted-foreground',
                  )}
                  aria-hidden="true"
                />
                {t(`routeDiag.verdict.${analysis.verdict}`, analysis.verdict)}
                {/* A verdict the backend is not confident in says so, rather
                    than being presented with the same weight as one it is. */}
                {analysis.confidence === 'low' ? (
                  <Badge tone="neutral">{t('routeDiag.confidence.low')}</Badge>
                ) : null}
              </p>
              <p className="mt-1 text-xs">{analysis.summary}</p>
              <p className="mt-1 text-2xs text-muted-foreground">
                {formatDateTime(analysis.checked_at, { locale: language, calendar, digits })}
              </p>
            </div>

            {analysis.suggested_fix?.length ? (
              <section>
                <h4 className="mb-1.5 text-xs font-medium">{t('routeDiag.suggestedFix')}</h4>
                <ol className="space-y-1 text-xs text-muted-foreground">
                  {(analysis.suggested_fix ?? []).map((fix, index) => (
                    <li key={fix} className="flex gap-2">
                      <span className="tabular shrink-0 text-muted-foreground">{index + 1}.</span>
                      <span>{fix}</span>
                    </li>
                  ))}
                </ol>
              </section>
            ) : null}

            <DisclosurePanel title={t('routeDiag.evidence')} contentClassName="space-y-2">
              {(analysis.evidence ?? []).map((evidence) => (
                <div key={evidence.name}>
                  <p className="text-xs font-medium">
                    {t(`routeDiag.evidenceName.${evidence.name}`, evidence.name)}
                  </p>
                  <p className="text-2xs text-muted-foreground">{evidence.detail}</p>
                  {evidence.data ? (
                    <TechnicalBlock className="mt-1 max-h-40 text-2xs">
                      {JSON.stringify(evidence.data, null, 2)}
                    </TechnicalBlock>
                  ) : null}
                </div>
              ))}
            </DisclosurePanel>
          </div>
        ) : !analyzeMutation.isPending ? (
          <p className="text-xs text-muted-foreground">{t('routeForm.preflight.hint')}</p>
        ) : null}
      </CardContent>
    </Card>
  )
}
