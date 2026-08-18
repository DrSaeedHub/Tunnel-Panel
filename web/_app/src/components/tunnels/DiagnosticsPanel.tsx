import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Ruler,
  Square,
  Waypoints,
  XCircle,
} from 'lucide-react'

import { api, csrfToken } from '@/lib/api'
import { apiUrl } from '@/lib/bootstrap'
import type {
  AnalyzeResult,
  DiagnosticRun,
  MtuProbeResponse,
  PingPacket,
  PingResult,
  SettingsResponse,
  TracerouteResult,
  Tunnel,
} from '@/lib/types'
import { formatMs, formatPercent } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Field, Input, SwitchField } from '../ui/form'
import { Badge, EmptyState, ErrorState, Skeleton } from '../ui/feedback'
import { Technical, TechnicalBlock } from '../ui/technical'
import { cn } from '@/lib/utils'

export function DiagnosticsPanel({ tunnel }: { tunnel: Tunnel }) {
  return (
    <div className="space-y-4">
      <AnalyzeCard tunnel={tunnel} />
      <div className="grid gap-4 lg:grid-cols-2">
        <PingCard tunnel={tunnel} />
        <div className="space-y-4">
          <MtuProbeCard tunnel={tunnel} />
          <TracerouteCard tunnel={tunnel} />
        </div>
      </div>
    </div>
  )
}

/**
 * The backend's verdict, rendered as a conclusion rather than a status code.
 *
 * The decision tree already did the reasoning; this shows what it concluded,
 * the evidence it collected on the way, and what to try — which is what an
 * operator actually needs at the moment something is broken.
 */
function AnalyzeCard({ tunnel }: { tunnel: Tunnel }) {
  const { t } = useTranslation()

  const analyzeMutation = useMutation({
    mutationFn: () => api.post<{ result: AnalyzeResult; run?: DiagnosticRun }>(
      `/tunnels/${tunnel.tunnel_id}/diagnostics/analyze`,
      {},
    ),
  })

  const result = analyzeMutation.data?.result

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('diagnostics.analyze.title')}
        </CardTitle>
        <Button
          variant="primary"
          size="sm"
          loading={analyzeMutation.isPending}
          onClick={() => analyzeMutation.mutate()}
        >
          {analyzeMutation.isPending ? t('diagnostics.analyze.running') : t('diagnostics.analyze.run')}
        </Button>
      </CardHeader>
      <CardContent>
        {analyzeMutation.isPending ? (
          <div className="space-y-2">
            <Skeleton className="h-6 w-40" />
            <Skeleton className="h-16" />
          </div>
        ) : analyzeMutation.error ? (
          <ErrorState error={analyzeMutation.error} onRetry={() => analyzeMutation.mutate()} compact />
        ) : !result ? (
          <p className="text-xs text-muted-foreground">{t('diagnostics.analyze.never')}</p>
        ) : (
          <VerdictCard result={result} />
        )}
      </CardContent>
    </Card>
  )
}

function VerdictCard({ result }: { result: AnalyzeResult }) {
  const { t } = useTranslation()

  const healthy = result.verdict === 'HEALTHY'
  const Icon = healthy ? CheckCircle2 : result.confidence === 'low' ? HelpCircle : XCircle
  // The verdict has a translated name where one exists, and the backend's own
  // string where it does not, so a new verdict is still legible.
  const verdictKey = `diagnostics.analyze.verdicts.${result.verdict}`
  const verdictLabel = t(verdictKey) === verdictKey ? result.verdict : t(verdictKey)

  return (
    <div className="space-y-3">
      <div
        className={cn(
          'flex items-start gap-3 rounded-md border p-3',
          healthy ? 'border-ok/30 bg-ok-muted' : 'border-danger/30 bg-danger-muted',
        )}
      >
        <Icon className={cn('mt-0.5 size-5 shrink-0', healthy ? 'text-ok' : 'text-danger')} aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm font-semibold">{verdictLabel}</p>
            <Badge tone={result.confidence === 'high' ? 'accent' : 'neutral'}>
              {t('diagnostics.analyze.confidence')}:{' '}
              {t(`diagnostics.analyze.confidenceLevel.${result.confidence}`, result.confidence)}
            </Badge>
          </div>
          <p className="mt-1 text-xs">{result.summary}</p>
        </div>
      </div>

      {result.suggested_fix?.length ? (
        <section>
          <h4 className="mb-1.5 text-xs font-medium">{t('diagnostics.analyze.suggestedFix')}</h4>
          <ul className="space-y-1 text-xs">
            {(result.suggested_fix ?? []).map((fix) => (
              <li key={fix} className="flex gap-2">
                <span aria-hidden="true" className="text-muted-foreground">
                  →
                </span>
                <span>{fix}</span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {(result.evidence ?? []).length ? (
        <section>
          <h4 className="mb-1.5 text-xs font-medium">{t('diagnostics.analyze.evidence')}</h4>
          <dl className="space-y-1.5">
            {(result.evidence ?? []).map((item) => (
              <div key={item.name} className="rounded-md border border-border bg-surface-sunken p-2">
                <dt className="text-2xs font-medium text-muted-foreground">{item.name}</dt>
                <dd className="text-xs">{item.detail}</dd>
              </div>
            ))}
          </dl>
        </section>
      ) : null}
    </div>
  )
}

/**
 * The manual probe.
 *
 * Results stream in packet by packet over SSE, which is what makes this useful
 * while something is intermittent, and the run is cancellable mid-flight by
 * deleting it — the backend stops the run rather than the browser merely
 * looking away.
 */
function PingCard({ tunnel }: { tunnel: Tunnel }) {
  const { t } = useTranslation()
  const { digits } = usePreferences()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<SettingsResponse>('/settings'),
    staleTime: 60_000,
  })
  const settings = settingsQuery.data?.settings ?? {}

  /**
   * A number from the settings, or the schema's own default for it.
   *
   * The fallbacks are the defaults declared in internal/settings/definition.go,
   * not a second set of numbers invented here. The maximum count used to fall
   * back to 1000 against a schema default of 10000, so a panel whose settings
   * had not loaded yet silently offered a tenth of the real ceiling.
   */
  const setting = (key: string, fallback: number) =>
    typeof settings[key] === 'number' ? (settings[key] as number) : fallback

  const maxCount = setting('diagnostics.manual_ping_max_count', 10000)

  /*
   * These four are the panel's defaults for the probe, and they come from the
   * settings. They were hardcoded literals -- 10, 1, 56, 2 -- against stored
   * settings of 100, 0.1 and 1, so three keys that the Settings page describes
   * in confident prose did nothing at all. The backend honours them perfectly
   * well when a request leaves them out (see pingRequest in internal/diag); it
   * was this form always sending its own numbers that defeated them.
   *
   * Null means "no override typed yet, follow the setting". Seeding useState
   * from the query instead would bake in whatever was known at first render and
   * leave the field stale once the settings actually arrived, which is the same
   * defect wearing a different hat.
   */
  const [countOverride, setCount] = useState<number | null>(null)
  const [intervalOverride, setInterval] = useState<number | null>(null)
  const [packetSizeOverride, setPacketSize] = useState<number | null>(null)
  const [timeoutOverride, setTimeoutSeconds] = useState<number | null>(null)
  const [dontFragment, setDontFragment] = useState(false)

  const count = countOverride ?? setting('diagnostics.manual_ping_count', 100)
  const interval = intervalOverride ?? setting('diagnostics.manual_ping_interval', 0.1)
  const timeout = timeoutOverride ?? setting('diagnostics.manual_ping_timeout', 1)
  // The schema has no diagnostics key for the probe's packet size. The manual
  // probe runs down the same native ICMP path as the monitor (§13.1), so it
  // takes the monitor's payload size rather than a literal -- same value as the
  // 56 that was hardcoded here, but now an operator can change it.
  const packetSize = packetSizeOverride ?? setting('monitor.packet_size', 56)

  const [packets, setPackets] = useState<PingPacket[]>([])
  const [summary, setSummary] = useState<PingResult | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const runIdRef = useRef<number | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const outputRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => () => abortRef.current?.abort(), [])

  // The output follows the newest packet, the way a terminal does.
  useEffect(() => {
    outputRef.current?.scrollTo({ top: outputRef.current.scrollHeight })
  }, [packets])

  const start = useCallback(async () => {
    setPackets([])
    setSummary(null)
    setError(null)
    setRunning(true)
    runIdRef.current = null

    const controller = new AbortController()
    abortRef.current = controller

    try {
      // Fetch rather than EventSource: this is a POST with a body, and
      // EventSource can only issue a GET.
      const response = await fetch(apiUrl(`/tunnels/${tunnel.tunnel_id}/diagnostics/ping`), {
        method: 'POST',
        credentials: 'same-origin',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream',
          'X-CSRF-Token': csrfToken(),
        },
        body: JSON.stringify({
          count,
          interval_seconds: interval,
          timeout_seconds: timeout,
          packet_size: packetSize,
          df: dontFragment || undefined,
        }),
      })

      if (!response.ok || !response.body) {
        const text = await response.text()
        throw new Error(text || `HTTP ${response.status}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })

        // Frames are separated by a blank line.
        let boundary = buffer.indexOf('\n\n')
        while (boundary !== -1) {
          const frame = buffer.slice(0, boundary)
          buffer = buffer.slice(boundary + 2)
          handleFrame(frame)
          boundary = buffer.indexOf('\n\n')
        }
      }
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === 'AbortError')) {
        setError(caught instanceof Error ? caught.message : String(caught))
      }
    } finally {
      setRunning(false)
      abortRef.current = null
      void queryClient.invalidateQueries({ queryKey: ['diagnostics', 'runs'] })
    }

    function handleFrame(frame: string) {
      let event = 'message'
      const dataLines: string[] = []
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) event = line.slice(6).trim()
        else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim())
      }
      if (!dataLines.length) return

      try {
        const payload = JSON.parse(dataLines.join('\n'))
        if (event === 'run') {
          runIdRef.current = payload.diagnostic_run_id ?? null
        } else if (event === 'packet') {
          setPackets((current) => [...current, payload as PingPacket])
        } else if (event === 'summary') {
          setSummary((payload.result ?? null) as PingResult | null)
        } else if (event === 'error') {
          setError(String(payload.message ?? ''))
        }
      } catch {
        // A malformed frame is skipped rather than ending the run.
      }
    }
  }, [count, interval, timeout, packetSize, dontFragment, tunnel.tunnel_id, queryClient])

  const stop = useCallback(async () => {
    const runId = runIdRef.current
    abortRef.current?.abort()
    setRunning(false)
    if (runId) {
      try {
        // Deleting the run is what cancels it on the backend; closing the
        // stream alone would leave it probing to completion.
        await api.delete(`/diagnostics/runs/${runId}`)
      } catch {
        toast({ tone: 'error', title: t('diagnostics.ping.stop') })
      }
    }
  }, [t, toast])

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Waypoints className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('diagnostics.ping.title')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">{t('diagnostics.ping.subtitle')}</p>

        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Field label={t('diagnostics.ping.count')} description={t('diagnostics.ping.maxCount', { count: maxCount })}>
            {(props) => (
              <Input
                {...props}
                type="number"
                dir="ltr"
                className="tabular"
                min={1}
                max={maxCount}
                value={count}
                onChange={(event) => setCount(Number(event.target.value))}
                disabled={running}
              />
            )}
          </Field>
          <Field label={t('diagnostics.ping.interval')}>
            {(props) => (
              <Input
                {...props}
                type="number"
                dir="ltr"
                className="tabular"
                min={0.1}
                step={0.1}
                value={interval}
                onChange={(event) => setInterval(Number(event.target.value))}
                disabled={running}
              />
            )}
          </Field>
          <Field label={t('diagnostics.ping.packetSize')}>
            {(props) => (
              <Input
                {...props}
                type="number"
                dir="ltr"
                className="tabular"
                min={8}
                value={packetSize}
                onChange={(event) => setPacketSize(Number(event.target.value))}
                disabled={running}
              />
            )}
          </Field>
          <Field label={t('diagnostics.ping.timeout')}>
            {(props) => (
              <Input
                {...props}
                type="number"
                dir="ltr"
                className="tabular"
                min={0.1}
                step={0.1}
                value={timeout}
                onChange={(event) => setTimeoutSeconds(Number(event.target.value))}
                disabled={running}
              />
            )}
          </Field>
        </div>

        <SwitchField
          label={t('diagnostics.ping.dontFragment')}
          checked={dontFragment}
          onCheckedChange={setDontFragment}
          disabled={running}
        />

        <div className="flex gap-2">
          {running ? (
            <Button variant="danger" size="sm" onClick={() => void stop()}>
              <Square className="size-3.5" aria-hidden="true" />
              {t('diagnostics.ping.stop')}
            </Button>
          ) : (
            <Button variant="primary" size="sm" onClick={() => void start()}>
              {t('diagnostics.ping.run')}
            </Button>
          )}
        </div>

        {error ? <ErrorState error={new Error(error)} compact /> : null}

        <div
          ref={outputRef}
          className="max-h-56 overflow-auto rounded-md border border-border bg-surface-sunken p-2 scrollbar-thin"
          role="log"
          aria-live="polite"
          aria-label={t('diagnostics.ping.outputLabel')}
          aria-busy={running}
        >
          {!packets.length && !running ? (
            <p className="p-2 text-xs text-muted-foreground">{t('diagnostics.ping.empty')}</p>
          ) : (
            <ol className="space-y-0.5">
              {packets.map((packet) => (
                <li key={`${packet.sequence}-${packet.at}`}>
                  <Technical
                    className={cn(
                      'block text-2xs',
                      packet.success ? 'text-foreground' : 'text-danger',
                    )}
                  >
                    {packet.success
                      ? t('diagnostics.ping.packet', {
                          seq: packet.sequence,
                          size: packet.size ?? 0,
                          from: packet.from ?? '',
                          rtt: formatMs(packet.rtt_ms ?? null, 'latin') ?? '',
                        })
                      : packet.error
                        ? t('diagnostics.ping.packetError', { seq: packet.sequence, error: packet.error })
                        : t('diagnostics.ping.packetLost', { seq: packet.sequence })}
                  </Technical>
                </li>
              ))}
            </ol>
          )}
        </div>

        {summary ? (
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-md border border-border p-2 text-2xs sm:grid-cols-4">
            <Figure label={t('monitor.sent')} value={String(summary.summary.sent)} />
            <Figure label={t('monitor.received')} value={String(summary.summary.received)} />
            <Figure label={t('monitor.loss')} value={formatPercent(summary.summary.loss_percent, digits)} />
            <Figure label={t('monitor.jitter')} value={formatMs(summary.summary.jitter_ms, digits) ?? '—'} />
            <Figure label={t('monitor.rttMin')} value={formatMs(summary.summary.rtt_min_ms, digits) ?? '—'} />
            <Figure label={t('monitor.rttAvg')} value={formatMs(summary.summary.rtt_avg_ms, digits) ?? '—'} />
            <Figure label={t('monitor.rttMax')} value={formatMs(summary.summary.rtt_max_ms, digits) ?? '—'} />
            {summary.cancelled ? (
              <div className="col-span-2 sm:col-span-4">
                <Badge tone="neutral">{t('diagnostics.ping.cancelled')}</Badge>
              </div>
            ) : null}
          </dl>
        ) : null}
      </CardContent>
    </Card>
  )
}

function MtuProbeCard({ tunnel }: { tunnel: Tunnel }) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const probeMutation = useMutation({
    mutationFn: () => api.post<MtuProbeResponse>(`/tunnels/${tunnel.tunnel_id}/diagnostics/mtu-probe`, {}),
  })

  const applyMutation = useMutation({
    mutationFn: (mtu: number) => api.patch(`/tunnels/${tunnel.tunnel_id}`, { mtu }),
    onSuccess: async (_data, mtu) => {
      await queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      toast({ tone: 'success', title: t('diagnostics.mtu.applied', { value: mtu }) })
    },
    onError: () => toast({ tone: 'error', title: t('errors.title') }),
  })

  const result = probeMutation.data?.result

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Ruler className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('diagnostics.mtu.title')}
        </CardTitle>
        <Button variant="secondary" size="sm" loading={probeMutation.isPending} onClick={() => probeMutation.mutate()}>
          {probeMutation.isPending ? t('diagnostics.mtu.running') : t('diagnostics.mtu.run')}
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground">{t('diagnostics.mtu.subtitle')}</p>

        {probeMutation.error ? (
          <ErrorState error={probeMutation.error} onRetry={() => probeMutation.mutate()} compact />
        ) : !result ? (
          <p className="text-xs text-muted-foreground">{t('diagnostics.mtu.empty')}</p>
        ) : (
          <>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-2xs">
              <Figure label={t('diagnostics.mtu.discovered')} value={String(result.discovered_path_mtu)} />
              <Figure label={t('diagnostics.mtu.recommended')} value={String(result.recommended_tunnel_mtu)} />
              <Figure label={t('diagnostics.mtu.current')} value={String(result.current_tunnel_mtu)} />
              <Figure label={t('diagnostics.mtu.overhead')} value={String(result.overhead)} />
            </dl>

            {result.matches ? (
              <p className="flex items-center gap-1.5 text-xs text-ok">
                <CheckCircle2 className="size-3.5" aria-hidden="true" />
                {t('diagnostics.mtu.matches')}
              </p>
            ) : (
              <div className="flex flex-wrap items-center gap-2">
                <p className="flex items-center gap-1.5 text-xs text-warn">
                  <AlertTriangle className="size-3.5" aria-hidden="true" />
                  {t('diagnostics.mtu.mismatch')}
                </p>
                <Button
                  size="sm"
                  variant="primary"
                  loading={applyMutation.isPending}
                  onClick={() => applyMutation.mutate(result.recommended_tunnel_mtu)}
                >
                  {t('diagnostics.mtu.applyRecommended', { value: result.recommended_tunnel_mtu })}
                </Button>
              </div>
            )}

            <details className="text-2xs">
              <summary className="cursor-pointer text-muted-foreground">{t('diagnostics.mtu.steps')}</summary>
              <ul className="mt-1.5 space-y-0.5">
                {(result.steps ?? []).map((step, index) => (
                  <li key={`${step.packet_size}-${index}`} className="flex items-center gap-2">
                    <Technical className="w-12 text-2xs">{step.packet_size}</Technical>
                    <span className={step.fits ? 'text-ok' : 'text-danger'}>
                      {step.fits ? t('diagnostics.mtu.stepFits') : t('diagnostics.mtu.stepBlocked')}
                    </span>
                    {step.detail ? <span className="text-muted-foreground">· {step.detail}</span> : null}
                  </li>
                ))}
              </ul>
            </details>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function TracerouteCard({ tunnel }: { tunnel: Tunnel }) {
  const { t } = useTranslation()
  const { digits } = usePreferences()

  const traceMutation = useMutation({
    mutationFn: () =>
      api.post<{ result: TracerouteResult; run?: DiagnosticRun }>(
        `/tunnels/${tunnel.tunnel_id}/diagnostics/traceroute`,
        {},
      ),
  })

  const result = traceMutation.data?.result

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Waypoints className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('diagnostics.traceroute.title')}
        </CardTitle>
        <Button variant="secondary" size="sm" loading={traceMutation.isPending} onClick={() => traceMutation.mutate()}>
          {traceMutation.isPending ? t('diagnostics.traceroute.running') : t('diagnostics.traceroute.run')}
        </Button>
      </CardHeader>
      <CardContent className="space-y-2">
        {traceMutation.error ? (
          <ErrorState error={traceMutation.error} onRetry={() => traceMutation.mutate()} compact />
        ) : !result ? (
          <p className="text-xs text-muted-foreground">{t('diagnostics.traceroute.empty')}</p>
        ) : (
          <>
            <p className="text-xs">{result.detail}</p>
            <ol className="space-y-1">
              {(result.hops ?? []).map((hop) => (
                <li key={hop.ttl} className="flex items-baseline gap-2 text-2xs">
                  <Technical className="w-6 shrink-0 text-muted-foreground">{hop.ttl}</Technical>
                  {hop.timeout ? (
                    <span className="text-muted-foreground">{t('diagnostics.traceroute.timeout')}</span>
                  ) : (
                    <>
                      <Technical>{(hop.addresses ?? []).join(', ')}</Technical>
                      <span className="tabular text-muted-foreground">
                        {(hop.rtts_ms ?? []).map((rtt) => formatMs(rtt, digits)).join(' · ')}
                      </span>
                    </>
                  )}
                </li>
              ))}
            </ol>
          </>
        )}
      </CardContent>
    </Card>
  )
}

export function DiagnosticRuns({ tunnelId }: { tunnelId: number }) {
  const { t } = useTranslation()
  const { calendar, digits, language } = usePreferences()

  const runsQuery = useQuery({
    queryKey: ['diagnostics', 'runs', tunnelId],
    queryFn: () => api.get<{ runs: DiagnosticRun[]; total: number }>('/diagnostics/runs', {
      query: { tunnel_id: tunnelId, limit: 10 },
    }),
    staleTime: 15_000,
  })

  if (runsQuery.isLoading) return <Skeleton className="h-24" />
  if (runsQuery.error) return <ErrorState error={runsQuery.error} onRetry={() => void runsQuery.refetch()} compact />

  const runs = runsQuery.data?.runs ?? []
  if (!runs.length) return <EmptyState title={t('diagnostics.runs.empty')} />

  return (
    <ul className="divide-y divide-border rounded-md border border-border">
      {runs.map((run) => (
        <li key={run.diagnostic_run_id} className="flex items-center justify-between gap-3 p-2 text-xs">
          <span className="flex items-center gap-2">
            {run.running ? (
              <Badge tone="accent">{t('states.loading')}</Badge>
            ) : run.is_success ? (
              <CheckCircle2 className="size-3.5 text-ok" aria-hidden="true" />
            ) : (
              <XCircle className="size-3.5 text-danger" aria-hidden="true" />
            )}
            <Technical className="text-xs">{run.type}</Technical>
          </span>
          <TimeLabel iso={run.started_date} locale={language} calendar={calendar} digits={digits} />
        </li>
      ))}
    </ul>
  )
}

function TimeLabel({
  iso,
  locale,
  calendar,
  digits,
}: {
  iso: string
  locale: string
  calendar: 'gregorian' | 'jalali'
  digits: 'latin' | 'persian'
}) {
  const formatted = new Date(iso)
  if (Number.isNaN(formatted.getTime())) return null
  return (
    <span className="text-2xs text-muted-foreground">
      {new Intl.DateTimeFormat(
        `${locale}-u-ca-${calendar === 'jalali' ? 'persian' : 'gregory'}-nu-${digits === 'persian' ? 'arabext' : 'latn'}`,
        { dateStyle: 'short', timeStyle: 'short' },
      ).format(formatted)}
    </span>
  )
}

function Figure({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>
        <Technical className="text-2xs font-medium">{value}</Technical>
      </dd>
    </div>
  )
}

export { TechnicalBlock }
