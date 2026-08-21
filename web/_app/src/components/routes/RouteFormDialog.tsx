import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Loader2, Plus, X } from 'lucide-react'

import { ApiError, api } from '@/lib/api'
import {
  LoadBalanceMode,
  NatMode,
  RouteMonitorMode,
  RouteProtocol,
  type HostInterface,
  type InterfacesResponse,
  type RouteListResponse,
  type RouteDestination,
  type RouteReachabilityResult,
  type RoutePreviewResponse,
  type RouteResultResponse,
  type RouteRule,
  type SettingsResponse,
  type SourceListsResponse,
  type TunnelListResponse,
  type TunnelRoutesResponse,
} from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
import {
  QuotaDraftFields,
  applyQuotaDrafts,
  draftFromStatus,
  emptyQuotaDraft,
  destinationQuota,
  ruleQuota,
  useQuotaStatuses,
  type QuotaDraft,
} from '../quota/TrafficLimit'
import { usePreferences } from '@/providers/PreferencesProvider'
import { formatMs, hasDisplayName, tunnelLabel } from '@/lib/format'
import { describeError } from '../ui/feedback'
import { routeVerificationFailures, routeVerificationPassed } from '@/hooks/useRouteActions'
import { Button } from '../ui/button'
import { Checkbox, Field, Input, Select, SwitchField, TechnicalInput } from '../ui/form'
import { DisclosurePanel } from '../ui/disclosure'
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../ui/overlay'
import { Badge } from '../ui/feedback'
import { Technical } from '../ui/technical'
import { RoutePreviewPanel } from './RoutePreviewPanel'
import { useDebounced } from '@/hooks/useDebounced'
import { cn } from '@/lib/utils'

/** The form's own shape: every field the operator can set, none nullable-by-absence. */
interface FormState {
  route_rule_title: string
  description: string
  route_protocol_id: number
  bind_address: string
  bind_port: string
  bind_port_range_end: string
  bind_interface: string
  destination_address: string
  destination_port: string
  destination_port_range_end: string
  nat_mode_id: number
  snat_address: string
  load_balance_mode_id: number
  tunnel_id: number | null
  is_clamp_mss_to_pmtu: boolean
  is_include_local_originated: boolean
  is_logging_enabled: boolean
  fwmark: string
  max_connections_per_source: string
  connection_rate_limit: string
  is_enabled: boolean
  /** The weight of the primary destination, which leads the list. */
  destination_weight: string
  /** The primary destination's own monitor port, when it needs one. */
  destination_monitor_port: string
  /** The shared address lists this rule allows, by identifier. */
  source_list_ids: number[]
  /** What this dialog does not edit about the primary destination. */
  destination_carried?: CarriedDestination
  destinations: {
    address: string
    port: string
    weight: string
    monitor_port: string
    carried?: CarriedDestination
  }[]

  // Monitoring. Empty means inherit, which is how a rule that has never
  // been given a policy keeps following the panel's.
  is_monitor_enabled: boolean
  monitor_mode_id: number
  monitor_interval_seconds: string
  monitor_timeout_seconds: string
  monitor_failure_threshold: string
  monitor_recovery_threshold: string
  allowed_sources: string[]
}

/**
 * The parts of a destination this dialog does not edit, carried through it.
 *
 * Saving a rule rewrites its whole destination list, so anything this form does
 * not send is a thing this form deletes. Taking a destination out of rotation
 * and setting its monitoring both happen on the rule's own page rather than
 * here, and neither should survive only until the next time somebody corrects
 * a title.
 */
type CarriedDestination = {
  is_enabled: boolean
  is_monitor_enabled: boolean | null
  monitor_interval_seconds: number | null
  monitor_timeout_seconds: number | null
  monitor_failure_threshold: number | null
  monitor_recovery_threshold: number | null
}

function carriedFrom(destination: RouteDestination | undefined): CarriedDestination | undefined {
  if (!destination) return undefined
  return {
    is_enabled: destination.is_enabled,
    is_monitor_enabled: destination.is_monitor_enabled ?? null,
    monitor_interval_seconds: destination.monitor_interval_seconds ?? null,
    monitor_timeout_seconds: destination.monitor_timeout_seconds ?? null,
    monitor_failure_threshold: destination.monitor_failure_threshold ?? null,
    monitor_recovery_threshold: destination.monitor_recovery_threshold ?? null,
  }
}

export function RouteFormDialog({
  open,
  onOpenChange,
  route,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Present when editing; absent when creating. */
  route?: RouteRule
  onCreated?: (created: RouteRule) => void
}) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { digits } = usePreferences()
  const queryClient = useQueryClient()

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<SettingsResponse>('/settings'),
    staleTime: 60_000,
  })
  const tunnelsQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 60_000,
    enabled: open,
  })
  const interfacesQuery = useQuery({
    queryKey: ['system', 'interfaces'],
    queryFn: () => api.get<InterfacesResponse>('/system/interfaces'),
    staleTime: 60_000,
    enabled: open,
  })
  // Every other rule, for the port-conflict check as you type.
  const routesQuery = useQuery({
    queryKey: ['routes', 'list'],
    queryFn: () => api.get<RouteListResponse>('/routes'),
    staleTime: 10_000,
    enabled: open,
  })

  const [form, setForm] = useState<FormState | null>(null)
  const [destinationMode, setDestinationMode] = useState<'manual' | 'tunnel'>('manual')
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [submitError, setSubmitError] = useState<string | null>(null)
  const errorRef = useRef<HTMLDivElement | null>(null)
  const [force, setForce] = useState(false)
  const [allowlistDraft, setAllowlistDraft] = useState('')
  // Traffic limits ride beside the rule rather than inside it: they are saved
  // through their own endpoint after the rule itself lands, which is what lets
  // the create dialog carry a limit for a rule that does not exist yet.
  // Keyed 'rule' or 'address:port'.
  const [quotaDrafts, setQuotaDrafts] = useState<Record<string, QuotaDraft>>({})
  const quotaStatuses = useQuotaStatuses(open)

  // Seeded once per opening, from the rule being edited or from the routes.*
  // settings the backend already resolves defaults from.
  useEffect(() => {
    if (!open) {
      setForm(null)
      setFieldErrors({})
      setSubmitError(null)
      setForce(false)
      setAllowlistDraft('')
      return
    }
    if (form) return
    if (route) {
      setForm(formFromRoute(route, settingsQuery.data?.settings['routes.monitor_enabled'] === true))
      setDestinationMode(route.tunnel_id ? 'tunnel' : 'manual')
    } else if (settingsQuery.isSuccess) {
      setForm(defaultsFrom(settingsQuery.data.settings))
      setDestinationMode('manual')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, route, settingsQuery.isSuccess])

  // The drafts start from what is already set, once per opening.
  useEffect(() => {
    if (!open) {
      setQuotaDrafts({})
      return
    }
    if (!route || !quotaStatuses.data) return
    const seeded: Record<string, QuotaDraft> = {
      rule: draftFromStatus(ruleQuota(quotaStatuses.data, route.route_rule_id)),
    }
    for (const destination of route.destinations ?? []) {
      const key = `${destination.address}:${destination.port}`
      seeded[key] = draftFromStatus(
        destinationQuota(quotaStatuses.data, route.route_rule_id, destination.address, destination.port),
      )
    }
    setQuotaDrafts((current) => (Object.keys(current).length ? current : seeded))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, route?.route_rule_id, quotaStatuses.data])

  const patch = useMemo(() => (form ? toPatch(form) : null), [form])
  // Debounced so typing a port does not fire a preview per keystroke.
  const debouncedPatch = useDebounced(patch, 400)

  const ready = Boolean(
    form?.route_rule_title && form?.bind_port && form?.destination_address && form?.destination_port,
  )

  const previewQuery = useQuery({
    queryKey: ['routes', 'preview', debouncedPatch],
    queryFn: () =>
      api.post<RoutePreviewResponse>('/routes/preview', {
        ...debouncedPatch,
        ...(route ? { route_rule_id: route.route_rule_id } : {}),
      }),
    enabled: open && Boolean(debouncedPatch) && ready,
    retry: false,
    staleTime: 0,
  })

  const submitMutation = useMutation({
    mutationFn: async () => {
      const body = { ...patch, force: force || undefined }
      return route
        ? api.patch<RouteResultResponse>(`/routes/${route.route_rule_id}`, body)
        : api.post<RouteResultResponse>('/routes', body)
    },
    // Whatever the outcome. A create that stores the rule and then fails to
    // install it leaves it listed and marked Inconsistent, and that is the one
    // rule the operator most needs to see: it is already holding the port.
    // Refreshing only on success left the page showing "No forwarding rules"
    // while the rule existed, so the obvious next move — try again — ran
    // straight into a conflict with something the page was not showing.
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ['routes'] })
      await queryClient.invalidateQueries({ queryKey: ['forwarding'] })
    },
    onSuccess: async (result) => {
      // Success is reported only once the backend's read-back agrees.
      if (!routeVerificationPassed(result.verification)) {
        const detail = routeVerificationFailures(result.verification).join(' · ')
        toast({
          tone: 'error',
          title: route ? t('routeForm.updatedTitle') : t('routeForm.createdTitle'),
          description: detail,
        })
        setSubmitError(detail)
        return
      }

      // The rule is in; now its traffic limits. A failure here must not read
      // as the rule failing — the rule saved — so it gets its own message.
      try {
        await saveQuotaDrafts(result.route)
      } catch (quotaError) {
        toast({
          tone: 'error',
          title: t('quota.title'),
          description: describeError(quotaError, t).message,
        })
      }

      toast({
        tone: 'success',
        title: route ? t('routeForm.updatedTitle') : t('routeForm.createdTitle'),
        description: t('routeForm.createdBody', { name: result.route.route_rule_title }),
      })
      onOpenChange(false)
      if (!route) onCreated?.(result.route)
    },
    onError: (error) => {
      // The banner is shown for every failure, field errors or not. Suppressing
      // it whenever the backend named a field assumed those fields were on
      // screen — but this form scrolls, the name and port sit at the top of it,
      // and the submit button is in the footer. An operator who had scrolled
      // down to the NAT section saw a rejected submission as nothing happening
      // at all.
      setFieldErrors(error instanceof ApiError ? error.fieldErrors : {})
      setSubmitError(describeError(error, t).message)
    },
  })

  // Every non-empty draft is written, and an emptied one removes the limit it
  // replaced. Keys are address:port, which is also how the backend stores
  // destination limits — so a renamed destination simply starts unlimited.
  async function saveQuotaDrafts(saved: RouteRule) {
    const entries = Object.entries(quotaDrafts).map(([key, draft]) => {
      if (key === 'rule') {
        return {
          subject: { scope: 'rule' as const, route_rule_id: saved.route_rule_id },
          draft,
          existing: ruleQuota(quotaStatuses.data, saved.route_rule_id),
        }
      }
      const at = key.lastIndexOf(':')
      const address = key.slice(0, at)
      const port = Number(key.slice(at + 1))
      return {
        subject: { scope: 'destination' as const, route_rule_id: saved.route_rule_id, address, port },
        draft,
        existing: destinationQuota(quotaStatuses.data, saved.route_rule_id, address, port),
      }
    })
    await applyQuotaDrafts(entries)
    await queryClient.invalidateQueries({ queryKey: ['quota'] })
  }

  // Bring the failure into view and put the cursor on the first field the
  // backend objected to, so the answer finds the operator rather than waiting
  // to be scrolled to. The offending controls are already marked aria-invalid
  // by Field, so the first one in document order is the topmost one.
  useEffect(() => {
    if (!submitError) return
    errorRef.current?.scrollIntoView?.({ block: 'nearest' })
    const dialog = errorRef.current?.closest('[role="dialog"]') ?? document
    dialog.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus?.()
  }, [submitError, fieldErrors])

  if (!form) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>
              {route ? t('routeForm.editTitle', { name: route.route_rule_title }) : t('routeForm.createTitle')}
            </DialogTitle>
          </DialogHeader>
          <DialogBody>
            <p className="text-sm text-muted-foreground">{t('states.loading')}</p>
          </DialogBody>
        </DialogContent>
      </Dialog>
    )
  }

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((current) => (current ? { ...current, [key]: value } : current))

  const defaultClampMss = settingsQuery.data?.settings['routes.default_clamp_mss'] !== false
  const tunnels = tunnelsQuery.data?.tunnels ?? []
  const interfaces = (interfacesQuery.data?.interfaces ?? []).filter(
    (iface: HostInterface) => !iface.name.startsWith('lo'),
  )
  const warnings = previewQuery.data?.warnings ?? []
  const bindsAny = isAny(form.bind_address)

  // The backend's own conflict rules, mirrored here so the answer arrives as
  // the operator types rather than when they submit (§12.2).
  const conflict = findConflict(form, route?.route_rule_id, routesQuery.data)

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>
            {route ? t('routeForm.editTitle', { name: route.route_rule_title }) : t('routeForm.createTitle')}
          </DialogTitle>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {submitError ? (
            <div
              ref={errorRef}
              data-testid="route-form-error"
              className="rounded-md border border-danger/30 bg-danger-muted px-3 py-2 text-xs text-danger"
              role="alert"
            >
              <p>{submitError}</p>
              {/* The per-field messages are repeated here as well as against
                  their fields. Each one names the rule it collides with, and
                  the field it belongs to may be scrolled well out of sight. */}
              {Object.keys(fieldErrors).length ? (
                <ul className="mt-1 list-disc space-y-0.5 ps-4">
                  {Object.entries(fieldErrors).map(([field, message]) => (
                    <li key={field}>{message}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}

          {/* 1 — Name. First, because it is how the operator will recognise
              this rule in a list of twenty. */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('routeForm.sectionName')}
            </h3>
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-64 flex-1">
                <Field
                  label={t('routeForm.fields.title')}
                  description={t('routeForm.help.title')}
                  error={fieldErrors['route_rule_title']}
                  required
                >
                  {(props) => (
                    <Input
                      {...props}
                      autoFocus
                      value={form.route_rule_title}
                      onChange={(event) => set('route_rule_title', event.target.value)}
                      placeholder={t('routeForm.fields.title')}
                    />
                  )}
                </Field>
              </div>
              {/* On/off is a status, not an advanced option, so it stands with
                  the name rather than at the bottom of a collapsed panel. */}
              <div className="pb-5">
                <SwitchField
                  label={t('routeForm.fields.enabled')}
                  checked={form.is_enabled}
                  onCheckedChange={(value) => set('is_enabled', value)}
                />
              </div>
            </div>
          </section>

          {/* 2 — Source */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('routeForm.sectionSource')}
            </h3>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Field
                label={t('routeForm.fields.bindAddress')}
                description={bindsAny ? t('routeForm.help.bindAny') : t('routeForm.help.bindAddress')}
                error={fieldErrors['bind_address']}
                className="lg:col-span-2"
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    value={form.bind_address}
                    onChange={(event) => set('bind_address', event.target.value)}
                    placeholder={t('routeForm.help.bindAddress')}
                  />
                )}
              </Field>
              <Field
                label={t('routeForm.fields.bindPort')}
                description={t('routeForm.help.bindPort')}
                error={fieldErrors['bind_port']}
                required
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={form.bind_port}
                    onChange={(event) => set('bind_port', event.target.value)}
                    placeholder="2044"
                  />
                )}
              </Field>
              <Field label={t('routeForm.fields.protocol')} error={fieldErrors['route_protocol_id']}>
                {(props) => (
                  <Select
                    id={props.id}
                    value={String(form.route_protocol_id)}
                    onValueChange={(value) => set('route_protocol_id', Number(value))}
                    options={Object.values(RouteProtocol).map((id) => ({
                      value: String(id),
                      label: t(`routes.protocol.${id}`),
                    }))}
                  />
                )}
              </Field>
            </div>

            <ConflictNotice conflict={conflict} />
          </section>

          {/* 3 — Destination, manual or through a tunnel */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('routeForm.sectionDestination')}
            </h3>

            <div className="inline-flex rounded-full border border-border/60 bg-surface-sunken p-0.5 text-2xs">
              {(
                [
                  ['manual', 'routeForm.destination.manual'],
                  ['tunnel', 'routeForm.destination.tunnel'],
                ] as const
              ).map(([value, labelKey]) => (
                <button
                  key={value}
                  type="button"
                  aria-pressed={destinationMode === value}
                  onClick={() => {
                    setDestinationMode(value)
                    if (value === 'manual') set('tunnel_id', null)
                  }}
                  className={
                    destinationMode === value
                      ? 'rounded-full bg-ink px-2.5 py-1 font-medium text-ink-foreground shadow-sm'
                      : 'rounded-full px-2.5 py-1 text-muted-foreground hover:text-foreground'
                  }
                >
                  {t(labelKey)}
                </button>
              ))}
            </div>

            {destinationMode === 'tunnel' ? (
              <TunnelDestination
                tunnels={tunnels}
                tunnelId={form.tunnel_id}
                onPick={(tunnelId, peer) => {
                  setForm((current) =>
                    current
                      ? {
                          ...current,
                          tunnel_id: tunnelId,
                          destination_address: peer || current.destination_address,
                          // A rule that relays over a tunnel gets MSS clamping
                          // by default, because that is exactly the case where
                          // its absence makes connections establish and then
                          // stall. The backend defaults it the same way from
                          // the same setting; doing it here too means the
                          // switch on screen agrees with what will be stored.
                          is_clamp_mss_to_pmtu: current.is_clamp_mss_to_pmtu || defaultClampMss,
                        }
                      : current,
                  )
                }}
              />
            ) : null}

            {/* One destination by default, and the same row repeated for the
                rest. Adding one used to mean setting the first here and the
                second in a different section, which read as two unrelated
                things rather than as a list. */}
            <DestinationList
              form={form}
              set={set}
              fieldErrors={fieldErrors}
              digits={digits}
            />
          </section>

          {/* 4 — Monitoring the destinations above */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('routeForm.sectionMonitoring')}
            </h3>
            <SwitchField
              label={t('routeForm.fields.monitorEnabled')}
              description={t('routeForm.help.monitorEnabled')}
              checked={form.is_monitor_enabled}
              onCheckedChange={(value) => set('is_monitor_enabled', value)}
            />

            {form.is_monitor_enabled ? (
              <>
                <Field
                  label={t('routeForm.fields.monitorMode')}
                  description={t(`routeForm.help.monitorMode.${form.monitor_mode_id}`)}
                >
                  {(props) => (
                    <Select
                      id={props.id}
                      value={String(form.monitor_mode_id)}
                      onValueChange={(value) => set('monitor_mode_id', Number(value))}
                      options={Object.values(RouteMonitorMode).map((id) => ({
                        value: String(id),
                        label: t(`routes.monitorMode.${id}`),
                      }))}
                    />
                  )}
                </Field>

                {/* Every one of these is optional: an empty box inherits the
                    panel-wide setting, which is what most rules want. */}
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  <Field label={t('routeForm.fields.monitorInterval')}>
                    {(props) => (
                      <TechnicalInput
                        {...props}
                        inputMode="numeric"
                        value={form.monitor_interval_seconds}
                        onChange={(event) => set('monitor_interval_seconds', event.target.value)}
                        placeholder={t('routeForm.inherited')}
                      />
                    )}
                  </Field>
                  <Field label={t('routeForm.fields.monitorTimeout')}>
                    {(props) => (
                      <TechnicalInput
                        {...props}
                        inputMode="numeric"
                        value={form.monitor_timeout_seconds}
                        onChange={(event) => set('monitor_timeout_seconds', event.target.value)}
                        placeholder={t('routeForm.inherited')}
                      />
                    )}
                  </Field>
                  <Field label={t('routeForm.fields.monitorFailures')}>
                    {(props) => (
                      <TechnicalInput
                        {...props}
                        inputMode="numeric"
                        value={form.monitor_failure_threshold}
                        onChange={(event) => set('monitor_failure_threshold', event.target.value)}
                        placeholder={t('routeForm.inherited')}
                      />
                    )}
                  </Field>
                  <Field
                    label={t('routeForm.fields.monitorRecoveries')}
                    description={t('routeForm.help.monitorRecoveries')}
                  >
                    {(props) => (
                      <TechnicalInput
                        {...props}
                        inputMode="numeric"
                        value={form.monitor_recovery_threshold}
                        onChange={(event) => set('monitor_recovery_threshold', event.target.value)}
                        placeholder={t('routeForm.inherited')}
                      />
                    )}
                  </Field>
                </div>

                {form.route_protocol_id !== RouteProtocol.TCP ? (
                  <p className="text-2xs text-muted-foreground">
                    {t('routeForm.help.monitorUdp')}
                  </p>
                ) : null}
              </>
            ) : null}
          </section>

          {/* 5 — NAT mode, in plain language rather than raw terminology */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('routeForm.sectionNat')}
            </h3>
            <fieldset className="space-y-2">
              <legend className="mb-1 text-xs text-muted-foreground">{t('routeForm.nat.legend')}</legend>
              {(
                [
                  [NatMode.Masquerade, 'masquerade'],
                  [NatMode.Snat, 'snat'],
                  [NatMode.None, 'none'],
                ] as const
              ).map(([id, key]) => (
                <label
                  key={id}
                  className={cnRadio(form.nat_mode_id === id)}
                >
                  <input
                    type="radio"
                    name="nat_mode"
                    className="mt-0.5"
                    checked={form.nat_mode_id === id}
                    onChange={() => set('nat_mode_id', id)}
                  />
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">{t(`routeForm.nat.${key}.label`)}</span>
                    <span className="block text-xs text-muted-foreground">{t(`routeForm.nat.${key}.body`)}</span>
                  </span>
                </label>
              ))}
            </fieldset>

            {form.nat_mode_id === NatMode.Snat ? (
              <Field
                label={t('routeForm.fields.snatAddress')}
                description={t('routeForm.help.snatAddress')}
                error={fieldErrors['snat_address']}
                required
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    value={form.snat_address}
                    onChange={(event) => set('snat_address', event.target.value)}
                    placeholder="203.0.113.10"
                  />
                )}
              </Field>
            ) : null}
          </section>

          {/* 5 — Advanced, collapsed */}
          <DisclosurePanel title={t('routeForm.sectionAdvanced')} contentClassName="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <Field
                label={t('routeForm.fields.bindPortRangeEnd')}
                description={t('routeForm.help.portRange')}
                error={fieldErrors['bind_port_range_end']}
                className="sm:col-span-2"
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={form.bind_port_range_end}
                    onChange={(event) => set('bind_port_range_end', event.target.value)}
                    placeholder="20100"
                  />
                )}
              </Field>
              <Field
                label={t('routeForm.fields.destinationPortRangeEnd')}
                description={
                  form.destinations.length ? t('routeForm.help.rangeNotBalanced') : undefined
                }
                error={fieldErrors['destination_port_range_end']}
                className="sm:col-span-2"
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    disabled={form.destinations.length > 0}
                    value={form.destinations.length ? '' : form.destination_port_range_end}
                    onChange={(event) => set('destination_port_range_end', event.target.value)}
                    placeholder="30100"
                  />
                )}
              </Field>

              <Field
                label={t('routeForm.fields.bindInterface')}
                description={t('routeForm.help.bindInterface')}
                error={fieldErrors['bind_interface']}
                className="sm:col-span-2"
              >
                {(props) => (
                  <Select
                    id={props.id}
                    value={form.bind_interface || 'any'}
                    onValueChange={(value) => set('bind_interface', value === 'any' ? '' : value)}
                    options={[
                      { value: 'any', label: t('routes.filter.all') },
                      ...interfaces.map((iface) => ({ value: iface.name, label: iface.name })),
                    ]}
                  />
                )}
              </Field>

              <Field
                label={t('routeForm.fields.fwmark')}
                description={t('routeForm.help.fwmark')}
                error={fieldErrors['fwmark']}
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={form.fwmark}
                    onChange={(event) => set('fwmark', event.target.value)}
                    placeholder="100"
                  />
                )}
              </Field>

              <Field
                label={t('routeForm.fields.maxConnectionsPerSource')}
                description={t('routeForm.help.maxConnectionsPerSource')}
                error={fieldErrors['max_connections_per_source']}
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={form.max_connections_per_source}
                    onChange={(event) => set('max_connections_per_source', event.target.value)}
                  />
                )}
              </Field>

              <Field
                label={t('routeForm.fields.connectionRateLimit')}
                description={t('routeForm.help.connectionRateLimit')}
                error={fieldErrors['connection_rate_limit']}
                className="sm:col-span-2"
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={form.connection_rate_limit}
                    onChange={(event) => set('connection_rate_limit', event.target.value)}
                  />
                )}
              </Field>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <SwitchField
                label={t('routeForm.fields.clampMss')}
                description={
                  form.tunnel_id ? t('routeForm.help.clampMssTunnel') : t('routeForm.help.clampMss')
                }
                checked={form.is_clamp_mss_to_pmtu}
                onCheckedChange={(value) => set('is_clamp_mss_to_pmtu', value)}
              />
              <SwitchField
                label={t('routeForm.fields.includeLocalOriginated')}
                description={t('routeForm.help.includeLocalOriginated')}
                checked={form.is_include_local_originated}
                onCheckedChange={(value) => set('is_include_local_originated', value)}
              />
              <SwitchField
                label={t('routeForm.fields.logging')}
                description={t('routeForm.help.logging')}
                checked={form.is_logging_enabled}
                onCheckedChange={(value) => set('is_logging_enabled', value)}
              />
            </div>

            <SourcesField
              lists={form.source_list_ids}
              onListsChange={(ids) => set('source_list_ids', ids)}
              addresses={form.allowed_sources}
              onAddressesChange={(entries) => set('allowed_sources', entries)}
              draft={allowlistDraft}
              onDraftChange={setAllowlistDraft}
              error={fieldErrors['allowed_sources']}
            />
          </DisclosurePanel>

          {/* Traffic limits, for the whole rule and for each destination.
              They save through their own endpoint after the rule does, so the
              same section works in the create dialog. */}
          <DisclosurePanel title={t('routeForm.sectionTraffic')} contentClassName="space-y-3">
            <p className="text-2xs text-muted-foreground">{t('routeForm.help.traffic')}</p>
            <QuotaDraftFields
              label={t('routeForm.quota.rule')}
              draft={quotaDrafts.rule ?? emptyQuotaDraft()}
              onChange={(draft) => setQuotaDrafts((current) => ({ ...current, rule: draft }))}
            />
            {[
              { address: form.destination_address, port: form.destination_port },
              ...form.destinations.map((destination) => ({
                address: destination.address,
                port: destination.port,
              })),
            ]
              .filter((destination) => destination.address && destination.port)
              .map((destination) => {
                const key = `${destination.address}:${destination.port}`
                return (
                  <QuotaDraftFields
                    key={key}
                    label={key}
                    draft={quotaDrafts[key] ?? emptyQuotaDraft()}
                    onChange={(draft) => setQuotaDrafts((current) => ({ ...current, [key]: draft }))}
                  />
                )
              })}
          </DisclosurePanel>

          {/* 6 — Preview: the exact ruleset, before anything is applied */}
          <RoutePreviewPanel
            preview={previewQuery.data}
            isLoading={previewQuery.isFetching}
            error={previewQuery.error}
            onRetry={() => void previewQuery.refetch()}
            defaultOpen={!route}
            ready={ready}
          />

          {warnings.length ? (
            <div className="space-y-2 rounded-md border border-warn/40 bg-warn-muted p-3">
              {warnings.map((warning) => (
                <p key={warning.code} className="flex items-start gap-2 text-xs">
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
                  {warning.message}
                </p>
              ))}
              <label className="flex items-center gap-2 pt-1 text-xs font-medium">
                <Checkbox checked={force} onCheckedChange={(value) => setForce(value === true)} />
                {t('routeForm.force')}
              </label>
              <p className="text-2xs text-muted-foreground">{t('routeForm.forceHint')}</p>
            </div>
          ) : null}
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={submitMutation.isPending}
            onClick={() => submitMutation.mutate()}
          >
            {submitMutation.isPending
              ? t('routeForm.applying')
              : route
                ? t('routeForm.submitEdit')
                : t('routeForm.submitCreate')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function cnRadio(active: boolean): string {
  return [
    'flex cursor-pointer items-start gap-2 rounded-md border p-3 transition-colors',
    active ? 'border-accent bg-accent-muted' : 'border-border hover:bg-muted',
  ].join(' ')
}

/** "Through a tunnel": pick one, and the destination prefills with its peer. */
function TunnelDestination({
  tunnels,
  tunnelId,
  onPick,
}: {
  tunnels: TunnelListResponse['tunnels']
  tunnelId: number | null
  onPick: (tunnelId: number, peerAddress: string) => void
}) {
  const { t } = useTranslation()

  // The peer address is what the backend derives for prefilling, so it comes
  // from the backend rather than being recomputed from the address list here.
  const peerQuery = useQuery({
    queryKey: ['tunnels', tunnelId, 'routes'],
    queryFn: () => api.get<TunnelRoutesResponse>(`/tunnels/${tunnelId}/routes`),
    enabled: Boolean(tunnelId),
    staleTime: 60_000,
  })

  useEffect(() => {
    if (tunnelId && peerQuery.data?.peer_address) onPick(tunnelId, peerQuery.data.peer_address)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peerQuery.data?.peer_address])

  if (!tunnels.length) {
    return <p className="text-xs text-muted-foreground">{t('routeForm.destination.noTunnels')}</p>
  }

  const selected = tunnels.find((entry) => entry.tunnel.tunnel_id === tunnelId)
  const down = selected && !(selected.observed?.is_up && selected.observed?.is_lower_up)

  return (
    <div className="space-y-2">
      <Field label={t('routeForm.destination.pickTunnel')}>
        {(props) => (
          <Select
            id={props.id}
            value={tunnelId ? String(tunnelId) : ''}
            onValueChange={(value) => onPick(Number(value), '')}
            placeholder={t('routeForm.destination.pickTunnel')}
            options={tunnels.map((entry) => ({
              value: String(entry.tunnel.tunnel_id),
              // Named by what the operator called it; the interface name joins
              // the endpoints below, where it is still the thing that has to
              // match what `ip link` shows.
              label: tunnelLabel(entry.tunnel),
              description: hasDisplayName(entry.tunnel)
                ? `${entry.tunnel.interface_name} · ${entry.tunnel.local_endpoint} → ${entry.tunnel.remote_endpoint}`
                : `${entry.tunnel.local_endpoint} → ${entry.tunnel.remote_endpoint}`,
            }))}
          />
        )}
      </Field>
      {selected && peerQuery.data?.peer_address ? (
        <p className="text-2xs text-muted-foreground">
          {t('routeForm.destination.prefilled', { name: tunnelLabel(selected.tunnel) })}
        </p>
      ) : null}
      {down ? (
        <p className="flex items-start gap-2 text-2xs text-warn">
          <AlertTriangle className="mt-0.5 size-3 shrink-0" aria-hidden="true" />
          {t('routeForm.destination.tunnelDown', { name: tunnelLabel(selected.tunnel) })}
        </p>
      ) : null}
    </div>
  )
}



/**
 * Every destination of a rule, as one list.
 *
 * A rule has one destination by default and the row for it is the section: the
 * second is added to the same list rather than configured somewhere else, which
 * is what made "add a destination" read as two unrelated settings. The
 * distribution mode appears with the second destination, because with one there
 * is nothing to distribute and the control was a choice about nothing.
 */
function DestinationList({
  form,
  set,
  fieldErrors,
  digits,
}: {
  form: FormState
  set: <K extends keyof FormState>(key: K, value: FormState[K]) => void
  fieldErrors: Record<string, string>
  digits: 'latin' | 'persian'
}) {
  const { t } = useTranslation()

  const extras = form.destinations
  const multiple = extras.length > 0
  const weighted = multiple && form.load_balance_mode_id === LoadBalanceMode.Weighted

  const update = (index: number, patch: Partial<FormState['destinations'][number]>) =>
    set(
      'destinations',
      extras.map((entry, i) => (i === index ? { ...entry, ...patch } : entry)),
    )

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <DestinationRow
          position={1}
          numbered={multiple}
          address={form.destination_address}
          port={form.destination_port}
          weight={form.destination_weight}
          weighted={weighted}
          monitored={form.is_monitor_enabled}
          monitorPort={form.destination_monitor_port}
          onMonitorPortChange={(value) => set('destination_monitor_port', value)}
          protocol={form.route_protocol_id}
          digits={digits}
          labelled
          addressError={fieldErrors['destination_address']}
          portError={fieldErrors['destination_port']}
          onAddressChange={(value) => set('destination_address', value)}
          onPortChange={(value) => set('destination_port', value)}
          onWeightChange={(value) => set('destination_weight', value)}
        />

        {extras.map((destination, index) => (
          <DestinationRow
            key={index}
            position={index + 2}
            numbered
            address={destination.address}
            port={destination.port}
            weight={destination.weight}
            weighted={weighted}
            monitored={form.is_monitor_enabled}
            monitorPort={destination.monitor_port}
            onMonitorPortChange={(value) => update(index, { monitor_port: value })}
            protocol={form.route_protocol_id}
            digits={digits}
            onAddressChange={(value) => update(index, { address: value })}
            onPortChange={(value) => update(index, { port: value })}
            onWeightChange={(value) => update(index, { weight: value })}
            onRemove={() => {
              const left = extras.filter((_, i) => i !== index)
              set('destinations', left)
              // The mirror of adding one. A second destination moves the
              // control off "Single destination" because two are distributed
              // whatever it says; the last one leaving has to move it back,
              // or the rule reads as balanced across a single backend.
              if (!left.length) set('load_balance_mode_id', LoadBalanceMode.None)
            }}
          />
        ))}

        <p className="text-2xs text-muted-foreground">
          {t('routeForm.help.destinationAddress')}
        </p>

        {fieldErrors['destinations'] ? (
          <p className="text-2xs text-danger">{fieldErrors['destinations']}</p>
        ) : null}

        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={() => {
            set('destinations', [...extras, { address: '', port: '', weight: '1', monitor_port: '' }])
            // A second destination is distributed whatever the mode says:
            // the ruleset falls back to round robin rather than sending
            // everything to the first. Saying so beats leaving a control
            // reading "Single destination" over a list of two.
            if (form.load_balance_mode_id === LoadBalanceMode.None) {
              set('load_balance_mode_id', LoadBalanceMode.RoundRobin)
            }
          }}
        >
          <Plus className="size-4" aria-hidden="true" />
          {t('routeForm.destination.add')}
        </Button>
      </div>

      {multiple ? (
        <Field
          label={t('routeForm.fields.loadBalance')}
          description={t('routeForm.help.destinations')}
        >
          {(props) => (
            <Select
              id={props.id}
              value={String(
                form.load_balance_mode_id === LoadBalanceMode.None
                  ? LoadBalanceMode.RoundRobin
                  : form.load_balance_mode_id,
              )}
              onValueChange={(value) => set('load_balance_mode_id', Number(value))}
              // "Single destination" is not among them: the list it sits
              // over has more than one, and choosing it would not make the
              // kernel send everything to the first.
              options={Object.values(LoadBalanceMode)
                .filter((id) => id !== LoadBalanceMode.None)
                .map((id) => ({ value: String(id), label: t(`routes.loadBalance.${id}`) }))}
            />
          )}
        </Field>
      ) : null}
    </div>
  )
}

/**
 * One destination: an address, a port, a weight where the rule distributes by
 * weight, and the probe that says whether anything is listening there.
 *
 * The first row carries the labels and the rest are labelled for assistive
 * technology only: repeating "Destination address" down a list is noise to a
 * reader who can see the column it is already under.
 */
function DestinationRow({
  position,
  numbered,
  address,
  port,
  weight,
  weighted,
  monitored,
  monitorPort,
  onMonitorPortChange,
  protocol,
  digits,
  labelled,
  addressError,
  portError,
  onAddressChange,
  onPortChange,
  onWeightChange,
  onRemove,
}: {
  position: number
  /** Positions appear only once there is more than one to tell apart. */
  numbered: boolean
  address: string
  port: string
  weight: string
  weighted: boolean
  /** Whether the rule monitors at all, which is what the knock port is for. */
  monitored: boolean
  monitorPort: string
  onMonitorPortChange: (value: string) => void
  protocol: number
  digits: 'latin' | 'persian'
  labelled?: boolean
  addressError?: string
  portError?: string
  onAddressChange: (value: string) => void
  onPortChange: (value: string) => void
  onWeightChange: (value: string) => void
  onRemove?: () => void
}) {
  const { t } = useTranslation()
  const probe = useDestinationProbe(address, Number(port), protocol)
  const usable = Boolean(address) && Number.isFinite(Number(port)) && Number(port) > 0

  const addressLabel = t('routeForm.fields.destinationAddress')
  const portLabel = t('routeForm.fields.destinationPort')
  const weightLabel = t('routeForm.fields.weight')
  // The column is under a heading that already says Destination, and the
  // full label does not fit the width the port needs.
  const portColumn = t('routeForm.fields.port')

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-end gap-2">
        {numbered ? (
          <span className="w-16 shrink-0 pb-2.5 text-2xs text-muted-foreground">
            {t('routeDetail.destinations.order', { index: position })}
          </span>
        ) : null}

        <div className="min-w-40 flex-1">
          {labelled ? (
            <Field label={addressLabel} error={addressError} required>
              {(props) => (
                <TechnicalInput
                  {...props}
                  value={address}
                  onChange={(event) => onAddressChange(event.target.value)}
                  placeholder="198.51.100.20"
                />
              )}
            </Field>
          ) : (
            <TechnicalInput
              value={address}
              onChange={(event) => onAddressChange(event.target.value)}
              placeholder="198.51.100.21"
              aria-label={addressLabel}
            />
          )}
        </div>

        <div className="w-24 shrink-0">
          {labelled ? (
            <Field label={portColumn} error={portError} required>
              {(props) => (
                <TechnicalInput
                  {...props}
                  inputMode="numeric"
                  value={port}
                  onChange={(event) => onPortChange(event.target.value)}
                  placeholder="2044"
                />
              )}
            </Field>
          ) : (
            <TechnicalInput
              inputMode="numeric"
              value={port}
              onChange={(event) => onPortChange(event.target.value)}
              placeholder="2044"
              aria-label={portLabel}
            />
          )}
        </div>

        {weighted ? (
          <div className="w-20 shrink-0">
            {labelled ? (
              <Field label={weightLabel}>
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={weight}
                    onChange={(event) => onWeightChange(event.target.value)}
                    placeholder="1"
                  />
                )}
              </Field>
            ) : (
              <TechnicalInput
                inputMode="numeric"
                value={weight}
                onChange={(event) => onWeightChange(event.target.value)}
                placeholder="1"
                aria-label={weightLabel}
              />
            )}
          </div>
        ) : null}

        {monitored ? (
          <div className="w-24 shrink-0">
            {labelled ? (
              <Field label={t('routeForm.fields.monitorPort')}>
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={monitorPort}
                    onChange={(event) => onMonitorPortChange(event.target.value)}
                    placeholder={port || '2044'}
                  />
                )}
              </Field>
            ) : (
              <TechnicalInput
                inputMode="numeric"
                value={monitorPort}
                onChange={(event) => onMonitorPortChange(event.target.value)}
                placeholder={port || '2044'}
                aria-label={t('routeForm.fields.monitorPort')}
              />
            )}
          </div>
        ) : null}

        <Button
          type="button"
          variant="secondary"
          size="sm"
          disabled={!usable || probe.busy}
          onClick={() => void probe.run()}
        >
          {probe.busy ? <Loader2 className="size-4 animate-spin" aria-hidden="true" /> : null}
          {probe.busy ? t('routeForm.preflight.running') : t('routeForm.preflight.run')}
        </Button>

        {onRemove ? (
          <Button
            type="button"
            variant="ghost"
            size="iconSm"
            className="mb-1.5"
            onClick={onRemove}
            aria-label={t('routeForm.destination.remove')}
          >
            <X className="size-4" aria-hidden="true" />
          </Button>
        ) : numbered ? (
          // Only to hold the column open under the rows that can be
          // removed. With one destination there is nothing to line up with.
          <span className="size-7 shrink-0" aria-hidden="true" />
        ) : null}
      </div>

      {/* The probe's answer under the row it belongs to: a refusal explains
          itself in a sentence, and a sentence does not fit inside the row. */}
      {probe.result ? (
        <p
          role="status"
          className={
            probe.result.reachable
              ? 'flex items-start gap-1 text-2xs text-ok'
              : probe.result.conclusive
                ? 'flex items-start gap-1 text-2xs text-danger'
                : 'flex items-start gap-1 text-2xs text-muted-foreground'
          }
        >
          {probe.result.reachable ? (
            <Check className="mt-0.5 size-3 shrink-0" aria-hidden="true" />
          ) : null}
          {probe.result.reachable
            ? t('routeForm.preflight.reachable', {
                latency: formatMs(probe.result.latency_ms ?? 0, digits) ?? '',
              })
            : probe.result.detail}
        </p>
      ) : null}
    </div>
  )
}

/** The reachability probe, run from this server before the rule exists. */
function useDestinationProbe(address: string, port: number, protocol: number) {
  const [result, setResult] = useState<RouteReachabilityResult | null>(null)
  const [busy, setBusy] = useState(false)

  const run = async () => {
    setBusy(true)
    setResult(null)
    try {
      setResult(
        await api.post<RouteReachabilityResult>('/routes/diagnostics/test', {
          address,
          port,
          protocol: protocol === RouteProtocol.UDP ? 'udp' : 'tcp',
        }),
      )
    } catch {
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  return { result, busy, run }
}

/** The port-conflict answer, as you type. */
function ConflictNotice({ conflict }: { conflict: Conflict | null }) {
  const { t } = useTranslation()
  if (!conflict) return null

  return (
    <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-muted p-2 text-xs" role="status">
      <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
      <span>
        {t('routeForm.conflict.portTaken', {
          protocol: t(`routes.protocol.${conflict.protocolId}`),
          address: conflict.address,
          port: conflict.port,
        })}{' '}
        <Badge>{conflict.title}</Badge>
      </span>
    </p>
  )
}

interface Conflict {
  title: string
  protocolId: number
  address: string
  port: string
}

/**
 * Another enabled rule claiming the same protocol, bind address and port.
 *
 * This mirrors the backend's check rather than replacing it: the backend still
 * refuses, and it also detects range overlap and a locally listening socket,
 * which the browser cannot see. What this buys is the answer arriving while the
 * operator is still typing instead of when they submit.
 */
function findConflict(
  form: FormState,
  editingId: number | undefined,
  routes: RouteListResponse | undefined,
): Conflict | null {
  const port = Number(form.bind_port)
  if (!Number.isFinite(port) || port <= 0) return null

  const end = Number(form.bind_port_range_end) || port
  for (const entry of routes?.routes ?? []) {
    const rule = entry.route
    if (rule.route_rule_id === editingId || !rule.is_enabled) continue
    if (!protocolsOverlap(rule.route_protocol_id, form.route_protocol_id)) continue
    if (!addressesOverlap(rule.bind_address, form.bind_address)) continue

    const otherEnd = rule.bind_port_range_end ?? rule.bind_port
    if (port <= otherEnd && rule.bind_port <= end) {
      return {
        title: rule.route_rule_title,
        protocolId: rule.route_protocol_id,
        address: form.bind_address || '0.0.0.0',
        port: end > port ? `${port}-${end}` : String(port),
      }
    }
  }
  return null
}

function protocolsOverlap(left: number, right: number): boolean {
  if (left === RouteProtocol.Both || right === RouteProtocol.Both) return true
  return left === right
}

function addressesOverlap(left: string, right: string): boolean {
  if (isAny(left) || isAny(right)) return true
  return left.trim() === right.trim()
}

function isAny(address: string): boolean {
  const trimmed = address.trim()
  return trimmed === '' || trimmed === '0.0.0.0' || trimmed === '::'
}

// ---------------------------------------------------------------- form state

function defaultsFrom(settings: Record<string, unknown>): FormState {
  const number = (key: string, fallback: number) =>
    typeof settings[key] === 'number' ? (settings[key] as number) : fallback

  return {
    route_rule_title: '',
    description: '',
    route_protocol_id: number('routes.default_protocol', RouteProtocol.TCP),
    // Left empty, the backend fills in this server's primary address and
    // returns it in the preview, so what is shown is what will be stored.
    bind_address: '',
    bind_port: '',
    bind_port_range_end: '',
    bind_interface: '',
    destination_address: '',
    destination_port: '',
    destination_port_range_end: '',
    nat_mode_id: number('routes.default_nat_mode', NatMode.Masquerade),
    snat_address: '',
    load_balance_mode_id: LoadBalanceMode.None,
    tunnel_id: null,
    is_clamp_mss_to_pmtu: false,
    is_include_local_originated: false,
    is_logging_enabled: false,
    fwmark: '',
    max_connections_per_source: '',
    connection_rate_limit: '',
    is_enabled: true,
    destination_weight: '1',
    destination_monitor_port: '',
    source_list_ids: [],
    destinations: [],
    is_monitor_enabled: settings['routes.monitor_enabled'] === true,
    monitor_mode_id: RouteMonitorMode.Report,
    monitor_interval_seconds: '',
    monitor_timeout_seconds: '',
    monitor_failure_threshold: '',
    monitor_recovery_threshold: '',
    allowed_sources: [],
  }
}

/** A stored optional number as a form field: absent becomes the empty box. */
function numberField(value: number | null | undefined): string {
  return value === null || value === undefined ? '' : String(value)
}

/**
 * Seeds the form from a stored rule.
 *
 * monitorsByDefault is the panel-wide setting, because a rule that has never
 * stated a policy of its own follows it: showing the switch off there would
 * be showing something other than what is happening, and saving the rule
 * would then pin the wrong answer.
 */
export function formFromRoute(route: RouteRule, monitorsByDefault = false): FormState {
  return {
    route_rule_title: route.route_rule_title,
    description: route.description,
    route_protocol_id: route.route_protocol_id,
    bind_address: route.bind_address,
    bind_port: String(route.bind_port),
    bind_port_range_end: route.bind_port_range_end ? String(route.bind_port_range_end) : '',
    bind_interface: route.bind_interface ?? '',
    destination_address: route.destination_address,
    destination_port: String(route.destination_port),
    destination_port_range_end: route.destination_port_range_end
      ? String(route.destination_port_range_end)
      : '',
    nat_mode_id: route.nat_mode_id,
    snat_address: route.snat_address ?? '',
    load_balance_mode_id: route.load_balance_mode_id,
    tunnel_id: route.tunnel_id,
    is_clamp_mss_to_pmtu: route.is_clamp_mss_to_pmtu,
    is_include_local_originated: route.is_include_local_originated,
    is_logging_enabled: route.is_logging_enabled,
    fwmark: route.fwmark === null ? '' : String(route.fwmark),
    max_connections_per_source:
      route.max_connections_per_source === null ? '' : String(route.max_connections_per_source),
    connection_rate_limit:
      route.connection_rate_limit === null ? '' : String(route.connection_rate_limit),
    is_enabled: route.is_enabled,
    // The primary destination is repeated in the destination rows by the
    // backend, so the extra ones are the tail.
    // Both lists are defended: the API sends arrays, but a rule that arrives
    // with null here used to throw inside the seed and take the whole page
    // down rather than opening the dialog.
    destination_weight: String((route.destinations ?? [])[0]?.weight ?? 1),
    destination_monitor_port: numberField((route.destinations ?? [])[0]?.monitor_port),
    destination_carried: carriedFrom((route.destinations ?? [])[0]),
    source_list_ids: (route.source_lists ?? []).map((list) => list.source_list_id),
    destinations: (route.destinations ?? []).slice(1).map((destination) => ({
      address: destination.address,
      port: String(destination.port),
      weight: String(destination.weight),
      monitor_port: numberField(destination.monitor_port),
      carried: carriedFrom(destination),
    })),
    is_monitor_enabled: route.is_monitor_enabled ?? monitorsByDefault,
    monitor_mode_id: route.monitor_mode_id ?? RouteMonitorMode.Report,
    monitor_interval_seconds: numberField(route.monitor_interval_seconds),
    monitor_timeout_seconds: numberField(route.monitor_timeout_seconds),
    monitor_failure_threshold: numberField(route.monitor_failure_threshold),
    monitor_recovery_threshold: numberField(route.monitor_recovery_threshold),
    allowed_sources: (route.allowed_sources ?? []).map((source) => source.cidr),
  }
}

/**
 * The request body.
 *
 * Empty strings become absent fields rather than empty values: the backend
 * distinguishes a field that was not mentioned from one explicitly cleared, and
 * an empty bind address means "this server's primary address", not "".
 */
export function toPatch(form: FormState): Record<string, unknown> {
  const number = (value: string): number | undefined => {
    const parsed = Number(value)
    return value.trim() && Number.isFinite(parsed) ? parsed : undefined
  }

  const patch: Record<string, unknown> = {
    route_rule_title: form.route_rule_title,
    route_protocol_id: form.route_protocol_id,
    bind_port: number(form.bind_port),
    destination_address: form.destination_address,
    destination_port: number(form.destination_port),
    nat_mode_id: form.nat_mode_id,
    load_balance_mode_id: form.load_balance_mode_id,
    is_clamp_mss_to_pmtu: form.is_clamp_mss_to_pmtu,
    is_include_local_originated: form.is_include_local_originated,
    is_logging_enabled: form.is_logging_enabled,
    is_enabled: form.is_enabled,
    tunnel_id: form.tunnel_id,
  }

  if (form.description) patch.description = form.description
  if (form.bind_address) patch.bind_address = form.bind_address
  if (form.bind_interface) patch.bind_interface = form.bind_interface
  if (form.snat_address) patch.snat_address = form.snat_address

  const bindEnd = number(form.bind_port_range_end)
  if (bindEnd !== undefined) patch.bind_port_range_end = bindEnd
  const destinationEnd = number(form.destination_port_range_end)
  if (destinationEnd !== undefined) patch.destination_port_range_end = destinationEnd

  // Nullable numbers: an empty field clears the limit rather than leaving the
  // previous one in place, which is what the operator means by clearing it.
  patch.fwmark = number(form.fwmark) ?? null
  patch.max_connections_per_source = number(form.max_connections_per_source) ?? null
  patch.connection_rate_limit = number(form.connection_rate_limit) ?? null

  if (form.allowed_sources.length) {
    patch.allowed_sources = form.allowed_sources.map((cidr) => ({ cidr }))
  } else {
    patch.allowed_sources = []
  }

  // Monitoring is always sent: turning it off is an instruction, and an
  // absent field would be read as "leave it as it was". The parameters are
  // nullable, because an empty one means "go back to inheriting this".
  patch.source_list_ids = form.source_list_ids
  patch.is_monitor_enabled = form.is_monitor_enabled
  patch.monitor_mode_id = form.monitor_mode_id
  patch.monitor_interval_seconds = number(form.monitor_interval_seconds) ?? null
  patch.monitor_timeout_seconds = number(form.monitor_timeout_seconds) ?? null
  patch.monitor_failure_threshold = number(form.monitor_failure_threshold) ?? null
  patch.monitor_recovery_threshold = number(form.monitor_recovery_threshold) ?? null

  // The destination list is always sent, with the primary leading it.
  //
  // It used to be sent only when there was more than one, and an absent field
  // reads to the backend as "leave it as it was". So a rule could grow a second
  // destination but never lose one: removing the last extra and saving left the
  // stored pair untouched, and the rule stayed in multi-destination mode with a
  // backend the operator had just deleted still taking traffic.
  const extras = form.destinations.filter((destination) => destination.address && destination.port)
  if (!extras.length) {
    // One destination is not balanced across anything. The control is hidden
    // at this point rather than reset, so the mode it was left on has to be
    // corrected here too -- a row also stops being a destination by having its
    // address cleared, which never passes through the remove button.
    patch.load_balance_mode_id = LoadBalanceMode.None
  }
  patch.destinations = [
    entry({
      address: form.destination_address,
      port: form.destination_port,
      weight: form.destination_weight,
      monitorPort: form.destination_monitor_port,
      carried: form.destination_carried,
      portRangeEnd: destinationEnd,
    }),
    ...extras.map((destination) =>
      entry({
        address: destination.address,
        port: destination.port,
        weight: destination.weight,
        monitorPort: destination.monitor_port,
        carried: destination.carried,
      }),
    ),
  ]

  return patch

  /**
   * One destination as the backend takes it.
   *
   * The carried fields ride along unchanged. Whether a destination is in
   * rotation, and how it is monitored, are decided on the rule's own page; this
   * dialog rewrites the list on every save and would erase both if it sent only
   * what it happens to show.
   */
  function entry(row: {
    address: string
    port: string
    weight: string
    monitorPort: string
    carried?: CarriedDestination
    portRangeEnd?: number
  }) {
    return {
      address: row.address,
      port: number(row.port) ?? 0,
      port_range_end: row.portRangeEnd,
      weight: number(row.weight) ?? 1,
      is_enabled: row.carried?.is_enabled ?? true,
      monitor_port: number(row.monitorPort) ?? null,
      is_monitor_enabled: row.carried?.is_monitor_enabled ?? null,
      monitor_interval_seconds: row.carried?.monitor_interval_seconds ?? null,
      monitor_timeout_seconds: row.carried?.monitor_timeout_seconds ?? null,
      monitor_failure_threshold: row.carried?.monitor_failure_threshold ?? null,
      monitor_recovery_threshold: row.carried?.monitor_recovery_threshold ?? null,
    }
  }
}

/**
 * Everything a rule allows traffic from, in one field: the shared address
 * lists as chips, and one-off addresses as tokens beside them. Typing an
 * address and pressing space, comma or Enter makes it a token; there is no Add
 * button because the space bar is the add button. Backspace on an empty input
 * takes the last token back.
 *
 * With nothing here at all, every source that can reach the bind address is
 * allowed — the field says so instead of sitting silently empty.
 */
export function SourcesField({
  lists,
  onListsChange,
  addresses,
  onAddressesChange,
  draft,
  onDraftChange,
  error,
}: {
  lists: number[]
  onListsChange: (ids: number[]) => void
  addresses: string[]
  onAddressesChange: (entries: string[]) => void
  draft: string
  onDraftChange: (value: string) => void
  error?: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [rejected, setRejected] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const query = useQuery({
    queryKey: ['source-lists'],
    queryFn: () => api.get<SourceListsResponse>('/source-lists'),
    staleTime: 60_000,
  })
  const allLists = query.data?.source_lists ?? []
  const byId = new Map(allLists.map((list) => [list.source_list_id, list]))

  const toggle = (id: number) =>
    onListsChange(lists.includes(id) ? lists.filter((one) => one !== id) : [...lists, id])

  /** Turns whatever is typed into tokens, and says why when it cannot. */
  const commit = (raw: string): boolean => {
    const parts = raw.split(/[\s,]+/).filter(Boolean)
    if (!parts.length) return true
    const bad = parts.find((part) => !looksLikeAddressOrCidr(part))
    if (bad) {
      setRejected(bad)
      return false
    }
    const fresh = parts.filter((part) => !addresses.includes(part))
    if (fresh.length) onAddressesChange([...addresses, ...fresh])
    setRejected(null)
    return true
  }

  return (
    <Field
      label={t('routeForm.fields.sourceLists')}
      description={t('routeForm.help.sources')}
      error={rejected ? t('routeForm.allowlist.invalid', { value: rejected }) : error}
    >
      {() => (
        <div className="space-y-2">
          {/* One container for all three kinds of content: list chips,
              address tokens, and the input that makes more of them. Clicking
              anywhere in it focuses the input, the way one field should. */}
          <div
            className={cn(
              'flex min-h-10 flex-wrap items-center gap-1.5 rounded-md border bg-surface-sunken px-2 py-1.5',
              rejected || error ? 'border-danger' : 'border-border',
            )}
            onClick={() => inputRef.current?.focus()}
          >
            {lists.map((id) => {
              const list = byId.get(id)
              return (
                <span
                  key={`list-${id}`}
                  className="inline-flex items-center gap-1 rounded-full bg-accent-muted px-2 py-0.5 text-2xs font-medium text-accent"
                >
                  {list?.name ?? String(id)}
                  <button
                    type="button"
                    onClick={() => toggle(id)}
                    aria-label={t('routeForm.allowlist.remove', { cidr: list?.name ?? String(id) })}
                    className="hover:text-foreground"
                  >
                    <X className="size-3" aria-hidden="true" />
                  </button>
                </span>
              )
            })}
            {addresses.map((cidr) => (
              <span
                key={cidr}
                className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 text-2xs"
              >
                <Technical className="text-2xs">{cidr}</Technical>
                <button
                  type="button"
                  onClick={() => onAddressesChange(addresses.filter((entry) => entry !== cidr))}
                  aria-label={t('routeForm.allowlist.remove', { cidr })}
                  className="text-muted-foreground hover:text-danger"
                >
                  <X className="size-3" aria-hidden="true" />
                </button>
              </span>
            ))}
            <input
              ref={inputRef}
              value={draft}
              onChange={(event) => {
                setRejected(null)
                const value = event.target.value
                // Space and comma are the add button.
                if (/[\s,]$/.test(value)) {
                  if (commit(value)) onDraftChange('')
                  else onDraftChange(value.replace(/[\s,]+$/, ''))
                  return
                }
                onDraftChange(value)
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter') {
                  event.preventDefault()
                  if (draft.trim() && commit(draft)) onDraftChange('')
                }
                if (event.key === 'Backspace' && !draft) {
                  if (addresses.length) {
                    onAddressesChange(addresses.slice(0, -1))
                  } else if (lists.length) {
                    onListsChange(lists.slice(0, -1))
                  }
                }
              }}
              onBlur={() => {
                if (draft.trim() && commit(draft)) onDraftChange('')
              }}
              placeholder={
                lists.length || addresses.length ? '' : t('routeForm.allowlist.placeholder')
              }
              aria-label={t('routeForm.fields.sourceLists')}
              className="min-w-28 flex-1 bg-transparent py-0.5 font-mono text-xs outline-none placeholder:text-muted-foreground"
            />
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="ms-auto"
              onClick={(event) => {
                event.stopPropagation()
                setOpen((value) => !value)
              }}
            >
              <Plus className="size-3.5" aria-hidden="true" />
              {t('routeForm.fields.addSourceList')}
            </Button>
          </div>

          {open ? (
            <ul className="max-h-56 overflow-auto rounded-md border border-border bg-surface-raised p-1 scrollbar-thin">
              {allLists.length === 0 ? (
                <li className="px-2 py-2 text-2xs text-muted-foreground">
                  {t('routeForm.help.noSourceLists')}
                </li>
              ) : null}
              {allLists.map((list) => {
                const picked = lists.includes(list.source_list_id)
                return (
                  <li key={list.source_list_id}>
                    <button
                      type="button"
                      aria-pressed={picked}
                      onClick={() => toggle(list.source_list_id)}
                      className={cn(
                        'flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-start text-xs transition-colors hover:bg-muted',
                        picked && 'bg-muted',
                      )}
                    >
                      <span className="min-w-0 flex-1 truncate font-medium">{list.name}</span>
                      <span className="tabular shrink-0 text-2xs text-muted-foreground">
                        {t('sourceLists.ranges', { count: list.entries?.length ?? 0 })}
                      </span>
                      {picked ? <Check className="size-3.5 shrink-0 text-ok" aria-hidden="true" /> : null}
                    </button>
                  </li>
                )
              })}
            </ul>
          ) : null}

          {!lists.length && !addresses.length ? (
            <p className="text-2xs text-muted-foreground">{t('routeForm.allowlist.empty')}</p>
          ) : null}
        </div>
      )}
    </Field>
  )
}

/**
 * Whether a typed token could be an address or a CIDR. The check is shaped
 * like the kernel's: four octets in range with an optional /0-32, or something
 * colon-separated with an optional /0-128. The backend has the final word; this
 * only keeps obvious typos from becoming tokens that fail later.
 */
export function looksLikeAddressOrCidr(value: string): boolean {
  const [address, prefix, extra] = value.split('/')
  if (extra !== undefined) return false

  if (address.includes(':')) {
    if (!/^[0-9a-fA-F:]{2,45}$/.test(address)) return false
    if (address.includes(':::')) return false
    if (!address.includes('::') && address.split(':').length !== 8) return false
    if (address.split(':').some((group) => group.length > 4)) return false
    if (prefix === undefined) return true
    const bits = Number(prefix)
    return /^\d{1,3}$/.test(prefix) && bits >= 0 && bits <= 128
  }

  const octets = address.split('.')
  if (octets.length !== 4) return false
  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet) || Number(octet) > 255) return false
  }
  if (prefix === undefined) return true
  const bits = Number(prefix)
  return /^\d{1,2}$/.test(prefix) && bits >= 0 && bits <= 32
}
