import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Loader2, Plus, X } from 'lucide-react'

import { ApiError, api } from '@/lib/api'
import {
  LoadBalanceMode,
  NatMode,
  RouteProtocol,
  type HostInterface,
  type InterfacesResponse,
  type RouteListResponse,
  type RouteReachabilityResult,
  type RoutePreviewResponse,
  type RouteResultResponse,
  type RouteRule,
  type SettingsResponse,
  type TunnelListResponse,
  type TunnelRoutesResponse,
} from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
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
  destinations: { address: string; port: string; weight: string }[]
  allowed_sources: string[]
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
      setForm(formFromRoute(route))
      setDestinationMode(route.tunnel_id ? 'tunnel' : 'manual')
    } else if (settingsQuery.isSuccess) {
      setForm(defaultsFrom(settingsQuery.data.settings))
      setDestinationMode('manual')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, route, settingsQuery.isSuccess])

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

          {/* 4 — NAT mode, in plain language rather than raw terminology */}
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
              <SwitchField
                label={t('routeForm.fields.enabled')}
                checked={form.is_enabled}
                onCheckedChange={(value) => set('is_enabled', value)}
              />
            </div>

            <AllowlistEditor
              entries={form.allowed_sources}
              draft={allowlistDraft}
              onDraftChange={setAllowlistDraft}
              onAdd={(cidr) => {
                set('allowed_sources', [...form.allowed_sources, cidr])
                setAllowlistDraft('')
              }}
              onRemove={(cidr) =>
                set(
                  'allowed_sources',
                  form.allowed_sources.filter((entry) => entry !== cidr),
                )
              }
              error={fieldErrors['allowed_sources']}
            />

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

function AllowlistEditor({
  entries,
  draft,
  onDraftChange,
  onAdd,
  onRemove,
  error,
}: {
  entries: string[]
  draft: string
  onDraftChange: (value: string) => void
  onAdd: (cidr: string) => void
  onRemove: (cidr: string) => void
  error?: string
}) {
  const { t } = useTranslation()

  return (
    <Field
      label={t('routeForm.fields.allowedSources')}
      description={t('routeForm.help.allowedSources')}
      error={error}
    >
      <div className="space-y-2">
        <div className="flex gap-2">
          <TechnicalInput
            value={draft}
            onChange={(event) => onDraftChange(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && draft.trim()) {
                event.preventDefault()
                onAdd(draft.trim())
              }
            }}
            placeholder={t('routeForm.allowlist.placeholder')}
            // Field labels its child by id, and this input is two elements down
            // inside a layout wrapper rather than being that child, so the
            // association never reaches it. It was the only control in this
            // dialog with no accessible name: a screen reader announced nothing
            // but the placeholder, which disappears as soon as anything is
            // typed. Naming it explicitly is independent of how Field wires up.
            aria-label={t('routeForm.fields.allowedSources')}
          />
          <Button
            type="button"
            variant="secondary"
            disabled={!draft.trim()}
            onClick={() => onAdd(draft.trim())}
          >
            <Plus className="size-4" aria-hidden="true" />
            {t('routeForm.allowlist.add')}
          </Button>
        </div>
        {entries.length ? (
          <div className="flex flex-wrap gap-2">
            {entries.map((cidr) => (
              <span
                key={cidr}
                className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 text-2xs"
              >
                <Technical className="text-2xs">{cidr}</Technical>
                <button
                  type="button"
                  onClick={() => onRemove(cidr)}
                  aria-label={t('routeForm.allowlist.remove', { cidr })}
                  className="text-muted-foreground hover:text-danger"
                >
                  <X className="size-3" aria-hidden="true" />
                </button>
              </span>
            ))}
          </div>
        ) : (
          <p className="text-2xs text-muted-foreground">{t('routeForm.allowlist.empty')}</p>
        )}
      </div>
    </Field>
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
            protocol={form.route_protocol_id}
            digits={digits}
            onAddressChange={(value) => update(index, { address: value })}
            onPortChange={(value) => update(index, { port: value })}
            onWeightChange={(value) => update(index, { weight: value })}
            onRemove={() =>
              set(
                'destinations',
                extras.filter((_, i) => i !== index),
              )
            }
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
            set('destinations', [...extras, { address: '', port: '', weight: '1' }])
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
    destinations: [],
    allowed_sources: [],
  }
}

export function formFromRoute(route: RouteRule): FormState {
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
    destinations: (route.destinations ?? []).slice(1).map((destination) => ({
      address: destination.address,
      port: String(destination.port),
      weight: String(destination.weight),
    })),
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
function toPatch(form: FormState): Record<string, unknown> {
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

  // The primary destination leads the list; the extras follow it.
  const extras = form.destinations.filter((destination) => destination.address && destination.port)
  if (extras.length) {
    patch.destinations = [
      {
        address: form.destination_address,
        port: number(form.destination_port) ?? 0,
        port_range_end: destinationEnd,
        weight: number(form.destination_weight) ?? 1,
        is_enabled: true,
      },
      ...extras.map((destination) => ({
        address: destination.address,
        port: number(destination.port) ?? 0,
        weight: number(destination.weight) ?? 1,
        is_enabled: true,
      })),
    ]
  }

  return patch
}
