import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Dices, Info } from 'lucide-react'

import { ApiError, api } from '@/lib/api'
import { cn } from '@/lib/utils'
import {
  PersistenceType,
  TunnelSide,
  TunnelType,
  type Capabilities,
  type CreateResponse,
  type PoolResponse,
  type PreviewResponse,
  type HostInterface,
  type InterfacesResponse,
  type SettingsResponse,
  type TunnelListResponse,
  type Tunnel,
  type TunnelInput,
} from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
import { describeError } from '../ui/feedback'
import { verificationFailures, verificationPassed } from '@/hooks/useTunnelActions'
import { Button } from '../ui/button'
import { Checkbox, Field, Input, Select, SwitchField, TechnicalInput } from '../ui/form'
import { DisclosurePanel } from '../ui/disclosure'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Tooltip,
} from '../ui/overlay'
import { Badge } from '../ui/feedback'
import { Technical } from '../ui/technical'
import { tunnelLabel } from '@/lib/format'
import { SideSelector } from './SideSelector'
import { PreviewPanel } from './PreviewPanel'
import { InheritedNumberField } from './InheritedField'

/**
 * The bounds internal/validate enforces, mirrored so the inputs cannot offer a
 * value the backend will refuse. They are MaxFwMark and MaxQueueLength in
 * internal/validate/validate.go; keeping them in step is what makes the
 * INVALID_FWMARK and INVALID_QUEUE_LENGTH messages reachable rather than
 * theoretical.
 */
const MAX_FWMARK = 4294967295
const MAX_QUEUE_LENGTH = 1000000
// The hop limit is the IPv6 spelling of the TTL and shares its bound; the
// encapsulation limit is its own field. Both match internal/validate exactly.
const MAX_HOP_LIMIT = 255
const MAX_ENCAP_LIMIT = 255

/** The tunnel types whose outer header is IPv6, and so have these two fields. */
const IPV6_TUNNEL_TYPES: number[] = [TunnelType.IP6GRE, TunnelType.IP6GRETAP]

/** Per-tunnel monitoring overrides, which are nullable on the backend. */
interface MonitorOverrides {
  monitor_interval_seconds: number | null
  monitor_timeout_seconds: number | null
  monitor_packet_size: number | null
  monitor_window_size: number | null
  monitor_degraded_loss_percent: number | null
  monitor_down_loss_percent: number | null
  monitor_degraded_rtt_ms: number | null
  monitor_state_change_samples: number | null
  monitor_target: string | null
}

type FormState = TunnelInput & MonitorOverrides

export function TunnelFormDialog({
  open,
  onOpenChange,
  tunnel,
  initial,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Present when editing; absent when creating. */
  tunnel?: Tunnel
  /** A prefilled payload, as the pairing-code import produces. */
  initial?: TunnelInput
  onCreated?: (created: Tunnel) => void
}) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<SettingsResponse>('/settings'),
    staleTime: 60_000,
  })
  const capabilitiesQuery = useQuery({
    queryKey: ['system', 'capabilities'],
    queryFn: () => api.get<Capabilities>('/system/capabilities'),
    staleTime: 300_000,
  })
  const poolsQuery = useQuery({
    queryKey: ['pools'],
    queryFn: () => api.get<{ pools: PoolResponse[] }>('/pools'),
    staleTime: 60_000,
  })
  // The tunnels that already exist, for the two things the form can tell an
  // operator before the backend has to refuse anything: which GRE keys are
  // taken, and which tunnel took them.
  const tunnelsQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 30_000,
  })
  // The addresses this server has. A GRE tunnel's local endpoint must be one of
  // them, so these are not a suggestion -- they are the whole of the valid
  // answer, and typing one out of a terminal in another window is work the
  // panel already knows how to save.
  const interfacesQuery = useQuery({
    queryKey: ['system', 'interfaces'],
    queryFn: () => api.get<InterfacesResponse>('/system/interfaces'),
    staleTime: 60_000,
  })

  const settings = settingsQuery.data?.settings ?? {}
  const [form, setForm] = useState<FormState | null>(null)
  const [manualAddressing, setManualAddressing] = useState(false)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [force, setForce] = useState(false)
  const [confirmRecreate, setConfirmRecreate] = useState(false)

  // The form is seeded once per opening, from the tunnel being edited, from a
  // pairing code, or from the panel's configured defaults.
  useEffect(() => {
    if (!open) {
      setForm(null)
      setFieldErrors({})
      setSubmitError(null)
      setForce(false)
      setConfirmRecreate(false)
      return
    }
    if (form) return
    if (tunnel) {
      setForm(formFromTunnel(tunnel))
      setManualAddressing(tunnel.address_pool_id === null)
    } else if (initial) {
      setForm({ ...blankOverrides(), ...initial })
      setManualAddressing(initial.address_pool_id === null && (initial.addresses ?? []).length > 0)
    } else if (settingsQuery.isSuccess) {
      setForm(defaultsFrom(settings, usedKeys))
      setManualAddressing(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, tunnel, initial, settingsQuery.isSuccess])

  const patch = useMemo(() => (form ? toPatch(form, manualAddressing) : null), [form, manualAddressing])

  // The preview is refreshed as the form changes, so what it shows is always
  // the plan for the values currently on screen.
  // Every key a live tunnel already answers to, and which tunnel that is.
  const keyOwners = useMemo(() => {
    const map = new Map<number, Tunnel>()
    for (const entry of tunnelsQuery.data?.tunnels ?? []) {
      if (entry.tunnel.tunnel_id === tunnel?.tunnel_id) continue
      for (const key of [entry.tunnel.ikey, entry.tunnel.okey]) {
        if (key !== null && key !== undefined) map.set(key, entry.tunnel)
      }
    }
    return map
  }, [tunnelsQuery.data, tunnel?.tunnel_id])
  const usedKeys = useMemo(() => new Set(keyOwners.keys()), [keyOwners])
  const keyOwner = form?.ikey !== null && form?.ikey !== undefined
    ? keyOwners.get(form.ikey)
    : undefined

  const previewQuery = useQuery({
    queryKey: ['tunnels', 'preview', patch],
    queryFn: () =>
      api.post<PreviewResponse>('/tunnels/preview', {
        ...patch,
        ...(tunnel ? { tunnel_id: tunnel.tunnel_id } : {}),
      }),
    enabled: open && Boolean(patch) && Boolean(form?.local_endpoint) && Boolean(form?.remote_endpoint),
    retry: false,
    staleTime: 0,
  })

  const submitMutation = useMutation({
    mutationFn: async () => {
      const body = {
        ...patch,
        force: force || undefined,
        confirm_recreate: confirmRecreate || undefined,
      }
      return tunnel
        ? api.patch<CreateResponse>(`/tunnels/${tunnel.tunnel_id}`, body)
        : api.post<CreateResponse>('/tunnels', body)
    },
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      await queryClient.invalidateQueries({ queryKey: ['monitor'] })

      // Success is reported only once the backend's verification agrees.
      if (!verificationPassed(result.verification)) {
        toast({
          tone: 'error',
          title: tunnel ? t('tunnelForm.updatedTitle') : t('tunnelForm.createdTitle'),
          description: verificationFailures(result.verification).join(' · '),
        })
        setSubmitError(verificationFailures(result.verification).join(' · '))
        return
      }

      toast({
        tone: 'success',
        title: tunnel ? t('tunnelForm.updatedTitle') : t('tunnelForm.createdTitle'),
        description: t('tunnelForm.createdBody', { name: tunnelLabel(result.tunnel) }),
      })
      onOpenChange(false)
      if (!tunnel) onCreated?.(result.tunnel)
    },
    onError: (error) => {
      if (error instanceof ApiError) {
        setFieldErrors(error.fieldErrors)
        setSubmitError(Object.keys(error.fieldErrors).length ? null : describeError(error, t).message)
      } else {
        setSubmitError(describeError(error, t).message)
      }
    },
  })

  if (!form) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent size="lg">
          <DialogHeader>
            <DialogTitle>{tunnel ? t('tunnelForm.editTitle', { name: tunnelLabel(tunnel) }) : t('tunnelForm.createTitle')}</DialogTitle>
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

  const tunnelTypes = (capabilitiesQuery.data?.tunnel_types ?? []).filter((type) => type.supported)
  const persistenceOptions = capabilitiesQuery.data?.persistence ?? []
  const pools = poolsQuery.data?.pools ?? []
  const mtuAdvice = previewQuery.data?.mtu
  const warnings = previewQuery.data?.warnings ?? []
  const requiresRecreate = previewQuery.data?.plan.requires_recreate ?? false

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>
            {tunnel ? t('tunnelForm.editTitle', { name: tunnelLabel(tunnel) }) : t('tunnelForm.createTitle')}
          </DialogTitle>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {submitError ? (
            <p className="rounded-md border border-danger/30 bg-danger-muted px-3 py-2 text-xs text-danger" role="alert">
              {submitError}
            </p>
          ) : null}

          {/* 1 — Type and side */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('tunnelForm.sectionType')}
            </h3>
            <Field
              label={t('tunnel.fields.displayName')}
              description={t('tunnel.help.displayName')}
              error={fieldErrors['display_name']}
            >
              {(props) => (
                <Input
                  {...props}
                  value={form.display_name ?? ''}
                  onChange={(event) => set('display_name', event.target.value)}
                  placeholder={t('tunnel.fields.displayNamePlaceholder')}
                />
              )}
            </Field>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field label={t('tunnel.fields.type')} error={fieldErrors['tunnel_type_id']}>
                {(props) => (
                  <Select
                    id={props.id}
                    value={String(form.tunnel_type_id)}
                    onValueChange={(value) => set('tunnel_type_id', Number(value))}
                    // Driven by the backend lookup: more tunnel types are
                    // coming, and none of them should need a frontend change.
                    options={
                      tunnelTypes.length
                        ? tunnelTypes.map((type) => ({
                            value: String(type.tunnel_type_id),
                            label: type.title,
                            description: type.note,
                          }))
                        : [{ value: String(TunnelType.GRE), label: 'GRE' }]
                    }
                  />
                )}
              </Field>

              <SideSelector value={form.tunnel_side_id} onChange={(value) => set('tunnel_side_id', value)} />
            </div>
          </section>

          {/* 2 — Endpoints and addressing */}
          <section className="space-y-3">
            <h3 className="display text-xs font-bold text-muted-foreground">
              {t('tunnelForm.sectionEndpoints')}
            </h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label={t('tunnel.fields.localEndpoint')}
                description={t('tunnel.help.localEndpoint')}
                error={fieldErrors['local_endpoint']}
                required
              >
                {(props) => (
                  <div className="space-y-1.5">
                    <TechnicalInput
                      {...props}
                      value={form.local_endpoint}
                      onChange={(event) => set('local_endpoint', event.target.value)}
                      placeholder="203.0.113.10"
                    />
                    <LocalAddressPicker
                      interfaces={interfacesQuery.data?.interfaces ?? []}
                      selected={form.local_endpoint}
                      onPick={(address) => set('local_endpoint', address)}
                    />
                  </div>
                )}
              </Field>
              <Field
                label={t('tunnel.fields.remoteEndpoint')}
                description={t('tunnel.help.remoteEndpoint')}
                error={fieldErrors['remote_endpoint']}
                required
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    value={form.remote_endpoint}
                    onChange={(event) => set('remote_endpoint', event.target.value)}
                    placeholder="198.51.100.20"
                  />
                )}
              </Field>
            </div>

            <AddressingSection
              form={form}
              set={set}
              manual={manualAddressing}
              onManualChange={setManualAddressing}
              pools={pools}
              errors={fieldErrors}
            />
          </section>

          {/* 3 — Advanced */}
          <DisclosurePanel title={t('tunnelForm.sectionAdvanced')} contentClassName="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field
                label={t('tunnel.fields.key')}
                description={t('tunnel.help.key')}
                error={fieldErrors['ikey'] ?? fieldErrors['okey']}
              >
                {(props) => (
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <TechnicalInput
                        {...props}
                        className="flex-1"
                        inputMode="numeric"
                        value={form.ikey ?? ''}
                        onChange={(event) => {
                          const value = event.target.value === '' ? null : Number(event.target.value)
                          // The two keys move together unless they are already
                          // different, which is the case the advanced pair covers.
                          setForm((current) =>
                            current ? { ...current, ikey: value, okey: value } : current,
                          )
                        }}
                        placeholder="2749365187"
                      />
                      <Button
                        type="button"
                        variant="secondary"
                        size="icon"
                        aria-label={t('tunnelForm.randomKey')}
                        title={t('tunnelForm.randomKey')}
                        onClick={() => {
                          const value = randomGreKey(usedKeys)
                          setForm((current) =>
                            current ? { ...current, ikey: value, okey: value } : current,
                          )
                        }}
                      >
                        <Dices className="size-4" aria-hidden="true" />
                      </Button>
                    </div>
                    {/* Not an error: the kernel identifies a tunnel by its
                        endpoints and its keys together, so the same key on a
                        different pair of endpoints is legal. It is still almost
                        always a mistake, and the tunnel that has it is the thing
                        worth naming. */}
                    {keyOwner ? (
                      <p className="flex items-start gap-1.5 text-2xs text-warn">
                        <AlertTriangle className="mt-0.5 size-3 shrink-0" aria-hidden="true" />
                        {t('tunnelForm.keyInUse', { name: tunnelLabel(keyOwner) })}
                      </p>
                    ) : null}
                  </div>
                )}
              </Field>

              <MtuField
                value={form.mtu}
                onChange={(value) => set('mtu', value)}
                advice={mtuAdvice}
                error={fieldErrors['mtu']}
              />

              <Field label={t('tunnel.fields.ttl')} description={t('tunnel.help.ttl')} error={fieldErrors['ttl']}>
                {(props) => (
                  <TechnicalInput
                    {...props}
                    inputMode="numeric"
                    value={form.ttl}
                    onChange={(event) => set('ttl', Number(event.target.value))}
                  />
                )}
              </Field>

              <Field label={t('tunnel.fields.tos')} error={fieldErrors['tos']}>
                {(props) => (
                  <TechnicalInput
                    {...props}
                    value={form.tos}
                    onChange={(event) => set('tos', event.target.value)}
                    placeholder="inherit"
                  />
                )}
              </Field>

              <Field
                label={t('tunnel.fields.interfaceName')}
                description={t('tunnel.help.interfaceName')}
                error={fieldErrors['interface_name']}
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    value={form.interface_name}
                    onChange={(event) => set('interface_name', event.target.value)}
                    placeholder="gre-a-0"
                  />
                )}
              </Field>

              <Field
                label={t('tunnel.fields.bindDevice')}
                description={t('tunnel.help.bindDevice')}
                error={fieldErrors['bind_device']}
              >
                {(props) => (
                  <TechnicalInput
                    {...props}
                    value={form.bind_device ?? ''}
                    onChange={(event) => set('bind_device', event.target.value)}
                  />
                )}
              </Field>

              {/*
                Both of these had a column, a type, bounds, a dedicated
                validation code and a translated label, and no control anywhere
                in the panel — so the API accepted them and the interface could
                not produce them. The bounds match internal/validate exactly, so
                the messages behind INVALID_FWMARK and INVALID_QUEUE_LENGTH are
                reachable rather than theoretical.

                Empty means "not set", which is the nullable column's own
                meaning, so leaving them alone sends null rather than zero.
              */}
              <Field
                label={t('tunnel.fields.fwmark')}
                description={t('tunnel.help.fwmark')}
                error={fieldErrors['fwmark']}
              >
                {(props) => (
                  <Input
                    {...props}
                    type="number"
                    inputMode="numeric"
                    dir="ltr"
                    className="tabular text-start"
                    min={0}
                    max={MAX_FWMARK}
                    value={form.fwmark ?? ''}
                    onChange={(event) =>
                      set('fwmark', event.target.value === '' ? null : Number(event.target.value))
                    }
                  />
                )}
              </Field>

              <Field
                label={t('tunnel.fields.txQueueLength')}
                description={t('tunnel.help.txQueueLength')}
                error={fieldErrors['tx_queue_length']}
              >
                {(props) => (
                  <Input
                    {...props}
                    type="number"
                    inputMode="numeric"
                    dir="ltr"
                    className="tabular text-start"
                    min={0}
                    max={MAX_QUEUE_LENGTH}
                    value={form.tx_queue_length ?? ''}
                    onChange={(event) =>
                      set('tx_queue_length', event.target.value === '' ? null : Number(event.target.value))
                    }
                  />
                )}
              </Field>

              {/*
                The hop limit and the encapsulation limit belong to the IPv6
                variants only, so they appear when one is selected rather than
                always. Both types are genuinely offered — the capabilities
                endpoint reports IP6GRE and IP6GRETAP supported through the ip
                command — so without these two controls an operator could create
                an IPv6 tunnel and had no way to set either, while the backend
                validated both and plan.go mapped the hop limit onto the link.
              */}
              {IPV6_TUNNEL_TYPES.includes(form.tunnel_type_id) ? (
                <>
                  <Field
                    label={t('tunnel.fields.hopLimit')}
                    description={t('tunnel.help.hopLimit')}
                    error={fieldErrors['hop_limit']}
                  >
                    {(props) => (
                      <Input
                        {...props}
                        type="number"
                        inputMode="numeric"
                        dir="ltr"
                        className="tabular text-start"
                        min={0}
                        max={MAX_HOP_LIMIT}
                        value={form.hop_limit ?? ''}
                        onChange={(event) =>
                          set('hop_limit', event.target.value === '' ? null : Number(event.target.value))
                        }
                      />
                    )}
                  </Field>

                  <Field
                    label={t('tunnel.fields.encapLimit')}
                    description={t('tunnel.help.encapLimit')}
                    error={fieldErrors['encap_limit']}
                  >
                    {(props) => (
                      <Input
                        {...props}
                        type="number"
                        inputMode="numeric"
                        dir="ltr"
                        className="tabular text-start"
                        min={0}
                        max={MAX_ENCAP_LIMIT}
                        value={form.encap_limit ?? ''}
                        onChange={(event) =>
                          set('encap_limit', event.target.value === '' ? null : Number(event.target.value))
                        }
                      />
                    )}
                  </Field>
                </>
              ) : null}

              <Field
                label={t('tunnel.fields.persistence')}
                description={t('tunnel.help.persistence')}
                error={fieldErrors['persistence_type_id']}
              >
                {(props) => (
                  <Select
                    id={props.id}
                    value={String(form.persistence_type_id)}
                    onValueChange={(value) => set('persistence_type_id', Number(value))}
                    options={
                      persistenceOptions.length
                        ? persistenceOptions.map((option) => ({
                            value: String(option.persistence_type_id),
                            label: option.title,
                            description: option.note,
                            // An unavailable backend is shown and disabled, so
                            // its absence is explained rather than mysterious.
                            disabled: !option.available,
                          }))
                        : [{ value: String(PersistenceType.Runtime), label: 'Runtime' }]
                    }
                  />
                )}
              </Field>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <SwitchField
                label={t('tunnel.fields.inputChecksum')}
                checked={form.has_input_checksum}
                onCheckedChange={(value) => set('has_input_checksum', value)}
              />
              <SwitchField
                label={t('tunnel.fields.outputChecksum')}
                checked={form.has_output_checksum}
                onCheckedChange={(value) => set('has_output_checksum', value)}
              />
              <SwitchField
                label={t('tunnel.fields.inputSequence')}
                checked={form.has_input_sequence}
                onCheckedChange={(value) => set('has_input_sequence', value)}
              />
              <SwitchField
                label={t('tunnel.fields.outputSequence')}
                checked={form.has_output_sequence}
                onCheckedChange={(value) => set('has_output_sequence', value)}
              />
              <SwitchField
                label={t('tunnel.fields.pmtudisc')}
                description={t('tunnel.help.pmtudisc')}
                checked={form.is_path_mtu_discovery}
                onCheckedChange={(value) => set('is_path_mtu_discovery', value)}
              />
              <SwitchField
                label={t('tunnel.fields.ignoreDf')}
                checked={form.is_ignore_df}
                onCheckedChange={(value) => set('is_ignore_df', value)}
              />
            </div>
          </DisclosurePanel>

          {/*
            4 — Monitoring.

            Each field either inherits the global setting or overrides it for
            this tunnel, which is exactly what the nullable column means and
            what monitor.ConfigFor resolves. The switch on each one turns the
            override on and off; clearing it sends null, which is the
            instruction to inherit again.
          */}
          <DisclosurePanel title={t('tunnelForm.sectionMonitoring')} contentClassName="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <InheritedNumberField
                label={t('diagnostics.ping.interval')}
                inheritedValue={numberOf(settings['monitor.interval_seconds'])}
                unit="s"
                value={form.monitor_interval_seconds}
                onChange={(value) => set('monitor_interval_seconds', value)}
              />
              <InheritedNumberField
                label={t('diagnostics.ping.timeout')}
                inheritedValue={numberOf(settings['monitor.timeout_seconds'])}
                unit="s"
                value={form.monitor_timeout_seconds}
                onChange={(value) => set('monitor_timeout_seconds', value)}
              />
              <InheritedNumberField
                label={t('diagnostics.ping.packetSize')}
                inheritedValue={numberOf(settings['monitor.packet_size'])}
                value={form.monitor_packet_size}
                onChange={(value) => set('monitor_packet_size', value)}
              />
              <InheritedNumberField
                label={t('monitor.loss') + ' · ' + t('monitor.state.Degraded')}
                inheritedValue={numberOf(settings['monitor.degraded_loss_pct'])}
                unit="%"
                value={form.monitor_degraded_loss_percent}
                onChange={(value) => set('monitor_degraded_loss_percent', value)}
              />
              <InheritedNumberField
                label={t('monitor.loss') + ' · ' + t('monitor.state.Down')}
                inheritedValue={numberOf(settings['monitor.down_loss_pct'])}
                unit="%"
                value={form.monitor_down_loss_percent}
                onChange={(value) => set('monitor_down_loss_percent', value)}
              />
              <InheritedNumberField
                label={t('monitor.latency') + ' · ' + t('monitor.state.Degraded')}
                inheritedValue={numberOf(settings['monitor.degraded_rtt_ms'])}
                unit="ms"
                value={form.monitor_degraded_rtt_ms}
                onChange={(value) => set('monitor_degraded_rtt_ms', value)}
              />
            </div>
          </DisclosurePanel>

          {/* 5 — Preview */}
          <PreviewPanel
            preview={previewQuery.data}
            isLoading={previewQuery.isFetching}
            error={previewQuery.error}
            onRetry={() => void previewQuery.refetch()}
            defaultOpen={!tunnel}
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
                {t('tunnelForm.force')}
              </label>
              <p className="text-2xs text-muted-foreground">{t('tunnelForm.forceHint')}</p>
            </div>
          ) : null}

          {requiresRecreate && tunnel ? (
            <label className="flex items-center gap-2 text-xs font-medium">
              <Checkbox
                checked={confirmRecreate}
                onCheckedChange={(value) => setConfirmRecreate(value === true)}
              />
              {t('tunnelForm.confirmRecreate')}
            </label>
          ) : null}
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={submitMutation.isPending}
            disabled={requiresRecreate && Boolean(tunnel) && !confirmRecreate}
            onClick={() => submitMutation.mutate()}
          >
            {submitMutation.isPending
              ? t('tunnelForm.applying')
              : tunnel
                ? t('tunnelForm.submitEdit')
                : t('tunnelForm.submitCreate')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The MTU field, with the backend's recommendation beside it.
 *
 * The recommendation is shown and the mismatch is explained, but the operator's
 * value is never overridden: they may know something about the path that the
 * underlay MTU does not say.
 */
function MtuField({
  value,
  onChange,
  advice,
  error,
}: {
  value: number
  onChange: (value: number) => void
  advice: PreviewResponse['mtu'] | undefined
  error?: string
}) {
  const { t } = useTranslation()
  const mismatched = advice && advice.recommended > 0 && advice.recommended !== value

  return (
    <Field
      label={t('tunnel.fields.mtu')}
      description={t('tunnel.help.mtu')}
      error={error}
      aside={
        advice?.breakdown?.length ? (
          <Tooltip
            content={
              <div className="space-y-0.5">
                <p className="font-medium">{t('tunnelForm.mtuAdvice.breakdown')}</p>
                {(advice.breakdown ?? []).map((term) => (
                  <p key={term.label}>
                    {term.label}: {term.bytes} B
                  </p>
                ))}
              </div>
            }
          >
            <button type="button" className="text-muted-foreground hover:text-foreground">
              <Info className="size-3.5" aria-hidden="true" />
            </button>
          </Tooltip>
        ) : null
      }
    >
      {(props) => (
        <div className="space-y-1.5">
          <TechnicalInput
            {...props}
            inputMode="numeric"
            value={value}
            onChange={(event) => onChange(Number(event.target.value))}
          />
          {advice ? (
            advice.recommended <= 0 ? (
              <p className="text-2xs text-muted-foreground">{t('tunnelForm.mtuAdvice.unknownUnderlay')}</p>
            ) : mismatched ? (
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-2xs text-warn">
                  {t('tunnelForm.mtuAdvice.mismatch', { recommended: advice.recommended })}
                </p>
                <Button size="sm" variant="secondary" onClick={() => onChange(advice.recommended)}>
                  {t('tunnelForm.mtuAdvice.useRecommended', { value: advice.recommended })}
                </Button>
              </div>
            ) : (
              <p className="flex items-center gap-1 text-2xs text-ok">
                <Check className="size-3" aria-hidden="true" />
                {t('tunnelForm.mtuAdvice.matches')}
              </p>
            )
          ) : null}
          {advice?.underlay_device ? (
            <p className="text-2xs text-muted-foreground">
              {t('tunnelForm.mtuAdvice.underlay', {
                device: advice.underlay_device,
                mtu: advice.underlay_mtu,
              })}
            </p>
          ) : null}
        </div>
      )}
    </Field>
  )
}

function AddressingSection({
  form,
  set,
  manual,
  onManualChange,
  pools,
  errors,
}: {
  form: FormState
  set: <K extends keyof FormState>(key: K, value: FormState[K]) => void
  manual: boolean
  onManualChange: (value: boolean) => void
  pools: PoolResponse[]
  errors: Record<string, string>
}) {
  const { t } = useTranslation()
  const primary = form.addresses[0]

  return (
    <div className="space-y-3 rounded-md border border-border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-medium">{t('tunnelForm.addressing.mode')}</span>
        <div className="inline-flex rounded-full border border-border/60 bg-surface-sunken p-0.5 text-2xs">
          {(
            [
              [false, 'tunnelForm.addressing.automatic'],
              [true, 'tunnelForm.addressing.manual'],
            ] as const
          ).map(([value, labelKey]) => (
            <button
              key={String(value)}
              type="button"
              aria-pressed={manual === value}
              onClick={() => {
                onManualChange(value)
                if (value) {
                  set('address_pool_id', null)
                } else {
                  set('addresses', [])
                  set('address_pool_id', pools[0]?.address_pool_id ?? null)
                }
              }}
              className={
                manual === value
                  ? 'rounded-full bg-ink px-2.5 py-1 font-medium text-ink-foreground shadow-sm'
                  : 'rounded-full px-2.5 py-1 text-muted-foreground hover:text-foreground'
              }
            >
              {t(labelKey)}
            </button>
          ))}
        </div>
      </div>

      {manual ? (
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label={t('tunnel.fields.address')} error={errors['addresses']} required>
            {(props) => (
              <TechnicalInput
                {...props}
                value={primary?.address ?? ''}
                onChange={(event) =>
                  set('addresses', [
                    {
                      address: event.target.value,
                      prefix_length: primary?.prefix_length ?? 30,
                      peer_address: primary?.peer_address,
                      is_primary: true,
                    },
                  ])
                }
                placeholder="10.77.0.1"
              />
            )}
          </Field>
          <Field label={t('tunnel.fields.prefixLength')}>
            {(props) => (
              <TechnicalInput
                {...props}
                inputMode="numeric"
                value={primary?.prefix_length ?? 30}
                onChange={(event) =>
                  set('addresses', [
                    {
                      address: primary?.address ?? '',
                      prefix_length: Number(event.target.value),
                      peer_address: primary?.peer_address,
                      is_primary: true,
                    },
                  ])
                }
              />
            )}
          </Field>
          <Field label={t('tunnel.fields.peerAddress')}>
            {(props) => (
              <TechnicalInput
                {...props}
                value={primary?.peer_address ?? ''}
                onChange={(event) =>
                  set('addresses', [
                    {
                      address: primary?.address ?? '',
                      prefix_length: primary?.prefix_length ?? 30,
                      peer_address: event.target.value,
                      is_primary: true,
                    },
                  ])
                }
                placeholder="10.77.0.2"
              />
            )}
          </Field>
        </div>
      ) : pools.length ? (
        <Field label={t('tunnelForm.addressing.pool')} error={errors['address_pool_id']}>
          {(props) => (
            <Select
              id={props.id}
              value={String(form.address_pool_id ?? pools[0]?.address_pool_id ?? '')}
              onValueChange={(value) => set('address_pool_id', Number(value))}
              options={pools.map((pool) => ({
                value: String(pool.address_pool_id),
                label: (
                  <span className="flex items-center gap-2">
                    <span>{pool.address_pool_title}</span>
                    <Technical className="text-2xs text-muted-foreground">{pool.cidr}</Technical>
                    {pool.is_public_range ? <Badge tone="warn">{t('settings.pools.publicRange')}</Badge> : null}
                  </span>
                ),
                description: t('settings.pools.capacity', {
                  used: pool.in_use,
                  total: pool.capacity.capacity,
                }),
                disabled: !pool.is_enabled,
              }))}
            />
          )}
        </Field>
      ) : (
        <p className="text-xs text-muted-foreground">{t('tunnelForm.addressing.noPools')}</p>
      )}

      {/* A pairing code brings the addresses the other end already committed
          to. They are kept even in automatic mode — the far end cannot be
          re-allocated — so they are shown rather than silently applied. */}
      {!manual && primary?.address ? (
        <p className="text-xs text-muted-foreground">
          {t('tunnelForm.addressing.pinned')}{' '}
          <Technical>
            {primary.address}/{primary.prefix_length}
          </Technical>
          {primary.peer_address ? (
            <>
              {' → '}
              <Technical>{primary.peer_address}</Technical>
            </>
          ) : null}
        </p>
      ) : null}
    </div>
  )
}

// ---------------------------------------------------------------- form state

function numberOf(value: unknown): number | undefined {
  return typeof value === 'number' ? value : undefined
}

function blankOverrides(): MonitorOverrides {
  return {
    monitor_interval_seconds: null,
    monitor_timeout_seconds: null,
    monitor_packet_size: null,
    monitor_window_size: null,
    monitor_degraded_loss_percent: null,
    monitor_down_loss_percent: null,
    monitor_degraded_rtt_ms: null,
    monitor_state_change_samples: null,
    monitor_target: null,
  }
}

/**
 * A new tunnel's starting values, from the panel's own settings.
 *
 * The defaults the backend ships with are the reference script's — MTU 1472,
 * TTL 255 — and every one of them is editable both here and globally in
 * settings.
 *
 * The GRE key is the exception and is drawn fresh every time. The kernel tells
 * two tunnels between the same pair of endpoints apart by their keys, so a
 * default one is a default collision: it works for the first tunnel and then
 * has to be changed by hand for every one after it, at the moment the operator
 * has least reason to expect a number they never touched to be the problem.
 */
function defaultsFrom(settings: Record<string, unknown>, used?: Set<number>): FormState {
  const number = (key: string, fallback: number) => numberOf(settings[key]) ?? fallback
  const boolean = (key: string, fallback: boolean) =>
    typeof settings[key] === 'boolean' ? (settings[key] as boolean) : fallback
  const text = (key: string, fallback: string) =>
    typeof settings[key] === 'string' ? (settings[key] as string) : fallback

  const key = randomGreKey(used)

  return {
    ...blankOverrides(),
    tunnel_type_id: number('tunnel.default_type', TunnelType.GRE),
    tunnel_side_id: TunnelSide.A,
    persistence_type_id: number('tunnel.default_persistence', PersistenceType.Systemd),
    interface_name: '',
    display_name: '',
    tunnel_number: null,
    local_endpoint: '',
    remote_endpoint: '',
    ttl: number('tunnel.default_ttl', 255),
    tos: text('tunnel.default_tos', 'inherit'),
    mtu: number('tunnel.default_mtu', 1472),
    ikey: key,
    okey: key,
    has_input_checksum: boolean('tunnel.default_csum', false),
    has_output_checksum: boolean('tunnel.default_csum', false),
    has_input_sequence: boolean('tunnel.default_seq', false),
    has_output_sequence: boolean('tunnel.default_seq', false),
    is_path_mtu_discovery: boolean('tunnel.default_pmtudisc', false),
    is_ignore_df: false,
    fwmark: null,
    tx_queue_length: null,
    hop_limit: null,
    encap_limit: null,
    address_pool_id: numberOf(settings['addressing.default_pool_id']) ?? null,
    addresses: [],
    is_enabled: true,
  }
}

function formFromTunnel(tunnel: Tunnel): FormState {
  return {
    tunnel_id: tunnel.tunnel_id,
    tunnel_type_id: tunnel.tunnel_type_id,
    tunnel_side_id: tunnel.tunnel_side_id,
    persistence_type_id: tunnel.persistence_type_id,
    interface_name: tunnel.interface_name,
    display_name: tunnel.display_name ?? '',
    tunnel_number: tunnel.tunnel_number,
    local_endpoint: tunnel.local_endpoint,
    remote_endpoint: tunnel.remote_endpoint,
    bind_device: tunnel.bind_device ?? undefined,
    ttl: tunnel.ttl,
    tos: tunnel.tos,
    mtu: tunnel.mtu,
    ikey: tunnel.ikey,
    okey: tunnel.okey,
    has_input_checksum: tunnel.has_input_checksum,
    has_output_checksum: tunnel.has_output_checksum,
    has_input_sequence: tunnel.has_input_sequence,
    has_output_sequence: tunnel.has_output_sequence,
    is_path_mtu_discovery: tunnel.is_path_mtu_discovery,
    is_ignore_df: tunnel.is_ignore_df,
    fwmark: tunnel.fwmark,
    tx_queue_length: tunnel.tx_queue_length,
    hop_limit: tunnel.hop_limit,
    encap_limit: tunnel.encap_limit,
    address_pool_id: tunnel.address_pool_id,
    addresses: (tunnel.addresses ?? []).map((address) => ({
      address: address.address,
      prefix_length: address.prefix_length,
      peer_address: address.peer_address ?? undefined,
      is_primary: address.is_primary,
    })),
    is_enabled: tunnel.is_enabled,
    monitor_interval_seconds: tunnel.monitor_interval_seconds,
    monitor_timeout_seconds: tunnel.monitor_timeout_seconds,
    monitor_packet_size: tunnel.monitor_packet_size,
    monitor_window_size: tunnel.monitor_window_size,
    monitor_degraded_loss_percent: tunnel.monitor_degraded_loss_percent,
    monitor_down_loss_percent: tunnel.monitor_down_loss_percent,
    monitor_degraded_rtt_ms: tunnel.monitor_degraded_rtt_ms,
    monitor_state_change_samples: tunnel.monitor_state_change_samples,
    monitor_target: tunnel.monitor_target,
  }
}

/**
 * The request body.
 *
 * Empty strings are dropped rather than sent: the backend distinguishes a field
 * that was not mentioned from one explicitly set to nothing, and an empty
 * interface name means "render it from the template", not "name it the empty
 * string".
 */
export function toPatch(form: FormState, manual: boolean): Record<string, unknown> {
  const patch: Record<string, unknown> = {
    tunnel_type_id: form.tunnel_type_id,
    tunnel_side_id: form.tunnel_side_id,
    persistence_type_id: form.persistence_type_id,
    local_endpoint: form.local_endpoint,
    remote_endpoint: form.remote_endpoint,
    ttl: form.ttl,
    tos: form.tos,
    mtu: form.mtu,
    ikey: form.ikey,
    okey: form.okey,
    has_input_checksum: form.has_input_checksum,
    has_output_checksum: form.has_output_checksum,
    has_input_sequence: form.has_input_sequence,
    has_output_sequence: form.has_output_sequence,
    is_path_mtu_discovery: form.is_path_mtu_discovery,
    is_ignore_df: form.is_ignore_df,
    is_enabled: form.is_enabled,
    // Always sent, unlike interface_name/bind_device below: display_name has
    // no "leave it alone" empty meaning, so clearing the field in the form
    // must clear it on the tunnel too.
    display_name: form.display_name ?? '',
  }

  if (form.interface_name) patch.interface_name = form.interface_name
  if (form.bind_device) patch.bind_device = form.bind_device

  if (manual) {
    patch.address_pool_id = null
    patch.addresses = form.addresses.filter((address) => address.address)
  } else {
    if (form.address_pool_id !== null) patch.address_pool_id = form.address_pool_id
    // Automatic addressing means "let the panel allocate", not "discard what
    // the form already holds". A pairing code arrives carrying both the pool
    // and the exact addresses the other end already committed to, and dropping
    // them here made this end allocate its own subnet — the two ends came up
    // healthy and carried nothing, which is the mismatch the pairing code
    // exists to prevent. The backend allocates only when no address is given,
    // so sending them pins the pair while keeping the tunnel in its pool.
    const explicit = form.addresses.filter((address) => address.address)
    if (explicit.length > 0) patch.addresses = explicit
    // The number picks the subnet and renders the name; both ends must agree.
    if (form.tunnel_number !== null && form.tunnel_number !== undefined) {
      patch.tunnel_number = form.tunnel_number
    }
  }

  // The monitoring overrides. null is meaningful rather than absent: it is how
  // a tunnel says "inherit the global", which the API tells apart from a field
  // the request never mentioned, so every one of them is always sent.
  patch.monitor_interval_seconds = form.monitor_interval_seconds
  patch.monitor_timeout_seconds = form.monitor_timeout_seconds
  patch.monitor_packet_size = form.monitor_packet_size
  patch.monitor_window_size = form.monitor_window_size
  patch.monitor_degraded_loss_percent = form.monitor_degraded_loss_percent
  patch.monitor_down_loss_percent = form.monitor_down_loss_percent
  patch.monitor_degraded_rtt_ms = form.monitor_degraded_rtt_ms
  patch.monitor_state_change_samples = form.monitor_state_change_samples

  return patch
}

/**
 * A GRE key nothing on this server is already using.
 *
 * The key is what the kernel tells two tunnels between the same pair of
 * endpoints apart, so a fresh one has to be picked for every tunnel and picking
 * it by hand is a coin flip an operator should not be asked to make. It comes
 * from the platform's own generator rather than Math.random because there is no
 * reason for it not to, and it is drawn again on a collision rather than
 * incremented, which would walk straight into the next taken one.
 */
export function randomGreKey(used: Set<number> = new Set()): number {
  const buffer = new Uint32Array(1)
  for (let attempt = 0; attempt < 32; attempt++) {
    crypto.getRandomValues(buffer)
    // Zero means "no key" to the kernel, so it is never what is meant here.
    const value = buffer[0] === 0 ? 1 : buffer[0]
    if (!used.has(value)) return value
  }
  return buffer[0] || 1
}

/**
 * The addresses this server has, offered under the local endpoint.
 *
 * A GRE tunnel's local endpoint has to be an address the host actually holds,
 * so this is not a list of suggestions -- it is the whole of the valid answer.
 * The globally routable ones come first because they are what a tunnel to
 * another site is almost always built on; the private ones are still shown,
 * because a tunnel across a datacentre's own network is a real thing and
 * hiding its endpoints would be deciding for the operator.
 */
function LocalAddressPicker({
  interfaces,
  selected,
  onPick,
}: {
  interfaces: HostInterface[]
  selected: string
  onPick: (address: string) => void
}) {
  const { t } = useTranslation()

  const addresses = useMemo(() => {
    const seen = new Set<string>()
    const out: { address: string; iface: string; routable: boolean }[] = []
    for (const iface of interfaces) {
      for (const entry of iface.addresses ?? []) {
        const address = entry.address.split('/')[0]
        if (!address || seen.has(address) || !isOfferableAddress(address)) continue
        seen.add(address)
        out.push({ address, iface: iface.name, routable: isRoutableAddress(address) })
      }
    }
    // Routable first, and stable within each group so the list does not
    // reshuffle between renders.
    return out.sort((a, b) => Number(b.routable) - Number(a.routable))
  }, [interfaces])

  if (!addresses.length) return null

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {addresses.map((entry) => (
        <button
          key={entry.address}
          type="button"
          onClick={() => onPick(entry.address)}
          aria-pressed={selected === entry.address}
          title={entry.iface}
          className={cn(
            'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-2xs transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            selected === entry.address
              ? 'bg-ink text-ink-foreground'
              : 'bg-muted text-muted-foreground hover:text-foreground',
          )}
        >
          <Technical className="text-2xs">{entry.address}</Technical>
          {!entry.routable ? (
            <span className="opacity-70">{t('tunnelForm.privateAddress')}</span>
          ) : null}
        </button>
      ))}
    </div>
  )
}

/**
 * Whether an address is worth offering as a local endpoint at all.
 *
 * Loopback and link-local are addresses the host holds and can never build a
 * tunnel on, so offering them would be offering a mistake.
 */
function isOfferableAddress(address: string): boolean {
  if (address.startsWith('127.') || address === '::1') return false
  if (address.startsWith('169.254.')) return false
  if (address.toLowerCase().startsWith('fe80')) return false
  return true
}

/** Whether an address is globally routable, which decides the order above. */
function isRoutableAddress(address: string): boolean {
  const parts = address.split('.')
  if (parts.length === 4) {
    const [a, b] = parts.map(Number)
    if (a === 10) return false
    if (a === 172 && b >= 16 && b <= 31) return false
    if (a === 192 && b === 168) return false
    if (a === 100 && b >= 64 && b <= 127) return false
    return true
  }
  const lower = address.toLowerCase()
  // fc00::/7 is the IPv6 equivalent of the ranges above.
  return !(lower.startsWith('fc') || lower.startsWith('fd'))
}
