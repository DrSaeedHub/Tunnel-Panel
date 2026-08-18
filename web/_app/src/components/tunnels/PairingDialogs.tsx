import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '@tanstack/react-query'

import { api } from '@/lib/api'
import type { FromPairingCodeResponse, PairingCodeResponse, TunnelInput } from '@/lib/types'
import { TunnelSide } from '@/lib/types'
import { Button } from '../ui/button'
import { Field, Textarea } from '../ui/form'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/overlay'
import { ErrorState, Skeleton } from '../ui/feedback'
import { CopyButton, Technical, TechnicalBlock } from '../ui/technical'

/**
 * The pairing code for a tunnel just created.
 *
 * It has to travel to the other server, and retyping a base64 blob by hand is
 * how the wrong key ends up on one end. The QR code is generated in the
 * browser and loaded on demand, so the encoder is not in the bundle an
 * operator downloads to look at a dashboard.
 */
export function PairingCodeDialog({
  tunnelId,
  open,
  onOpenChange,
}: {
  tunnelId: number
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const [qr, setQr] = useState<string | null>(null)

  const codeQuery = useQuery({
    queryKey: ['tunnels', tunnelId, 'pairing-code'],
    queryFn: () => api.get<PairingCodeResponse>(`/tunnels/${tunnelId}/pairing-code`),
    enabled: open,
    staleTime: 60_000,
  })

  const code = codeQuery.data?.pairing_code

  useEffect(() => {
    if (!code) {
      setQr(null)
      return
    }
    let cancelled = false
    void import('qrcode').then(async (module) => {
      try {
        const url = await module.default.toDataURL(code, { margin: 1, width: 240, errorCorrectionLevel: 'M' })
        if (!cancelled) setQr(url)
      } catch {
        if (!cancelled) setQr(null)
      }
    })
    return () => {
      cancelled = true
    }
  }, [code])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('pairing.title')}</DialogTitle>
          <DialogDescription>{t('pairing.body')}</DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {codeQuery.isLoading ? (
            <Skeleton className="h-40" />
          ) : codeQuery.error ? (
            <ErrorState error={codeQuery.error} onRetry={() => void codeQuery.refetch()} compact />
          ) : code ? (
            <>
              <div className="flex flex-col items-center gap-3">
                {qr ? (
                  <img
                    src={qr}
                    alt={t('pairing.qrAlt')}
                    className="rounded-md border border-border bg-white p-2"
                    width={240}
                    height={240}
                  />
                ) : (
                  <Skeleton className="size-60" />
                )}
                <p className="text-2xs text-muted-foreground">{t('pairing.qrTitle')}</p>
              </div>

              <div className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium">{t('pairing.codeLabel')}</span>
                  <CopyButton value={code} label={t('pairing.copy')} />
                </div>
                <TechnicalBlock className="max-h-32 whitespace-pre-wrap break-all">{code}</TechnicalBlock>
              </div>

              <p className="text-2xs text-muted-foreground">{codeQuery.data?.note ?? t('pairing.note')}</p>
            </>
          ) : null}
        </DialogBody>

        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            {t('actions.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/**
 * Importing the other end's pairing code.
 *
 * The backend decodes it and flips the side; nothing is created until the
 * operator has seen the decoded values and submitted them through the ordinary
 * create form, preview and all.
 */
export function ImportPairingCodeDialog({
  open,
  onOpenChange,
  onDecoded,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onDecoded: (input: TunnelInput) => void
}) {
  const { t } = useTranslation()
  const [code, setCode] = useState('')

  useEffect(() => {
    if (!open) setCode('')
  }, [open])

  const decodeMutation = useMutation({
    mutationFn: () => api.post<FromPairingCodeResponse>('/tunnels/from-pairing-code', { pairing_code: code.trim() }),
  })

  const decoded = decodeMutation.data

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('pairing.importTitle')}</DialogTitle>
          <DialogDescription>{t('pairing.importBody')}</DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          <Field label={t('pairing.codeLabel')}>
            {(props) => (
              <Textarea
                {...props}
                dir="ltr"
                className="technical min-h-24 text-xs"
                value={code}
                onChange={(event) => setCode(event.target.value)}
                spellCheck={false}
              />
            )}
          </Field>

          {decodeMutation.error ? (
            <ErrorState error={decodeMutation.error} compact />
          ) : null}

          {decoded ? (
            <div className="space-y-2 rounded-md border border-border bg-surface-sunken p-3">
              <p className="text-xs font-medium">{t('pairing.decoded')}</p>
              <dl className="grid gap-x-4 gap-y-1 text-2xs sm:grid-cols-2">
                <Pair label={t('tunnel.fields.localEndpoint')} value={decoded.tunnel.local_endpoint} />
                <Pair label={t('tunnel.fields.remoteEndpoint')} value={decoded.tunnel.remote_endpoint} />
                {/* The side is the one value on this screen the operator is
                    here to check -- the whole point of the flip -- so show the
                    label, not the lookup id it happens to be stored as. */}
                <Pair
                  label={t('tunnel.fields.side')}
                  value={
                    decoded.tunnel.tunnel_side_id === TunnelSide.A
                      ? t('tunnel.side.a')
                      : t('tunnel.side.b')
                  }
                />
                <Pair label={t('tunnel.fields.mtu')} value={String(decoded.tunnel.mtu)} />
                <Pair label={t('tunnel.fields.key')} value={String(decoded.tunnel.ikey ?? '')} />
                <Pair label={t('tunnel.fields.ttl')} value={String(decoded.tunnel.ttl)} />
                {(decoded.tunnel.addresses ?? []).map((address) => (
                  <Pair
                    key={address.address}
                    label={t('tunnel.fields.address')}
                    value={`${address.address}/${address.prefix_length}`}
                  />
                ))}
              </dl>
              <p className="text-2xs text-muted-foreground">{decoded.note || t('pairing.decodedNote')}</p>
            </div>
          ) : null}
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          {decoded ? (
            <Button
              variant="primary"
              onClick={() => {
                onDecoded(decoded.tunnel)
                onOpenChange(false)
              }}
            >
              {t('pairing.createFromCode')}
            </Button>
          ) : (
            <Button
              variant="primary"
              disabled={!code.trim()}
              loading={decodeMutation.isPending}
              onClick={() => decodeMutation.mutate()}
            >
              {t('pairing.decode')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Pair({ label, value }: { label: string; value: string }) {
  if (!value) return null
  return (
    <div className="flex items-baseline gap-2">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd>
        <Technical className="text-2xs">{value}</Technical>
      </dd>
    </div>
  )
}
