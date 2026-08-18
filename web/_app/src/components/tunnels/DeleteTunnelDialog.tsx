import { useEffect, useState } from 'react'
import { Trans, useTranslation } from 'react-i18next'
import { AlertTriangle } from 'lucide-react'

import { ApiError } from '@/lib/api'
import { PersistenceType, type Tunnel } from '@/lib/types'
import { useTunnelActions } from '@/hooks/useTunnelActions'
import { Button } from '../ui/button'
import { Checkbox, Field, TechnicalInput } from '../ui/form'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/overlay'
import { Technical } from '../ui/technical'
import { TunnelRoutesWarning } from '../routes/TunnelRoutesCard'

/**
 * Deleting a tunnel.
 *
 * Three things make this different from every other action. The dialog states
 * exactly what will be removed rather than asking a generic "are you sure".
 * The operator has to type the tunnel's name, so the confirmation cannot be
 * clicked through by reflex. And when the backend refuses because the tunnel
 * carries the operator's own connection, that refusal becomes a prominent
 * second acknowledgement instead of an error they have to decipher.
 */
export function DeleteTunnelDialog({
  tunnel,
  open,
  onOpenChange,
  onDeleted,
}: {
  tunnel: Tunnel
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: () => void
}) {
  const { t } = useTranslation()
  const actions = useTunnelActions()

  const [typed, setTyped] = useState('')
  const [wouldCutAccess, setWouldCutAccess] = useState<string | null>(null)
  const [acknowledged, setAcknowledged] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!open) {
      setTyped('')
      setWouldCutAccess(null)
      setAcknowledged(false)
      setSubmitting(false)
    }
  }, [open])

  const nameMatches = typed.trim() === tunnel.interface_name
  const blocked = wouldCutAccess !== null && !acknowledged

  const submit = async () => {
    if (!nameMatches || blocked || submitting) return
    setSubmitting(true)
    try {
      const done = await actions.remove(tunnel.tunnel_id, tunnel.interface_name, {
        iUnderstandIMayLoseAccess: acknowledged,
      })
      if (done) {
        onOpenChange(false)
        onDeleted?.()
      }
    } catch (error) {
      // The backend guards this rather than the browser, because only it knows
      // which address the request arrived on.
      if (error instanceof ApiError && error.code === 'WOULD_CUT_OWN_ACCESS') {
        setWouldCutAccess(error.message)
      }
    } finally {
      setSubmitting(false)
    }
  }

  const removals = [
    t('deleteDialog.removes.interface', { name: tunnel.interface_name }),
    tunnel.persistence_type_id !== PersistenceType.Runtime ? t('deleteDialog.removes.units') : null,
    t('deleteDialog.removes.keepalive'),
    t('deleteDialog.removes.monitoring'),
  ].filter(Boolean) as string[]

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-danger">
            <AlertTriangle className="size-4" aria-hidden="true" />
            {t('deleteDialog.title', { name: tunnel.interface_name })}
          </DialogTitle>
          <DialogDescription>{t('deleteDialog.body')}</DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          <ul className="space-y-1.5 rounded-md border border-border bg-surface-sunken p-3 text-xs">
            {removals.map((item) => (
              <li key={item} className="flex gap-2">
                <span aria-hidden="true" className="text-muted-foreground">
                  •
                </span>
                <span>{item}</span>
              </li>
            ))}
          </ul>

          {/* Deleting a tunnel leaves the forwarding rules that relayed over
              it installed and correct, and removes the path they used. Naming
              them here is the difference between a deliberate change and a
              relay that quietly stopped (§10). */}
          <TunnelRoutesWarning tunnelId={tunnel.tunnel_id} />

          {wouldCutAccess ? (
            <div className="space-y-2 rounded-md border-2 border-danger bg-danger-muted p-3">
              <p className="flex items-center gap-2 text-sm font-semibold text-danger">
                <AlertTriangle className="size-4" aria-hidden="true" />
                {t('deleteDialog.ownConnectionTitle')}
              </p>
              <p className="text-xs">{t('deleteDialog.ownConnectionBody')}</p>
              <p className="text-2xs text-muted-foreground">{wouldCutAccess}</p>
              <label className="flex items-start gap-2 pt-1 text-xs font-medium">
                <Checkbox
                  checked={acknowledged}
                  onCheckedChange={(value) => setAcknowledged(value === true)}
                  className="mt-0.5"
                />
                {t('deleteDialog.ownConnectionAck')}
              </label>
            </div>
          ) : null}

          <Field
            label={
              <Trans
                i18nKey="deleteDialog.typeToConfirm"
                values={{ name: tunnel.interface_name }}
                components={{ 1: <Technical>{''}</Technical> }}
              />
            }
            error={typed.length > 0 && !nameMatches ? t('deleteDialog.typeMismatch') : undefined}
          >
            {(props) => (
              <TechnicalInput
                {...props}
                value={typed}
                onChange={(event) => setTyped(event.target.value)}
                placeholder={tunnel.interface_name}
                autoComplete="off"
              />
            )}
          </Field>
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          <Button variant="danger" disabled={!nameMatches || blocked} loading={submitting} onClick={() => void submit()}>
            {submitting ? t('deleteDialog.deleting') : t('deleteDialog.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
