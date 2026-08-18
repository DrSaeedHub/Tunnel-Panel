import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle } from 'lucide-react'

import type { RouteRule } from '@/lib/types'
import { useRouteActions } from '@/hooks/useRouteActions'
import { Button } from '../ui/button'
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../ui/overlay'
import { RouteFlow, endpointLabel } from './RouteFlow'

/**
 * Deleting a forwarding rule.
 *
 * The flow is repeated in the dialog rather than only the name, because the
 * name is what an operator chose and the flow is what actually stops working.
 */
export function DeleteRouteDialog({
  route,
  open,
  onOpenChange,
}: {
  route: RouteRule
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const actions = useRouteActions()
  const [forwardingOffer, setForwardingOffer] = useState(false)

  const primary = route.destinations[0]
  const bind = endpointLabel(route.bind_address || '0.0.0.0', route.bind_port, route.bind_port_range_end)
  const destination = primary
    ? endpointLabel(primary.address, primary.port, primary.port_range_end)
    : endpointLabel(route.destination_address, route.destination_port, route.destination_port_range_end)

  const remove = async () => {
    const report = await actions.remove(route.route_rule_id, route.route_rule_title)
    if (!report) return
    // The panel offers to revert IP forwarding and never does it by itself, so
    // the offer outlives the dialog that triggered it.
    if (report.forwarding_can_be_reverted) {
      setForwardingOffer(true)
      return
    }
    onOpenChange(false)
  }

  if (forwardingOffer) {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('deleteRoute.forwardingOffer.title')}</DialogTitle>
          </DialogHeader>
          <DialogBody>
            <p className="text-sm text-muted-foreground">{t('deleteRoute.forwardingOffer.body')}</p>
          </DialogBody>
          <DialogFooter>
            <Button variant="primary" onClick={() => onOpenChange(false)}>
              {t('actions.close')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t('deleteRoute.title', { name: route.route_rule_title })}</DialogTitle>
        </DialogHeader>
        <DialogBody className="space-y-3">
          <p className="text-sm text-muted-foreground">{t('deleteRoute.body')}</p>
          <div className="rounded-md border border-border bg-surface-sunken p-3">
            <RouteFlow bind={bind} destination={destination} />
          </div>
          {route.is_enabled ? (
            <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-muted p-3 text-xs">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
              {t('deleteRoute.body')}
            </p>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          <Button
            variant="danger"
            loading={actions.pending === route.route_rule_id}
            onClick={() => void remove()}
          >
            {t('deleteRoute.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
