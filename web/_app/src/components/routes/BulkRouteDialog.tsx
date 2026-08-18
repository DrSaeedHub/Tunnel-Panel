import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle } from 'lucide-react'

import type { RouteRule } from '@/lib/types'
import { useRouteActions } from '@/hooks/useRouteActions'
import { Button } from '../ui/button'
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '../ui/overlay'
import { RouteFlow, endpointLabel } from './RouteFlow'

export type BulkAction = 'enable' | 'disable' | 'delete'

/**
 * Enable, disable or delete several rules after one confirmation.
 *
 * Each rule is applied on its own, because the API has no bulk enable or
 * disable endpoint and every change is a transactional replacement of the whole
 * netfilter namespace. What that costs the operator is stated rather than
 * hidden: the dialog says the rules are applied in turn, and if one fails the
 * run stops there instead of leaving them to discover a half-applied set.
 */
export function BulkRouteDialog({
  action,
  routes,
  open,
  onOpenChange,
  onDone,
}: {
  action: BulkAction
  routes: RouteRule[]
  open: boolean
  onOpenChange: (open: boolean) => void
  onDone: () => void
}) {
  const { t } = useTranslation()
  const actions = useRouteActions()
  const [progress, setProgress] = useState<number | null>(null)
  const [failures, setFailures] = useState<string[]>([])

  const destructive = action === 'delete'
  const title = destructive
    ? t('routes.bulk.confirmDeleteTitle', { count: routes.length })
    : t('routes.bulk.confirmTitle', { count: routes.length })
  const body = {
    enable: t('routes.bulk.confirmEnable'),
    disable: t('routes.bulk.confirmDisable'),
    delete: t('routes.bulk.confirmDelete'),
  }[action]

  const run = async () => {
    setFailures([])
    const failed: string[] = []

    for (const [index, rule] of routes.entries()) {
      setProgress(index)
      const ok =
        action === 'delete'
          ? Boolean(await actions.remove(rule.route_rule_id, rule.route_rule_title))
          : await actions.run(rule.route_rule_id, action, rule.route_rule_title)
      if (!ok) {
        failed.push(rule.route_rule_title)
        // Stopping here keeps the outcome comprehensible: everything before
        // this rule is applied, everything after it is untouched.
        break
      }
    }

    setProgress(null)
    if (failed.length) {
      setFailures(failed)
      return
    }
    onDone()
  }

  const running = progress !== null

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
        </DialogHeader>
        <DialogBody className="space-y-3">
          <p className="text-sm text-muted-foreground">{body}</p>

          <ul className="max-h-56 space-y-1.5 overflow-auto rounded-md border border-border bg-surface-sunken p-3 scrollbar-thin">
            {routes.map((rule) => {
              const primary = rule.destinations[0]
              return (
                <li key={rule.route_rule_id} className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-medium">{rule.route_rule_title}</span>
                  <RouteFlow
                    size="sm"
                    bind={endpointLabel(rule.bind_address || '0.0.0.0', rule.bind_port, rule.bind_port_range_end)}
                    destination={
                      primary
                        ? endpointLabel(primary.address, primary.port, primary.port_range_end)
                        : endpointLabel(
                            rule.destination_address,
                            rule.destination_port,
                            rule.destination_port_range_end,
                          )
                    }
                  />
                </li>
              )
            })}
          </ul>

          <p className="text-2xs text-muted-foreground">{t('routes.bulk.sequential')}</p>

          {running ? (
            <p className="text-xs" role="status">
              {t('routes.bulk.progress', { done: (progress ?? 0) + 1, total: routes.length })}
            </p>
          ) : null}

          {failures.length ? (
            <p className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-muted p-3 text-xs text-danger" role="alert">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
              {t('routes.bulk.failed', { count: failures.length })} — {failures.join(', ')}
            </p>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)} disabled={running}>
            {t('actions.cancel')}
          </Button>
          <Button variant={destructive ? 'danger' : 'primary'} loading={running} onClick={() => void run()}>
            {destructive ? t('routes.bulk.delete') : t('actions.apply')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
