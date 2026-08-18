import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle } from 'lucide-react'

import { api } from '@/lib/api'
import { ReconcileStatus, type ReconcileItem, type ReconcileReport } from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, describeError } from '../ui/feedback'
import { Technical } from '../ui/technical'

/**
 * What the panel and the server disagree about.
 *
 * A tunnel can be Up and still wrong: drifted means the interface no longer
 * matches what is stored, missing means it is gone, and inconsistent means a
 * previous apply half-completed. None of that is visible in monitoring state,
 * which is why it gets its own card rather than a colour on a row.
 *
 * The card is absent entirely when everything agrees, so it means something
 * when it appears.
 */
export function AttentionCard() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const reconcileQuery = useQuery({
    queryKey: ['reconcile'],
    queryFn: () => api.get<ReconcileReport>('/reconcile'),
    staleTime: 30_000,
  })

  /**
   * The actions the report offers, each actually reachable.
   *
   * Only reapply was ever wired, and reapply needs a tunnel_id, which an
   * unmanaged interface does not have — so the card told an operator to "Adopt
   * it to manage it here, or ignore it if something else owns it" beside no
   * control at all. The endpoints and the wording were both already there.
   *
   * Driven off item.actions rather than a hardcoded list, so an action the
   * backend starts offering appears here without a change.
   */
  const act = useMutation({
    mutationFn: ({ action, item }: { action: ReconcileAction; item: ReconcileItem }) => {
      switch (action) {
        case 'adopt':
          return api.post('/reconcile/adopt', { interface_name: item.interface_name })
        case 'ignore':
          return api.post('/reconcile/ignore', { interface_name: item.interface_name, ignored: true })
        case 'unignore':
          return api.post('/reconcile/ignore', { interface_name: item.interface_name, ignored: false })
        case 'forget':
          return api.post(`/reconcile/${item.tunnel_id}/forget`, {})
        default:
          return api.post(`/reconcile/${item.tunnel_id}/reapply`, {})
      }
    },
    // Invalidation in onSettled, not onSuccess: a failed action can still have
    // changed what the report says, and leaving the card showing the state from
    // before is how a rule that had really been applied kept reading as absent.
    onSettled: async () => {
      await queryClient.invalidateQueries({ queryKey: ['reconcile'] })
      await queryClient.invalidateQueries({ queryKey: ['tunnels'] })
      await queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
    onSuccess: (_result, { action }) => toast({ tone: 'success', title: t(`reconcile.${action}`) }),
    onError: (error, { action }) =>
      toast({
        tone: 'error',
        title: t(`reconcile.${action}`),
        description: describeError(error, t).message,
      }),
  })

  const items = (reconcileQuery.data?.items ?? []).filter(
    (item) => item.reconcile_status_id !== ReconcileStatus.InSync && !item.is_ignored,
  )

  if (reconcileQuery.isLoading || !items.length) return null

  return (
    <Card className="border-warn/40">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-warn">
          <AlertTriangle className="size-4" aria-hidden="true" />
          {t('reconcile.title')}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <AttentionRow
              key={item.interface_name}
              item={item}
              busy={act.isPending}
              onAct={(action) => act.mutate({ action, item })}
            />
          ))}
        </ul>
      </CardContent>
    </Card>
  )
}

/**
 * The actions this card offers. `delete` is deliberately not among them: it
 * destroys an interface and the specification requires a typed confirmation for
 * that, which belongs on the tunnel's own page, and the row already links there.
 */
const ROW_ACTIONS = ['adopt', 'reapply', 'forget', 'ignore', 'unignore'] as const
type ReconcileAction = (typeof ROW_ACTIONS)[number]

function AttentionRow({
  item,
  busy,
  onAct,
}: {
  item: ReconcileItem
  busy: boolean
  onAct: (action: ReconcileAction) => void
}) {
  const { t } = useTranslation()

  const statusKey =
    {
      [ReconcileStatus.InSync]: 'InSync',
      [ReconcileStatus.Drifted]: 'Drifted',
      [ReconcileStatus.Missing]: 'Missing',
      [ReconcileStatus.Unmanaged]: 'Unmanaged',
      [ReconcileStatus.Inconsistent]: 'Inconsistent',
    }[item.reconcile_status_id] ?? 'Drifted'

  const tone = item.reconcile_status_id === ReconcileStatus.Inconsistent ? 'danger' : 'warn'

  return (
    <li className="flex flex-wrap items-start justify-between gap-3 py-2.5">
      <div className="min-w-0">
        <p className="flex flex-wrap items-center gap-2 text-sm">
          {item.tunnel_id ? (
            <Link to={`/tunnels/${item.tunnel_id}`} className="font-medium hover:underline">
              <Technical>{item.interface_name}</Technical>
            </Link>
          ) : (
            <Technical className="font-medium">{item.interface_name}</Technical>
          )}
          <Badge tone={tone}>{t(`reconcile.status.${statusKey}`)}</Badge>
        </p>
        <p className="mt-0.5 text-xs text-muted-foreground">{item.detail}</p>

        {item.diffs?.length ? (
          <ul className="mt-1 space-y-0.5">
            {(item.diffs ?? []).map((diff) => (
              <li key={diff.field} className="flex flex-wrap items-center gap-1.5 text-2xs">
                <span className="text-muted-foreground">{diff.field}</span>
                <span className="text-muted-foreground">{t('reconcile.expected')}</span>
                <Technical className="text-2xs">{diff.expected}</Technical>
                <span className="text-muted-foreground">{t('reconcile.observed')}</span>
                <Technical className="text-2xs">{diff.observed}</Technical>
              </li>
            ))}
          </ul>
        ) : null}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {ROW_ACTIONS.filter((action) => item.actions.includes(action))
          // reapply and forget address a tunnel the panel has a record of; adopt
          // and ignore address an interface it does not. Neither is reachable
          // without the corresponding identifier.
          .filter((action) => (action === 'reapply' || action === 'forget' ? !!item.tunnel_id : true))
          .map((action) => (
            <Button
              key={action}
              variant={action === 'adopt' ? 'primary' : 'secondary'}
              size="sm"
              loading={busy}
              onClick={() => onAct(action)}
            >
              {t(`reconcile.${action}`)}
            </Button>
          ))}
      </div>
    </li>
  )
}
