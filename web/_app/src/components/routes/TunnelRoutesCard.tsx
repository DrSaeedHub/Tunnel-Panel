import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { Waypoints } from 'lucide-react'

import { api } from '@/lib/api'
import type { TunnelRoutesResponse } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, EmptyState, ErrorState, Skeleton } from '../ui/feedback'
import { Technical } from '../ui/technical'
import { RouteFlow } from './RouteFlow'

/**
 * The forwarding rules relaying over one tunnel, on its detail page (§10).
 *
 * A tunnel is not only a link here — it is the path other things depend on, and
 * the operator about to restart it should be able to see what crosses it
 * without going to look.
 */
export function TunnelRoutesCard({ tunnelId }: { tunnelId: number }) {
  const { t } = useTranslation()

  const query = useQuery({
    queryKey: ['tunnels', tunnelId, 'routes'],
    queryFn: () => api.get<TunnelRoutesResponse>(`/tunnels/${tunnelId}/routes`),
    staleTime: 30_000,
  })

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle className="flex items-center gap-2">
            <Waypoints className="size-4 text-muted-foreground" aria-hidden="true" />
            {t('tunnelRoutes.title')}
          </CardTitle>
          {query.data?.peer_address ? (
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t('tunnelRoutes.peerAddress')}: <Technical className="text-xs">{query.data.peer_address}</Technical>
            </p>
          ) : null}
        </div>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-16" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
        ) : !(query.data?.routes ?? []).length ? (
          <EmptyState title={t('tunnelRoutes.empty')} />
        ) : (
          <div className="space-y-2">
            <ul className="divide-y divide-border rounded-md border border-border">
              {(query.data?.routes ?? []).map((dependant) => (
                <li key={dependant.route_rule_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 p-2">
                  <Link
                    to={`/routes/${dependant.route_rule_id}`}
                    className="min-w-0 flex-1 truncate text-xs font-medium hover:underline"
                  >
                    {dependant.title}
                  </Link>
                  <Badge>{dependant.protocol.toUpperCase()}</Badge>
                  {!dependant.is_enabled ? <Badge>{t('states.disabled')}</Badge> : null}
                  <RouteFlow size="sm" bind={dependant.bind} destination={dependant.destination} />
                </li>
              ))}
            </ul>
            <p className="text-2xs text-muted-foreground">{t('tunnelRoutes.note')}</p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * The same list, as the warning shown before a tunnel is taken away.
 *
 * It renders nothing when no enabled rule depends on the tunnel, so its
 * presence in a dialog always means something.
 */
export function TunnelRoutesWarning({ tunnelId }: { tunnelId: number }) {
  const { t } = useTranslation()

  const query = useQuery({
    queryKey: ['tunnels', tunnelId, 'routes'],
    queryFn: () => api.get<TunnelRoutesResponse>(`/tunnels/${tunnelId}/routes`),
    staleTime: 30_000,
  })

  const affected = (query.data?.routes ?? []).filter((dependant) => dependant.is_enabled)
  if (!affected.length) return null

  return (
    <div className="rounded-md border border-warn/40 bg-warn-muted p-3">
      <p className="text-xs font-medium">{t('tunnelRoutes.dependsWarning', { count: affected.length })}</p>
      <ul className="mt-1.5 space-y-1">
        {affected.map((dependant) => (
          <li key={dependant.route_rule_id} className="flex flex-wrap items-center gap-2 text-2xs">
            <span className="font-medium">{dependant.title}</span>
            <RouteFlow size="sm" bind={dependant.bind} destination={dependant.destination} />
          </li>
        ))}
      </ul>
      <p className="mt-1.5 text-2xs text-muted-foreground">{t('tunnelRoutes.note')}</p>
    </div>
  )
}
