import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, RefreshCw } from 'lucide-react'

import { api } from '@/lib/api'
import type { RouteConnectionList } from '@/lib/types'
import { formatCount, formatDuration, formatVolume } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Badge, EmptyState, ErrorState, Skeleton } from '../ui/feedback'
import { Technical } from '../ui/technical'

/**
 * The live connections crossing one rule.
 *
 * This is what an operator actually wants when they ask "is anyone using it",
 * so it lists the flows rather than counting them. The distinction that matters
 * is between an empty table and an unreadable one: a host where connection
 * tracking cannot be read says so, because presenting that as "nobody is
 * connected" would be a wrong answer rather than a missing one.
 */
export function RouteConnectionsPanel({ routeRuleId }: { routeRuleId: number }) {
  const { t } = useTranslation()
  const { digits, language, units } = usePreferences()

  const query = useQuery({
    queryKey: ['routes', routeRuleId, 'connections'],
    queryFn: () => api.get<RouteConnectionList>(`/routes/${routeRuleId}/connections`),
    // Reading the conntrack table is expensive on a busy host, so this is
    // polled slowly and on demand rather than streamed.
    refetchInterval: 10_000,
  })

  const list = query.data
  const durationLabels = {
    day: t('units.day'),
    hour: t('units.hour'),
    minute: t('units.minute'),
    second: t('units.second'),
  }

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>{t('routeDetail.connections.title')}</CardTitle>
          {list?.available ? (
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t('routeDetail.connections.total', { count: list.total })}
              {list.reader ? ` · ${t('routeDetail.connections.reader', { name: list.reader })}` : ''}
            </p>
          ) : null}
        </div>
        <Button
          variant="ghost"
          size="sm"
          loading={query.isFetching}
          onClick={() => void query.refetch()}
          aria-label={t('actions.refresh')}
        >
          <RefreshCw className="size-4" aria-hidden="true" />
        </Button>
      </CardHeader>
      <CardContent>
        {query.isLoading ? (
          <div className="space-y-2">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-24" />
          </div>
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
        ) : !list?.available ? (
          <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-muted p-3 text-xs">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
            <span>
              {t('routeDetail.connections.unavailable')}
              {list?.detail ? <span className="block text-2xs text-muted-foreground">{list.detail}</span> : null}
            </span>
          </p>
        ) : !(list.connections ?? []).length ? (
          <EmptyState title={t('routeDetail.connections.empty')} body={list.detail} />
        ) : (
          <div className="space-y-3">
            <div className="max-h-80 overflow-auto rounded-md border border-border scrollbar-thin">
              <table className="w-full text-2xs">
                <caption className="sr-only">{t('routeDetail.connections.title')}</caption>
                <thead className="sticky top-0 bg-surface-sunken">
                  <tr>
                    <th scope="col" className="p-2 text-start font-medium">
                      {t('routeDetail.connections.source')}
                    </th>
                    <th scope="col" className="p-2 text-start font-medium">
                      {t('routeDetail.connections.destination')}
                    </th>
                    <th scope="col" className="p-2 text-start font-medium">
                      {t('routeDetail.connections.state')}
                    </th>
                    <th scope="col" className="p-2 text-start font-medium">
                      {t('routeDetail.connections.age')}
                    </th>
                    <th scope="col" className="p-2 text-start font-medium">
                      {t('routeDetail.connections.bytes')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {(list.connections ?? []).map((flow, index) => (
                    <tr key={`${flow.source_address}:${flow.source_port}-${index}`}>
                      <td className="p-2">
                        <Technical className="text-2xs">
                          {`${flow.source_address}:${flow.source_port}`}
                        </Technical>
                      </td>
                      <td className="p-2">
                        <Technical className="text-2xs">
                          {`${flow.destination_address}:${flow.destination_port}`}
                        </Technical>
                      </td>
                      <td className="p-2">
                        {/* UDP has no transport state; inventing one would be
                            worse than the dash. */}
                        {flow.state ? (
                          <Badge>{flow.state}</Badge>
                        ) : (
                          <span className="text-muted-foreground">{t('routeDetail.connections.noState')}</span>
                        )}
                      </td>
                      <td className="tabular p-2">
                        {flow.age_seconds
                          ? formatDuration(flow.age_seconds, digits, durationLabels)
                          : t('routeDetail.connections.noState')}
                      </td>
                      <td className="tabular p-2">
                        {formatVolume(flow.rx_bytes, units).text} / {formatVolume(flow.tx_bytes, units).text}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {list.by_source && Object.keys(list.by_source).length > 1 ? (
              <div className="flex flex-wrap gap-2">
                {Object.entries(list.by_source)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([source, count]) => (
                    <Badge key={source}>
                      <Technical className="text-2xs">{source}</Technical>
                      {` · ${formatCount(count, digits, language)}`}
                    </Badge>
                  ))}
              </div>
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
