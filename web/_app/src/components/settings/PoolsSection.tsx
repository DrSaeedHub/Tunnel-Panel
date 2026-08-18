import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Pencil, Plus, Trash2 } from 'lucide-react'

import { api } from '@/lib/api'
import type { PoolResponse } from '@/lib/types'
import { formatCount } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Field, Input, SwitchField, TechnicalInput } from '../ui/form'
import { Badge, EmptyState, ErrorState, Skeleton, describeError } from '../ui/feedback'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Tooltip,
} from '../ui/overlay'
import { Technical } from '../ui/technical'

/**
 * Address pools.
 *
 * A pool covering globally routable space is flagged wherever it appears: the
 * addresses in it belong to real hosts on the internet, and allocating tunnel
 * addresses from it quietly makes those destinations unreachable from this
 * server. The backend already computes the flag; this makes sure it is never
 * shown without the explanation.
 */
export function PoolsSection() {
  const { t } = useTranslation()
  const { digits, language } = usePreferences()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [editing, setEditing] = useState<PoolResponse | null>(null)
  const [creating, setCreating] = useState(false)

  const poolsQuery = useQuery({
    queryKey: ['pools'],
    queryFn: () => api.get<{ pools: PoolResponse[]; total: number }>('/pools'),
    staleTime: 30_000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.delete(`/pools/${id}`),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['pools'] })
      toast({ tone: 'success', title: t('actions.delete') })
    },
    onError: (error) => toast({ tone: 'error', title: t('actions.delete'), description: describeError(error, t).message }),
  })

  const pools = poolsQuery.data?.pools ?? []

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{t('settings.pools.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('settings.pools.subtitle')}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => setCreating(true)}>
          <Plus className="size-4" aria-hidden="true" />
          {t('settings.pools.add')}
        </Button>
      </CardHeader>
      <CardContent>
        {poolsQuery.isLoading ? (
          <Skeleton className="h-24" />
        ) : poolsQuery.error ? (
          <ErrorState error={poolsQuery.error} onRetry={() => void poolsQuery.refetch()} compact />
        ) : !pools.length ? (
          <EmptyState title={t('settings.pools.empty')} />
        ) : (
          <ul className="divide-y divide-border">
            {pools.map((pool) => (
              <li key={pool.address_pool_id} className="flex flex-wrap items-start justify-between gap-3 py-3">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    {pool.address_pool_title}
                    <Technical className="text-xs text-muted-foreground">{pool.cidr}</Technical>
                    {!pool.is_enabled ? <Badge>{t('states.disabled')}</Badge> : null}
                    {pool.is_public_range ? (
                      <Tooltip content={t('settings.pools.publicRangeWarning')}>
                        <span>
                          <Badge tone="danger">
                            <AlertTriangle className="size-3" aria-hidden="true" />
                            {t('settings.pools.publicRange')}
                          </Badge>
                        </span>
                      </Tooltip>
                    ) : null}
                  </p>
                  <p className="mt-0.5 text-2xs text-muted-foreground">
                    {t('settings.pools.capacity', {
                      used: formatCount(pool.in_use, digits, language),
                      total: formatCount(pool.capacity.capacity, digits, language),
                    })}
                    {pool.description ? ` · ${pool.description}` : ''}
                  </p>
                  {pool.is_public_range ? (
                    <p className="mt-1 text-2xs text-danger">{t('settings.pools.publicRangeWarning')}</p>
                  ) : null}
                </div>
                <div className="flex shrink-0 gap-1">
                  <Button variant="ghost" size="iconSm" onClick={() => setEditing(pool)} aria-label={t('actions.edit')}>
                    <Pencil className="size-3.5" aria-hidden="true" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="iconSm"
                    aria-label={t('actions.delete')}
                    onClick={() => {
                      if (window.confirm(t('settings.pools.deleteConfirm', { name: pool.address_pool_title }))) {
                        deleteMutation.mutate(pool.address_pool_id)
                      }
                    }}
                  >
                    <Trash2 className="size-3.5 text-danger" aria-hidden="true" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      <PoolDialog
        open={creating || Boolean(editing)}
        pool={editing}
        onOpenChange={(open) => {
          if (!open) {
            setCreating(false)
            setEditing(null)
          }
        }}
      />
    </Card>
  )
}

function PoolDialog({
  open,
  pool,
  onOpenChange,
}: {
  open: boolean
  pool: PoolResponse | null
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [title, setTitle] = useState('')
  const [cidr, setCidr] = useState('')
  const [prefixLength, setPrefixLength] = useState(30)
  const [description, setDescription] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [errors, setErrors] = useState<Record<string, string>>({})

  // Seeded when the dialog opens, so reopening on a different pool does not
  // show the previous one's values.
  const [seededFor, setSeededFor] = useState<number | null | undefined>(undefined)
  if (open && seededFor !== (pool?.address_pool_id ?? null)) {
    setSeededFor(pool?.address_pool_id ?? null)
    setTitle(pool?.address_pool_title ?? '')
    setCidr(pool?.cidr ?? '')
    setPrefixLength(pool?.prefix_length ?? 30)
    setDescription(pool?.description ?? '')
    setEnabled(pool?.is_enabled ?? true)
    setErrors({})
  }
  if (!open && seededFor !== undefined) setSeededFor(undefined)

  const saveMutation = useMutation({
    mutationFn: () => {
      const body = {
        address_pool_title: title,
        cidr,
        prefix_length: prefixLength,
        description,
        is_enabled: enabled,
      }
      return pool
        ? api.put(`/pools/${pool.address_pool_id}`, body)
        : api.post('/pools', body)
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['pools'] })
      toast({ tone: 'success', title: t('actions.save') })
      onOpenChange(false)
    },
    onError: (error) => {
      const described = describeError(error, t)
      setErrors(error instanceof Error && 'fieldErrors' in error ? (error as never) : {})
      toast({ tone: 'error', title: t('actions.save'), description: described.message })
    },
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{pool ? t('settings.pools.edit') : t('settings.pools.add')}</DialogTitle>
        </DialogHeader>
        <DialogBody className="space-y-3">
          <Field label={t('settings.pools.name')} error={errors['address_pool_title']}>
            {(props) => <Input {...props} value={title} onChange={(event) => setTitle(event.target.value)} />}
          </Field>
          <Field label={t('settings.pools.cidr')} error={errors['cidr']}>
            {(props) => (
              <TechnicalInput
                {...props}
                value={cidr}
                onChange={(event) => setCidr(event.target.value)}
                placeholder="10.10.0.0/16"
              />
            )}
          </Field>
          <Field label={t('settings.pools.prefixLength')} error={errors['prefix_length']}>
            {(props) => (
              <Input
                {...props}
                type="number"
                dir="ltr"
                className="tabular"
                min={8}
                max={31}
                value={prefixLength}
                onChange={(event) => setPrefixLength(Number(event.target.value))}
              />
            )}
          </Field>
          <Field label={t('settings.pools.description')}>
            {(props) => (
              <Input {...props} value={description} onChange={(event) => setDescription(event.target.value)} />
            )}
          </Field>
          <SwitchField label={t('settings.pools.enabled')} checked={enabled} onCheckedChange={setEnabled} />
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          <Button variant="primary" loading={saveMutation.isPending} onClick={() => saveMutation.mutate()}>
            {t('actions.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
