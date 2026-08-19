import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Pencil, Plus, Trash2, Upload } from 'lucide-react'

import { api } from '@/lib/api'
import type { SourceList, SourceListsResponse } from '@/lib/types'
import { formatCount } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Field, Input, Textarea } from '../ui/form'
import { Badge, EmptyState, ErrorState, Skeleton, describeError } from '../ui/feedback'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/overlay'
import { Technical } from '../ui/technical'

/**
 * The named address lists a forwarding rule allows traffic from.
 *
 * The reason they exist is repetition: a relay that should only serve one
 * mobile operator needs several hundred ranges, and a second relay serving the
 * same operator needs the same several hundred. Kept here they have one home,
 * and editing them reaches every rule that allows them.
 */
export function SourceListsSection() {
  const { t } = useTranslation()
  const { digits, language } = usePreferences()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [editing, setEditing] = useState<SourceList | null>(null)
  const [creating, setCreating] = useState(false)

  const query = useQuery({
    queryKey: ['source-lists'],
    queryFn: () => api.get<SourceListsResponse>('/source-lists'),
  })

  const remove = useMutation({
    mutationFn: (list: SourceList) => api.delete(`/source-lists/${list.source_list_id}`),
    onSuccess: async (_result, list) => {
      toast({ tone: 'success', title: t('sourceLists.deleted', { name: list.name }) })
      await queryClient.invalidateQueries({ queryKey: ['source-lists'] })
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('actions.delete'), description: describeError(error, t).message }),
  })

  const lists = query.data?.source_lists ?? []

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle>{t('sourceLists.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('sourceLists.intro')}</p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => setCreating(true)}>
          <Plus className="size-4" aria-hidden="true" />
          {t('sourceLists.create')}
        </Button>
      </CardHeader>

      <CardContent>
        {query.isLoading ? (
          <Skeleton className="h-24" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} compact />
        ) : !lists.length ? (
          <EmptyState title={t('sourceLists.empty')} body={t('sourceLists.emptyBody')} />
        ) : (
          <ul className="divide-y divide-border">
            {lists.map((list) => (
              <li key={list.source_list_id} className="flex flex-wrap items-start gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
                    {list.name}
                    <Badge tone="neutral">
                      {t('sourceLists.ranges', { count: list.entries?.length ?? 0 })}
                    </Badge>
                    {/* A list rules depend on cannot be deleted, and saying so
                        before the button is pressed beats a refusal after. */}
                    {list.used_by > 0 ? (
                      <Badge tone="accent">
                        {t('sourceLists.usedBy', {
                          count: list.used_by,
                          formatted: formatCount(list.used_by, digits, language),
                        })}
                      </Badge>
                    ) : null}
                    {list.is_built_in ? (
                      <Badge tone="neutral">{t('sourceLists.builtIn')}</Badge>
                    ) : null}
                  </p>
                  {list.description ? (
                    <p className="mt-0.5 text-xs text-muted-foreground">{list.description}</p>
                  ) : null}
                  {list.entries?.length ? (
                    <Technical className="mt-1 block truncate text-2xs text-muted-foreground">
                      {list.entries
                        .slice(0, 4)
                        .map((entry) => entry.cidr)
                        .join(', ')}
                      {list.entries.length > 4 ? ' …' : ''}
                    </Technical>
                  ) : null}
                </div>

                <div className="flex gap-1">
                  <Button
                    variant="ghost"
                    size="iconSm"
                    aria-label={t('actions.edit')}
                    onClick={() => setEditing(list)}
                  >
                    <Pencil className="size-4" aria-hidden="true" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="iconSm"
                    aria-label={t('actions.delete')}
                    disabled={list.used_by > 0 || remove.isPending}
                    onClick={() => remove.mutate(list)}
                  >
                    <Trash2 className="size-4" aria-hidden="true" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>

      {creating || editing ? (
        <SourceListDialog
          list={editing}
          open
          onOpenChange={(open) => {
            if (!open) {
              setCreating(false)
              setEditing(null)
            }
          }}
        />
      ) : null}
    </Card>
  )
}

/**
 * Creating and replacing a list.
 *
 * The ranges are one text box rather than a row of inputs because that is how
 * they arrive: pasted out of somewhere else, or read out of a file. The server
 * splits them, so an operator never has to work out what separator this
 * particular box wants.
 */
function SourceListDialog({
  list,
  open,
  onOpenChange,
}: {
  list: SourceList | null
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const fileInput = useRef<HTMLInputElement>(null)

  const [name, setName] = useState(list?.name ?? '')
  const [description, setDescription] = useState(list?.description ?? '')
  const [entries, setEntries] = useState(
    (list?.entries ?? []).map((entry) => entry.cidr).join('\n'),
  )
  const [error, setError] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: () => {
      const body = { name, description, entries }
      return list
        ? api.put(`/source-lists/${list.source_list_id}`, body)
        : api.post('/source-lists', body)
    },
    onSuccess: async (result: unknown) => {
      const reapplied = (result as { reapplied?: number })?.reapplied ?? 0
      toast({
        tone: 'success',
        title: list ? t('sourceLists.saved', { name }) : t('sourceLists.created', { name }),
        // Editing a list reinstalls the rules that allow it. An operator who
        // thought nothing used this one should find that out here.
        description: reapplied ? t('sourceLists.reapplied', { count: reapplied }) : undefined,
      })
      await queryClient.invalidateQueries({ queryKey: ['source-lists'] })
      await queryClient.invalidateQueries({ queryKey: ['routes'] })
      onOpenChange(false)
    },
    onError: (cause) => setError(describeError(cause, t).message),
  })

  // The file is read in the browser and sent as text. It is the same field the
  // text box fills, so a .txt and a paste are one code path on both sides.
  const readFile = async (file: File) => {
    const text = await file.text()
    setEntries((current) => (current.trim() ? `${current.trim()}\n${text}` : text))
  }

  const count = entries.split(/[\s,]+/).filter(Boolean).length

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{list ? t('sourceLists.editTitle', { name: list.name }) : t('sourceLists.createTitle')}</DialogTitle>
        </DialogHeader>

        <DialogBody className="space-y-3">
          <Field label={t('sourceLists.name')} description={t('sourceLists.nameHelp')} required>
            {(props) => (
              <Input
                {...props}
                value={name}
                onChange={(event) => setName(event.target.value)}
                placeholder="MCI"
              />
            )}
          </Field>

          <Field label={t('sourceLists.note')}>
            {(props) => (
              <Input
                {...props}
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                placeholder={t('sourceLists.notePlaceholder')}
              />
            )}
          </Field>

          <Field
            label={t('sourceLists.entries')}
            description={t('sourceLists.entriesHelp')}
            aside={
              <span className="tabular text-2xs text-muted-foreground">
                {t('sourceLists.counted', { count })}
              </span>
            }
          >
            {(props) => (
              <Textarea
                {...props}
                rows={10}
                className="technical"
                value={entries}
                onChange={(event) => setEntries(event.target.value)}
                placeholder={'5.22.0.0/20\n2.144.0.0/14\n192.0.2.7'}
              />
            )}
          </Field>

          <div>
            <input
              ref={fileInput}
              type="file"
              accept=".txt,.csv,.list,text/plain"
              className="sr-only"
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) void readFile(file)
                event.target.value = ''
              }}
            />
            <Button variant="secondary" size="sm" onClick={() => fileInput.current?.click()}>
              <Upload className="size-4" aria-hidden="true" />
              {t('sourceLists.fromFile')}
            </Button>
          </div>

          {error ? (
            <p className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-muted p-3 text-xs text-danger">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden="true" />
              {error}
            </p>
          ) : null}
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            {t('actions.cancel')}
          </Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={!name.trim()}
            onClick={() => save.mutate()}
          >
            {t('actions.save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
