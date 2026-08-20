import { useEffect, useMemo, useState } from 'react'
import { Link as RouterLink, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, RotateCcw, Save, Search, X } from 'lucide-react'

import { ApiError, api } from '@/lib/api'
import type { SettingSchemaEntry, SettingsResponse, SettingsSchemaResponse } from '@/lib/types'
import { settingsPages } from '@/lib/settingsSections'
import { useToast } from '@/providers/ToastProvider'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/form'
import { EmptyState, ErrorState, Skeleton, describeError } from '@/components/ui/feedback'
import { SettingField } from '@/components/settings/SettingField'
import { PoolsSection } from '@/components/settings/PoolsSection'
import { SourceListsSection } from '@/components/settings/SourceListsSection'
import { TuningSection } from '@/components/settings/TuningSection'
import { AccountSection, BackupSection } from '@/components/settings/AccountAndBackup'
import { PanelAddressSection } from '@/components/settings/PanelAddressSection'
import { DatabaseSection } from '@/components/settings/DatabaseSection'
import { cn } from '@/lib/utils'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

/**
 * Settings as pages, not one long scroll.
 *
 * The sidebar (and, on a phone, the pill row here) lists one entry per
 * section; the page shows only that section's fields. A search cuts across
 * every section, because an operator hunting for a key does not know which
 * page it lives on.
 */
export default function SettingsPage() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [params] = useSearchParams()

  const section = params.get('section') ?? ''
  const [search, setSearch] = useState('')
  const [draft, setDraft] = useState<Record<string, unknown>>({})
  const [errors, setErrors] = useState<Record<string, string>>({})

  useDocumentTitle(t('settings.title'))

  const schemaQuery = useQuery({
    queryKey: ['settings', 'schema'],
    queryFn: () => api.get<SettingsSchemaResponse>('/settings/schema'),
    staleTime: 300_000,
  })

  const saveMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) => api.put<SettingsResponse>('/settings', values),
    onSuccess: async (data) => {
      queryClient.setQueryData(['settings'], data)
      await queryClient.invalidateQueries({ queryKey: ['settings', 'schema'] })
      setDraft({})
      setErrors({})
      toast({ tone: 'success', title: t('settings.saved') })
    },
    onError: (error) => {
      // Per-key errors come back from the backend and land on their own field.
      if (error instanceof ApiError) setErrors(error.fieldErrors)
      toast({
        tone: 'error',
        title: t('settings.saveFailed'),
        description: describeError(error, t).message,
      })
    },
  })

  const resetMutation = useMutation({
    mutationFn: (keys: string[]) => api.post<SettingsResponse>('/settings/reset', { keys }),
    onSuccess: async (data) => {
      queryClient.setQueryData(['settings'], data)
      await queryClient.invalidateQueries({ queryKey: ['settings', 'schema'] })
      setDraft({})
      toast({ tone: 'success', title: t('settings.saved') })
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('errors.title'), description: describeError(error, t).message }),
  })

  const entries = useMemo(() => schemaQuery.data?.settings ?? [], [schemaQuery.data])

  // Grouped by the backend's own categories, so a new category needs no change
  // here either.
  const grouped = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const matching = needle
      ? entries.filter(
          (entry) =>
            entry.key.toLowerCase().includes(needle) ||
            entry.description.toLowerCase().includes(needle),
        )
      : entries

    const map = new Map<string, SettingSchemaEntry[]>()
    for (const entry of matching) {
      map.set(entry.category, [...(map.get(entry.category) ?? []), entry])
    }
    return map
  }, [entries, search])

  const categories = useMemo(
    () => schemaQuery.data?.categories ?? [...grouped.keys()],
    [schemaQuery.data, grouped],
  )
  const pages = useMemo(() => settingsPages(categories), [categories])
  const currentPage = pages.find((page) => page.key === section) ?? pages[0]
  const searching = search.trim().length > 0
  const dirtyCount = Object.keys(draft).length

  // Leaving with unsaved settings loses them, so the browser asks first.
  useEffect(() => {
    if (!dirtyCount) return
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', handler)
    return () => window.removeEventListener('beforeunload', handler)
  }, [dirtyCount])

  const valueOf = (entry: SettingSchemaEntry) =>
    Object.prototype.hasOwnProperty.call(draft, entry.key) ? draft[entry.key] : entry.value

  if (schemaQuery.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-9 w-64" />
        {Array.from({ length: 3 }).map((_, index) => (
          <Skeleton key={index} className="h-48" />
        ))}
      </div>
    )
  }

  if (schemaQuery.error) {
    return <ErrorState error={schemaQuery.error} onRetry={() => void schemaQuery.refetch()} />
  }

  const categoryCard = (category: string) => {
    const sectionEntries = grouped.get(category) ?? []
    return (
      <Card key={category} id={`settings-${category}`}>
        <CardHeader>
          <div>
            <CardTitle>{t(`settings.category.${category}`, category)}</CardTitle>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {t(`settings.categoryHelp.${category}`, '')}
            </p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              const keys = sectionEntries.map((entry) => entry.key)
              if (window.confirm(t('settings.resetConfirm', { count: keys.length }))) {
                resetMutation.mutate(keys)
              }
            }}
          >
            <RotateCcw className="size-3.5" aria-hidden="true" />
            {t('settings.resetSection')}
          </Button>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          {sectionEntries.map((entry) => (
            <SettingField
              key={entry.key}
              entry={entry}
              value={valueOf(entry)}
              dirty={Object.prototype.hasOwnProperty.call(draft, entry.key)}
              error={errors[entry.key]}
              onChange={(value) =>
                setDraft((current) => {
                  const next = { ...current }
                  // Setting a value back to what is stored is not a change.
                  if (JSON.stringify(value) === JSON.stringify(entry.value)) delete next[entry.key]
                  else next[entry.key] = value
                  return next
                })
              }
            />
          ))}
        </CardContent>
      </Card>
    )
  }

  const extraPanel = (extra: (typeof currentPage.extras)[number]) => {
    switch (extra) {
      case 'density':
        return <DensityCard key="density" />
      case 'pools':
        return (
          <div key="pools" id="settings-pools">
            <PoolsSection />
          </div>
        )
      case 'sourceLists':
        return (
          <div key="sourceLists" id="settings-source-lists">
            <SourceListsSection />
          </div>
        )
      case 'tuning':
        return (
          <div key="tuning" id="settings-tuning">
            <TuningSection />
          </div>
        )
      case 'address':
        return <PanelAddressSection key="address" />
      case 'database':
        return <DatabaseSection key="database" />
      case 'account':
        return <AccountSection key="account" />
      case 'backup':
        return <BackupSection key="backup" />
    }
  }

  return (
    <div className="space-y-4">
      {/* Sticky under the plate's top bar, so save stays reachable however
          deep the operator has scrolled into the schema. */}
      <div className="sticky top-16 z-20 -mx-1 flex flex-wrap items-center gap-2 rounded-full bg-plate/90 px-1 py-1.5 backdrop-blur">
        <div className="relative min-w-0 flex-1 sm:max-w-xs">
          <Search
            className="pointer-events-none absolute top-1/2 size-4 -translate-y-1/2 text-muted-foreground [inset-inline-start:0.625rem]"
            aria-hidden="true"
          />
          <Input
            data-shortcut="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={t('settings.search')}
            aria-label={t('settings.search')}
            className="rounded-full [padding-inline-start:2.25rem]"
          />
        </div>

        <div className="ms-auto flex items-center gap-2">
          {dirtyCount ? (
            <>
              <span className="text-xs text-accent">{t('settings.dirty', { count: dirtyCount })}</span>
              <Button variant="ghost" size="sm" onClick={() => setDraft({})}>
                <X className="size-4" aria-hidden="true" />
                {t('actions.discard')}
              </Button>
            </>
          ) : null}
          <Button
            variant="primary"
            size="sm"
            disabled={!dirtyCount}
            loading={saveMutation.isPending}
            onClick={() => saveMutation.mutate(draft)}
          >
            <Save className="size-4" aria-hidden="true" />
            {t('actions.save')}
          </Button>
        </div>
      </div>

      {/* The phone's section switcher; on desktop the sidebar tree does this. */}
      <nav className="flex gap-1.5 overflow-x-auto pb-1 scrollbar-thin lg:hidden" aria-label={t('settings.title')}>
        {pages.map(({ key, Icon, labelKey }) => {
          const active = !searching && currentPage.key === key
          return (
            <RouterLink
              key={key}
              to={`/settings?section=${key}`}
              aria-current={active ? 'page' : undefined}
              className={cn(
                'inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                active
                  ? 'bg-ink text-ink-foreground shadow-sm'
                  : 'bg-surface text-muted-foreground shadow-sm hover:text-foreground',
              )}
            >
              <Icon className="size-3.5" aria-hidden="true" />
              {t(labelKey)}
            </RouterLink>
          )
        })}
      </nav>

      {searching ? (
        !grouped.size ? (
          <Card>
            <CardContent>
              <EmptyState illustration="empty-search" title={t('settings.noMatch', { query: search })} />
            </CardContent>
          </Card>
        ) : (
          categories.filter((category) => grouped.has(category)).map(categoryCard)
        )
      ) : (
        <>
          {currentPage.categories.filter((category) => grouped.has(category)).map(categoryCard)}
          {currentPage.extras.map(extraPanel)}
        </>
      )}
    </div>
  )
}

/**
 * Density, shown rather than described: each choice is a miniature of the
 * product at that density, so the difference is visible before it is applied.
 */
function DensityCard() {
  const { t } = useTranslation()
  const { density, setDensity } = usePreferences()

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('settings.display.density')}</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2">
        {(
          [
            ['comfortable', 'settings.display.densityComfortable'],
            ['compact', 'settings.display.densityCompact'],
          ] as const
        ).map(([mode, labelKey]) => {
          const active = density === mode
          return (
            <button
              key={mode}
              type="button"
              aria-pressed={active}
              onClick={() => setDensity(mode)}
              className={cn(
                'rounded-lg border p-3.5 text-start transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                active ? 'border-accent bg-accent-muted/40' : 'border-border hover:bg-muted/50',
              )}
            >
              <span className="flex items-center justify-between gap-2">
                <span className="text-xs font-medium">{t(labelKey)}</span>
                {active ? <Check className="size-3.5 text-accent" aria-hidden="true" /> : null}
              </span>
              {/* A miniature table at this density. Decorative: the label above
                  carries the meaning. */}
              <span
                className="mt-2.5 block overflow-hidden rounded-md border border-border/60 bg-surface"
                aria-hidden="true"
              >
                {[0, 1, 2].map((row) => (
                  <span
                    key={row}
                    className={cn(
                      'flex items-center gap-2 border-b border-border/60 px-2.5 last:border-b-0',
                      mode === 'comfortable' ? 'py-2.5' : 'py-1',
                    )}
                  >
                    <span className={cn('size-2 shrink-0 rounded-full', row === 1 ? 'bg-warn/70' : 'bg-ok/70')} />
                    <span className="h-1.5 w-16 rounded-full bg-foreground/25" />
                    <span className="ms-auto h-1.5 w-8 rounded-full bg-muted-foreground/40" />
                  </span>
                ))}
              </span>
            </button>
          )
        })}
      </CardContent>
    </Card>
  )
}
