import { useTranslation } from 'react-i18next'
import { AlertTriangle, FileText, ListChecks, RefreshCw, Terminal, Undo2 } from 'lucide-react'

import type { PreviewResponse } from '@/lib/types'
import { DisclosurePanel } from '../ui/disclosure'
import { ErrorState, Skeleton } from '../ui/feedback'
import { Technical, TechnicalBlock } from '../ui/technical'

/**
 * What the backend will actually do, shown before it does it.
 *
 * This is a trust feature, not a developer nicety: the operator sees the exact
 * commands and the exact unit file that will be written, including the rollback
 * that runs if a step fails and the checks that will be made afterwards. It is
 * the difference between a panel that says "trust me" and one that shows its
 * work.
 */
export function PreviewPanel({
  preview,
  isLoading,
  error,
  onRetry,
  defaultOpen = false,
}: {
  preview: PreviewResponse | undefined
  isLoading: boolean
  error: unknown
  onRetry?: () => void
  defaultOpen?: boolean
}) {
  const { t } = useTranslation()

  return (
    <DisclosurePanel
      title={t('tunnelForm.preview.title')}
      description={t('tunnelForm.preview.subtitle')}
      defaultOpen={defaultOpen}
      contentClassName="space-y-4"
    >
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-24" />
        </div>
      ) : error ? (
        <ErrorState error={error} onRetry={onRetry} compact />
      ) : !preview ? (
        <p className="text-xs text-muted-foreground">{t('tunnelForm.preview.loading')}</p>
      ) : (
        <>
          {preview.plan.requires_recreate ? (
            <div className="rounded-md border border-warn/40 bg-warn-muted p-3">
              <p className="flex items-center gap-2 text-xs font-medium text-warn">
                <AlertTriangle className="size-3.5" aria-hidden="true" />
                {t('tunnelForm.preview.recreate')}
              </p>
              <p className="mt-1 text-2xs">{t('tunnelForm.preview.recreateBody')}</p>
              {preview.plan.recreate_reasons?.length ? (
                <ul className="mt-1.5 space-y-0.5 text-2xs text-muted-foreground">
                  {(preview.plan.recreate_reasons ?? []).map((reason) => (
                    <li key={reason}>• {reason}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}

          {preview.diffs?.length ? (
            <Section icon={<RefreshCw className="size-3.5" aria-hidden="true" />} title={t('tunnelForm.preview.diffs')}>
              <ul className="space-y-1 text-2xs">
                {(preview.diffs ?? []).map((diff) => (
                  <li key={diff.field} className="flex flex-wrap items-center gap-1.5">
                    <span className="text-muted-foreground">{diff.field}</span>
                    <Technical className="text-2xs line-through opacity-70">{diff.from || '—'}</Technical>
                    <span aria-hidden="true">→</span>
                    <Technical className="text-2xs">{diff.to || '—'}</Technical>
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}

          {(preview.plan.steps ?? []).length ? (
            <Section
              icon={<Terminal className="size-3.5" aria-hidden="true" />}
              title={t('tunnelForm.preview.operations')}
            >
              <ol className="space-y-1.5">
                {(preview.plan.steps ?? []).map((step, index) => (
                  <li key={`${step.kind}-${index}`} className="space-y-0.5">
                    <p className="text-2xs text-muted-foreground">{step.description}</p>
                    {step.argv?.length ? (
                      <Technical className="block overflow-x-auto text-2xs">{step.argv.join(' ')}</Technical>
                    ) : null}
                  </li>
                ))}
              </ol>
            </Section>
          ) : (
            <p className="text-xs text-muted-foreground">{t('tunnelForm.preview.noChanges')}</p>
          )}

          {(preview.plan.files ?? []).length ? (
            <Section icon={<FileText className="size-3.5" aria-hidden="true" />} title={t('tunnelForm.preview.files')}>
              <div className="space-y-2">
                {(preview.plan.files ?? []).map((file) => (
                  <div key={file.path}>
                    <Technical className="block text-2xs text-muted-foreground">{file.path}</Technical>
                    {file.content ? <TechnicalBlock copyable>{file.content}</TechnicalBlock> : null}
                  </div>
                ))}
              </div>
            </Section>
          ) : null}

          {(preview.plan.rollback ?? []).length ? (
            <Section icon={<Undo2 className="icon-directional size-3.5" aria-hidden="true" />} title={t('tunnelForm.preview.rollback')}>
              <ul className="space-y-0.5 text-2xs text-muted-foreground">
                {(preview.plan.rollback ?? []).map((step, index) => (
                  <li key={`${step.kind}-rollback-${index}`}>• {step.description}</li>
                ))}
              </ul>
            </Section>
          ) : null}

          {preview.plan.verification?.length ? (
            <Section
              icon={<ListChecks className="size-3.5" aria-hidden="true" />}
              title={t('tunnelForm.preview.verification')}
            >
              <ul className="space-y-0.5 text-2xs text-muted-foreground">
                {(preview.plan.verification ?? []).map((check) => (
                  <li key={check}>• {check}</li>
                ))}
              </ul>
            </Section>
          ) : null}
        </>
      )}
    </DisclosurePanel>
  )
}

function Section({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode
  title: string
  children: React.ReactNode
}) {
  return (
    <section>
      <h4 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium">
        {icon}
        {title}
      </h4>
      {children}
    </section>
  )
}
