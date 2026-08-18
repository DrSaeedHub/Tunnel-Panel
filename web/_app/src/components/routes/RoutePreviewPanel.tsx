import { useTranslation } from 'react-i18next'
import { FileText, ListChecks, Terminal, Undo2 } from 'lucide-react'

import type { RoutePreviewResponse } from '@/lib/types'
import { DisclosurePanel } from '../ui/disclosure'
import { ErrorState, Skeleton } from '../ui/feedback'
import { Technical, TechnicalBlock } from '../ui/technical'

/**
 * The exact ruleset that will be submitted, shown before it is.
 *
 * Same trust model as the tunnel preview, and the same reason: an apply here
 * replaces the panel's whole netfilter namespace in one transaction, and an
 * operator is entitled to read what that transaction contains before it runs.
 * What is displayed is the backend's own rendering — the same bytes handed to
 * `nft` — not a reconstruction of it.
 */
export function RoutePreviewPanel({
  preview,
  isLoading,
  error,
  onRetry,
  defaultOpen = false,
  ready,
}: {
  preview: RoutePreviewResponse | undefined
  isLoading: boolean
  error: unknown
  onRetry?: () => void
  defaultOpen?: boolean
  /** False while the form still lacks the fields a plan needs. */
  ready: boolean
}) {
  const { t } = useTranslation()

  return (
    <DisclosurePanel
      title={t('routeForm.preview.title')}
      description={t('routeForm.preview.subtitle')}
      defaultOpen={defaultOpen}
      contentClassName="space-y-4"
      aside={
        preview?.plan.backend ? (
          <span className="text-2xs text-muted-foreground">
            {t('routeForm.preview.backend', { name: preview.plan.backend })}
          </span>
        ) : null
      }
    >
      {!ready ? (
        <p className="text-xs text-muted-foreground">{t('routeForm.preview.loading')}</p>
      ) : isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-32" />
        </div>
      ) : error ? (
        <ErrorState error={error} onRetry={onRetry} compact />
      ) : !preview ? (
        <p className="text-xs text-muted-foreground">{t('routeForm.preview.loading')}</p>
      ) : (
        <>
          {preview.payload ? (
            <Section icon={<Terminal className="size-3.5" aria-hidden="true" />} title={t('routeForm.preview.payload')}>
              <TechnicalBlock copyable>{preview.payload}</TechnicalBlock>
            </Section>
          ) : null}

          {(preview.plan.steps ?? []).length ? (
            <Section
              icon={<ListChecks className="size-3.5" aria-hidden="true" />}
              title={t('routeForm.preview.operations')}
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
          ) : null}

          {(preview.plan.files ?? []).length ? (
            <Section icon={<FileText className="size-3.5" aria-hidden="true" />} title={t('routeForm.preview.files')}>
              <ul className="space-y-0.5">
                {(preview.plan.files ?? []).map((file) => (
                  <li key={file.path}>
                    <Technical className="block text-2xs text-muted-foreground">{file.path}</Technical>
                  </li>
                ))}
              </ul>
            </Section>
          ) : null}

          {(preview.plan.rollback ?? []).length ? (
            <Section
              icon={<Undo2 className="icon-directional size-3.5" aria-hidden="true" />}
              title={t('routeForm.preview.rollback')}
            >
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
              title={t('routeForm.preview.verification')}
            >
              <ul className="space-y-0.5 text-2xs text-muted-foreground">
                {(preview.plan.verification ?? []).map((check) => (
                  <li key={check}>• {check}</li>
                ))}
              </ul>
            </Section>
          ) : null}

          {preview.note ? <p className="text-2xs text-muted-foreground">{preview.note}</p> : null}
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
