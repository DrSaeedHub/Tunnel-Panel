import { useTranslation } from 'react-i18next'

import { Skeleton } from '../ui/feedback'

/**
 * The shape of a page while its module or its data loads.
 *
 * Deliberately a skeleton rather than a spinner: it holds the layout still, so
 * content does not jump into place when it arrives.
 */
export function PageSkeleton() {
  const { t } = useTranslation()
  return (
    <div className="space-y-4 p-6" role="status" aria-busy="true" aria-label={t('states.loading')}>
      <Skeleton className="h-7 w-48" />
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-32" />
        ))}
      </div>
      <Skeleton className="h-64" />
    </div>
  )
}
