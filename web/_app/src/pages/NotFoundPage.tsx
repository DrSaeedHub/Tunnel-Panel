import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Compass } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/feedback'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

export default function NotFoundPage() {
  const { t } = useTranslation()
  // Without this the tab keeps the title of whatever page the operator came
  // from, so a 404 reads as though it were still that page.
  useDocumentTitle(t('errors.notFound'))
  return (
    <EmptyState
      icon={<Compass className="size-5" aria-hidden="true" />}
      title={t('errors.notFound')}
      action={
        <Button asChild variant="secondary">
          <Link to="/">{t('nav.dashboard')}</Link>
        </Button>
      }
    />
  )
}
