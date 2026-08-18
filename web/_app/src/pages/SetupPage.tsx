import { useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Network, ShieldCheck } from 'lucide-react'

import { ApiError, NetworkError } from '@/lib/api'
import { useAuth } from '@/providers/AuthProvider'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/form'
import { LanguageMenu } from '@/components/layout/LanguageMenu'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

/**
 * The hard floor the backend enforces. Below it the form will not submit,
 * because the request would only come back rejected.
 */
const MIN_PASSWORD_LENGTH = 8

/**
 * Advice, not a rule. A longer password is better and the hint says so, but
 * nothing here refuses one that is shorter: a form that rejects the password
 * somebody has already chosen mostly teaches them to append two digits to it.
 */
const RECOMMENDED_PASSWORD_LENGTH = 12

export default function SetupPage() {
  const { t } = useTranslation()
  const { status, setup } = useAuth()
  const navigate = useNavigate()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})

  useDocumentTitle(t('setup.title'))

  // Once an account exists this page has no purpose, and the backend refuses
  // it anyway.
  if (status === 'authenticated') return <Navigate to="/" replace />
  if (status === 'anonymous') return <Navigate to="/login" replace />

  const mismatch = confirmation.length > 0 && password !== confirmation
  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (submitting || mismatch || tooShort) return

    setSubmitting(true)
    setError(null)
    setFieldErrors({})

    try {
      await setup(username, password)
      navigate('/', { replace: true })
    } catch (caught) {
      if (caught instanceof NetworkError) {
        setError(t('errors.network'))
      } else if (caught instanceof ApiError) {
        setFieldErrors(caught.fieldErrors)
        setError(Object.keys(caught.fieldErrors).length ? null : caught.message)
      } else {
        setError(t('errors.title'))
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="flex justify-end p-4">
        <LanguageMenu />
      </div>

      <div className="flex flex-1 items-start justify-center px-4 pb-16 pt-4 sm:items-center sm:pt-0">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex flex-col items-center gap-4 text-center">
            <div className="grid size-14 place-items-center rounded-full bg-ink text-ink-foreground shadow-slab">
              <Network className="size-6" aria-hidden="true" />
            </div>
            <div>
              <h1 className="display text-3xl font-bold tracking-tight">{t('setup.title')}</h1>
              <p className="mt-2 text-xs text-muted-foreground">{t('setup.subtitle')}</p>
            </div>
          </div>

          <form onSubmit={submit} className="card-surface space-y-4 rounded-xl p-6 shadow-pop">
            {error ? (
              <p className="rounded-md border border-danger/30 bg-danger-muted px-3 py-2 text-xs text-danger" role="alert">
                {error}
              </p>
            ) : null}

            <Field label={t('setup.username')} htmlFor="setup-username" error={fieldErrors['username']}>
              {(props) => (
                <Input
                  {...props}
                  name="username"
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  autoFocus
                  required
                  dir="ltr"
                />
              )}
            </Field>

            <Field
              label={t('setup.password')}
              htmlFor="setup-password"
              description={t('setup.passwordHint', { count: RECOMMENDED_PASSWORD_LENGTH })}
              error={fieldErrors['password']}
            >
              {(props) => (
                <Input
                  {...props}
                  name="new-password"
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="new-password"
                  minLength={MIN_PASSWORD_LENGTH}
                  required
                  dir="ltr"
                />
              )}
            </Field>

            <Field
              label={t('setup.confirmPassword')}
              htmlFor="setup-confirm"
              error={mismatch ? t('setup.mismatch') : undefined}
            >
              {(props) => (
                <Input
                  {...props}
                  name="confirm-password"
                  type="password"
                  value={confirmation}
                  onChange={(event) => setConfirmation(event.target.value)}
                  autoComplete="new-password"
                  required
                  dir="ltr"
                />
              )}
            </Field>

            <Button
              type="submit"
              variant="primary"
              className="w-full"
              loading={submitting}
              disabled={mismatch || tooShort}
            >
              <ShieldCheck className="size-4" aria-hidden="true" />
              {submitting ? t('setup.submitting') : t('setup.submit')}
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}
