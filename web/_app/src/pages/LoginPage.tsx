import { useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Eye, EyeOff, Network } from 'lucide-react'

import { ApiError, NetworkError } from '@/lib/api'
import { formatRelative } from '@/lib/format'
import { useAuth } from '@/providers/AuthProvider'
import { usePreferences } from '@/providers/PreferencesProvider'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/form'
import { LanguageMenu } from '@/components/layout/LanguageMenu'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

export default function LoginPage() {
  const { t } = useTranslation()
  const { status, login, sessionExpired, clearExpiry } = useAuth()
  const { language } = usePreferences()
  const navigate = useNavigate()
  const location = useLocation()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [revealed, setRevealed] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Where the operator was going before being sent here.
  const intended = (location.state as { from?: string } | null)?.from ?? '/'

  useDocumentTitle(t('login.title'))

  if (status === 'setup-required') return <Navigate to="/setup" replace />
  if (status === 'authenticated') return <Navigate to={intended} replace />

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (submitting) return

    setSubmitting(true)
    setError(null)
    clearExpiry()

    try {
      await login(username, password)
      navigate(intended, { replace: true })
    } catch (caught) {
      setError(describeLoginFailure(caught, t, language))
      setPassword('')
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
              <h1 className="display text-3xl font-bold tracking-tight">{t('app.name')}</h1>
              <p className="mt-2 text-xs text-muted-foreground">{t('login.subtitle')}</p>
            </div>
            {/* Two endpoints, one tunnel: the whole product as a section
                drawing. Decorative — every value it hints at is in the copy. */}
            <svg viewBox="0 0 240 24" className="w-56 text-muted-foreground/50" aria-hidden="true" focusable="false">
              <circle cx="7" cy="12" r="3.5" fill="currentColor" />
              <line x1="13" y1="12" x2="100" y2="12" stroke="currentColor" strokeWidth="1.5" />
              <rect x="100" y="5" width="40" height="14" rx="7" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="3 3" />
              <line x1="140" y1="12" x2="227" y2="12" stroke="currentColor" strokeWidth="1.5" />
              <circle cx="233" cy="12" r="3.5" fill="currentColor" />
            </svg>
          </div>

          <form onSubmit={submit} className="card-surface space-y-4 rounded-xl p-6 shadow-pop">
            {sessionExpired ? (
              <p className="rounded-md border border-border bg-muted px-3 py-2 text-xs text-muted-foreground" role="status">
                {t('login.expired')}
              </p>
            ) : null}

            {error ? (
              <p className="rounded-md border border-danger/30 bg-danger-muted px-3 py-2 text-xs text-danger" role="alert">
                {error}
              </p>
            ) : null}

            <Field label={t('login.username')} htmlFor="username">
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

            <Field label={t('login.password')} htmlFor="password">
              {(props) => (
                <div className="relative">
                  <Input
                    {...props}
                    name="password"
                    type={revealed ? 'text' : 'password'}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="current-password"
                    required
                    dir="ltr"
                    className="[padding-inline-end:2.5rem]"
                  />
                  <button
                    type="button"
                    onClick={() => setRevealed((v) => !v)}
                    aria-label={revealed ? t('login.hidePassword') : t('login.showPassword')}
                    className="absolute inset-y-0 flex items-center px-3 text-muted-foreground hover:text-foreground [inset-inline-end:0]"
                  >
                    {revealed ? (
                      <EyeOff className="size-4" aria-hidden="true" />
                    ) : (
                      <Eye className="size-4" aria-hidden="true" />
                    )}
                  </button>
                </div>
              )}
            </Field>

            <Button type="submit" variant="primary" className="w-full" loading={submitting}>
              {submitting ? t('login.submitting') : t('login.submit')}
            </Button>
          </form>
        </div>
      </div>
    </div>
  )
}

/**
 * Turns a failed sign-in into something the operator can act on.
 *
 * Bad credentials give one message whether or not the user exists — the backend
 * is careful not to reveal which, and repeating that distinction here would
 * undo it. Being locked out is different: that is worth explaining, including
 * when it lifts.
 */
export function describeLoginFailure(
  error: unknown,
  t: (key: string, options?: Record<string, unknown>) => string,
  language: string,
): string {
  if (error instanceof NetworkError) return t('errors.network')
  if (!(error instanceof ApiError)) return t('errors.title')

  switch (error.code) {
    case 'INVALID_CREDENTIALS':
      return t('login.invalid')
    case 'ACCOUNT_LOCKED': {
      const until = error.details['locked_until']
      if (typeof until === 'string') {
        return t('login.locked', { when: formatRelative(until, language) })
      }
      return t('login.lockedNoTime')
    }
    case 'RATE_LIMITED':
      return t('login.rateLimited')
    case 'ACCOUNT_INACTIVE':
      return t('login.inactive')
    default:
      return error.message || t('errors.title')
  }
}
