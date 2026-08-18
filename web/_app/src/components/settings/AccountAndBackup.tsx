import { useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation } from '@tanstack/react-query'
import { Download, Upload } from 'lucide-react'

import { ApiError, api } from '@/lib/api'
import { apiUrl } from '@/lib/bootstrap'
import type { BackupImportAction, User } from '@/lib/types'
import { useAuth } from '@/providers/AuthProvider'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Field, Input } from '../ui/form'
import { Badge, describeError } from '../ui/feedback'
import { Technical } from '../ui/technical'

const MIN_PASSWORD_LENGTH = 1

export function AccountSection() {
  const { t } = useTranslation()
  const { user, refetch } = useAuth()
  const { toast } = useToast()

  const [username, setUsername] = useState(user?.username ?? '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})

  const mismatch = confirmation.length > 0 && newPassword !== confirmation

  const saveMutation = useMutation({
    mutationFn: () =>
      api.put<User>('/auth/me', {
        username: username !== user?.username ? username : undefined,
        current_password: currentPassword,
        new_password: newPassword || undefined,
      }),
    onSuccess: () => {
      toast({
        tone: 'success',
        title: newPassword ? t('settings.account.changed') : t('settings.account.usernameChanged'),
      })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmation('')
      setErrors({})
      refetch()
    },
    onError: (error) => {
      if (error instanceof ApiError) setErrors(error.fieldErrors)
      toast({ tone: 'error', title: t('errors.title'), description: describeError(error, t).message })
    },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('settings.account.title')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('settings.account.username')} error={errors['username']}>
            {(props) => (
              <Input
                {...props}
                dir="ltr"
                autoComplete="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
              />
            )}
          </Field>
          <Field label={t('settings.account.currentPassword')} error={errors['current_password']}>
            {(props) => (
              <Input
                {...props}
                type="password"
                dir="ltr"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(event) => setCurrentPassword(event.target.value)}
              />
            )}
          </Field>
          <Field label={t('settings.account.newPassword')} error={errors['new_password']}>
            {(props) => (
              <Input
                {...props}
                type="password"
                dir="ltr"
                autoComplete="new-password"
                minLength={MIN_PASSWORD_LENGTH}
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
              />
            )}
          </Field>
          <Field
            label={t('settings.account.confirmPassword')}
            error={mismatch ? t('setup.mismatch') : undefined}
          >
            {(props) => (
              <Input
                {...props}
                type="password"
                dir="ltr"
                autoComplete="new-password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            )}
          </Field>
        </div>

        <Button
          variant="primary"
          size="sm"
          disabled={!currentPassword || mismatch}
          loading={saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          {t('actions.saveChanges')}
        </Button>
      </CardContent>
    </Card>
  )
}

/**
 * Export and import of the panel's configuration.
 *
 * An import is previewed first: the backend's dry run lists every action it
 * would take, and nothing is written until the operator has read that list.
 */
export function BackupSection() {
  const { t } = useTranslation()
  const { toast } = useToast()
  const fileInput = useRef<HTMLInputElement | null>(null)
  const [preview, setPreview] = useState<BackupImportAction[] | null>(null)
  const [backup, setBackup] = useState<unknown>(null)

  const importMutation = useMutation({
    mutationFn: ({ dryRun }: { dryRun: boolean }) =>
      api.post<{ actions: BackupImportAction[] }>('/backup/import', { backup, dry_run: dryRun }),
    onSuccess: (result, variables) => {
      if (variables.dryRun) {
        setPreview(result.actions)
      } else {
        toast({ tone: 'success', title: t('settings.backup.applied') })
        setPreview(null)
        setBackup(null)
      }
    },
    onError: (error) =>
      toast({ tone: 'error', title: t('settings.backup.import'), description: describeError(error, t).message }),
  })

  const onFile = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text())
      setBackup(parsed)
      setPreview(null)
      importMutation.mutate({ dryRun: true })
    } catch {
      toast({ tone: 'error', title: t('settings.backup.import'), description: t('errors.validation') })
    }
  }

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{t('settings.backup.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('settings.backup.subtitle')}</p>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Button asChild variant="secondary" size="sm">
            {/* A plain link so the browser handles the download and the session
                cookie goes with it. */}
            <a href={apiUrl('/backup/export')} download="gre-panel-backup.json">
              <Download className="size-4" aria-hidden="true" />
              {t('settings.backup.export')}
            </a>
          </Button>
          <p className="mt-1 text-2xs text-muted-foreground">{t('settings.backup.exportHint')}</p>
        </div>

        <div className="border-t border-border pt-4">
          <input
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            className="sr-only"
            onChange={(event) => {
              const file = event.target.files?.[0]
              if (file) void onFile(file)
              event.target.value = ''
            }}
          />
          <Button variant="secondary" size="sm" onClick={() => fileInput.current?.click()}>
            <Upload className="size-4" aria-hidden="true" />
            {t('settings.backup.chooseFile')}
          </Button>
          <p className="mt-1 text-2xs text-muted-foreground">{t('settings.backup.importHint')}</p>

          {preview ? (
            <div className="mt-3 space-y-2">
              <p className="text-xs font-medium">{t('settings.backup.preview')}</p>
              {preview.length ? (
                <ul className="max-h-56 divide-y divide-border overflow-auto rounded-md border border-border scrollbar-thin">
                  {preview.map((action, index) => (
                    <li key={`${action.kind}-${action.target}-${index}`} className="flex items-baseline gap-2 p-2 text-2xs">
                      <Badge tone={action.error ? 'danger' : action.action === 'skip' ? 'neutral' : 'accent'}>
                        {action.action}
                      </Badge>
                      <span className="text-muted-foreground">{action.kind}</span>
                      <Technical className="text-2xs">{action.target}</Technical>
                      {action.detail ? <span className="text-muted-foreground">· {action.detail}</span> : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted-foreground">{t('settings.backup.noActions')}</p>
              )}

              {preview.length ? (
                <Button
                  variant="primary"
                  size="sm"
                  loading={importMutation.isPending}
                  onClick={() => importMutation.mutate({ dryRun: false })}
                >
                  {t('settings.backup.apply')}
                </Button>
              ) : null}
            </div>
          ) : null}
        </div>
      </CardContent>
    </Card>
  )
}
