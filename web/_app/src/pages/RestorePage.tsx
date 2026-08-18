import { useCallback, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Database, Upload, AlertTriangle, CheckCircle2 } from 'lucide-react'

import { csrfToken } from '@/lib/api'
import { apiUrl, panelUrl } from '@/lib/bootstrap'
import { Button } from '@/components/ui/button'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

/**
 * Where a restore has got to.
 *
 * The upload and the restoration are separate phases with separate progress,
 * and conflating them is what makes a restore feel like a hang: the browser can
 * measure bytes leaving, and knows nothing at all about what happens after the
 * last one. The server reports the rest, and the final phase — the panel
 * restarting — can only be observed by watching for it to answer again, because
 * the restart ends the connection that would have reported it.
 */
type Phase =
  | 'idle'
  | 'uploading'
  | 'verifying'
  | 'installing'
  | 'restarting'
  | 'done'
  | 'failed'

interface Counts {
  users: number
  tunnels: number
  routes: number
}

const PHASE_ORDER: Phase[] = ['uploading', 'verifying', 'installing', 'restarting', 'done']

export default function RestorePage() {
  const { t } = useTranslation()
  useDocumentTitle(t('restore.title', { defaultValue: 'Restore a database' }))

  const [phase, setPhase] = useState<Phase>('idle')
  const [uploaded, setUploaded] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [counts, setCounts] = useState<Counts | null>(null)
  const [file, setFile] = useState<File | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  /**
   * Waits for the panel to answer again after the restart.
   *
   * It insists on the panel's own health envelope rather than any reply,
   * because a bare 404 is what something else on that port would say, and
   * treating "something answered" as "the panel is back" would send the
   * operator to a page that is not the panel.
   */
  const waitForPanel = useCallback(async () => {
    const deadline = Date.now() + 90_000
    while (Date.now() < deadline) {
      try {
        const response = await fetch(apiUrl('/system/health'), { credentials: 'include' })
        if (response.ok) {
          const body = await response.json()
          if (body && typeof body.status === 'string') {
            setPhase('done')
            // The accounts in the restored database are the ones that exist
            // now, so whatever session this page held is meaningless.
            window.location.assign(panelUrl("/"))
            return
          }
        }
      } catch {
        // Expected while it is down; that is what is being waited for.
      }
      await new Promise((resolve) => setTimeout(resolve, 1000))
    }
    setError(
      t('restore.timedOut', {
        defaultValue:
          'The panel has not answered in 90 seconds. The database was restored; open the panel again to check on it.',
      }),
    )
    setPhase('failed')
  }, [t])

  const submit = useCallback(
    (chosen: File) => {
      setError(null)
      setCounts(null)
      setUploaded(0)
      setPhase('uploading')

      // XMLHttpRequest rather than fetch, for one reason: it reports upload
      // progress and fetch does not. A restore of a large database with no
      // moving bar is indistinguishable from a stalled one.
      const form = new FormData()
      form.append('file', chosen)

      const xhr = new XMLHttpRequest()
      xhr.open('POST', apiUrl('/system/restore'))
      xhr.withCredentials = true
      const token = csrfToken()
      if (token) xhr.setRequestHeader('X-CSRF-Token', token)

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) setUploaded(event.loaded / event.total)
      }

      // The server does the rest, and the phases it goes through are short;
      // this shows them as soon as the upload is in rather than leaving the
      // bar full and the page silent.
      xhr.upload.onload = () => setPhase('verifying')

      xhr.onload = () => {
        let body: { detail?: string; counts?: Counts; restarting?: boolean; error?: { message?: string } } = {}
        try {
          body = JSON.parse(xhr.responseText)
        } catch {
          // Falls through to the status check below.
        }
        if (xhr.status >= 200 && xhr.status < 300) {
          if (body.counts) setCounts(body.counts)
          if (body.restarting) {
            setPhase('restarting')
            void waitForPanel()
          } else {
            setPhase('done')
          }
          return
        }
        setError(
          body.error?.message ??
            t('restore.failed', { defaultValue: 'The restore was refused.' }),
        )
        setPhase('failed')
      }

      xhr.onerror = () => {
        setError(t('restore.networkFailed', { defaultValue: 'The upload could not be sent.' }))
        setPhase('failed')
      }

      xhr.send(form)
    },
    [t, waitForPanel],
  )

  const busy = phase !== 'idle' && phase !== 'failed' && phase !== 'done'
  const stepIndex = PHASE_ORDER.indexOf(phase)

  return (
    <div className="mx-auto w-full max-w-2xl space-y-6 p-6">
      <header className="space-y-2">
        <h1 className="display flex items-center gap-3 text-3xl font-bold tracking-tight">
          <span className="grid size-10 shrink-0 place-items-center rounded-full bg-ink text-ink-foreground shadow-sm">
            <Database className="size-5" aria-hidden />
          </span>
          {t('restore.title', { defaultValue: 'Restore a database' })}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t('restore.intro', {
            defaultValue:
              'Upload a .db file taken from a panel. Its tunnels and forwarding rules are applied to this server once the panel restarts.',
          })}
        </p>
      </header>

      <div className="rounded-lg bg-warn-muted p-4 text-sm">
        <p className="flex items-start gap-2">
          <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
          <span>
            {t('restore.warning', {
              defaultValue:
                'This replaces everything the panel currently knows, including who can log in. You will be signed out and will need an account from the uploaded database. The current database is kept as panel.db.previous on the server.',
            })}
          </span>
        </p>
      </div>

      {phase === 'idle' || phase === 'failed' ? (
        <div className="space-y-4">
          <label
            htmlFor="restore-file"
            className="hatch-soft flex cursor-pointer flex-col items-center gap-2 rounded-xl border border-dashed border-border p-8 text-center transition-colors hover:bg-muted/50"
          >
            <Upload className="size-8 text-muted-foreground" aria-hidden />
            <span className="font-medium">
              {file
                ? file.name
                : t('restore.choose', { defaultValue: 'Choose a .db file' })}
            </span>
            {file ? (
              <span dir="ltr" className="technical text-xs text-muted-foreground">
                {(file.size / 1024).toFixed(0)} KB
              </span>
            ) : null}
            <input
              ref={inputRef}
              id="restore-file"
              type="file"
              accept=".db,application/vnd.sqlite3,application/octet-stream"
              className="sr-only"
              onChange={(event) => {
                const chosen = event.target.files?.[0] ?? null
                setFile(chosen)
                setError(null)
              }}
            />
          </label>

          <Button
            className="w-full"
            disabled={!file}
            onClick={() => {
              if (file) submit(file)
            }}
          >
            {t('restore.start', { defaultValue: 'Restore this database' })}
          </Button>
        </div>
      ) : null}

      {busy || phase === 'done' ? (
        <ol className="space-y-3">
          {PHASE_ORDER.map((step, index) => {
            const reached = stepIndex >= index
            const current = phase === step
            return (
              <li key={step} className="flex items-center gap-3">
                <span
                  className={`flex size-6 shrink-0 items-center justify-center rounded-full border text-xs ${
                    reached ? 'border-transparent bg-ink text-ink-foreground' : 'border-border text-muted-foreground'
                  }`}
                  aria-hidden
                >
                  {phase === 'done' || stepIndex > index ? (
                    <CheckCircle2 className="size-4" />
                  ) : (
                    index + 1
                  )}
                </span>
                <div className="flex-1">
                  <p className={current ? 'font-medium' : 'text-muted-foreground'}>
                    {t(`restore.step.${step}`, { defaultValue: defaultStepLabel(step) })}
                  </p>
                  {step === 'uploading' && (phase === 'uploading' || stepIndex > 0) ? (
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full bg-accent transition-[width] duration-200"
                        style={{ width: `${Math.round((stepIndex > 0 ? 1 : uploaded) * 100)}%` }}
                      />
                    </div>
                  ) : null}
                </div>
              </li>
            )
          })}
        </ol>
      ) : null}

      {counts ? (
        <p className="text-sm text-muted-foreground">
          {t('restore.counts', {
            defaultValue:
              'Restoring {{users}} account(s), {{tunnels}} tunnel(s) and {{routes}} forwarding rule(s).',
            users: counts.users,
            tunnels: counts.tunnels,
            routes: counts.routes,
          })}
        </p>
      ) : null}

      {error ? (
        <p role="alert" className="rounded-lg bg-danger-muted p-3 text-sm text-danger">
          {error}
        </p>
      ) : null}
    </div>
  )
}

function defaultStepLabel(step: Phase): string {
  switch (step) {
    case 'uploading':
      return 'Uploading the file'
    case 'verifying':
      return 'Checking that it is a panel database'
    case 'installing':
      return 'Putting it in place'
    case 'restarting':
      return 'Restarting the panel and applying tunnels and rules'
    case 'done':
      return 'Done — opening the panel'
    default:
      return step
  }
}
