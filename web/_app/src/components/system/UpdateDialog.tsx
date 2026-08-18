import { useTranslation } from 'react-i18next'
import { AlertTriangle, CheckCircle2, Download, ExternalLink, Loader2, RefreshCw } from 'lucide-react'

import { panelUrl } from '@/lib/bootstrap'
import { useUpdate } from '@/providers/UpdateProvider'
import { usePreferences } from '@/providers/PreferencesProvider'
import { formatDateTime } from '@/lib/format'
import { Button } from '../ui/button'
import { Badge, describeError } from '../ui/feedback'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/overlay'
import { Technical, TechnicalBlock } from '../ui/technical'

/**
 * Updating the panel, from the panel.
 *
 * The awkward part of this screen is the middle of it: applying an update
 * restarts the panel, so the page watching the update loses the server it is
 * watching. That is not an error and is deliberately not shown as one — the
 * poll simply fails while the panel is down, and the panel coming back with a
 * finished run is what ends the wait. What it did is read back from the
 * transient unit the installer ran in, which outlives the restart.
 */
export function UpdateDialog() {
  const { t } = useTranslation()
  const { status, isOpen, close, check, isChecking, start, isStarting, startError, applying, error } =
    useUpdate()
  const { digits, language, calendar } = usePreferences()

  const state = status?.state
  const stage = state?.stage ?? 'idle'
  const latest = status?.latest.version ?? ''
  const running = applying || stage === 'running'
  const available = Boolean(status?.update_available)

  // The record of the last run outlives that run: a panel updated in March
  // still reports it in June. So a version on offer takes precedence over a
  // finished run — otherwise the success screen from the last update would
  // stand between the operator and the next one, with no button on it.
  const showDone = !running && stage === 'succeeded' && !available
  const showFailed = !running && stage === 'failed' && !available
  const showOffer = !running && !showDone && !showFailed

  const title = (() => {
    if (running) return t('update.dialog.applyingTitle')
    if (showDone) return t('update.dialog.doneTitle')
    if (showFailed) return t('update.dialog.failedTitle')
    if (available) return t('update.dialog.availableTitle', { version: latest })
    return t('update.dialog.currentTitle')
  })()

  return (
    <Dialog open={isOpen} onOpenChange={(next) => (next ? undefined : close())}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            {t('update.dialog.running', { version: status?.current_version ?? '' })}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {running ? <ApplyingBody /> : null}
          {showDone ? <SucceededBody /> : null}
          {showFailed ? <FailedBody /> : null}
          {showOffer ? <OfferBody /> : null}

          {/* The panel itself could not be asked — a session that has just
              expired, or a panel that is already restarting. Distinct from a
              check that reached the panel and failed at the release host, which
              is reported with the rest of the answer below. */}
          {!status && error ? (
            <p className="rounded-md border border-danger/40 bg-danger-muted p-3 text-sm">
              {describeError(error, t).message}
            </p>
          ) : null}

          {startError ? (
            <p className="rounded-md border border-danger/40 bg-danger-muted p-3 text-sm">
              {describeError(startError, t).message}
            </p>
          ) : null}

          {/* Where the answer came from, and when. A panel that cannot reach
              the release host says so here rather than looking up to date. */}
          <dl className="grid gap-1 border-t border-border/60 pt-3 text-xs text-muted-foreground">
            <div className="flex flex-wrap items-center gap-x-2">
              <dt>{t('update.source')}</dt>
              <dd>
                <Technical>{status?.source ?? ''}</Technical>
              </dd>
            </div>
            {status?.checked_at ? (
              <div className="flex flex-wrap items-center gap-x-2">
                <dt>{t('update.checkedAt')}</dt>
                <dd>{formatDateTime(status.checked_at, { locale: language, calendar, digits })}</dd>
              </div>
            ) : null}
            {status?.error ? <p className="text-danger">{status.error}</p> : null}
          </dl>
        </DialogBody>

        <DialogFooter>
          <Button variant="ghost" onClick={close}>
            {t('actions.close')}
          </Button>
          {!running && !showDone ? (
            <Button variant="secondary" onClick={check} loading={isChecking}>
              <RefreshCw className="size-4" aria-hidden="true" />
              {t('update.actions.check')}
            </Button>
          ) : null}
          {/* Offered whenever there is something to install, including after a
              run that failed: retrying is the obvious next thing to try. */}
          {!running && available && status?.can_apply ? (
            <Button variant="primary" onClick={() => start(latest)} loading={isStarting}>
              <Download className="size-4" aria-hidden="true" />
              {t('update.actions.install', { version: latest })}
            </Button>
          ) : null}
          {showDone ? (
            <Button variant="primary" onClick={() => window.location.assign(panelUrl('/'))}>
              {t('update.actions.reload')}
            </Button>
          ) : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** What is on offer, or why nothing is. */
function OfferBody() {
  const { t } = useTranslation()
  const { status } = useUpdate()
  if (!status) return null

  if (!status.update_available) {
    return (
      <div className="space-y-3">
        <p className="text-sm">
          {status.note ? status.note : t('update.upToDate', { version: status.current_version })}
        </p>
        {status.latest.version ? (
          <p className="text-xs text-muted-foreground">
            {t('update.latestSeen', { version: status.latest.version })}
          </p>
        ) : null}
        {!status.enabled ? <p className="text-xs text-muted-foreground">{t('update.checkingOff')}</p> : null}
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Technical>{status.current_version}</Technical>
        <span aria-hidden="true">→</span>
        <Badge tone="accent">
          <Technical>{status.latest.version}</Technical>
        </Badge>
      </div>

      <p className="text-sm text-muted-foreground">{t('update.dialog.whatHappens')}</p>

      {status.latest.notes ? (
        <div className="space-y-1">
          <p className="text-xs font-medium">{t('update.notes')}</p>
          <TechnicalBlock className="max-h-56 whitespace-pre-wrap">{status.latest.notes}</TechnicalBlock>
        </div>
      ) : null}

      {status.latest.url ? (
        <a
          href={status.latest.url}
          target="_blank"
          rel="noreferrer noopener"
          className="inline-flex items-center gap-1 text-xs text-accent underline-offset-4 hover:underline"
        >
          {t('update.releasePage')}
          <ExternalLink className="size-3" aria-hidden="true" />
        </a>
      ) : null}

      {!status.can_apply ? (
        <p className="rounded-md border border-warn/40 bg-warn-muted p-3 text-sm">{status.reason}</p>
      ) : null}

      {/* A previous attempt that failed is part of the picture here: the
          operator is being asked to press the same button again. */}
      {status.state.stage === 'failed' ? (
        <p className="rounded-md border border-danger/40 bg-danger-muted p-3 text-sm">
          {status.state.error || t('update.dialog.failed')}
        </p>
      ) : null}
    </div>
  )
}

/** The stretch where the panel is being replaced under the page. */
function ApplyingBody() {
  const { t } = useTranslation()
  const { status } = useUpdate()
  const state = status?.state

  return (
    <div className="space-y-3">
      <p className="flex items-center gap-2 text-sm">
        <Loader2 className="size-4 animate-spin" aria-hidden="true" />
        {t('update.dialog.applying', { version: state?.target_version ?? '' })}
      </p>
      <p className="text-sm text-muted-foreground">{t('update.dialog.restartWarning')}</p>
      <UpdateLog />
    </div>
  )
}

function SucceededBody() {
  const { t } = useTranslation()
  const { status } = useUpdate()
  const state = status?.state

  return (
    <div className="space-y-3">
      <p className="flex items-center gap-2 text-sm">
        <CheckCircle2 className="size-4 text-ok" aria-hidden="true" />
        {t('update.dialog.done', {
          from: state?.from_version ?? '',
          to: status?.current_version ?? state?.target_version ?? '',
        })}
      </p>
      {/* The bundle is content-hashed, so the page in front of the operator is
          the old one until it is reloaded. */}
      <p className="text-sm text-muted-foreground">{t('update.dialog.reloadHint')}</p>
      <UpdateLog />
    </div>
  )
}

function FailedBody() {
  const { t } = useTranslation()
  const { status } = useUpdate()
  const state = status?.state

  return (
    <div className="space-y-3">
      <p className="flex items-start gap-2 text-sm">
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden="true" />
        {state?.error || t('update.dialog.failed')}
      </p>
      <p className="text-sm text-muted-foreground">{t('update.dialog.failedHint')}</p>
      <UpdateLog />
    </div>
  )
}

/** The installer's own output, which is the only evidence of what happened. */
function UpdateLog() {
  const { t } = useTranslation()
  const { status } = useUpdate()
  const lines = status?.state.log ?? []
  if (!lines.length) return null

  return (
    <div className="space-y-1">
      <p className="text-xs font-medium">{t('update.log')}</p>
      <TechnicalBlock className="max-h-56" copyable>
        {lines.join('\n')}
      </TechnicalBlock>
    </div>
  )
}
