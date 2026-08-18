import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '@tanstack/react-query'
import { AlertTriangle, ExternalLink } from 'lucide-react'

import { ApiError, api } from '@/lib/api'
import type { PanelAddress, PanelAddressChange } from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
import { Button } from '../ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Field, Input, SwitchField } from '../ui/form'
import { Badge, Skeleton, describeError } from '../ui/feedback'
import { Technical } from '../ui/technical'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '../ui/overlay'

/**
 * How long to keep asking the new address before giving up and handing the
 * operator a link instead.
 *
 * A restart on these hosts takes about two seconds. Sixty is far longer than
 * that on purpose: the cost of waiting a little too long is a few extra
 * seconds, and the cost of giving up too early is telling an operator their
 * panel is gone when it is on its way back.
 */
const COME_BACK_TIMEOUT_MS = 60_000
const POLL_INTERVAL_MS = 1_000

/**
 * Where the panel serves itself.
 *
 * This is not a generated settings field, and the difference matters. The
 * generated form saves a value and tells you it saved; this one has to
 * bind-test the port before storing it, refuse the port the SSH daemon is on,
 * tell the operator the new URL *before* the change breaks their connection,
 * and then find out whether the panel came back. None of that fits a text box
 * with a Save button.
 */
export function PanelAddressSection() {
  const { t } = useTranslation()
  const { toast } = useToast()

  const addressQuery = useQuery({
    queryKey: ['system', 'address'],
    queryFn: () => api.get<PanelAddress>('/system/address'),
  })
  const current = addressQuery.data

  const [port, setPort] = useState('')
  const [webPath, setWebPath] = useState('')
  const [atRoot, setAtRoot] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [moving, setMoving] = useState<PanelAddressChange | null>(null)

  // The form follows the server until the operator touches it.
  useEffect(() => {
    if (!current) return
    setPort(String(current.port))
    setWebPath(current.web_path)
    setAtRoot(current.web_path === '')
  }, [current])

  const nextWebPath = atRoot ? '' : webPath.trim()
  const changed =
    !!current && (Number(port) !== current.port || nextWebPath !== current.web_path)

  const moveMutation = useMutation({
    mutationFn: () =>
      api.post<PanelAddressChange>('/system/address', {
        port: Number(port),
        web_path: nextWebPath,
      }),
    onSuccess: (result) => {
      setConfirming(false)
      setErrors({})
      setMoving(result)
    },
    onError: (error) => {
      setConfirming(false)
      if (error instanceof ApiError) setErrors(error.fieldErrors)
      toast({
        tone: 'error',
        title: t('settings.address.failed'),
        description: describeError(error, t).message,
      })
    },
  })

  if (addressQuery.isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>{t('settings.address.title')}</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-24" />
        </CardContent>
      </Card>
    )
  }
  if (!current) return null

  const previewURL = buildURL(current.url, Number(port), nextWebPath)

  return (
    <Card id="settings-address">
      <CardHeader>
        <div>
          <CardTitle>{t('settings.address.title')}</CardTitle>
          <p className="mt-0.5 text-xs text-muted-foreground">{t('settings.address.subtitle')}</p>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* A panel that is not where it was configured to be says so here
            first, because this is the screen an operator opens to find out. */}
        {current.fallback ? (
          <div className="flex gap-2 rounded-md border border-warning/40 bg-warning/10 p-3 text-xs">
            <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warning" aria-hidden="true" />
            <div>
              <p className="font-medium">
                {t('settings.address.fallbackTitle', {
                  wanted: current.fallback.wanted_port,
                  serving: current.fallback.serving_port,
                })}
              </p>
              <Technical className="mt-1 block text-2xs">{current.fallback.reason}</Technical>
            </div>
          </div>
        ) : null}

        {current.env_file.disagrees ? (
          <p className="rounded-md bg-muted p-3 text-2xs text-muted-foreground">
            {t('settings.address.envDisagrees', {
              path: current.env_file.path,
              port: current.env_file.port,
              webPath: current.env_file.web_path || t('settings.address.rootLabel'),
            })}
          </p>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label={t('settings.address.port')}
            error={errors['port']}
            description={t('settings.address.portHelp')}
          >
            {(props) => (
              <Input
                {...props}
                type="number"
                min={1}
                max={65535}
                dir="ltr"
                value={port}
                onChange={(event) => setPort(event.target.value)}
              />
            )}
          </Field>

          <Field
            label={t('settings.address.webPath')}
            error={errors['web_path']}
            description={t('settings.address.webPathHelp')}
          >
            {(props) => (
              <Input
                {...props}
                dir="ltr"
                disabled={atRoot}
                placeholder={atRoot ? t('settings.address.rootLabel') : undefined}
                value={atRoot ? '' : webPath}
                onChange={(event) => setWebPath(event.target.value)}
              />
            )}
          </Field>
        </div>

        {/* The empty web path needs a control of its own. An empty text box
            reads as "not filled in yet", and this is a deliberate choice with
            a real consequence — the panel is served at the root, where a scan
            will find it. */}
        <SwitchField
          label={t('settings.address.serveAtRoot')}
          description={t('settings.address.serveAtRootHelp')}
          checked={atRoot}
          onCheckedChange={(next) => setAtRoot(next)}
        />

        {current.protected_ports.length ? (
          <p className="text-2xs text-muted-foreground">
            {t('settings.address.protected')}{' '}
            {current.protected_ports.map((entry) => (
              <Badge key={entry.port} tone="neutral" className="mx-0.5">
                {entry.port}
              </Badge>
            ))}
          </p>
        ) : null}

        {!current.can_apply ? (
          <p className="text-2xs text-warning">{current.cannot_apply_why}</p>
        ) : null}

        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="sm"
            disabled={!changed}
            onClick={() => setConfirming(true)}
          >
            {t('settings.address.move')}
          </Button>
          {changed ? (
            <span className="text-2xs text-muted-foreground">
              {t('settings.address.willBecome')} <Technical>{previewURL}</Technical>
            </span>
          ) : null}
        </div>
      </CardContent>

      {/* The confirmation names the destination before anything happens. This
          is the last moment the operator's current connection is guaranteed to
          work, so it is the last moment they can be told where to go. */}
      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('settings.address.confirmTitle')}</DialogTitle>
            <DialogDescription>{t('settings.address.confirmBody')}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">{t('settings.address.newUrl')}</p>
              <Technical className="block text-sm">{previewURL}</Technical>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">{t('settings.address.oldUrl')}</p>
              <Technical className="block text-sm">{current.url}</Technical>
            </div>
            <p className="text-xs text-muted-foreground">{t('settings.address.confirmRollback')}</p>
            {nextWebPath !== current.web_path && current.web_path !== '' ? (
              <p className="text-xs text-warning">{t('settings.address.confirmSignIn')}</p>
            ) : null}
          </DialogBody>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setConfirming(false)}>
              {t('actions.cancel')}
            </Button>
            <Button
              variant="primary"
              size="sm"
              loading={moveMutation.isPending}
              onClick={() => moveMutation.mutate()}
            >
              {t('settings.address.moveConfirm')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {moving ? <MovingDialog change={moving} onGiveUp={() => setMoving(null)} /> : null}
    </Card>
  )
}

/**
 * What the operator watches while the panel restarts.
 *
 * It polls the new address's health endpoint — the real one, not a special
 * endpoint invented for this — and sends the browser there on the first
 * success. That endpoint answers any origin precisely so this poll can run: the
 * page is on the old origin and the panel is coming back on a new one.
 *
 * It never spins forever. After the timeout it stops and shows both URLs as
 * plain links, with the reason, because at that point the honest thing is to
 * let the operator look rather than to keep pretending.
 */
function MovingDialog({ change, onGiveUp }: { change: PanelAddressChange; onGiveUp: () => void }) {
  const { t } = useTranslation()
  const [elapsed, setElapsed] = useState(0)
  const [gaveUp, setGaveUp] = useState(false)
  const startedAt = useRef(Date.now())

  useEffect(() => {
    if (!change.restarting) return
    let cancelled = false

    const tick = async () => {
      if (cancelled) return
      const waited = Date.now() - startedAt.current
      setElapsed(waited)
      if (waited > COME_BACK_TIMEOUT_MS) {
        setGaveUp(true)
        return
      }
      try {
        // no-store, because a cached answer from before the restart would
        // report the panel as back when it has not moved yet.
        const response = await fetch(change.health_url, { cache: 'no-store', mode: 'cors' })
        if (response.ok && !cancelled) {
          window.location.assign(change.url)
          return
        }
      } catch {
        // Still down, or the browser refused the cross-origin request while
        // nothing was listening. Either way, keep waiting.
      }
      if (!cancelled) window.setTimeout(tick, POLL_INTERVAL_MS)
    }

    void tick()
    return () => {
      cancelled = true
    }
  }, [change])

  return (
    <Dialog open onOpenChange={() => undefined}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {gaveUp ? t('settings.address.stillWaitingTitle') : t('settings.address.movingTitle')}
          </DialogTitle>
          <DialogDescription>
            {change.restarting
              ? gaveUp
                ? t('settings.address.stillWaitingBody')
                : t('settings.address.movingBody', { seconds: Math.round(elapsed / 1000) })
              : change.detail}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3 text-sm">
          <div>
            <p className="text-xs text-muted-foreground">{t('settings.address.newUrl')}</p>
            <a
              className="inline-flex items-center gap-1 text-sm text-accent underline"
              href={change.url}
            >
              <Technical>{change.url}</Technical>
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          </div>
          {gaveUp || !change.restarting ? (
            <div>
              <p className="text-xs text-muted-foreground">{t('settings.address.oldUrl')}</p>
              <a
                className="inline-flex items-center gap-1 text-sm text-accent underline"
                href={change.previous_url}
              >
                <Technical>{change.previous_url}</Technical>
                <ExternalLink className="size-3" aria-hidden="true" />
              </a>
            </div>
          ) : null}
          {!change.session_survives ? (
            <p className="text-xs text-warning">{t('settings.address.confirmSignIn')}</p>
          ) : null}
        </DialogBody>
        {gaveUp || !change.restarting ? (
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={onGiveUp}>
              {t('actions.close')}
            </Button>
          </DialogFooter>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

/**
 * Rebuilds a URL with a different port and path, for the preview.
 *
 * The empty web path is why this is a function rather than a template: an
 * empty segment interpolated between two slashes produces `//`, which is not
 * the URL the panel serves.
 */
export function buildURL(currentURL: string, port: number, webPath: string): string {
  let origin: URL
  try {
    origin = new URL(currentURL)
  } catch {
    return currentURL
  }
  origin.port = String(port)
  origin.pathname = webPath ? `/${webPath}/` : '/'
  return origin.toString()
}
