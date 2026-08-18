import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { cn } from '@/lib/utils'

export type ToastTone = 'success' | 'error' | 'info'

export interface Toast {
  id: number
  tone: ToastTone
  title: string
  description?: string
  /** Offered on failures, so a toast is never a dead end. */
  onRetry?: () => void
  /**
   * A named action, for a notification that exists to offer one — the update
   * notice and its Update button. Distinct from onRetry, which repeats what
   * just failed and is labelled for the caller.
   */
  action?: { label: string; onClick: () => void }
  /**
   * Keeps this toast on screen until somebody closes it.
   *
   * The default is a countdown, which is right for "saved" and wrong for
   * anything the operator is meant to act on: a notice that a new version
   * exists cannot both offer a button and take it away five seconds later.
   * Failures are persistent whether or not this is set, for the same reason.
   */
  persistent?: boolean
  /**
   * Identity across raises. A toast raised again under a key that is already on
   * screen replaces it rather than stacking a second copy — which is what
   * happens otherwise when a live query re-answers, or when the operator moves
   * between pages and the component that raises it mounts again.
   */
  key?: string
  /** Called when this toast is closed, however it is closed. */
  onDismiss?: () => void
}

interface ToastContextValue {
  toast: (toast: Omit<Toast, 'id'>) => void
  dismiss: (id: number) => void
  /** Closes whatever is on screen under this key, if anything is. */
  dismissKey: (key: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

/** Successes disappear on their own; failures stay until dismissed. */
const SUCCESS_TIMEOUT_MS = 5000

/**
 * The panel's notifications.
 *
 * This provider is mounted above the router, which is what makes a toast
 * survive navigation: moving between pages unmounts the page, not this, so a
 * notice raised on the dashboard is still there on the settings screen. The
 * timers are the only thing that removes one by itself, and they are deliberate
 * per toast rather than global.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)
  // Timers and dismissal callbacks by toast id, held outside the state on
  // purpose: a state updater may be run more than once for one update, and a
  // callback fired from inside one would run twice for a single close.
  const timers = useRef(new Map<number, number>())
  const handlers = useRef(new Map<number, () => void>())
  // Which toast is currently on screen under each key.
  const keyed = useRef(new Map<string, number>())

  const forget = useCallback((id: number) => {
    const handle = timers.current.get(id)
    if (handle !== undefined) window.clearTimeout(handle)
    timers.current.delete(id)
    handlers.current.delete(id)
    for (const [key, held] of keyed.current) {
      if (held === id) keyed.current.delete(key)
    }
  }, [])

  const dismiss = useCallback(
    (id: number) => {
      const onDismiss = handlers.current.get(id)
      forget(id)
      setToasts((current) => current.filter((t) => t.id !== id))
      onDismiss?.()
    },
    [forget],
  )

  const dismissKey = useCallback(
    (key: string) => {
      const id = keyed.current.get(key)
      if (id !== undefined) dismiss(id)
    },
    [dismiss],
  )

  const toast = useCallback(
    (input: Omit<Toast, 'id'>) => {
      const id = nextId.current++
      // A keyed toast replaces its predecessor, so the same notice raised twice
      // — by a live query re-answering, or by a component mounting again after
      // the operator moved between pages — is one notice and not a stack.
      const previous = input.key ? keyed.current.get(input.key) : undefined
      if (previous !== undefined) forget(previous)
      if (input.key) keyed.current.set(input.key, id)
      if (input.onDismiss) handlers.current.set(id, input.onDismiss)

      setToasts((current) => [
        ...current.filter((t) => t.id !== previous),
        { ...input, id },
      ])

      // Anything the operator has to act on stays: a failure to read, or a
      // notice carrying a button. Only a plain success counts itself down.
      if (input.tone !== 'error' && !input.persistent) {
        timers.current.set(id, window.setTimeout(() => dismiss(id), SUCCESS_TIMEOUT_MS))
      }
    },
    [dismiss, forget],
  )

  const value = useMemo(() => ({ toast, dismiss, dismissKey }), [toast, dismiss, dismissKey])

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

function ToastViewport({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  const { t } = useTranslation()
  if (!toasts.length) return null

  return (
    // Anchored to the inline-end edge, so it slides in from the right in
    // English and the left in Farsi without a second rule.
    <div
      className="pointer-events-none fixed bottom-24 z-50 flex w-full max-w-sm flex-col gap-2 px-4 lg:bottom-4 [inset-inline-end:0]"
      role="region"
      aria-live="polite"
      aria-label={t('a11y.liveRegion')}
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={cn(
            'pointer-events-auto animate-slide-in rounded-lg border p-3 shadow-lg backdrop-blur',
            toast.tone === 'success' && 'border-ok/40 bg-ok-muted text-foreground',
            toast.tone === 'error' && 'border-danger/40 bg-danger-muted text-foreground',
            toast.tone === 'info' && 'border-border bg-surface-raised text-foreground',
          )}
          role={toast.tone === 'error' ? 'alert' : 'status'}
        >
          <div className="flex items-start gap-2">
            <ToastIcon tone={toast.tone} />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{toast.title}</p>
              {toast.description ? (
                <p className="mt-0.5 break-words text-xs text-muted-foreground">{toast.description}</p>
              ) : null}
              {toast.action ? (
                <button
                  type="button"
                  onClick={() => toast.action?.onClick()}
                  className="mt-2 rounded-md bg-ink px-2.5 py-1 text-xs font-medium text-ink-foreground hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {toast.action.label}
                </button>
              ) : null}
              {toast.onRetry ? (
                <button
                  type="button"
                  onClick={() => {
                    onDismiss(toast.id)
                    toast.onRetry?.()
                  }}
                  className="mt-2 rounded-md border border-border px-2 py-1 text-xs font-medium hover:bg-muted"
                >
                  {t('actions.retry')}
                </button>
              ) : null}
            </div>
            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              aria-label={t('actions.dismiss')}
            >
              <X className="size-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

function ToastIcon({ tone }: { tone: ToastTone }) {
  const className = 'mt-0.5 size-4 shrink-0'
  if (tone === 'success') return <CheckCircle2 className={cn(className, 'text-ok')} aria-hidden="true" />
  if (tone === 'error') return <AlertTriangle className={cn(className, 'text-danger')} aria-hidden="true" />
  return <Info className={cn(className, 'text-muted-foreground')} aria-hidden="true" />
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext)
  if (!context) throw new Error('useToast must be used inside ToastProvider')
  return context
}
