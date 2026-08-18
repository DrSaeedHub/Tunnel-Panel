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
}

interface ToastContextValue {
  toast: (toast: Omit<Toast, 'id'>) => void
  dismiss: (id: number) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

/** Successes disappear on their own; failures stay until dismissed. */
const SUCCESS_TIMEOUT_MS = 5000

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(1)

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id))
  }, [])

  const toast = useCallback(
    (input: Omit<Toast, 'id'>) => {
      const id = nextId.current++
      setToasts((current) => [...current, { ...input, id }])
      if (input.tone !== 'error') {
        window.setTimeout(() => dismiss(id), SUCCESS_TIMEOUT_MS)
      }
    },
    [dismiss],
  )

  const value = useMemo(() => ({ toast, dismiss }), [toast, dismiss])

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
