import { forwardRef, useCallback, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { hasDisplayName, tunnelLabel, type NamedTunnel } from '@/lib/format'
import { cn } from '@/lib/utils'

export interface TechnicalProps extends React.HTMLAttributes<HTMLSpanElement> {
  /** The value. Always Latin script, always left-to-right, never translated. */
  children: React.ReactNode
  /** Adds a copy control beside the value. */
  copyable?: boolean
  /** The exact text to copy, when the rendered form differs from it. */
  copyValue?: string
}

/**
 * Renders a technical value — an IP address, CIDR, interface name, GRE key,
 * MAC address, shell command or file path.
 *
 * Two things make this mandatory rather than cosmetic. First, `dir="ltr"` with
 * `unicode-bidi: isolate` stops the bidi algorithm reordering the value when it
 * sits inside Farsi text: without isolation `172.17.7.1/30` renders with its
 * parts transposed and the operator reads a different address than the one
 * stored. Second, tabular monospace keeps columns aligned and stops digits
 * jittering as live figures update.
 *
 * Every such value in the panel goes through this component. That is what makes
 * the rule enforceable rather than a convention.
 */
export const Technical = forwardRef<HTMLSpanElement, TechnicalProps>(
  ({ children, className, copyable, copyValue, ...props }, ref) => {
    const text = copyValue ?? (typeof children === 'string' ? children : String(children ?? ''))

    if (!copyable) {
      return (
        <span ref={ref} dir="ltr" className={cn('technical', className)} {...props}>
          {children}
        </span>
      )
    }

    return (
      <span className="inline-flex items-center gap-1 align-middle">
        <span ref={ref} dir="ltr" className={cn('technical', className)} {...props}>
          {children}
        </span>
        <CopyButton value={text} />
      </span>
    )
  },
)
Technical.displayName = 'Technical'

/**
 * What a tunnel is called: its display name when it has one, its interface name
 * otherwise.
 *
 * The two are typeset differently on purpose. A display name is prose the
 * operator wrote and is set in the body face; an interface name is a technical
 * value and goes through `Technical`, with the bidi isolation that keeps it
 * readable inside Farsi text. Rendering both through this component is what
 * stops one screen showing `gre-a-1` while the next shows the name beside it.
 */
export function TunnelName({
  tunnel,
  className,
  copyable,
}: {
  tunnel: NamedTunnel
  className?: string
  /** Only honoured for the interface name; a display name is not a value to copy. */
  copyable?: boolean
}) {
  if (!hasDisplayName(tunnel)) {
    return (
      <Technical className={className} copyable={copyable}>
        {tunnel.interface_name}
      </Technical>
    )
  }
  return <span className={className}>{tunnelLabel(tunnel)}</span>
}

/**
 * A block of technical text — a rendered unit file, a command, a diagnostic
 * transcript. Same isolation rules, but it wraps and scrolls.
 */
export function TechnicalBlock({
  children,
  className,
  copyable,
  ...props
}: React.HTMLAttributes<HTMLPreElement> & { copyable?: boolean }) {
  const text = typeof children === 'string' ? children : ''
  return (
    <div className="relative">
      <pre
        dir="ltr"
        className={cn(
          'technical max-h-96 overflow-auto whitespace-pre rounded-md border border-border bg-surface-sunken p-3 text-xs leading-relaxed scrollbar-thin',
          className,
        )}
        {...props}
      >
        {children}
      </pre>
      {copyable && text ? (
        <span className="absolute top-2 [inset-inline-end:0.5rem]">
          <CopyButton value={text} />
        </span>
      ) : null}
    </div>
  )
}

export function CopyButton({ value, label }: { value: string; label?: string }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  const [failed, setFailed] = useState(false)
  const buttonRef = useRef<HTMLButtonElement>(null)

  const copy = useCallback(async () => {
    const button = buttonRef.current
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        // Clipboard access needs a secure context, which a panel reached over
        // plain HTTP on a private address does not have. The fallback textarea
        // goes beside the button, not on document.body: inside an open dialog
        // the focus trap treats a body-level textarea as an escape and pulls
        // focus straight back, so execCommand ran with no live selection and
        // the pairing code was never copied.
        const area = document.createElement('textarea')
        area.value = value
        area.setAttribute('readonly', '')
        area.setAttribute('aria-hidden', 'true')
        area.style.position = 'absolute'
        area.style.insetInlineStart = '-9999px'
        const host = button?.parentElement ?? document.body
        host.appendChild(area)
        area.select()
        const accepted = document.execCommand('copy')
        host.removeChild(area)
        // The selection took the focus; hand it back to the control.
        button?.focus()
        if (!accepted) throw new Error('copy refused')
      }
      setCopied(true)
      setFailed(false)
      window.setTimeout(() => setCopied(false), 1600)
    } catch {
      setFailed(true)
      setCopied(false)
      window.setTimeout(() => setFailed(false), 2400)
    }
  }, [value])

  const title = failed ? t('actions.copyFailed') : copied ? t('actions.copied') : (label ?? t('actions.copy'))

  return (
    <button
      ref={buttonRef}
      type="button"
      onClick={() => void copy()}
      title={title}
      aria-label={title}
      className={cn(
        'inline-flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        failed && 'text-danger',
        copied && 'text-ok',
      )}
    >
      {copied ? (
        <Check className="size-3.5" aria-hidden="true" />
      ) : (
        <Copy className="size-3.5" aria-hidden="true" />
      )}
      <span className="sr-only" role="status">
        {copied ? t('actions.copied') : ''}
      </span>
    </button>
  )
}
