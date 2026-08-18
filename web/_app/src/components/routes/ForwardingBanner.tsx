import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { AlertTriangle } from 'lucide-react'

import { api } from '@/lib/api'
import type { ForwardingResponse } from '@/lib/types'
import { usePreferences } from '@/providers/PreferencesProvider'
import { formatCount, formatPercent } from '@/lib/format'
import { useToast } from '@/providers/ToastProvider'
import { describeError } from '../ui/feedback'
import { Button } from '../ui/button'

/**
 * The state of the kernel parameter every forwarding rule depends on.
 *
 * A ruleset that is installed, verified and correct still carries nothing when
 * `ip_forward` is off, and nothing on the rules themselves says so. That is the
 * one condition worth interrupting the page for; everything else the backend
 * warns about is shown here too, but quietly.
 */
export function ForwardingBanner({
  forwarding,
  enabledRules,
  onChanged,
}: {
  forwarding: ForwardingResponse | undefined
  enabledRules: number
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const { toast } = useToast()
  const { digits, language } = usePreferences()
  const [busy, setBusy] = useState(false)

  if (!forwarding) return null
  const status = forwarding.forwarding
  const warnings = forwarding.warnings ?? []

  const enable = async () => {
    setBusy(true)
    try {
      await api.post('/system/forwarding/enable', {})
      toast({ tone: 'success', title: t('routes.forwardingOff.done') })
      onChanged()
    } catch (error) {
      toast({
        tone: 'error',
        title: t('routes.forwardingOff.action'),
        description: describeError(error, t).message,
      })
    } finally {
      setBusy(false)
    }
  }

  // Forwarding being off only matters once something depends on it.
  if (!status.ipv4_forwarding && enabledRules > 0) {
    return (
      <div className="rounded-md border border-danger/40 bg-danger-muted p-3">
        <p className="flex items-center gap-2 text-sm font-medium text-danger">
          <AlertTriangle className="size-4 shrink-0" aria-hidden="true" />
          {t('routes.forwardingOff.title')}
        </p>
        <p className="mt-1 text-xs">{t('routes.forwardingOff.body')}</p>
        <Button variant="primary" size="sm" className="mt-2" loading={busy} onClick={() => void enable()}>
          {t('routes.forwardingOff.action')}
        </Button>
      </div>
    )
  }

  if (!warnings.length) return null

  return (
    <div className="space-y-1 rounded-md border border-warn/40 bg-warn-muted p-3">
      {warnings.map((warning) => (
        <p key={warning.code} className="flex items-start gap-2 text-xs">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-warn" aria-hidden="true" />
          {warning.message}
        </p>
      ))}
      {status.conntrack_max > 0 ? (
        <p className="text-2xs text-muted-foreground">
          {t('routes.conntrack.usage', {
            used: formatCount(status.conntrack_count, digits, language),
            max: formatCount(status.conntrack_max, digits, language),
          })}
          {' · '}
          {formatPercent(status.conntrack_usage_percent, digits)}
        </p>
      ) : null}
    </div>
  )
}
