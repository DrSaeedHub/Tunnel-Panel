import { useCallback, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { ApiError, api } from '@/lib/api'
import type { ActionResponse, DeleteReport, VerifyReport } from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
import { describeError } from '@/components/ui/feedback'

export type TunnelAction = 'up' | 'down' | 'restart' | 'reapply'

export interface ActionState {
  /** The tunnel currently being changed, so its row can show progress. */
  pending: number | null
  run: (tunnelId: number, action: TunnelAction, name: string) => Promise<boolean>
  remove: (tunnelId: number, name: string, options: DeleteOptions) => Promise<boolean>
  setMonitoring: (tunnelId: number, enabled: boolean, name: string) => Promise<boolean>
}

export interface DeleteOptions {
  /** Set when the backend has told us this tunnel carries the operator's own connection. */
  iUnderstandIMayLoseAccess?: boolean
}

/**
 * Mutating actions on a tunnel.
 *
 * Nothing here is optimistic. The panel exists because the script it replaces
 * claimed success on the strength of a command returning zero; a tunnel is
 * reported as changed only once the backend's own verification says so, and a
 * verification that failed is reported as a failure even though the HTTP call
 * succeeded.
 */
export function useTunnelActions(): ActionState {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [pending, setPending] = useState<number | null>(null)

  const invalidate = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['tunnels'] }),
      queryClient.invalidateQueries({ queryKey: ['monitor'] }),
      queryClient.invalidateQueries({ queryKey: ['reconcile'] }),
    ])
  }, [queryClient])

  const run = useCallback(
    async (tunnelId: number, action: TunnelAction, name: string) => {
      setPending(tunnelId)
      try {
        const result = await api.post<ActionResponse>(`/tunnels/${tunnelId}/${action}`, {})
        await invalidate()

        if (!verificationPassed(result.verification)) {
          toast({
            tone: 'error',
            title: describeAction(action, name, t),
            description: verificationFailures(result.verification).join(' · ') || t('errors.title'),
          })
          return false
        }

        // The backend returns the forwarding rules that relayed over this
        // tunnel and have just lost their path. Saying so at the moment of the
        // action is the difference between a deliberate change and a relay
        // that quietly stopped (§10).
        const warnings = (result.warnings ?? []).map((warning) => warning.message).join(' · ')
        toast({
          tone: warnings ? 'info' : 'success',
          title: describeAction(action, name, t),
          description: warnings || undefined,
        })
        return true
      } catch (error) {
        toast({
          tone: 'error',
          title: describeAction(action, name, t),
          description: describeError(error, t).message,
        })
        return false
      } finally {
        setPending(null)
      }
    },
    [invalidate, t, toast],
  )

  const remove = useCallback(
    async (tunnelId: number, name: string, options: DeleteOptions) => {
      setPending(tunnelId)
      try {
        await api.delete<DeleteReport>(`/tunnels/${tunnelId}`, {
          i_understand_i_may_lose_access: options.iUnderstandIMayLoseAccess || undefined,
        })
        await invalidate()
        toast({ tone: 'success', title: t('deleteDialog.deleted', { name }) })
        return true
      } catch (error) {
        // A refusal to cut the operator's own connection is not a failure to
        // report as one: the dialog turns it into the acknowledgement prompt.
        if (error instanceof ApiError && error.code === 'WOULD_CUT_OWN_ACCESS') throw error
        toast({
          tone: 'error',
          title: t('actions.delete'),
          description: describeError(error, t).message,
        })
        return false
      } finally {
        setPending(null)
      }
    },
    [invalidate, t, toast],
  )

  const setMonitoring = useCallback(
    async (tunnelId: number, enabled: boolean, name: string) => {
      setPending(tunnelId)
      try {
        await api.post(`/tunnels/${tunnelId}/monitor/${enabled ? 'enable' : 'disable'}`, {})
        await invalidate()
        toast({
          tone: 'success',
          title: enabled ? t('monitor.enableMonitoring') : t('monitor.disableMonitoring'),
          description: name,
        })
        return true
      } catch (error) {
        toast({
          tone: 'error',
          title: enabled ? t('monitor.enableMonitoring') : t('monitor.disableMonitoring'),
          description: describeError(error, t).message,
        })
        return false
      } finally {
        setPending(null)
      }
    },
    [invalidate, t, toast],
  )

  return { pending, run, remove, setMonitoring }
}

/**
 * Whether an apply actually succeeded.
 *
 * A skipped check is neither a pass nor a failure and must not be counted as
 * either, and a non-fatal check that failed — peer reachability, which depends
 * on the far end existing yet — is reported without failing the operation.
 */
export function verificationPassed(report: VerifyReport | undefined): boolean {
  if (!report) return true
  if (report.ok) return true
  return !(report.checks ?? []).some((check) => check.fatal && !check.ok && !check.skipped)
}

export function verificationFailures(report: VerifyReport | undefined): string[] {
  if (!report) return []
  if (report.failures?.length) return report.failures
  return report.checks
    .filter((check) => check.fatal && !check.ok && !check.skipped)
    .map((check) => check.detail || check.name)
}

function describeAction(
  action: TunnelAction,
  name: string,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  const label = {
    up: t('actions.enable'),
    down: t('actions.disable'),
    restart: t('actions.restart'),
    reapply: t('actions.reapply'),
  }[action]
  return `${label} · ${name}`
}
