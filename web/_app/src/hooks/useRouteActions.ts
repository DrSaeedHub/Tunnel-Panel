import { useCallback, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { api } from '@/lib/api'
import type {
  RouteActionResponse,
  RouteDeleteReport,
  RouteDuplicateResponse,
  RouteVerifyReport,
} from '@/lib/types'
import { useToast } from '@/providers/ToastProvider'
import { describeError } from '@/components/ui/feedback'

export type RouteAction = 'enable' | 'disable' | 'reapply'

export interface RouteActionState {
  /** The rule currently being changed, so its row can show progress. */
  pending: number | null
  /** True while a whole-ruleset operation — reorder or apply-all — is running. */
  bulkPending: boolean
  run: (routeRuleId: number, action: RouteAction, name: string) => Promise<boolean>
  remove: (routeRuleId: number, name: string) => Promise<RouteDeleteReport | null>
  duplicate: (routeRuleId: number, name: string) => Promise<RouteDuplicateResponse | null>
  reorder: (routeRuleIds: number[]) => Promise<boolean>
  applyAll: () => Promise<boolean>
}

/**
 * Mutating actions on a forwarding rule.
 *
 * Nothing here is optimistic, for the same reason nothing in the tunnel actions
 * is: the backend replaces the whole netfilter namespace in one transaction and
 * then reads it back, and a rule is reported as changed only once that
 * verification agrees. An HTTP 200 with a failed verification is a failure.
 */
export function useRouteActions(): RouteActionState {
  const { t } = useTranslation()
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [pending, setPending] = useState<number | null>(null)
  const [bulkPending, setBulkPending] = useState(false)

  const invalidate = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ['routes'] }),
      // A rule changing can change the forwarding picture and the reconcile
      // report, and deleting the last one can offer to revert forwarding.
      queryClient.invalidateQueries({ queryKey: ['forwarding'] }),
      queryClient.invalidateQueries({ queryKey: ['reconcile'] }),
    ])
  }, [queryClient])

  const run = useCallback(
    async (routeRuleId: number, action: RouteAction, name: string) => {
      setPending(routeRuleId)
      try {
        const result = await api.post<RouteActionResponse>(`/routes/${routeRuleId}/${action}`, {})

        if (!routeVerificationPassed(result.verification)) {
          toast({
            tone: 'error',
            title: describeAction(action, name, t),
            description: routeVerificationFailures(result.verification).join(' · ') || t('errors.title'),
          })
          return false
        }

        toast({ tone: 'success', title: describeAction(action, name, t) })
        return true
      } catch (error) {
        toast({
          tone: 'error',
          title: describeAction(action, name, t),
          description: describeError(error, t).message,
        })
        return false
      } finally {
        // In finally, not on the success path: a rule whose action failed
        // half-way is precisely the one whose state the list has to show.
        await invalidate()
        setPending(null)
      }
    },
    [invalidate, t, toast],
  )

  const remove = useCallback(
    async (routeRuleId: number, name: string) => {
      setPending(routeRuleId)
      try {
        const report = await api.delete<RouteDeleteReport>(`/routes/${routeRuleId}`, {})
        toast({ tone: 'success', title: t('deleteRoute.deleted', { name }) })
        return report
      } catch (error) {
        toast({
          tone: 'error',
          title: t('actions.delete'),
          description: describeError(error, t).message,
        })
        return null
      } finally {
        // In finally, not on the success path: a rule whose action failed
        // half-way is precisely the one whose state the list has to show.
        await invalidate()
        setPending(null)
      }
    },
    [invalidate, t, toast],
  )

  const duplicate = useCallback(
    async (routeRuleId: number, name: string) => {
      setPending(routeRuleId)
      try {
        const result = await api.post<RouteDuplicateResponse>(`/routes/${routeRuleId}/duplicate`, {})
        toast({
          tone: 'success',
          title: t('routes.duplicated', { name: result.route.route_rule_title }),
          description: t('routes.duplicateNote'),
        })
        return result
      } catch (error) {
        toast({
          tone: 'error',
          title: `${t('actions.duplicate')} · ${name}`,
          description: describeError(error, t).message,
        })
        return null
      } finally {
        // In finally, not on the success path: a rule whose action failed
        // half-way is precisely the one whose state the list has to show.
        await invalidate()
        setPending(null)
      }
    },
    [invalidate, t, toast],
  )

  const reorder = useCallback(
    async (routeRuleIds: number[]) => {
      setBulkPending(true)
      try {
        const result = await api.post<{ verification: RouteVerifyReport }>('/routes/reorder', {
          route_rule_ids: routeRuleIds,
        })
        if (!routeVerificationPassed(result.verification)) {
          toast({
            tone: 'error',
            title: t('routes.order.title'),
            description: routeVerificationFailures(result.verification).join(' · '),
          })
          return false
        }
        toast({ tone: 'success', title: t('routes.order.saved') })
        return true
      } catch (error) {
        toast({
          tone: 'error',
          title: t('routes.order.title'),
          description: describeError(error, t).message,
        })
        return false
      } finally {
        await invalidate()
        setBulkPending(false)
      }
    },
    [invalidate, t, toast],
  )

  const applyAll = useCallback(async () => {
    setBulkPending(true)
    try {
      const result = await api.post<{ verification: RouteVerifyReport; rules_applied: number }>(
        '/routes/apply-all',
        {},
      )
      if (!routeVerificationPassed(result.verification)) {
        toast({
          tone: 'error',
          title: t('routes.applyAll'),
          description: routeVerificationFailures(result.verification).join(' · '),
        })
        return false
      }
      toast({
        tone: 'success',
        title: t('routes.applyAllDone'),
        description: t('routes.bulk.applied', { count: result.rules_applied }),
      })
      return true
    } catch (error) {
      toast({ tone: 'error', title: t('routes.applyAll'), description: describeError(error, t).message })
      return false
    } finally {
      await invalidate()
      setBulkPending(false)
    }
  }, [invalidate, t, toast])

  return { pending, bulkPending, run, remove, duplicate, reorder, applyAll }
}

/**
 * Whether an apply actually succeeded.
 *
 * A skipped check is neither a pass nor a failure — a disabled rule installs
 * nothing, so its rules-present check is skipped rather than failed — and a
 * non-fatal check that failed is reported without failing the operation.
 */
export function routeVerificationPassed(report: RouteVerifyReport | undefined): boolean {
  if (!report) return true
  if (report.ok) return true
  return !(report.checks ?? []).some((check) => check.fatal && !check.ok && !check.skipped)
}

export function routeVerificationFailures(report: RouteVerifyReport | undefined): string[] {
  if (!report) return []
  if (report.failures?.length) return report.failures
  return report.checks
    .filter((check) => check.fatal && !check.ok && !check.skipped)
    .map((check) => check.detail || check.name)
}

function describeAction(
  action: RouteAction,
  name: string,
  t: (key: string, options?: Record<string, unknown>) => string,
): string {
  const label = {
    enable: t('actions.enable'),
    disable: t('actions.disable'),
    reapply: t('actions.reapply'),
  }[action]
  return `${label} · ${name}`
}
