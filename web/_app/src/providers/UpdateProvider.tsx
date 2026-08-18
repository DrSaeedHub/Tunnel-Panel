import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'

import { api } from '@/lib/api'
import type { UpdateStatus } from '@/lib/types'
import { useToast } from './ToastProvider'
import { UpdateDialog } from '@/components/system/UpdateDialog'

/** The toast key, so the notice is one notice however often it is raised. */
export const UPDATE_TOAST_KEY = 'panel-update'

/** Which version the operator has already closed the notice for. */
const DISMISSED_KEY = 'gre-panel:update-dismissed'

/** How often the status is polled while an update is actually running. */
const APPLYING_POLL_MS = 3000

/** And how often otherwise. The backend caches; this is not a check per poll. */
const IDLE_POLL_MS = 15 * 60 * 1000

interface UpdateContextValue {
  status?: UpdateStatus
  isLoading: boolean
  /** Why the panel could not be asked, when it could not be asked. */
  error: unknown
  /** An explicit "check again", which waits on the release host. */
  check: () => void
  isChecking: boolean
  /** Starts the update. The panel restarts partway through it. */
  start: (version?: string) => void
  isStarting: boolean
  startError: unknown
  /** True from the moment the update is started until it resolves. */
  applying: boolean
  open: () => void
  close: () => void
  isOpen: boolean
}

const UpdateContext = createContext<UpdateContextValue | null>(null)

function readDismissed(): string {
  try {
    return localStorage.getItem(DISMISSED_KEY) ?? ''
  } catch {
    // A browser with storage denied simply gets the notice again next time,
    // which is a better failure than no notice at all.
    return ''
  }
}

function rememberDismissed(version: string) {
  try {
    localStorage.setItem(DISMISSED_KEY, version)
  } catch {
    // Nothing to do: see readDismissed.
  }
}

/**
 * Everything about "is this panel out of date", in one place above the pages.
 *
 * It is mounted inside the application shell rather than on a page, which is
 * what makes it survive moving between tabs: the pages come and go under the
 * shell, and the poll, the dialog and the notice do not restart with them. The
 * notice itself is raised through the toast provider, which sits higher still,
 * so it stays up even if this remounts.
 */
export function UpdateProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const { toast, dismissKey } = useToast()
  const queryClient = useQueryClient()

  const [isOpen, setOpen] = useState(false)
  // Set when this browser starts an update, so the poll keeps going through the
  // stretch where the panel is down and the status endpoint answers nothing.
  const [applying, setApplying] = useState(false)
  const [dismissedVersion, setDismissedVersion] = useState(readDismissed)
  // The version the notice is currently up for, so re-answers of the query do
  // not raise it again and again.
  const announced = useRef('')

  const statusQuery = useQuery({
    queryKey: ['system', 'update'],
    queryFn: () => api.get<UpdateStatus>('/system/update'),
    // The panel is often on a server with no outbound access, where a check
    // never succeeds; retrying it on every mount would only add latency.
    retry: false,
    staleTime: 60_000,
    refetchInterval: (query) =>
      applying || query.state.data?.state.stage === 'running' || query.state.data?.checking
        ? APPLYING_POLL_MS
        : IDLE_POLL_MS,
  })

  const status = statusQuery.data
  const stage = status?.state.stage

  const checkMutation = useMutation({
    mutationFn: () => api.post<UpdateStatus>('/system/update/check'),
    onSuccess: (next) => queryClient.setQueryData(['system', 'update'], next),
  })

  const startMutation = useMutation({
    mutationFn: (version?: string) =>
      api.post<UpdateStatus>('/system/update', version ? { version } : undefined),
    onSuccess: (next) => {
      setApplying(true)
      queryClient.setQueryData(['system', 'update'], next)
    },
  })

  // An update that has resolved stops the fast poll, whichever way it went.
  useEffect(() => {
    if (applying && (stage === 'succeeded' || stage === 'failed')) setApplying(false)
  }, [applying, stage])

  const open = useCallback(() => setOpen(true), [])
  const close = useCallback(() => setOpen(false), [])

  const start = useCallback(
    (version?: string) => {
      startMutation.mutate(version)
    },
    [startMutation],
  )

  // The notice itself. It carries the button, it stays until it is closed, and
  // closing it is remembered per version: an operator who has decided not to
  // update to v0.2.0 today should not be asked again on every page they open,
  // and should be told about v0.3.0 when it lands.
  useEffect(() => {
    if (!status?.update_available) return
    const version = status.latest.version
    if (!version || version === dismissedVersion || announced.current === version) return

    announced.current = version
    toast({
      tone: 'info',
      key: UPDATE_TOAST_KEY,
      persistent: true,
      title: t('update.available.title', { version }),
      description: t('update.available.body', { current: status.current_version }),
      action: { label: t('update.actions.open'), onClick: () => setOpen(true) },
      onDismiss: () => {
        rememberDismissed(version)
        setDismissedVersion(version)
      },
    })
  }, [status, dismissedVersion, toast, t])

  // Once the update is under way the notice has done its job, and leaving it up
  // would offer a button for something already happening. Deliberately not on
  // "succeeded": that state outlives its run, and taking the notice down for a
  // finished update would hide the next version behind the last one.
  useEffect(() => {
    if (stage === 'running' || applying) dismissKey(UPDATE_TOAST_KEY)
  }, [stage, applying, dismissKey])

  const value = useMemo<UpdateContextValue>(
    () => ({
      status,
      isLoading: statusQuery.isLoading,
      error: statusQuery.error,
      check: () => checkMutation.mutate(),
      isChecking: checkMutation.isPending || Boolean(status?.checking),
      start,
      isStarting: startMutation.isPending,
      startError: startMutation.error,
      applying: applying || stage === 'running',
      open,
      close,
      isOpen,
    }),
    [
      status,
      statusQuery.isLoading,
      statusQuery.error,
      checkMutation,
      start,
      startMutation.isPending,
      startMutation.error,
      applying,
      stage,
      open,
      close,
      isOpen,
    ],
  )

  return (
    <UpdateContext.Provider value={value}>
      {children}
      <UpdateDialog />
    </UpdateContext.Provider>
  )
}

export function useUpdate(): UpdateContextValue {
  const context = useContext(UpdateContext)
  if (!context) throw new Error('useUpdate must be used inside UpdateProvider')
  return context
}
