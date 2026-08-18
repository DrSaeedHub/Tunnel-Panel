import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'

import { ApiError, api, setUnauthorizedHandler } from '@/lib/api'
import type { HealthResponse, Session, User } from '@/lib/types'

export type AuthStatus = 'loading' | 'authenticated' | 'anonymous' | 'setup-required'

interface AuthContextValue {
  status: AuthStatus
  user: User | null
  /** Set when a session ended mid-use, so the login page can explain why. */
  sessionExpired: boolean
  login: (username: string, password: string) => Promise<Session>
  setup: (username: string, password: string) => Promise<Session>
  logout: () => Promise<void>
  clearExpiry: () => void
  refetch: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [sessionExpired, setSessionExpired] = useState(false)

  // Health is public and reports whether an account exists at all, which is
  // how the first-run screen is reached without guessing from a 503.
  const healthQuery = useQuery({
    queryKey: ['health'],
    queryFn: () => api.get<HealthResponse>('/system/health'),
    refetchInterval: 30_000,
    retry: 1,
  })

  const setupRequired = healthQuery.data?.setup_required === true

  const meQuery = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: async () => {
      try {
        return await api.get<User>('/auth/me')
      } catch (error) {
        // An expired or absent session is an answer, not a failure: the panel
        // shows the login page rather than an error card.
        if (error instanceof ApiError && (error.status === 401 || error.status === 503)) return null
        throw error
      }
    },
    enabled: healthQuery.isSuccess && !setupRequired,
    retry: false,
    staleTime: 60_000,
  })

  // Any request rejected for want of a session drops the panel back to the
  // login page, remembering where the operator was.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSessionExpired(true)
      queryClient.setQueryData(['auth', 'me'], null)
    })
    return () => setUnauthorizedHandler(null)
  }, [queryClient])

  const status: AuthStatus = useMemo(() => {
    if (healthQuery.isLoading) return 'loading'
    if (setupRequired) return 'setup-required'
    if (meQuery.isLoading) return 'loading'
    return meQuery.data ? 'authenticated' : 'anonymous'
  }, [healthQuery.isLoading, setupRequired, meQuery.isLoading, meQuery.data])

  const login = useCallback(
    async (username: string, password: string) => {
      const session = await api.post<Session>('/auth/login', { username, password })
      setSessionExpired(false)
      queryClient.setQueryData(['auth', 'me'], session.user)
      await queryClient.invalidateQueries()
      return session
    },
    [queryClient],
  )

  const setup = useCallback(
    async (username: string, password: string) => {
      const session = await api.post<Session>('/auth/setup', { username, password })
      setSessionExpired(false)
      queryClient.setQueryData(['auth', 'me'], session.user)
      await queryClient.invalidateQueries()
      return session
    },
    [queryClient],
  )

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } finally {
      setSessionExpired(false)
      queryClient.setQueryData(['auth', 'me'], null)
      queryClient.clear()
    }
  }, [queryClient])

  const value: AuthContextValue = {
    status,
    user: meQuery.data ?? null,
    sessionExpired,
    login,
    setup,
    logout,
    clearExpiry: () => setSessionExpired(false),
    refetch: () => {
      void healthQuery.refetch()
      void meQuery.refetch()
    },
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
