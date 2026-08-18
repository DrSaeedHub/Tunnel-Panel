import { Suspense, lazy } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'

import { AppShell } from './components/layout/AppShell'
import { PageSkeleton } from './components/layout/PageSkeleton'
import { PreferencesProvider } from './providers/PreferencesProvider'
import { useAuth } from './providers/AuthProvider'

// Code-split by route: the bundle ships inside the Go binary, so a page the
// operator never opens should not be downloaded when they sign in.
const LoginPage = lazy(() => import('./pages/LoginPage'))
const SetupPage = lazy(() => import('./pages/SetupPage'))
const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const TunnelsPage = lazy(() => import('./pages/TunnelsPage'))
const TunnelDetailPage = lazy(() => import('./pages/TunnelDetailPage'))
const RoutesPage = lazy(() => import('./pages/RoutesPage'))
const RouteDetailPage = lazy(() => import('./pages/RouteDetailPage'))
const SettingsPage = lazy(() => import('./pages/SettingsPage'))
const RestorePage = lazy(() => import('./pages/RestorePage'))
const NotFoundPage = lazy(() => import('./pages/NotFoundPage'))

export default function App() {
  const { status } = useAuth()

  return (
    <PreferencesProvider authenticated={status === 'authenticated'}>
      <Suspense fallback={<PageSkeleton />}>
        <Routes>
          <Route path="/setup" element={<SetupPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route
            element={
              <RequireAuth>
                <AppShell />
              </RequireAuth>
            }
          >
            <Route path="/" element={<DashboardPage />} />
            <Route path="/tunnels" element={<TunnelsPage />} />
            <Route path="/tunnels/:id" element={<TunnelDetailPage />} />
            <Route path="/routes" element={<RoutesPage />} />
            <Route path="/routes/:id" element={<RouteDetailPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/restore" element={<RestorePage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
    </PreferencesProvider>
  )
}

/**
 * Blocks every application route behind a session.
 *
 * The route the operator asked for is carried into the login page's location
 * state, so after signing in they land where they were going rather than on the
 * dashboard.
 */
function RequireAuth({ children }: { children: React.ReactNode }) {
  const { status } = useAuth()
  const location = useLocation()

  if (status === 'loading') return <PageSkeleton />
  if (status === 'setup-required') return <Navigate to="/setup" replace />
  if (status === 'anonymous') {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  }
  return <>{children}</>
}
