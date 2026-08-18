import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'

import App from './App'
import { routerBasename } from './lib/bootstrap'
import { ApiError } from './lib/api'
import { ErrorBoundary } from './components/ErrorBoundary'
import { reloadOnceForStaleAssets } from './lib/recovery'
import { AuthProvider } from './providers/AuthProvider'
import { ToastProvider } from './providers/ToastProvider'
import { TooltipProvider } from './components/ui/overlay'
// Bundled fonts: the panel must never fetch a webfont at runtime, because the
// servers it runs on may have no outbound access at all.
import '@fontsource-variable/bricolage-grotesque'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import '@fontsource/vazirmatn/400.css'
import '@fontsource/vazirmatn/500.css'
import '@fontsource/vazirmatn/700.css'
import './i18n'
import './styles/index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The panel is a live view of one server: refetching on focus is what an
      // operator expects when they come back to the tab.
      refetchOnWindowFocus: true,
      staleTime: 5_000,
      retry: (failureCount, error) => {
        // Retrying a rejected session or a validation failure only delays the
        // answer; neither will succeed on a second attempt.
        if (error instanceof ApiError) {
          if (error.status === 401 || error.status === 403 || error.status === 404) return false
          if (error.status >= 400 && error.status < 500) return false
        }
        return failureCount < 2
      },
    },
    mutations: { retry: false },
  },
})

// Vite raises this when a preloaded chunk cannot be fetched, which is what an
// upgrade does to every tab that was already open. Catching it here recovers
// before React ever renders the failure.
window.addEventListener('vite:preloadError', (event) => {
  if (reloadOnceForStaleAssets()) event.preventDefault()
})

createRoot(document.getElementById('root') as HTMLElement).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter basename={routerBasename}>
          <AuthProvider>
            <TooltipProvider delayDuration={200} skipDelayDuration={400}>
              <ToastProvider>
                <App />
              </ToastProvider>
            </TooltipProvider>
          </AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>,
)
