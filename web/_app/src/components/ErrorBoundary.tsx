import { Component, type ErrorInfo, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import {
  attemptedStaleAssetReload,
  isStaleAssetError,
  reloadOnceForStaleAssets,
} from '../lib/recovery'

// React unmounts the whole tree when a render throws and nothing catches it,
// which leaves the document with an empty root: no message, no navigation, no
// way back except a reload the operator has no reason to suspect. This catches
// that and puts something readable on the screen instead.

interface Props {
  children: ReactNode
  /** Injectable so a test can drive the recovery path without navigating. */
  onStaleAsset?: () => boolean
  /** Injectable so a test can say whether this tab recently tried to recover. */
  recentlyAttempted?: () => boolean
}

interface State {
  error: Error | null
  /** True once a reload has been attempted and did not resolve the failure. */
  reloadSpent: boolean
  /** True when the failure is the assets rather than the application. */
  stale: boolean
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, reloadSpent: false, stale: false }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // React does not preserve the original rejection when a lazy import fails,
    // so the error arriving here may be an unrecognisable "Cannot read
    // properties of undefined (reading 'default')". A recovery attempt this
    // tab made moments ago is the dependable signal that the assets, and not
    // the application, are what broke.
    const attempted = this.props.recentlyAttempted ?? attemptedStaleAssetReload
    const stale = isStaleAssetError(error) || attempted()

    if (stale) {
      this.setState({ stale: true })
      // Recoverable without troubling the operator — but the cooldown decides,
      // because the failing route is still the current URL after a reload.
      if ((this.props.onStaleAsset ?? reloadOnceForStaleAssets)()) return
      this.setState({ reloadSpent: true })
    }

    // Kept: the panel has no client-side error reporting, so the console is
    // the only place an operator or a support session can read the stack.
    console.error('The interface failed to render.', error, info.componentStack)
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children
    return (
      <ErrorScreen
        error={this.state.error}
        reloadSpent={this.state.reloadSpent}
        stale={this.state.stale}
      />
    )
  }
}

function ErrorScreen({
  error,
  reloadSpent,
  stale: staleFromState,
}: {
  error: Error
  reloadSpent: boolean
  stale: boolean
}) {
  // Every string carries an English defaultValue: if what broke was the
  // translation bundle itself, a boundary that renders raw i18n keys is barely
  // better than the blank page it replaced.
  const { t } = useTranslation()
  const stale = staleFromState || isStaleAssetError(error)

  return (
    <div
      role="alert"
      className="flex min-h-screen items-center justify-center bg-background p-6 text-foreground"
    >
      <div className="w-full max-w-lg space-y-4 rounded-lg border border-border bg-card p-6 shadow-sm">
        <h1 className="text-lg font-semibold">
          {t('errors.title', { defaultValue: 'Something went wrong' })}
        </h1>

        <p className="text-sm text-muted-foreground">
          {stale
            ? t('errors.staleAssets', {
                defaultValue:
                  'The panel was updated while this page was open, so part of it could no longer be loaded. Reloading will pick up the new version.',
              })
            : t('errors.internal', { defaultValue: 'The panel hit an unexpected error.' })}
        </p>

        {stale && reloadSpent ? (
          <p className="text-sm text-muted-foreground">
            {t('errors.reloadDidNotHelp', {
              defaultValue:
                'Reloading once did not resolve it, so the page has been left as it is rather than reloading again.',
            })}
          </p>
        ) : null}

        <button
          type="button"
          onClick={() => window.location.reload()}
          className="rounded bg-accent px-4 py-2 text-sm font-medium text-accent-foreground hover:opacity-90"
        >
          {t('errors.reload', { defaultValue: 'Reload the panel' })}
        </button>

        <details className="text-xs text-muted-foreground">
          <summary className="cursor-pointer">
            {t('errors.technicalDetails', { defaultValue: 'Technical details' })}
          </summary>
          <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words">
            {error.message || String(error)}
          </pre>
        </details>
      </div>
    </div>
  )
}
