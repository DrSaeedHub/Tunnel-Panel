import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ErrorBoundary } from './ErrorBoundary'

// An upgrade replaces every content-hashed chunk at once, so a tab that was
// open across one asks for assets the new binary does not serve. Before this
// boundary existed the result was <div id="root"></div> with no children, no
// text and no buttons — during an upgrade, which is when an operator is most
// likely to be looking at the panel.

function Boom({ error }: { error: Error }): never {
  throw error
}

describe('ErrorBoundary', () => {
  let consoleError: { mockRestore: () => void }

  beforeEach(() => {
    // React logs the caught error itself; the test asserts behaviour, not noise.
    consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    // Each case renders into document.body; without this the next case finds
    // the previous case's alert as well as its own.
    cleanup()
    consoleError.mockRestore()
    vi.restoreAllMocks()
  })

  it('renders a readable failure instead of an empty root when a child throws', () => {
    const { container } = render(
      <ErrorBoundary>
        <Boom error={new Error('the tunnels table exploded')} />
      </ErrorBoundary>,
    )

    // The precise defect being guarded: a root with nothing in it.
    expect(container.innerHTML).not.toBe('')
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.getByText('Something went wrong')).toBeTruthy()

    // And a way out that does not require knowing to press F5 on a white page.
    expect(screen.getByRole('button', { name: 'Reload the panel' })).toBeTruthy()
  })

  it('keeps the underlying message reachable rather than swallowing it', () => {
    render(
      <ErrorBoundary>
        <Boom error={new Error('the tunnels table exploded')} />
      </ErrorBoundary>,
    )
    expect(screen.getByText('the tunnels table exploded')).toBeTruthy()
  })

  it('reloads once when a chunk is missing, and explains rather than looping if that did not help', () => {
    const onStaleAsset = vi.fn().mockReturnValue(true)
    const chunkError = new Error('Failed to fetch dynamically imported module: /assets/RoutesPage-abc123.js')

    const { unmount } = render(
      <ErrorBoundary onStaleAsset={onStaleAsset}>
        <Boom error={chunkError} />
      </ErrorBoundary>,
    )
    expect(onStaleAsset).toHaveBeenCalled()
    // A reload is under way, so the operator is not told anything is wrong.
    expect(screen.queryByText(/did not resolve it/)).toBeNull()
    unmount()
    cleanup()

    // Second time round the tab is inside its cooldown.
    const spent = vi.fn().mockReturnValue(false)
    render(
      <ErrorBoundary onStaleAsset={spent}>
        <Boom error={chunkError} />
      </ErrorBoundary>,
    )
    expect(screen.getByRole('alert')).toBeTruthy()
    expect(screen.getByText(/was updated while this page was open/)).toBeTruthy()
    expect(screen.getByText(/did not resolve it/)).toBeTruthy()
  })

  it('recognises a lost lazy-import rejection from the tab having just tried to recover', () => {
    // What actually reaches the boundary when a chunk 404s is React's own
    // error, not the browser's. On a live panel it read "Cannot read
    // properties of undefined (reading 'default')", which is indistinguishable
    // from an ordinary bug. Without this the operator is told the panel hit an
    // unexpected error, when in fact it was upgraded underneath them.
    render(
      <ErrorBoundary
        onStaleAsset={vi.fn().mockReturnValue(false)}
        recentlyAttempted={vi.fn().mockReturnValue(true)}
      >
        <Boom error={new TypeError("Cannot read properties of undefined (reading 'default')")} />
      </ErrorBoundary>,
    )
    expect(screen.getByText(/was updated while this page was open/)).toBeTruthy()
  })

  it('still calls an ordinary bug an ordinary bug', () => {
    render(
      <ErrorBoundary
        onStaleAsset={vi.fn().mockReturnValue(false)}
        recentlyAttempted={vi.fn().mockReturnValue(false)}
      >
        <Boom error={new TypeError("Cannot read properties of undefined (reading '0')")} />
      </ErrorBoundary>,
    )
    expect(screen.getByText('The panel hit an unexpected error.')).toBeTruthy()
    expect(screen.queryByText(/was updated while this page was open/)).toBeNull()
  })

  it('leaves a working tree alone', () => {
    render(
      <ErrorBoundary>
        <p>the dashboard</p>
      </ErrorBoundary>,
    )
    expect(screen.getByText('the dashboard')).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })
})
