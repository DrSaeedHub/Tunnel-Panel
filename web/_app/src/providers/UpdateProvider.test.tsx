import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom'

import type { UpdateStatus } from '@/lib/types'
import { ToastProvider } from './ToastProvider'
import { PreferencesProvider } from './PreferencesProvider'
import { TooltipProvider } from '@/components/ui/overlay'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { UpdateProvider, useUpdate } = await import('./UpdateProvider')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

beforeEach(() => {
  localStorage.clear()
})

function status(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    current_version: 'v0.1.5',
    latest: { version: 'v0.2.0', url: 'https://example.invalid/r/v0.2.0', notes: 'Fixed things.' },
    update_available: true,
    checking: false,
    source: 'DrSaeedHub/Tunnel-Panel',
    enabled: true,
    can_apply: true,
    state: { stage: 'idle' },
    ...overrides,
  }
}

/** Stands in for the dashboard footer, which is where the button lives. */
function VersionButton() {
  const { open, status: current } = useUpdate()
  return (
    <button onClick={open}>
      version {current?.current_version ?? ''}
    </button>
  )
}

function renderShell(children = <VersionButton />) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/']}>
        <PreferencesProvider authenticated={false}>
          <TooltipProvider>
            <ToastProvider>
              <UpdateProvider>
                <Routes>
                  <Route
                    path="/"
                    element={
                      <>
                        {children}
                        <Link to="/tunnels">tunnels</Link>
                      </>
                    }
                  />
                  <Route path="/tunnels" element={<p>the tunnels page</p>} />
                </Routes>
              </UpdateProvider>
            </ToastProvider>
          </TooltipProvider>
        </PreferencesProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('the update notice', () => {
  it('announces a new version with a button, and stays up while the operator works', async () => {
    vi.mocked(api.get).mockResolvedValue(status())

    renderShell()

    const notice = await screen.findByText('Version v0.2.0 is available')
    expect(notice).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'View update' })).toBeInTheDocument()

    // Moving to another tab is the case this is really about: the notice is
    // raised above the router, so navigating does not take it away.
    fireEvent.click(screen.getByText('tunnels'))
    expect(screen.getByText('the tunnels page')).toBeInTheDocument()
    expect(screen.getByText('Version v0.2.0 is available')).toBeInTheDocument()
  })

  it('closes only when the operator closes it, and then stays closed for that version', async () => {
    vi.mocked(api.get).mockResolvedValue(status())

    const first = renderShell()
    await screen.findByText('Version v0.2.0 is available')

    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(screen.queryByText('Version v0.2.0 is available')).not.toBeInTheDocument()

    // A fresh page load — the operator reloading, or coming back tomorrow —
    // must not raise the same notice again.
    first.unmount()
    renderShell()
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(screen.queryByText('Version v0.2.0 is available')).not.toBeInTheDocument()

    // But the next release is a different answer and is announced.
    cleanup()
    vi.mocked(api.get).mockResolvedValue(
      status({ latest: { version: 'v0.3.0' }, update_available: true }),
    )
    renderShell()
    expect(await screen.findByText('Version v0.3.0 is available')).toBeInTheDocument()
  })

  it('says nothing when the panel is on the current release', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({ update_available: false, latest: { version: 'v0.1.5' } }),
    )

    renderShell()
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(screen.queryByText(/is available/)).not.toBeInTheDocument()
  })

  it('opens the dialog from the notice and installs the version on offer', async () => {
    vi.mocked(api.get).mockResolvedValue(status())
    vi.mocked(api.post).mockResolvedValue(
      status({ state: { stage: 'running', target_version: 'v0.2.0', from_version: 'v0.1.5' } }),
    )

    renderShell()
    fireEvent.click(await screen.findByRole('button', { name: 'View update' }))

    fireEvent.click(await screen.findByRole('button', { name: 'Update to v0.2.0' }))

    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/system/update', { version: 'v0.2.0' }))
    // While it runs the dialog says what is happening rather than offering the
    // button again, and the notice has done its job and is taken down.
    expect(await screen.findByText(/Installing v0.2.0/)).toBeInTheDocument()
    expect(screen.queryByText('Version v0.2.0 is available')).not.toBeInTheDocument()
  })

  it('explains an installation that cannot update itself instead of offering a dead button', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({ can_apply: false, reason: 'This panel is not running under systemd.' }),
    )

    renderShell()
    fireEvent.click(await screen.findByRole('button', { name: 'View update' }))

    expect(await screen.findByText('This panel is not running under systemd.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Update to v0.2.0' })).not.toBeInTheDocument()
  })

  it('reports a finished update and offers the reload the new interface needs', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({
        current_version: 'v0.2.0',
        update_available: false,
        state: {
          stage: 'succeeded',
          from_version: 'v0.1.5',
          target_version: 'v0.2.0',
          log: ['step: done'],
        },
      }),
    )

    renderShell()
    fireEvent.click(await screen.findByText(/^version/))

    expect(await screen.findByText('Updated from v0.1.5 to v0.2.0.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reload the panel' })).toBeInTheDocument()
  })

  // The record of a finished run outlives it. A panel updated months ago still
  // reports that success, and it must not stand between the operator and the
  // version that is available now.
  it('offers a new version even when the last update finished long ago', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({
        state: { stage: 'succeeded', from_version: 'v0.1.0', target_version: 'v0.1.5' },
      }),
    )

    renderShell()
    fireEvent.click(await screen.findByRole('button', { name: 'View update' }))

    expect(await screen.findByRole('button', { name: 'Update to v0.2.0' })).toBeInTheDocument()
    expect(screen.queryByText(/Updated from/)).not.toBeInTheDocument()
  })

  it('lets a failed update be retried, with the failure still in view', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({
        state: { stage: 'failed', error: 'The installer exited with status 3.' },
      }),
    )

    renderShell()
    fireEvent.click(await screen.findByRole('button', { name: 'View update' }))

    expect(await screen.findByText('The installer exited with status 3.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Update to v0.2.0' })).toBeInTheDocument()
  })

  it('shows what the installer said when the update failed', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({
        update_available: false,
        state: {
          stage: 'failed',
          error: 'The installer exited with status 3.',
          log: ['checksum mismatch'],
        },
      }),
    )

    renderShell()
    fireEvent.click(await screen.findByText(/^version/))

    expect(await screen.findByText('The installer exited with status 3.')).toBeInTheDocument()
    expect(screen.getByText(/checksum mismatch/)).toBeInTheDocument()
  })
})
