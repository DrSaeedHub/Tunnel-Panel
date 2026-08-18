import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import type { UpdateStatus } from '@/lib/types'
import { ToastProvider } from '@/providers/ToastProvider'
import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { TooltipProvider } from '@/components/ui/overlay'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

/**
 * The build that served this page, fixed for the whole file: the backend
 * injects it into index.html once, and the bundle reads it once at load. The
 * cases below vary what the panel now reports instead, which is the half that
 * really does change under an open page.
 *
 * Hoisted, because that is what "once at load" means here: bootstrap reads the
 * global the first time anything imports it, and the imports above this line
 * run first.
 */
const SERVED = vi.hoisted(() => {
  const version = 'v0.1.5'
  window.__GRE_PANEL__ = { base_path: '/', api_base_path: '/api/v1', version }
  return version
})

const { api } = await import('@/lib/api')
const { UpdateProvider, useUpdate } = await import('@/providers/UpdateProvider')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

beforeEach(() => {
  localStorage.clear()
})

function status(overrides: Partial<UpdateStatus> = {}): UpdateStatus {
  return {
    current_version: SERVED,
    latest: { version: SERVED },
    update_available: false,
    checking: false,
    source: 'DrSaeedHub/Tunnel-Panel',
    enabled: true,
    can_apply: true,
    state: { stage: 'idle' },
    ...overrides,
  }
}

function Opener() {
  const { open } = useUpdate()
  return <button onClick={open}>open the dialog</button>
}

function renderShell() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <PreferencesProvider authenticated={false}>
          <TooltipProvider>
            <ToastProvider>
              <UpdateProvider>
                <Opener />
              </UpdateProvider>
            </ToastProvider>
          </TooltipProvider>
        </PreferencesProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/**
 * An update replaces the binary and restarts it under an open page. The record
 * of that run is kept, so what tells the operator whether they are looking at
 * the old interface is not the record but the version: the page came from one
 * build and the panel is answering from another.
 */
describe('the update dialog after a run has finished', () => {
  it('asks for a reload while the page is still the one the old build served', async () => {
    vi.mocked(api.get).mockResolvedValue(
      status({
        current_version: 'v0.2.0',
        latest: { version: 'v0.2.0' },
        state: { stage: 'succeeded', from_version: SERVED, target_version: 'v0.2.0' },
      }),
    )

    renderShell()
    fireEvent.click(await screen.findByRole('button', { name: 'open the dialog' }))

    expect(await screen.findByText('Updated from v0.1.5 to v0.2.0.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reload the panel' })).toBeInTheDocument()
  })

  it('gets out of the way once the page has been reloaded onto the new build', async () => {
    // The bug this covers: the finished run outlives itself, so the success
    // screen stood in front of the dialog forever with no button past it, and
    // the panel could never be updated from the panel a second time.
    vi.mocked(api.get).mockResolvedValue(
      status({ state: { stage: 'succeeded', from_version: 'v0.1.0', target_version: SERVED } }),
    )

    renderShell()
    fireEvent.click(await screen.findByRole('button', { name: 'open the dialog' }))

    expect(
      await screen.findByText('This panel is on v0.1.5, which is the current release.'),
    ).toBeInTheDocument()
    expect(screen.queryByText(/Updated from/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reload the panel' })).not.toBeInTheDocument()
    // And the way to the next version is open again.
    expect(screen.getByRole('button', { name: 'Check again' })).toBeInTheDocument()
  })
})
