import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { ToastProvider } from '@/providers/ToastProvider'
import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { TooltipProvider } from '@/components/ui/overlay'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), del: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { PanelAddressSection, buildURL } = await import('./PanelAddressSection')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function address(overrides: Record<string, unknown> = {}) {
  return {
    bind_host: '0.0.0.0',
    port: 8443,
    web_path: 'panel-a1b2c3',
    base_path: '/panel-a1b2c3/',
    url: 'http://203.0.113.10:8443/panel-a1b2c3/',
    sources: { port: 'database', web_path: 'database' },
    can_apply: true,
    protected_ports: [{ port: 22, reason: 'the SSH daemon is listening on it', process: 'sshd' }],
    env_file: { path: '/etc/gre-panel.env', port: 8443, web_path: 'panel-a1b2c3', disagrees: false },
    ...overrides,
  }
}

function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>
          <TooltipProvider>
            <MemoryRouter>
              <PanelAddressSection />
            </MemoryRouter>
          </TooltipProvider>
        </ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.get).mockImplementation(async () => address() as never)
})

describe('PanelAddressSection', () => {
  it('shows where the panel is, and the ports it will refuse', async () => {
    mount()
    expect(await screen.findByDisplayValue('8443')).toBeTruthy()
    expect(screen.getByDisplayValue('panel-a1b2c3')).toBeTruthy()
    // The SSH port is named before anything is submitted, rather than the
    // operator finding out by being refused.
    expect(screen.getByText('22')).toBeTruthy()
  })

  /**
   * The confirmation has to name the destination, and it has to do so before
   * the request is sent.
   *
   * This is the whole point of the flow: applying the change breaks the
   * connection this page is on, so the last moment the operator can be told
   * where to go is before the button is pressed. A dialog that appeared after
   * the POST would be racing the restart.
   */
  it('names the new URL before it sends anything', async () => {
    mount()
    const port = await screen.findByDisplayValue('8443')
    fireEvent.change(port, { target: { value: '9000' } })

    fireEvent.click(screen.getByRole('button', { name: /move the panel/i }))

    const dialog = await screen.findByRole('dialog')
    expect(dialog.textContent).toContain('http://203.0.113.10:9000/panel-a1b2c3/')
    // And the address they are on now, so they can get back.
    expect(dialog.textContent).toContain('http://203.0.113.10:8443/panel-a1b2c3/')
    // Nothing has been sent yet.
    expect(api.post).not.toHaveBeenCalled()
  })

  it('sends nothing when the confirmation is cancelled', async () => {
    mount()
    fireEvent.change(await screen.findByDisplayValue('8443'), { target: { value: '9000' } })
    fireEvent.click(screen.getByRole('button', { name: /move the panel/i }))
    await screen.findByRole('dialog')

    fireEvent.click(screen.getByRole('button', { name: /^cancel$/i }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(api.post).not.toHaveBeenCalled()
  })

  /**
   * An empty web path is a configuration, not an unfilled box, so it needs a
   * control that says what it means. Typing nothing into a text field reads as
   * "not done yet"; a switch labelled "Serve at the root" reads as a decision.
   */
  it('offers the root as a deliberate choice and sends an empty web path for it', async () => {
    vi.mocked(api.post).mockResolvedValue({
      url: 'http://203.0.113.10:8443/',
      previous_url: 'http://203.0.113.10:8443/panel-a1b2c3/',
      port: 8443,
      web_path: '',
      health_url: 'http://203.0.113.10:8443/api/v1/system/health',
      restarting: true,
      session_survives: false,
      detail: '',
    } as never)

    mount()
    await screen.findByDisplayValue('8443')
    fireEvent.click(screen.getByRole('switch', { name: /serve at the root/i }))
    fireEvent.click(screen.getByRole('button', { name: /move the panel/i }))

    const dialog = await screen.findByRole('dialog')
    // The preview is the root URL with no double slash.
    expect(dialog.textContent).toContain('http://203.0.113.10:8443/')
    expect(dialog.textContent).not.toContain('8443//')
    // Losing the session is expected here, and the dialog says so rather than
    // letting the next screen look like a failure.
    expect(dialog.textContent).toMatch(/sign in again/i)

    fireEvent.click(screen.getByRole('button', { name: /^move it$/i }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/system/address', { port: 8443, web_path: '' }),
    )
  })

  it('says so when the panel is not where it was configured to be', async () => {
    vi.mocked(api.get).mockImplementation(
      async () =>
        address({
          fallback: {
            wanted_port: 9000,
            serving_port: 8443,
            reason: 'listen tcp 0.0.0.0:9000: bind: address already in use',
            at: '2026-08-17T00:00:00Z',
          },
        }) as never,
    )
    mount()
    expect(await screen.findByText(/could not be bound/i)).toBeTruthy()
    expect(screen.getByText(/address already in use/)).toBeTruthy()
  })

  it('explains when the environment file disagrees rather than leaving it to be discovered', async () => {
    vi.mocked(api.get).mockImplementation(
      async () =>
        address({
          env_file: { path: '/etc/gre-panel.env', port: 8443, web_path: 'old-path', disagrees: true },
        }) as never,
    )
    mount()
    expect(await screen.findByText(/\/etc\/gre-panel\.env still says/i)).toBeTruthy()
  })

  it('does not offer to move the panel when it cannot restart itself', async () => {
    vi.mocked(api.get).mockImplementation(
      async () =>
        address({
          can_apply: false,
          cannot_apply_why: 'This panel was not started by systemd, so it cannot restart itself.',
        }) as never,
    )
    mount()
    expect(await screen.findByText(/not started by systemd/i)).toBeTruthy()
  })

  it('will not submit a change that changes nothing', async () => {
    mount()
    await screen.findByDisplayValue('8443')
    const move = screen.getByRole('button', { name: /move the panel/i }) as HTMLButtonElement
    expect(move.disabled).toBe(true)
  })
})

describe('buildURL', () => {
  /**
   * The empty web path is the case that produces `//` in every naive
   * implementation, and `http://host:8443//` is not the URL the panel serves.
   */
  it('never produces a double slash', () => {
    expect(buildURL('http://host:8443/abc/', 9000, 'def')).toBe('http://host:9000/def/')
    expect(buildURL('http://host:8443/abc/', 9000, '')).toBe('http://host:9000/')
    expect(buildURL('http://host:8443/', 8443, 'abc')).toBe('http://host:8443/abc/')
  })

  it('returns the input unchanged when it is not a URL at all', () => {
    expect(buildURL('not a url', 9000, 'abc')).toBe('not a url')
  })
})
