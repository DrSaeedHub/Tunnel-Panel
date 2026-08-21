import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

import type { QuotaStatus } from '@/lib/types'
import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { ToastProvider } from '@/providers/ToastProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { QuotaBadge, QuotaRow } = await import('./TrafficLimit')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>{children}</ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>
  )
}

const GB = 1_000_000_000

function status(overrides: Partial<QuotaStatus> = {}): QuotaStatus {
  return {
    limit_bytes: 100 * GB,
    mode_id: 10,
    period_id: 40,
    used_bytes: 34 * GB,
    exhausted: false,
    stopped: false,
    ...overrides,
  }
}

describe('the traffic limit row', () => {
  it('is one quiet button until a limit exists', () => {
    render(wrap(<QuotaRow subject={{ scope: 'tunnel', tunnel_id: 1 }} />))
    expect(screen.getByRole('button', { name: /set traffic limit/i })).toBeInTheDocument()
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument()
  })

  it('shows the figure and the window once a limit is set', () => {
    render(wrap(<QuotaRow subject={{ scope: 'tunnel', tunnel_id: 1 }} status={status()} />))
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
    expect(screen.getByText(/per month/i)).toBeInTheDocument()
    // Under the limit: no badge at all. A list of healthy limits is silence.
    expect(screen.queryByText(/over limit/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/stopped/i)).not.toBeInTheDocument()
  })

  it('says which of the two answers happened at the limit', () => {
    const { unmount } = render(
      wrap(
        <QuotaRow
          subject={{ scope: 'tunnel', tunnel_id: 1 }}
          status={status({ used_bytes: 120 * GB, exhausted: true })}
        />,
      ),
    )
    // Warn mode: the traffic still flows, and the row says so.
    expect(screen.getByText(/over limit/i)).toBeInTheDocument()
    unmount()

    render(
      wrap(
        <QuotaRow
          subject={{ scope: 'tunnel', tunnel_id: 1 }}
          status={status({ mode_id: 20, used_bytes: 120 * GB, exhausted: true, stopped: true })}
        />,
      ),
    )
    expect(screen.getByText(/stopped at limit/i)).toBeInTheDocument()
  })

  it('saves a limit in bytes with the chosen window and mode', async () => {
    vi.mocked(api.put).mockResolvedValue({})
    render(wrap(<QuotaRow subject={{ scope: 'rule', route_rule_id: 7 }} />))

    fireEvent.click(screen.getByRole('button', { name: /set traffic limit/i }))
    fireEvent.change(await screen.findByLabelText(/allowance/i), { target: { value: '50' } })
    fireEvent.click(screen.getByRole('button', { name: /^save$/i }))

    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/quota', {
        scope: 'rule',
        route_rule_id: 7,
        limit_bytes: 50 * GB,
        mode_id: 10,
        period_id: 40,
      }),
    )
  })

  it('resets the count through the reset endpoint, not by saving', async () => {
    vi.mocked(api.post).mockResolvedValue({})
    render(
      wrap(
        <QuotaRow
          subject={{ scope: 'destination', route_rule_id: 7, address: '172.17.1.2', port: 8080 }}
          status={status({ stopped: true, exhausted: true, mode_id: 20 })}
        />,
      ),
    )

    fireEvent.click(screen.getByRole('button', { name: /edit the traffic limit/i }))
    fireEvent.click(await screen.findByRole('button', { name: /reset usage/i }))

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/quota/reset', {
        scope: 'destination',
        route_rule_id: 7,
        address: '172.17.1.2',
        port: 8080,
      }),
    )
    expect(api.put).not.toHaveBeenCalled()
  })

  it('removes a limit by saving zero', async () => {
    vi.mocked(api.put).mockResolvedValue({})
    render(wrap(<QuotaRow subject={{ scope: 'tunnel', tunnel_id: 1 }} status={status()} />))

    fireEvent.click(screen.getByRole('button', { name: /edit the traffic limit/i }))
    fireEvent.click(await screen.findByRole('button', { name: /remove limit/i }))

    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/quota', expect.objectContaining({ limit_bytes: 0 })),
    )
  })
})

describe('the list badge', () => {
  it('is nothing at all until a limit is reached', () => {
    const { container } = render(wrap(<QuotaBadge status={status()} />))
    expect(container).toBeEmptyDOMElement()
  })
})
