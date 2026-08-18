import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

import type { Tunnel } from '@/lib/types'
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
const { DiagnosticsPanel } = await import('./DiagnosticsPanel')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

/**
 * Deliberately unlike the literals the form used to hardcode (10, 1, 56, 2) and
 * unlike the schema defaults (100, 0.1, 1, 56), so this test cannot pass by
 * coincidence against either the old code or a fallback that ignores the store.
 */
const STORED = {
  'diagnostics.manual_ping_count': 37,
  'diagnostics.manual_ping_interval': 0.25,
  'diagnostics.manual_ping_timeout': 4.5,
  'diagnostics.manual_ping_max_count': 4242,
  'monitor.packet_size': 128,
}

function tunnel(): Tunnel {
  return {
    tunnel_id: 3,
    tunnel_type_id: 10,
    tunnel_side_id: 10,
    persistence_type_id: 10,
    interface_name: 'gre-a-1',
    tunnel_number: 1,
    local_endpoint: '203.0.113.10',
    remote_endpoint: '203.0.113.20',
    mtu: 1472,
    is_enabled: true,
    apply_status_id: 20,
    addresses: [],
    created_date: '2026-08-16T10:00:00.000Z',
    updated_date: '2026-08-16T10:00:00.000Z',
    is_deleted: false,
  } as unknown as Tunnel
}

function wrap(children: ReactNode, client: QueryClient) {
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>
          <TooltipProvider>{children}</TooltipProvider>
        </ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>
  )
}

let client: QueryClient

beforeEach(() => {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  vi.mocked(api.get).mockImplementation(async (path: string) => {
    if (path === '/settings') return { settings: STORED } as never
    if (path.startsWith('/diagnostics/runs')) return { runs: [], total: 0 } as never
    return {} as never
  })
})

describe('DiagnosticsPanel manual probe', () => {
  /**
   * The probe form ignored the settings that configure it.
   *
   * Its four inputs were seeded from hardcoded literals, so
   * diagnostics.manual_ping_count, .manual_ping_interval and .manual_ping_timeout
   * were stored, described on the Settings page, and had no effect whatsoever.
   * Saving and reloading them would have looked like it worked, because they
   * really do persist -- they simply never reached the form. The backend has
   * always honoured them for a request that omits them; this form never omitted
   * them.
   */
  it('seeds every probe parameter from the stored settings', async () => {
    render(wrap(<DiagnosticsPanel tunnel={tunnel()} />, client))

    const count = (await screen.findByLabelText(/^Count/)) as HTMLInputElement
    await waitFor(() => expect(count.value).toBe('37'))

    expect((screen.getByLabelText(/^Interval/) as HTMLInputElement).value).toBe('0.25')
    expect((screen.getByLabelText(/^Timeout/) as HTMLInputElement).value).toBe('4.5')
    // No diagnostics key exists for the payload size, and the manual probe runs
    // down the same ICMP path as the monitor, so it follows the monitor's.
    expect((screen.getByLabelText(/^Packet size/) as HTMLInputElement).value).toBe('128')
  })

  it('takes the maximum count from the settings rather than a lower invention', async () => {
    render(wrap(<DiagnosticsPanel tunnel={tunnel()} />, client))

    const count = (await screen.findByLabelText(/^Count/)) as HTMLInputElement
    await waitFor(() => expect(count.max).toBe('4242'))
  })

  /**
   * The settings query resolves after the first render, so a form that seeded
   * useState directly would show the fallback and stay there. This is the same
   * defect in a different shape, and it is worth its own assertion.
   */
  it('picks up settings that arrive after the first render', async () => {
    let release: (value: unknown) => void = () => {}
    const pending = new Promise((resolve) => {
      release = resolve
    })
    vi.mocked(api.get).mockImplementation(async (path: string) => {
      if (path === '/settings') {
        await pending
        return { settings: STORED } as never
      }
      if (path.startsWith('/diagnostics/runs')) return { runs: [], total: 0 } as never
      return {} as never
    })

    render(wrap(<DiagnosticsPanel tunnel={tunnel()} />, client))

    const count = (await screen.findByLabelText(/^Count/)) as HTMLInputElement
    // Before the settings land the field shows the schema's own default.
    expect(count.value).toBe('100')

    release({})
    await waitFor(() => expect(count.value).toBe('37'))
  })
})
