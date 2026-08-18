import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

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
const { default: TunnelDetailPage } = await import('./TunnelDetailPage')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

/** A tunnel that is thoroughly, unambiguously down. */
function downStatus() {
  return {
    tunnel_id: 3,
    state: 'Down',
    monitor_state_id: 40,
    enabled: true,
    target: '172.17.1.2',
    stats: {
      loss_percent: 100,
      rtt_avg_ms: null,
      rtt_min_ms: null,
      rtt_max_ms: null,
      jitter_ms: null,
      sent: 58,
      received: 0,
      lost: 58,
      last_reply_at: null,
    },
    events: [],
  }
}

function tunnel() {
  return {
    tunnel: {
      tunnel_id: 3,
      tunnel_type_id: 10,
      tunnel_side_id: 10,
      persistence_type_id: 10,
      interface_name: 'gre-a-1',
      tunnel_number: 1,
      local_endpoint: '203.0.113.10',
      remote_endpoint: '203.0.113.20',
      bind_device: null,
      ttl: 255,
      tos: 'inherit',
      mtu: 1472,
      ikey: 2749365187,
      okey: 2749365187,
      is_enabled: true,
      apply_status_id: 20,
      addresses: [
        { tunnel_address_id: 1, tunnel_id: 3, address: '172.17.1.1', prefix_length: 30,
          peer_address: '172.17.1.2', address_family_id: 10, is_primary: true, sort_order: 0,
          created_date: '', updated_date: '', is_deleted: false },
      ],
      created_date: '2026-08-16T10:00:00.000Z',
      updated_date: '2026-08-16T10:00:00.000Z',
      is_deleted: false,
    },
    // What the kernel is observed to hold, which is what the Configuration tab
    // renders in its "On this server" card.
    observed: {
      exists: true,
      mtu: 1472,
      oper_state: 'UNKNOWN',
      flags: ['POINTOPOINT', 'NOARP', 'UP', 'LOWER_UP'],
    },
  }
}

function mountAt(tab: string) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>
          <TooltipProvider>
            <MemoryRouter initialEntries={[`/tunnels/3?tab=${tab}`]}>
              <Routes>
                <Route path="/tunnels/:id" element={<TunnelDetailPage />} />
              </Routes>
            </MemoryRouter>
          </TooltipProvider>
        </ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.mocked(api.get).mockImplementation(async (path: string) => {
    if (path === '/tunnels/3') return tunnel() as never
    if (path === '/tunnels/3/status') return downStatus() as never
    if (path.startsWith('/tunnels/3/history')) return { points: [] } as never
    if (path.startsWith('/audit')) return { entries: [], total: 0 } as never
    if (path.startsWith('/settings')) return { settings: {} } as never
    if (path.startsWith('/routes')) return { routes: [], total: 0 } as never
    if (path.startsWith('/diagnostics')) return { runs: [], total: 0 } as never
    return {} as never
  })
})

describe('TunnelDetailPage', () => {
  /**
   * The monitoring card announced "Up" on a tunnel that was down.
   *
   * Its title was hardcoded to the translation key `monitor.state.Up`, so it
   * said "Up" whatever the tunnel was doing - directly above 100% loss, 58
   * sent, 0 received, and a timeline of transitions to Down. An operator
   * reading a dead tunnel was told it was up.
   */
  it('does not title the monitoring card with a state the tunnel is not in', async () => {
    mountAt('overview')

    // The statistics are on screen, so the card really did render.
    expect(await screen.findByText('Sent')).toBeTruthy()
    // 58 sent and 58 lost, so there are two of them.
    expect(screen.getAllByText('58').length).toBe(2)
    expect(screen.getByText('100%')).toBeTruthy()

    const headings = screen.getAllByRole('heading').map((h) => h.textContent?.trim())
    expect(headings).toContain('Monitoring')
    // Nothing on this page may claim the tunnel is up while it is down.
    expect(headings).not.toContain('Up')
  })

  /**
   * Two rows of the Configuration tab were labelled with the raw API field
   * names, `oper_state` and `flags`, while every other row on the same card
   * went through the translation table. Untranslated in both languages, and
   * leaking the wire format to the operator.
   *
   * The assertion is deliberately about the shape of the whole view rather
   * than about those two rows, so the class cannot come back somewhere else.
   */
  it('labels every field on the configuration tab in prose, never as a wire identifier', async () => {
    const { container } = mountAt('configuration')

    await waitFor(() => expect(container.querySelectorAll('dt').length).toBeGreaterThan(5))

    const raw = [...container.querySelectorAll('dt')]
      .map((dt) => dt.textContent?.trim() ?? '')
      .filter((label) => /^[a-z0-9]+(_[a-z0-9]+)+$/.test(label))

    expect(raw).toEqual([])
  })

  it('renders the observed kernel state under readable labels', async () => {
    mountAt('configuration')

    expect(await screen.findByText('Operational state')).toBeTruthy()
    expect(screen.getByText('Interface flags')).toBeTruthy()
    expect(screen.getByText('UNKNOWN')).toBeTruthy()
  })
})
