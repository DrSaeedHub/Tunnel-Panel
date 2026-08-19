import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'

import { PreferencesProvider } from '@/providers/PreferencesProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { RouteConnectionsPanel } = await import('./RouteConnectionsPanel')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function flow(source: string, destination: string) {
  return {
    protocol: 'tcp',
    source_address: source,
    source_port: 51234,
    bind_address: '203.0.113.10',
    bind_port: 8080,
    destination_address: destination,
    destination_port: 8080,
    state: 'ESTABLISHED',
    age_seconds: 30,
    tx_bytes: 1000,
    rx_bytes: 2000,
    tx_packets: 10,
    rx_packets: 20,
  }
}

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>{children}</PreferencesProvider>
    </QueryClientProvider>
  )
}

/**
 * An undifferentiated list of flows stops answering anything once a rule has
 * two destinations: the question becomes "who is on that one".
 */
describe('the live connections of a relay', () => {
  it('narrows the table to one destination and back', async () => {
    vi.mocked(api.get).mockResolvedValue({
      route_rule_id: 1,
      reader: 'conntrack',
      available: true,
      connections: [
        flow('198.51.100.7', '172.17.1.2'),
        flow('198.51.100.8', '172.17.1.2'),
        flow('198.51.100.9', '172.17.2.2'),
      ],
      total: 3,
      by_destination: [
        { address: '172.17.1.2', port: 8080, connections: 2, rx_bytes: 0, tx_bytes: 0 },
        { address: '172.17.2.2', port: 8080, connections: 1, rx_bytes: 0, tx_bytes: 0 },
      ],
      new_per_second: 0,
      checked_at: '',
    })

    render(wrap(<RouteConnectionsPanel routeRuleId={1} />))

    expect(await screen.findByText('198.51.100.9:51234')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /172\.17\.1\.2:8080/ }))
    expect(screen.getByText('198.51.100.7:51234')).toBeInTheDocument()
    expect(screen.queryByText('198.51.100.9:51234')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: /All destinations/ }))
    expect(screen.getByText('198.51.100.9:51234')).toBeInTheDocument()
  })

  it('offers no destination filter for a rule that has one destination', async () => {
    vi.mocked(api.get).mockResolvedValue({
      route_rule_id: 1,
      reader: 'conntrack',
      available: true,
      connections: [flow('198.51.100.7', '172.17.1.2')],
      total: 1,
      by_destination: [
        { address: '172.17.1.2', port: 8080, connections: 1, rx_bytes: 0, tx_bytes: 0 },
      ],
      new_per_second: 0,
      checked_at: '',
    })

    render(wrap(<RouteConnectionsPanel routeRuleId={1} />))

    expect(await screen.findByText('198.51.100.7:51234')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /All destinations/ })).toBeNull()
  })
})
