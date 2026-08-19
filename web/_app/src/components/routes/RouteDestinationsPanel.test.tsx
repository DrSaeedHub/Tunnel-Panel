import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'

import { LoadBalanceMode, RouteProtocol, type RouteRule } from '@/lib/types'
import { PreferencesProvider } from '@/providers/PreferencesProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { RouteDestinationsPanel } = await import('./RouteDestinationsPanel')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function destination(address: string, order: number, overrides = {}) {
  return {
    route_destination_id: order,
    route_rule_id: 1,
    address,
    port: 8080,
    port_range_end: null,
    weight: 1,
    is_enabled: true,
    sort_order: order,
    created_date: '',
    updated_date: '',
    is_deleted: false,
    ...overrides,
  }
}

/** A relay across two backends, which is the case the panel exists for. */
function route(overrides: Partial<RouteRule> = {}): RouteRule {
  return {
    route_rule_id: 1,
    route_rule_title: 'Web relay',
    description: '',
    route_protocol_id: RouteProtocol.TCP,
    address_family_id: 10,
    bind_address: '203.0.113.10',
    bind_port: 8080,
    bind_port_range_end: null,
    bind_interface: null,
    destination_address: '172.17.1.2',
    destination_port: 8080,
    destination_port_range_end: null,
    nat_mode_id: 10,
    snat_address: null,
    load_balance_mode_id: LoadBalanceMode.RoundRobin,
    tunnel_id: null,
    is_clamp_mss_to_pmtu: false,
    is_include_local_originated: false,
    is_logging_enabled: false,
    fwmark: null,
    max_connections_per_source: null,
    connection_rate_limit: null,
    is_enabled: true,
    apply_status_id: 20,
    last_applied_date: null,
    last_apply_error: null,
    sort_order: 1,
    tags_json: null,
    created_date: '',
    updated_date: '',
    is_deleted: false,
    destinations: [destination('172.17.1.2', 1), destination('172.17.2.2', 2)],
    allowed_sources: [],
    ...overrides,
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

describe('the destinations of a relay', () => {
  it('gives every destination its own line and its real share of the traffic', async () => {
    vi.mocked(api.get).mockResolvedValue({
      route_rule_id: 1,
      reader: 'conntrack',
      available: true,
      connections: [],
      total: 100,
      by_destination: [
        { address: '172.17.1.2', port: 8080, connections: 75, rx_bytes: 3000, tx_bytes: 1000 },
        { address: '172.17.2.2', port: 8080, connections: 25, rx_bytes: 1000, tx_bytes: 500 },
      ],
      new_per_second: 0,
      checked_at: '',
    })

    render(wrap(<RouteDestinationsPanel route={route()} />))

    expect(await screen.findByText('172.17.1.2:8080')).toBeInTheDocument()
    expect(screen.getByText('172.17.2.2:8080')).toBeInTheDocument()
    expect(screen.getByText('75 connections open')).toBeInTheDocument()
    expect(screen.getByText('25 connections open')).toBeInTheDocument()

    // What the rule intends beside what is happening. Round robin over two
    // destinations intends half each, and 75/25 is the thing worth seeing.
    expect(screen.getAllByText('Expected 50%')).toHaveLength(2)
    const meters = screen.getAllByRole('meter')
    expect(meters.map((meter) => meter.getAttribute('aria-valuenow'))).toEqual(['75', '25'])
  })

  it('calls out a destination that is taking nothing while the others are busy', async () => {
    vi.mocked(api.get).mockResolvedValue({
      route_rule_id: 1,
      reader: 'conntrack',
      available: true,
      connections: [],
      total: 40,
      by_destination: [
        { address: '172.17.1.2', port: 8080, connections: 40, rx_bytes: 0, tx_bytes: 0 },
      ],
      new_per_second: 0,
      checked_at: '',
    })

    render(wrap(<RouteDestinationsPanel route={route()} />))

    expect(await screen.findByText('Taking nothing')).toBeInTheDocument()
    expect(screen.getByText(/Either it is refusing them/)).toBeInTheDocument()
  })

  it('says the split is unknown rather than showing an even one it cannot read', async () => {
    vi.mocked(api.get).mockResolvedValue({
      route_rule_id: 1,
      reader: 'conntrack',
      available: false,
      detail: 'the conntrack module is not loaded',
      connections: [],
      total: 0,
      new_per_second: 0,
      checked_at: '',
    })

    render(wrap(<RouteDestinationsPanel route={route()} />))

    expect(await screen.findByText(/where the traffic is actually going cannot be shown/)).toBeInTheDocument()
    // The configuration is still the configuration, so it is still listed.
    expect(screen.getByText('172.17.1.2:8080')).toBeInTheDocument()
    expect(screen.getByText('172.17.2.2:8080')).toBeInTheDocument()
    expect(screen.queryByRole('meter')).toBeNull()
  })

  it('keeps a destination the rule no longer has but conntrack still shows', async () => {
    vi.mocked(api.get).mockResolvedValue({
      route_rule_id: 1,
      reader: 'conntrack',
      available: true,
      connections: [],
      total: 12,
      by_destination: [
        { address: '172.17.9.9', port: 8080, connections: 12, rx_bytes: 0, tx_bytes: 0 },
      ],
      new_per_second: 0,
      checked_at: '',
    })

    render(wrap(<RouteDestinationsPanel route={route()} />))

    expect(await screen.findByText('172.17.9.9:8080')).toBeInTheDocument()
    expect(screen.getByText('Not a destination of this rule')).toBeInTheDocument()
  })
})
