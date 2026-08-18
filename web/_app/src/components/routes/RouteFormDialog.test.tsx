import { describe, expect, it } from 'vitest'

import { formFromRoute } from './RouteFormDialog'
import type { RouteRule } from '@/lib/types'

// Opening a rule for editing seeds the form from the rule. Both child lists
// were read straight through — route.allowed_sources.map(...) and
// route.destinations.slice(1) — and a nil slice on the Go side marshals to
// JSON null, not []. Every rule created without an allowed-source list, which
// is nearly all of them, therefore threw here and took the whole page down:
// clicking Edit produced an error screen rather than the dialog.
//
// The backend now sends arrays. This is the second half of that fix: the seed
// survives a null whatever the wire says, because a page that dies is a far
// worse failure than a field that starts empty.

function rule(overrides: Partial<RouteRule> = {}): RouteRule {
  return {
    route_rule_id: 1,
    route_rule_title: 'relay',
    description: '',
    route_protocol_id: 10,
    address_family_id: 10,
    bind_address: '203.0.113.10',
    bind_port: 9300,
    bind_port_range_end: null,
    bind_interface: null,
    destination_address: '198.51.100.20',
    destination_port: 9300,
    destination_port_range_end: null,
    nat_mode_id: 10,
    snat_address: null,
    load_balance_mode_id: 10,
    tunnel_id: null,
    is_clamp_mss_to_pmtu: false,
    is_include_local_originated: false,
    is_logging_enabled: false,
    fwmark: null,
    max_connections_per_source: null,
    connection_rate_limit: null,
    is_enabled: true,
    sort_order: 0,
    destinations: [],
    allowed_sources: [],
    ...overrides,
  } as RouteRule
}

describe('formFromRoute', () => {
  it('seeds a rule whose lists arrived as null instead of arrays', () => {
    const seeded = formFromRoute(
      rule({
        allowed_sources: null as unknown as RouteRule['allowed_sources'],
        destinations: null as unknown as RouteRule['destinations'],
      }),
    )

    expect(seeded.allowed_sources).toEqual([])
    expect(seeded.destinations).toEqual([])
  })

  it('still carries the real lists through when they are present', () => {
    const seeded = formFromRoute(
      rule({
        destinations: [
          { route_destination_id: 1, route_rule_id: 1, address: '198.51.100.20', port: 9301, weight: 1, is_enabled: true },
          { route_destination_id: 2, route_rule_id: 1, address: '198.51.100.21', port: 9302, weight: 3, is_enabled: true },
        ] as unknown as RouteRule['destinations'],
        allowed_sources: [
          { route_allowed_source_id: 1, route_rule_id: 1, cidr: '203.0.113.0/24' },
        ] as unknown as RouteRule['allowed_sources'],
      }),
    )

    // The primary destination is repeated by the backend, so only the tail is
    // shown as extra rows.
    expect(seeded.destinations).toEqual([{ address: '198.51.100.21', port: '9302', weight: '3' }])
    expect(seeded.allowed_sources).toEqual(['203.0.113.0/24'])
  })
})
