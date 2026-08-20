import { describe, expect, it } from 'vitest'

import { formFromRoute, toPatch } from './RouteFormDialog'
import { LoadBalanceMode, type RouteRule } from '@/lib/types'

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
    expect(seeded.destinations).toMatchObject([
      { address: '198.51.100.21', port: '9302', weight: '3', monitor_port: '' },
    ])
    expect(seeded.allowed_sources).toEqual(['203.0.113.0/24'])
    // The primary's own weight rides along with it. It used to be sent as 1
    // whatever it was stored as, so a weighted rule could not weight the
    // destination it leads with and saving one silently reset it.
    expect(seeded.destination_weight).toBe('1')
  })
})

/**
 * A rule could grow a destination but never lose one.
 *
 * The destination list was sent only when there was more than one of them, and
 * an absent field reads to the backend as "leave this as it was". So removing
 * the last extra destination and pressing save changed nothing: the rule kept
 * both, stayed in multi-destination mode, and went on sending traffic to a
 * backend the operator had just deleted.
 */
describe('saving a rule that is down to one destination', () => {
  const twoDestinations = [
    {
      route_destination_id: 1, route_rule_id: 1, address: '198.51.100.20', port: 9300,
      weight: 1, is_enabled: true,
    },
    {
      route_destination_id: 2, route_rule_id: 1, address: '198.51.100.21', port: 9301,
      weight: 1, is_enabled: true,
    },
  ] as unknown as RouteRule['destinations']

  it('sends the shortened list rather than leaving it out', () => {
    const seeded = formFromRoute(rule({ destinations: twoDestinations, load_balance_mode_id: 20 }))
    expect(seeded.destinations).toHaveLength(1)

    const patch = toPatch({ ...seeded, destinations: [] })

    expect(patch.destinations).toHaveLength(1)
    expect(patch.destinations).toMatchObject([{ address: '198.51.100.20', port: 9300 }])
    // And the rule stops claiming to balance across a single backend.
    expect(patch.load_balance_mode_id).toBe(LoadBalanceMode.None)
  })

  it('counts a row whose address was cleared as gone, not as a destination', () => {
    const seeded = formFromRoute(rule({ destinations: twoDestinations, load_balance_mode_id: 20 }))
    // Emptying the field never passes through the remove button, so this is the
    // path where a stale balancing mode would otherwise survive.
    const patch = toPatch({
      ...seeded,
      destinations: [{ ...seeded.destinations[0], address: '' }],
    })

    expect(patch.destinations).toHaveLength(1)
    expect(patch.load_balance_mode_id).toBe(LoadBalanceMode.None)
  })

  it('still sends both when both are real', () => {
    const seeded = formFromRoute(rule({ destinations: twoDestinations, load_balance_mode_id: 20 }))
    const patch = toPatch(seeded)

    expect(patch.destinations).toHaveLength(2)
    expect(patch.load_balance_mode_id).toBe(20)
  })
})

/**
 * Whether a destination is in rotation, and how it is monitored, are decided on
 * the rule's own page. This dialog rewrites the whole list on every save, so
 * anything it does not send is something it deletes -- and correcting a title
 * would silently put a destination back into rotation that somebody had taken
 * out on purpose.
 */
describe('the parts of a destination this dialog does not edit', () => {
  it('carries them back unchanged', () => {
    const seeded = formFromRoute(
      rule({
        destinations: [
          {
            route_destination_id: 1, route_rule_id: 1, address: '198.51.100.20', port: 9300,
            weight: 1, is_enabled: true, monitor_failure_threshold: 5,
          },
          {
            route_destination_id: 2, route_rule_id: 1, address: '198.51.100.21', port: 9301,
            weight: 2, is_enabled: false, is_monitor_enabled: true, monitor_interval_seconds: 12,
          },
        ] as unknown as RouteRule['destinations'],
      }),
    )

    const sent = toPatch(seeded).destinations as Record<string, unknown>[]
    expect(sent[0]).toMatchObject({ is_enabled: true, monitor_failure_threshold: 5 })
    expect(sent[1]).toMatchObject({
      is_enabled: false,
      is_monitor_enabled: true,
      monitor_interval_seconds: 12,
    })
  })

  it('gives a newly added destination the sensible defaults', () => {
    const seeded = formFromRoute(rule())
    const patch = toPatch({
      ...seeded,
      destinations: [{ address: '198.51.100.30', port: '9302', weight: '1', monitor_port: '' }],
    })

    const sent = patch.destinations as Record<string, unknown>[]
    expect(sent[1]).toMatchObject({ address: '198.51.100.30', is_enabled: true })
    expect(sent[1].is_monitor_enabled).toBeNull()
  })
})
