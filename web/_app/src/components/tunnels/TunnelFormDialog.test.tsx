import { describe, expect, it } from 'vitest'

import { toPatch } from './TunnelFormDialog'
import { TunnelSide } from '@/lib/types'

// The regression these cover is the one a pairing code exists to prevent.
//
// A code carries the addresses the far end already committed to, and it carries
// the pool they came from. The form read the pool, decided the addressing was
// "automatic", and sent the pool without the addresses — so this end allocated
// a subnet of its own. Both ends came up, reported themselves healthy, and
// carried nothing, which is exactly the mismatch the code removes the
// opportunity for.

function form(overrides: Record<string, unknown> = {}) {
  return {
    tunnel_type_id: 1,
    tunnel_side_id: TunnelSide.B,
    persistence_type_id: 1,
    local_endpoint: '203.0.113.10',
    remote_endpoint: '198.51.100.20',
    ttl: 64,
    tos: 'inherit',
    mtu: 1397,
    ikey: null,
    okey: null,
    has_input_checksum: false,
    has_output_checksum: false,
    has_input_sequence: false,
    has_output_sequence: false,
    is_path_mtu_discovery: false,
    is_ignore_df: false,
    is_enabled: true,
    address_pool_id: 1,
    tunnel_number: 2,
    addresses: [
      { address: '172.17.2.2', prefix_length: 30, peer_address: '172.17.2.1', is_primary: true },
    ],
    ...overrides,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any
}

describe('toPatch', () => {
  it('keeps the addresses a pairing code carried, pool and all', () => {
    const patch = toPatch(form(), false)

    expect(patch.addresses).toEqual([
      { address: '172.17.2.2', prefix_length: 30, peer_address: '172.17.2.1', is_primary: true },
    ])
    // The pool is kept too: dropping it would leave this end's allocator free
    // to hand the same subnet to another tunnel later.
    expect(patch.address_pool_id).toBe(1)
  })

  it('sends the tunnel number, which picks the subnet and renders the name', () => {
    expect(toPatch(form(), false).tunnel_number).toBe(2)
  })

  it('still asks the panel to allocate when the form holds no addresses', () => {
    const patch = toPatch(form({ addresses: [], tunnel_number: null }), false)

    expect(patch.addresses).toBeUndefined()
    expect(patch.tunnel_number).toBeUndefined()
    expect(patch.address_pool_id).toBe(1)
  })

  it('clears the pool when the operator addresses by hand', () => {
    const patch = toPatch(form(), true)

    expect(patch.address_pool_id).toBeNull()
    expect(patch.addresses).toHaveLength(1)
  })

  it('drops a half-typed address rather than sending it', () => {
    const patch = toPatch(
      form({ addresses: [{ address: '', prefix_length: 30, is_primary: true }] }),
      false,
    )
    expect(patch.addresses).toBeUndefined()
  })
})
