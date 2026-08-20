import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { ToastProvider } from '@/providers/ToastProvider'
import { TunnelSide } from '@/lib/types'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { randomGreKey, toPatch, TunnelFormDialog } = await import('./TunnelFormDialog')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function wrapDialog(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>{children}</ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>
  )
}

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

/**
 * The GRE key a new tunnel starts with.
 *
 * It used to come from a setting, which meant every tunnel on a server started
 * with the same one. The kernel tells two tunnels between the same pair of
 * endpoints apart by their keys, so a shared default is a collision waiting for
 * the second tunnel -- and one an operator has no reason to suspect, because
 * they never touched the number.
 */
describe('the GRE key a new tunnel starts with', () => {
  it('is drawn fresh rather than being the same one every time', () => {
    const drawn = new Set<number>()
    for (let i = 0; i < 50; i++) drawn.add(randomGreKey())
    // Fifty draws from a 32-bit space collide with vanishing probability, so
    // anything but a large set here means it is not really being drawn.
    expect(drawn.size).toBeGreaterThan(45)
  })

  it('never returns zero, which the kernel reads as no key at all', () => {
    for (let i = 0; i < 200; i++) expect(randomGreKey()).not.toBe(0)
  })

  it('avoids the keys the server is already using', () => {
    // Every value but one is taken, so the only legal answer is that one.
    const used = new Set<number>()
    const free = 4242
    const original = crypto.getRandomValues.bind(crypto)
    let call = 0
    // The first few draws land on taken keys; the generator has to keep going
    // rather than return one of them or give up.
    vi.spyOn(crypto, 'getRandomValues').mockImplementation(((array: Uint32Array) => {
      array[0] = call++ < 3 ? 7 : free
      return array
    }) as never)
    used.add(7)

    expect(randomGreKey(used)).toBe(free)
    vi.mocked(crypto.getRandomValues).mockRestore()
    void original
  })
})

/**
 * Changing a GRE key on a tunnel that already exists.
 *
 * The kernel cannot alter a key in place, so the change needs the interface
 * rebuilt, and the panel asks before doing that. It used to ask with a checkbox
 * at the foot of a long scrolling form, and disable Save until it was ticked —
 * so from the footer, where the button lives, the whole of the interaction was
 * a Save button that would not click and no stated reason. A tunnel's key could
 * not be changed at all without finding the checkbox first.
 */
describe('changing something that needs the tunnel rebuilt', () => {
  const existing = {
    tunnel_id: 7,
    tunnel_number: 2,
    interface_name: 'gre-b-2',
    display_name: null,
    tunnel_type_id: 1,
    tunnel_side_id: TunnelSide.B,
    persistence_type_id: 1,
    local_endpoint: '203.0.113.10',
    remote_endpoint: '198.51.100.20',
    bind_device: null,
    ttl: 64,
    tos: 'inherit',
    mtu: 1397,
    ikey: 111111,
    okey: 111111,
    has_input_checksum: false,
    has_output_checksum: false,
    has_input_sequence: false,
    has_output_sequence: false,
    is_path_mtu_discovery: false,
    is_ignore_df: false,
    fwmark: null,
    tx_queue_length: null,
    hop_limit: null,
    encap_limit: null,
    is_enabled: true,
    is_name_templated: true,
    address_pool_id: 1,
    addresses: [
      { address: '172.17.2.2', prefix_length: 30, peer_address: '172.17.2.1', is_primary: true },
    ],
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  } as any

  function preview(overrides: Record<string, unknown> = {}) {
    return {
      plan: {
        operation: 'update',
        interface: 'gre-b-2',
        steps: [],
        rollback: [],
        files: [],
        requires_recreate: true,
        recreate_reasons: ['ikey changes from 111111 to 222222, which the kernel cannot alter on a running tunnel'],
      },
      mtu: {},
      warnings: [],
      diffs: [{ field: 'ikey', from: '111111', to: '222222', in_place: false }],
      tunnel: existing,
      ...overrides,
    }
  }

  async function openEditor(previewResponse: Record<string, unknown>) {
    const { api } = await import('@/lib/api')
    vi.mocked(api.get).mockImplementation(async (path: string) => {
      if (path === '/settings') return { settings: {} }
      if (path === '/system/capabilities') {
        return { tunnel_types: [{ id: 1, name: 'gre', supported: true }], persistence: [] }
      }
      if (path === '/pools') return { pools: [] }
      if (path === '/tunnels') return { tunnels: [] }
      if (path === '/system/interfaces') return { interfaces: [] }
      if (path === '/tunnels/side-info') {
        return {
          summary: 'One end is A and the other is B.',
          sides: [
            { tunnel_side_id: TunnelSide.A, title: 'Side A', description: '' },
            { tunnel_side_id: TunnelSide.B, title: 'Side B', description: '' },
          ],
          identical_on_both_ends: [],
          tunnel_side_ids: { a: TunnelSide.A, b: TunnelSide.B },
        }
      }
      return undefined
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any
    vi.mocked(api.post).mockResolvedValue(previewResponse)
    vi.mocked(api.patch).mockResolvedValue({
      tunnel: existing,
      plan: previewResponse.plan,
      verification: { ok: true, checks: [] },
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any)
    return api
  }

  it('lets the button be pressed and explains the rebuild instead', async () => {
    const api = await openEditor(preview())
    render(wrapDialog(<TunnelFormDialog open onOpenChange={() => {}} tunnel={existing} />))

    const save = await screen.findByRole('button', { name: /save changes/i })
    expect(save).not.toBeDisabled()
    // The form says a rebuild is coming before anything is pressed.
    await screen.findByText(/saving this rebuilds the interface/i)
    fireEvent.click(save)

    // Nothing is sent yet: the rebuild is stated first.
    expect(api.patch).not.toHaveBeenCalled()
    expect(await screen.findByText(/rebuilds the tunnel/i)).toBeInTheDocument()
    // Including the far end, which is the half of a key change the panel cannot
    // do anything about and the operator has to.
    expect(screen.getByText(/far end has to be given the same key/i)).toBeInTheDocument()
    // And the backend's own reason for the rebuild, rather than a bare claim.
    expect(screen.getByText(/cannot alter on a running tunnel/i)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /rebuild the tunnel/i }))
    await waitFor(() =>
      expect(api.patch).toHaveBeenCalledWith('/tunnels/7', expect.objectContaining({ confirm_recreate: true })),
    )
  })

  it('says nothing about a key when no key is changing', async () => {
    await openEditor(
      preview({
        diffs: [{ field: 'remote_endpoint', from: '198.51.100.20', to: '198.51.100.21', in_place: false }],
        plan: { ...preview().plan, recreate_reasons: ['remote_endpoint changes'] },
      }),
    )
    render(wrapDialog(<TunnelFormDialog open onOpenChange={() => {}} tunnel={existing} />))

    await screen.findByText(/saving this rebuilds the interface/i)
    fireEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(await screen.findByText(/rebuilds the tunnel/i)).toBeInTheDocument()
    expect(screen.queryByText(/far end has to be given the same key/i)).not.toBeInTheDocument()
  })

  it('sends straight away when nothing has to be rebuilt', async () => {
    const api = await openEditor(
      preview({ plan: { ...preview().plan, requires_recreate: false, recreate_reasons: [] }, diffs: [] }),
    )
    render(wrapDialog(<TunnelFormDialog open onOpenChange={() => {}} tunnel={existing} />))

    fireEvent.click(await screen.findByRole('button', { name: /save changes/i }))
    await waitFor(() => expect(api.patch).toHaveBeenCalled())
    expect(screen.queryByText(/rebuilds the tunnel/i)).not.toBeInTheDocument()
  })
})
