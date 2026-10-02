import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'

import { ToastProvider } from '@/providers/ToastProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), del: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { AttentionCard } = await import('./AttentionCard')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

/** What the reconcile report on server A actually returned. */
function report() {
  return {
    items: [
      {
        interface_name: 'gre-ir-15',
        reconcile_status_id: 40, // Unmanaged
        status: 'Unmanaged',
        detail:
          'gre-ir-15 was created by the install script this panel replaces. Adopting it imports its ' +
          'parameters from the kernel; the interface is never renamed and never interrupted.',
        actions: ['adopt', 'ignore'],
        is_ignored: false,
      },
      {
        tunnel_id: 3,
        interface_name: 'gre-a-1',
        reconcile_status_id: 20, // Drifted
        status: 'Drifted',
        detail: 'The MTU on this server does not match what is stored.',
        // The wire spelling, from FieldDiff in internal/reconcile.
        diffs: [
          { field: 'mtu', desired: '1472', actual: '1400' },
          { field: 'tunnel_attributes', desired: 'present', actual: 'the interface reports none' },
        ],
        actions: ['reapply', 'forget', 'delete'],
        is_ignored: false,
      },
    ],
  }
}

function wrap(children: ReactNode, client: QueryClient) {
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>
        <MemoryRouter>{children}</MemoryRouter>
      </ToastProvider>
    </QueryClientProvider>
  )
}

let client: QueryClient

beforeEach(() => {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  vi.mocked(api.get).mockImplementation(async (path: string) => {
    if (path === '/reconcile') return report() as never
    return {} as never
  })
  vi.mocked(api.post).mockResolvedValue({} as never)
})

/**
 * The card told the operator to adopt an interface and offered no way to do it.
 *
 * Only reapply was ever wired, and reapply is gated on a tunnel_id, which an
 * unmanaged interface has none of — so every unmanaged row rendered its
 * invitation beside no control at all. `reconcile.adopt`, `reconcile.forget`
 * and `reconcile.ignore` existed in both locales and were referenced by nothing;
 * POST /reconcile/adopt and /reconcile/{id}/forget existed in the router and
 * were called by nothing. The whole adoption path was unreachable from the
 * browser, which is also how §3.2 says to exercise it.
 */
describe('AttentionCard', () => {
  it('offers every action the report says the item has', async () => {
    render(wrap(<AttentionCard />, client))

    expect(await screen.findByRole('button', { name: 'Adopt' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Ignore' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Reapply' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Forget' })).toBeTruthy()
  })

  it('adopts the interface the row is about', async () => {
    render(wrap(<AttentionCard />, client))

    ;(await screen.findByRole('button', { name: 'Adopt' })).click()

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/reconcile/adopt', { interface_name: 'gre-ir-15' }),
    )
  })

  it('ignores by name and reapplies by identifier', async () => {
    render(wrap(<AttentionCard />, client))

    ;(await screen.findByRole('button', { name: 'Ignore' })).click()
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/reconcile/ignore', {
        interface_name: 'gre-ir-15',
        ignored: true,
      }),
    )

    screen.getByRole('button', { name: 'Reapply' }).click()
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/reconcile/3/reapply', {}))
  })

  it('does not offer delete here, which needs a typed confirmation', async () => {
    render(wrap(<AttentionCard />, client))

    await screen.findByRole('button', { name: 'Reapply' })
    expect(screen.queryByRole('button', { name: /delete/i })).toBeNull()
  })

  /**
   * Every drifted row rendered its diff with both values blank.
   *
   * The backend's FieldDiff is {field, desired, actual}; the type here said
   * expected/observed, so the card read two properties that never arrive and
   * printed "mtu Stored On this server" with nothing after either word -- the
   * one part of the report that says what actually drifted.
   */
  it('shows what was stored and what the server holds for each drifted field', async () => {
    render(wrap(<AttentionCard />, client))

    // The diff's own line, not the row around it.
    const diff = (await screen.findByText('1472')).closest('li') as HTMLElement
    expect(diff).toHaveTextContent('1472')
    expect(diff).toHaveTextContent('1400')
    // The field by its label, not its wire name.
    expect(diff).toHaveTextContent('MTU')
    expect(diff).not.toHaveTextContent('mtu')
  })

  it('lays a diff that is a sentence out by its own direction', async () => {
    render(wrap(<AttentionCard />, client))

    // A phrase the backend wrote rather than a value, which is translated
    // with the request and may be in either script.
    const phrase = await screen.findByText('the interface reports none')
    expect(phrase).toHaveAttribute('dir', 'auto')
    // A value stays a technical token, left-to-right whatever the page.
    expect(screen.getByText('1400')).toHaveAttribute('dir', 'ltr')
  })

  it('refreshes the report even when an action fails', async () => {
    // A failed action can still have changed what the report says. Leaving the
    // card showing the state from before is the same defect that made a rule
    // which had really been applied keep reading as absent.
    vi.mocked(api.post).mockRejectedValue(new Error('nope'))
    const invalidate = vi.spyOn(client, 'invalidateQueries')

    render(wrap(<AttentionCard />, client))
    ;(await screen.findByRole('button', { name: 'Adopt' })).click()

    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ['reconcile'] }),
    )
  })
})
