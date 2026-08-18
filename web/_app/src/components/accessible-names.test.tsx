import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

import { ToastProvider } from '@/providers/ToastProvider'
import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { TooltipProvider } from '@/components/ui/overlay'

// Every control an operator can type into or toggle needs a name a screen
// reader can announce. One did not: the source-allowlist CIDR box, whose only
// description was its placeholder — and a placeholder is announced
// inconsistently and vanishes the moment anything is typed.
//
// The cause is a class rather than an incident. Field labels its child by id,
// and every other control in these dialogs is that child. That one sat two
// elements further down, inside a wrapper that puts an Add button beside it, so
// the id never reached it. Nothing warns about that: the markup reads correctly,
// the label renders, and only the association is missing. The next control
// nested a level deeper will look just as correct and be just as anonymous.
//
// So this asks the question of every control in both large forms at once,
// rather than of the one that was found by hand.

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), del: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { RouteFormDialog } = await import('./routes/RouteFormDialog')
const { TunnelFormDialog } = await import('./tunnels/TunnelFormDialog')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

/** Enough of each response for the dialogs to render every control. */
function stubApi() {
  vi.mocked(api.get).mockImplementation(async (path: string) => {
    if (path.startsWith('/settings')) return { settings: {} }
    if (path.startsWith('/system/interfaces')) {
      return { interfaces: [{ name: 'eth0', is_up: true, addresses: [] }] }
    }
    if (path.startsWith('/system/capabilities')) {
      return {
        managers: [
          {
            name: 'netlink',
            available: true,
            tunnel_types: {
              gre: { supported: true, manager: 'netlink' },
              gretap: { supported: true, manager: 'netlink' },
              ip6gre: { supported: true, manager: 'ip_command' },
              ip6gretap: { supported: true, manager: 'ip_command' },
            },
          },
        ],
      }
    }
    if (path.startsWith('/tunnels/side-info')) {
      return {
        summary: 'One end is A, the other is B.',
        sides: [
          { id: 10, name: 'A', title: 'Side A', summary: 'the first end' },
          { id: 20, name: 'B', title: 'Side B', summary: 'the second end' },
        ],
        identical_on_both_ends: [],
        tunnel_side_ids: { a: 10, b: 20 },
      }
    }
    if (path.startsWith('/tunnels')) return { tunnels: [] }
    if (path.startsWith('/routes')) return { routes: [], total: 0 }
    if (path.startsWith('/pools')) return { pools: [] }
    return {}
  })
}

function wrap(node: React.ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <PreferencesProvider authenticated>
          <TooltipProvider>
            <ToastProvider>{node}</ToastProvider>
          </TooltipProvider>
        </PreferencesProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/**
 * Every control the operator can put a value into. Buttons are excluded: their
 * text is their name, and they are covered by being findable by role and name
 * everywhere else in this suite.
 */
const VALUE_ROLES = ['textbox', 'combobox', 'spinbutton', 'checkbox', 'switch'] as const

/** Below this, the dialog plainly did not render and the test proves nothing. */
const EXPECTED_MINIMUM = 6

async function unnamedControlsIn(container: HTMLElement): Promise<string[]> {
  const offenders: string[] = []
  for (const role of VALUE_ROLES) {
    for (const el of screen.queryAllByRole(role)) {
      if (!container.contains(el)) continue
      const name = el.getAttribute('aria-label')?.trim()
      const labelledBy = el.getAttribute('aria-labelledby')
      const byId = el.id ? container.querySelector(`label[for="${CSS.escape(el.id)}"]`) : null
      const wrapping = el.closest('label')
      if (name || (labelledBy && document.getElementById(labelledBy)) || byId || wrapping) continue
      offenders.push(
        `${role} ${el.getAttribute('name') || el.getAttribute('placeholder') || '(no name, no placeholder)'}`,
      )
    }
  }
  return offenders
}

describe('accessible names', () => {
  it('every control in the create-rule dialog has one', async () => {
    stubApi()
    const { container } = wrap(<RouteFormDialog open onOpenChange={() => {}} />)

    // The allowlist and the rest of the advanced options live behind a
    // disclosure, so open everything before asking.
    await waitFor(() => expect(screen.getAllByRole('textbox').length).toBeGreaterThan(0))
    for (const button of screen.queryAllByRole('button')) {
      if (/advanced/i.test(button.textContent ?? '')) button.click()
    }
    await waitFor(() => expect(screen.getAllByRole('textbox').length).toBeGreaterThan(1))

    // A dialog that failed to render has no controls and no offenders, which
    // would pass this test while proving nothing.
    const counted = VALUE_ROLES.flatMap((role) => screen.queryAllByRole(role)).length
    expect(counted, 'the dialog rendered no value controls at all').toBeGreaterThan(EXPECTED_MINIMUM)

    const offenders = await unnamedControlsIn(container.ownerDocument.body)
    expect(offenders, `controls a screen reader cannot announce: ${offenders.join(', ')}`).toEqual([])
  })

  it('every control in the create-tunnel dialog has one', async () => {
    stubApi()
    const { container } = wrap(<TunnelFormDialog open onOpenChange={() => {}} />)

    await waitFor(() => expect(screen.getAllByRole('textbox').length).toBeGreaterThan(0))
    for (const button of screen.queryAllByRole('button')) {
      if (/advanced|monitoring/i.test(button.textContent ?? '')) button.click()
    }
    await waitFor(() => expect(screen.getAllByRole('textbox').length).toBeGreaterThan(1))

    // A dialog that failed to render has no controls and no offenders, which
    // would pass this test while proving nothing.
    const counted = VALUE_ROLES.flatMap((role) => screen.queryAllByRole(role)).length
    expect(counted, 'the dialog rendered no value controls at all').toBeGreaterThan(EXPECTED_MINIMUM)

    const offenders = await unnamedControlsIn(container.ownerDocument.body)
    expect(offenders, `controls a screen reader cannot announce: ${offenders.join(', ')}`).toEqual([])
  })
})
