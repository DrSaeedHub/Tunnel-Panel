import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen } from '@testing-library/react'
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
const { RouteRulesPanel } = await import('./RouteRulesPanel')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>{children}</PreferencesProvider>
    </QueryClientProvider>
  )
}

/**
 * The drifted half of the generated-rules tab.
 *
 * The reconcile report says which part of a rule is missing from the kernel as
 * a FieldDiff -- {field, desired, actual} on the wire. The type here named the
 * two values expected/observed, so every line of this panel was a badge beside
 * two blanks: it said something was wrong and never what.
 */
describe('RouteRulesPanel', () => {
  it('says what the rule should install and what the kernel holds instead', async () => {
    vi.mocked(api.get).mockImplementation(async (path: string) => {
      if (path === '/reconcile') {
        return {
          checked_at: '',
          items: [],
          counts: {},
          routes: [
            {
              route_rule_id: 4,
              title: 'web',
              reconcile_status_id: 20,
              status: 'Drifted',
              detail: 'Part of this rule is missing from the kernel.',
              diffs: [
                {
                  field: 'dnat',
                  desired: 'tcp 0.0.0.0:8443 forwarded to 172.17.1.2:443',
                  actual: 'missing from the kernel',
                },
              ],
              actions: ['reapply'],
              expected_rules: 2,
              installed_rules: 1,
            },
          ],
          route_counts: {},
          route_findings: {},
        } as never
      }
      return undefined as never
    })
    vi.mocked(api.post).mockResolvedValue({ payload: '' } as never)

    render(wrap(<RouteRulesPanel routeRuleId={4} />))

    const desired = await screen.findByText('tcp 0.0.0.0:8443 forwarded to 172.17.1.2:443')
    const actual = screen.getByText('missing from the kernel')
    // Both are the backend's sentences, laid out by their own direction.
    expect(desired).toHaveAttribute('dir', 'auto')
    expect(actual).toHaveAttribute('dir', 'auto')
    // A part of a rule has no tunnel-field label, so it keeps the backend's name.
    expect(screen.getByText('dnat')).toBeInTheDocument()
  })
})
