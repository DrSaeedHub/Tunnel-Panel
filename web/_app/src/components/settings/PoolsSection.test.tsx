import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'

import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { ToastProvider } from '@/providers/ToastProvider'
import { TooltipProvider } from '@/components/ui/overlay'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api, ApiError } = await import('@/lib/api')
const { PoolsSection } = await import('./PoolsSection')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>
          <TooltipProvider>{children}</TooltipProvider>
        </ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>
  )
}

/**
 * A pool the backend refused, field by field.
 *
 * The dialog stored the ApiError itself as its map of field errors, so each
 * field looked itself up as a property of the error object -- `cidr`,
 * `prefix_length` -- found nothing, and the reason the pool was refused never
 * appeared under the field it was about.
 */
describe('the address pool dialog', () => {
  it('puts each validation message under the field it belongs to', async () => {
    vi.mocked(api.get).mockResolvedValue({ pools: [], total: 0 } as never)
    vi.mocked(api.post).mockRejectedValue(
      new ApiError(422, {
        code: 'VALIDATION_FAILED',
        message: 'The pool was not accepted.',
        field: '',
        details: {
          fields: [
            { field: 'address_pool_title', code: 'VALIDATION_FAILED', message: 'A pool needs a name.' },
            { field: 'cidr', code: 'INVALID_ADDRESS', message: '10.0.0.0/33 is not a range.' },
          ],
        },
      }),
    )

    render(wrap(<PoolsSection />))
    fireEvent.click(await screen.findByRole('button', { name: /add pool/i }))
    fireEvent.click(await screen.findByRole('button', { name: /^save$/i }))

    // Each under its own input, wired to it as its description.
    const name = await screen.findByText('A pool needs a name.')
    expect(screen.getByLabelText('Name')).toHaveAttribute('aria-describedby', name.id)
    const cidr = screen.getByText('10.0.0.0/33 is not a range.')
    expect(screen.getByLabelText('Range')).toHaveAttribute('aria-describedby', cidr.id)
    // The backend's sentence keeps its own direction inside either layout.
    expect(name).toHaveAttribute('dir', 'auto')
  })
})
