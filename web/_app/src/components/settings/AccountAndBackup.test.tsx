import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import type { ReactNode } from 'react'

import { ToastProvider } from '@/providers/ToastProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { BackupSection } = await import('./AccountAndBackup')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <ToastProvider>{children}</ToastProvider>
    </QueryClientProvider>
  )
}

/**
 * The preview of what importing a backup would do.
 *
 * Each line printed the backend's own tokens -- "would fail", "tunnel" -- in
 * English whatever the interface was in, and the reason an item would fail was
 * in every response and rendered nowhere.
 */
describe('the backup import preview', () => {
  it('names each action and kind, and says why an item would fail', async () => {
    vi.mocked(api.post).mockResolvedValue({
      actions: [
        {
          kind: 'tunnel',
          target: 'gre-a-1',
          action: 'would fail',
          error: 'The remote endpoint is not an address.',
        },
        { kind: 'pool', target: '10.250.0.0/24', action: 'would create' },
        { kind: 'setting', target: 'display.theme', action: 'skip', detail: 'already set' },
      ],
    } as never)

    const { container } = render(wrap(<BackupSection />))
    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    // Only what the section reads from the chosen file: jsdom's File has no
    // text() to read it with.
    const file = { name: 'backup.json', text: async () => JSON.stringify({ settings: {} }) }
    fireEvent.change(input, { target: { files: [file] } })

    expect(await screen.findByText('Would fail')).toBeInTheDocument()
    expect(screen.getByText('Would create')).toBeInTheDocument()
    expect(screen.getByText('Skip')).toBeInTheDocument()
    expect(screen.getByText('Tunnel')).toBeInTheDocument()
    expect(screen.getByText('Address pool')).toBeInTheDocument()
    expect(screen.getByText('Setting')).toBeInTheDocument()
    expect(screen.queryByText('would fail')).toBeNull()

    const reason = screen.getByText('The remote endpoint is not an address.')
    expect(reason).toHaveAttribute('dir', 'auto')
  })
})
