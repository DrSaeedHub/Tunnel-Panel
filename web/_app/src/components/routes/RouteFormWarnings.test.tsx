import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

import i18n from '@/i18n'
import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { ToastProvider } from '@/providers/ToastProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api, ApiError } = await import('@/lib/api')
const { RouteFormDialog } = await import('./RouteFormDialog')

afterEach(async () => {
  cleanup()
  vi.clearAllMocks()
  localStorage.removeItem('gre-panel:preferences')
  await i18n.changeLanguage('en')
})

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <QueryClientProvider client={client}>
      <PreferencesProvider authenticated={false}>
        <ToastProvider>{children}</ToastProvider>
      </PreferencesProvider>
    </QueryClientProvider>
  )
}

// An existing rule, so the form is complete on open and previews at once.
const existing = {
  route_rule_id: 4,
  route_rule_title: 'Relay',
  description: '',
  route_protocol_id: 10,
  address_family_id: 10,
  bind_address: '203.0.113.10',
  bind_port: 18500,
  bind_port_range_end: null,
  bind_interface: null,
  destination_address: '198.51.100.20',
  destination_port: 443,
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
  destinations: [{ address: '198.51.100.20', port: 443, weight: 1 }],
  allowed_sources: [],
  source_lists: [],
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
} as any

const plan = { operation: 'update', backend: 'nftables', steps: [], rollback: [], files: [] }

function answerReads() {
  vi.mocked(api.get).mockImplementation(async (path: string) => {
    if (path === '/settings') return { settings: {} } as never
    if (path === '/routes') return { routes: [] } as never
    if (path === '/tunnels') return { tunnels: [] } as never
    if (path === '/system/interfaces') return { interfaces: [] } as never
    if (path === '/source-lists') return { source_lists: [] } as never
    return {} as never
  })
}

const portInUse = () =>
  new ApiError(422, {
    code: 'VALIDATION_FAILED',
    message: 'python3 (pid 42) is listening on tcp/every local address on port 18500.',
    field: 'bind_port',
    details: {
      fields: [
        {
          field: 'bind_port',
          code: 'PORT_IN_USE',
          message: 'python3 (pid 42) is listening on tcp/every local address on port 18500.',
          details: { process_name: 'python3', process_id: 42, port: 18500, protocol: 'tcp' },
        },
      ],
    },
  })

describe('RouteFormDialog warnings', () => {
  // Warnings never stop a rule. The override sat under every one of them, so
  // an operator read a warning as something to override -- and then saw the
  // rule applied anyway without it.
  it('shows advisory warnings without offering an override', async () => {
    answerReads()
    vi.mocked(api.post).mockResolvedValue({
      plan,
      payload: '',
      warnings: [{ code: 'NAT_HIDES_CLIENT_ADDRESS', message: 'backend text' }],
    } as never)

    render(wrap(<RouteFormDialog open onOpenChange={() => {}} route={existing} />))

    expect(await screen.findByText(/destination sees this server rather than the client/)).toBeInTheDocument()
    expect(screen.getByText(/None of them stops it from being applied/)).toBeInTheDocument()
    expect(screen.queryByText('Apply anyway')).not.toBeInTheDocument()
  })

  // The two refusals the override exists for came back as preview errors with
  // no warnings, and the override was only drawn beside warnings: the one
  // case it was needed for was the one case it could not be reached.
  it('offers the override for a port in use, and previews with it once ticked', async () => {
    answerReads()
    vi.mocked(api.post).mockImplementation(async (_path: string, body?: unknown) => {
      if ((body as { force?: boolean })?.force) {
        return {
          plan,
          payload: '',
          warnings: [
            {
              code: 'PORT_IN_USE_FORCED',
              message: 'backend text',
              details: { process_name: 'python3', process_id: 42, port: 18500 },
            },
          ],
        } as never
      }
      throw portInUse()
    })

    render(wrap(<RouteFormDialog open onOpenChange={() => {}} route={existing} />))

    expect(await screen.findByText('Apply anyway')).toBeInTheDocument()
    expect(screen.getByText(/is listening on port/)).toHaveTextContent('python3 (pid 42)')

    fireEvent.click(screen.getByRole('checkbox', { name: 'Apply anyway' }))

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/routes/preview', expect.objectContaining({ force: true })),
    )
    expect(await screen.findByText(/that service stops receiving traffic/)).toBeInTheDocument()
    // Still there, so the operator can take it back.
    expect(screen.getByText('Apply anyway')).toBeInTheDocument()
  })

  // In Persian the backend's English sentence was dropped into a right-to-left
  // line and its leading count jumped to the far end.
  it('says the warning in the interface language, isolated from the line direction', async () => {
    localStorage.setItem('gre-panel:preferences', JSON.stringify({ language: 'fa' }))
    answerReads()
    vi.mocked(api.post).mockResolvedValue({
      plan,
      payload: '',
      warnings: [
        {
          code: 'IP_FORWARDING_DISABLED',
          message: 'backend text',
          details: { family: 'ipv4', stage: 'preview' },
        },
      ],
    } as never)

    render(wrap(<RouteFormDialog open onOpenChange={() => {}} route={existing} />))

    const line = await screen.findByText(/فوروارد IP روی این سرور خاموش است/)
    expect(line).toHaveAttribute('dir', 'auto')
    expect(screen.queryByText('backend text')).not.toBeInTheDocument()
  })
})
