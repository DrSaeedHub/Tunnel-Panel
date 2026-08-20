import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'

import type { TuningReading, TuningReport } from '@/lib/types'
import { PreferencesProvider } from '@/providers/PreferencesProvider'
import { ToastProvider } from '@/providers/ToastProvider'

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api')
  return {
    ...actual,
    api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  }
})

const { api } = await import('@/lib/api')
const { TuningSection } = await import('./TuningSection')

afterEach(() => {
  cleanup()
  vi.clearAllMocks()
})

function reading(overrides: Partial<TuningReading> = {}): TuningReading {
  return {
    key: 'net.ipv4.tcp_fin_timeout',
    group: 'throughput',
    title: 'How long to wait for the other side to finish closing',
    explain: 'A relay with many short connections is better off reclaiming them sooner.',
    current: '60',
    recommended: '15',
    available: true,
    matches: false,
    kind: 'number',
    min: 5,
    max: 600,
    unit: 'seconds',
    desired: '',
    custom: false,
    drifted: false,
    ...overrides,
  }
}

function report(readings: TuningReading[], overrides: Partial<TuningReport> = {}): TuningReport {
  return {
    facts: { MemoryMB: 2048, Cores: 2, LiveConnections: 1200 },
    panel_managed: false,
    sysctl_path: '/etc/sysctl.d/99-gre-panel-tuning.conf',
    readings,
    pending: readings.filter((r) => !r.matches).length,
    safety_pending: 0,
    ...overrides,
  }
}

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

describe('tuning the kernel by hand', () => {
  it('sends only the parameter that was edited', async () => {
    vi.mocked(api.get).mockResolvedValue(
      report([
        reading(),
        reading({ key: 'net.core.somaxconn', title: 'Connections waiting to be accepted', current: '4096' }),
      ]),
    )
    vi.mocked(api.post).mockResolvedValue({ applied: 1 })

    render(wrap(<TuningSection />))
    const field = await screen.findByLabelText(/finish closing/i)
    fireEvent.change(field, { target: { value: '30' } })

    fireEvent.click(await screen.findByRole('button', { name: /save 1 change/i }))

    // Only the touched key travels. Sending the whole page would freeze every
    // other parameter at whatever it happened to be when the page was opened,
    // which is not what saving one field means.
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/system/tuning/set', {
        values: { 'net.ipv4.tcp_fin_timeout': '30' },
      }),
    )
  })

  it('starts from what the panel is keeping, not from what the kernel holds', async () => {
    vi.mocked(api.get).mockResolvedValue(
      report([reading({ current: '60', desired: '25', custom: true, drifted: true })]),
    )

    render(wrap(<TuningSection />))
    const field = (await screen.findByLabelText(/finish closing/i)) as HTMLInputElement
    expect(field.value).toBe('25')
    // A value the panel is keeping that the kernel does not hold is somebody
    // else's doing, and saying so is more use than showing one number.
    expect(screen.getByText(/something else changed it/i)).toBeInTheDocument()
  })

  it('refuses to save a value outside what the parameter takes', async () => {
    vi.mocked(api.get).mockResolvedValue(report([reading()]))

    render(wrap(<TuningSection />))
    const field = await screen.findByLabelText(/finish closing/i)
    fireEvent.change(field, { target: { value: '99999' } })

    const save = await screen.findByRole('button', { name: /save 1 change/i })
    await waitFor(() => expect(save).toBeDisabled())
    expect(api.post).not.toHaveBeenCalled()

    fireEvent.change(field, { target: { value: '30' } })
    await waitFor(() => expect(save).not.toBeDisabled())
  })

  it('fills the field with the suggestion when asked, without applying anything else', async () => {
    vi.mocked(api.get).mockResolvedValue(
      report([
        reading(),
        reading({ key: 'net.core.somaxconn', title: 'Connections waiting to be accepted' }),
      ]),
    )

    render(wrap(<TuningSection />))
    const [useIt] = await screen.findAllByRole('button', { name: /use the suggestion/i })
    fireEvent.click(useIt)

    const field = (await screen.findByLabelText(/finish closing/i)) as HTMLInputElement
    expect(field.value).toBe('15')
    // Filling a field is not applying it: nothing has been sent yet.
    expect(api.post).not.toHaveBeenCalled()
    expect(await screen.findByRole('button', { name: /save 1 change/i })).toBeInTheDocument()
  })

  it('lets a value be typed for a choice the kernel does not publish a list for', async () => {
    vi.mocked(api.get).mockResolvedValue(
      report([
        reading({
          key: 'net.core.default_qdisc',
          title: 'How outgoing packets are queued',
          kind: 'choice',
          open: true,
          min: undefined,
          max: undefined,
          unit: undefined,
          current: 'pfifo_fast',
          recommended: 'fq',
          choices: [
            { value: 'fq', detail: 'a fair turn each' },
            { value: 'fq_codel', detail: 'and keeps queues short' },
          ],
        }),
      ]),
    )
    vi.mocked(api.post).mockResolvedValue({ applied: 1 })

    render(wrap(<TuningSection />))
    const field = await screen.findByLabelText(/outgoing packets/i)
    // Not one of the suggestions. The panel cannot ask this kernel what
    // queueing disciplines it has, so it does not pretend to know.
    fireEvent.change(field, { target: { value: 'htb' } })
    fireEvent.click(await screen.findByRole('button', { name: /save 1 change/i }))

    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/system/tuning/set', {
        values: { 'net.core.default_qdisc': 'htb' },
      }),
    )
  })

  it('offers to stop keeping a parameter it is keeping', async () => {
    vi.mocked(api.get).mockResolvedValue(report([reading({ desired: '25', custom: true })]))
    vi.mocked(api.post).mockResolvedValue({ applied: 0 })

    render(wrap(<TuningSection />))
    fireEvent.click(await screen.findByRole('button', { name: /stop keeping this/i }))

    // An empty value is how the panel is told to let go. The kernel keeps what
    // it has; only the record goes.
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/system/tuning/set', {
        values: { 'net.ipv4.tcp_fin_timeout': '' },
      }),
    )
  })

  it('says nothing is editable for a parameter this kernel does not have', async () => {
    vi.mocked(api.get).mockResolvedValue(
      report([reading({ available: false, current: '', matches: false })]),
    )

    render(wrap(<TuningSection />))
    expect(await screen.findByText(/not on this kernel/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/finish closing/i)).not.toBeInTheDocument()
  })
})
