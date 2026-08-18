import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { Link, MemoryRouter, Route, Routes } from 'react-router-dom'

import { ToastProvider, useToast } from './ToastProvider'

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

/**
 * Notifications the operator is meant to act on.
 *
 * Two behaviours here are load-bearing and neither is visible in a screenshot:
 * a notice carrying a button must not take the button away on a timer, and it
 * must survive the operator moving between pages — the provider is mounted
 * above the router precisely so that it does.
 */
function Raiser({ persistent }: { persistent?: boolean }) {
  const { toast } = useToast()
  return (
    <button
      onClick={() =>
        toast({
          tone: 'info',
          title: 'Version v0.2.0 is available',
          persistent,
          action: { label: 'View update', onClick: () => undefined },
        })
      }
    >
      raise
    </button>
  )
}

describe('toasts', () => {
  it('keeps a persistent notice up long past the countdown a plain one gets', () => {
    vi.useFakeTimers()

    render(
      <ToastProvider>
        <Raiser persistent />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByText('raise'))
    expect(screen.getByText('Version v0.2.0 is available')).toBeInTheDocument()

    act(() => vi.advanceTimersByTime(60_000))

    expect(screen.getByText('Version v0.2.0 is available')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'View update' })).toBeInTheDocument()
  })

  it('still counts an ordinary notice down, so staying is a property of the toast', () => {
    vi.useFakeTimers()

    render(
      <ToastProvider>
        <Raiser />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByText('raise'))
    expect(screen.getByText('Version v0.2.0 is available')).toBeInTheDocument()

    act(() => vi.advanceTimersByTime(6000))

    expect(screen.queryByText('Version v0.2.0 is available')).not.toBeInTheDocument()
  })

  it('survives moving between pages', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <ToastProvider>
          <Routes>
            <Route
              path="/"
              element={
                <>
                  <Raiser persistent />
                  <Link to="/settings">settings</Link>
                </>
              }
            />
            <Route path="/settings" element={<p>the settings page</p>} />
          </Routes>
        </ToastProvider>
      </MemoryRouter>,
    )

    fireEvent.click(screen.getByText('raise'))
    fireEvent.click(screen.getByText('settings'))

    expect(screen.getByText('the settings page')).toBeInTheDocument()
    expect(screen.getByText('Version v0.2.0 is available')).toBeInTheDocument()
  })

  it('replaces a keyed notice instead of stacking copies of it', () => {
    function KeyedRaiser() {
      const { toast } = useToast()
      return (
        <button
          onClick={() =>
            toast({ tone: 'info', key: 'panel-update', persistent: true, title: 'Update available' })
          }
        >
          raise
        </button>
      )
    }

    render(
      <ToastProvider>
        <KeyedRaiser />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByText('raise'))
    fireEvent.click(screen.getByText('raise'))
    fireEvent.click(screen.getByText('raise'))

    expect(screen.getAllByText('Update available')).toHaveLength(1)
  })

  it('tells the raiser when it was closed, which is how a dismissal is remembered', () => {
    const onDismiss = vi.fn()

    function Dismissible() {
      const { toast } = useToast()
      return (
        <button
          onClick={() => toast({ tone: 'info', title: 'Update available', persistent: true, onDismiss })}
        >
          raise
        </button>
      )
    }

    render(
      <ToastProvider>
        <Dismissible />
      </ToastProvider>,
    )
    fireEvent.click(screen.getByText('raise'))
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }))

    expect(screen.queryByText('Update available')).not.toBeInTheDocument()
    expect(onDismiss).toHaveBeenCalledTimes(1)
  })
})
