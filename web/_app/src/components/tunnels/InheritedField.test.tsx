import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'

import { TooltipProvider } from '@/components/ui/overlay'
import { InheritedNumberField } from './InheritedField'

afterEach(cleanup)

function renderField(props: Parameters<typeof InheritedNumberField>[0]) {
  return render(
    <TooltipProvider>
      <InheritedNumberField {...props} />
    </TooltipProvider>,
  )
}

/**
 * monitor.degraded_rtt_ms is the only monitoring setting with a nil default —
 * "null disables the latency criterion" — and it was the only one where the
 * override's starting value of `inheritedValue ?? 0` was wrong.
 *
 * The semantics are "Degraded at or above this RTT", so 0 ms means degraded
 * whenever the average round trip is at least zero: permanently Degraded, on
 * every tunnel it is applied to, with nothing on screen explaining why.
 * Flipping a switch on a criterion that was switched off handed the operator
 * the most aggressive value the field can take.
 */
describe('InheritedNumberField with no inherited value', () => {
  const base = {
    label: 'Latency · Degraded',
    inheritedValue: undefined,
    value: null,
    onChange: () => {},
    unit: 'ms',
  }

  it('shows nothing rather than zero while inheriting', () => {
    renderField({ ...base })

    const input = screen.getByRole('spinbutton') as HTMLInputElement
    expect(input.value).toBe('')
    expect(input.disabled).toBe(true)
    // And says plainly that there is no inherited value, rather than "0 ms".
    expect(screen.getByText(/—/)).toBeTruthy()
  })

  it('starts an override empty instead of at zero', () => {
    const onChange = vi.fn()
    renderField({ ...base, onChange })

    fireEvent.click(screen.getByRole('switch'))

    // Nothing is submitted merely by switching the override on. It used to send
    // 0, which the backend stores and the monitor then honours for ever.
    expect(onChange).not.toHaveBeenCalledWith(0)
    const input = screen.getByRole('spinbutton') as HTMLInputElement
    expect(input.value).toBe('')
    expect(input.disabled).toBe(false)
  })

  it('sends the value the operator actually types', () => {
    const onChange = vi.fn()
    renderField({ ...base, onChange })

    fireEvent.click(screen.getByRole('switch'))
    fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '250' } })

    expect(onChange).toHaveBeenCalledWith(250)
  })

  it('stays switched on while empty, rather than springing back', () => {
    // The backend column has only "a value" or "null meaning inherit", so
    // "switched on but empty" exists only in the form and has to be held there.
    renderField({ ...base })
    const toggle = screen.getByRole('switch')

    fireEvent.click(toggle)
    expect(toggle.getAttribute('aria-checked')).toBe('true')
    expect((screen.getByRole('spinbutton') as HTMLInputElement).disabled).toBe(false)
  })
})

describe('InheritedNumberField with an inherited value', () => {
  const base = {
    label: 'Interval',
    inheritedValue: 1,
    value: null,
    onChange: () => {},
    unit: 's',
  }

  it('shows the inherited value while inheriting', () => {
    renderField({ ...base })
    const input = screen.getByRole('spinbutton') as HTMLInputElement
    expect(input.value).toBe('1')
    expect(input.disabled).toBe(true)
  })

  it('starts an override from the inherited value, which is the neutral start', () => {
    const onChange = vi.fn()
    renderField({ ...base, onChange })

    fireEvent.click(screen.getByRole('switch'))

    expect(onChange).toHaveBeenCalledWith(1)
  })

  it('goes back to inheriting when switched off', () => {
    const onChange = vi.fn()
    renderField({ ...base, value: 5, onChange })

    fireEvent.click(screen.getByRole('switch'))

    expect(onChange).toHaveBeenCalledWith(null)
  })
})
