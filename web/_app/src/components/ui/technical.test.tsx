import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import { CopyButton, Technical, TechnicalBlock } from './technical'

/**
 * Bidirectional isolation is the most common way a bilingual panel gets a
 * technical value wrong, and the failure is silent: the value is still there,
 * still selectable, still correct in the DOM — it simply displays with its
 * parts in a different order, and the operator reads an address that is not the
 * one stored.
 *
 * These tests assert the two properties that prevent it, on the one component
 * every such value goes through.
 */
describe('Technical', () => {
  it('isolates the value from the surrounding text direction', () => {
    render(
      <p dir="rtl" lang="fa">
        نشانی تونل <Technical>172.17.7.1/30</Technical> است
      </p>,
    )

    const value = screen.getByText('172.17.7.1/30')

    // An explicit direction on the element itself: inheriting RTL from the
    // paragraph is exactly what scrambles it.
    expect(value).toHaveAttribute('dir', 'ltr')
    // And isolation, so the bidi algorithm treats it as one opaque run rather
    // than reordering its dot-separated parts against the Farsi around it.
    expect(value).toHaveClass('technical')
  })

  it.each([
    ['an IPv4 address', '203.0.113.10'],
    ['a CIDR', '10.77.0.0/30'],
    ['an interface name', 'gre-a-0'],
    ['a GRE key', '2749365187'],
    ['a MAC address', '02:42:ac:11:00:02'],
    ['a file path', '/etc/systemd/system/gre-a-0.service'],
    ['a shell command', 'ip link add gre-a-0 type gre local 203.0.113.10'],
    ['an IPv6 address', '2001:db8::1'],
  ])('renders %s left-to-right', (_label, value) => {
    render(<Technical>{value}</Technical>)
    const element = screen.getByText(value)
    expect(element).toHaveAttribute('dir', 'ltr')
    expect(element).toHaveClass('technical')
  })

  it('keeps a block of technical text isolated too', () => {
    render(<TechnicalBlock>{'[NetDev]\nName=gre-a-0\nKind=gre'}</TechnicalBlock>)
    const block = screen.getByText(/Name=gre-a-0/)
    expect(block).toHaveAttribute('dir', 'ltr')
    expect(block).toHaveClass('technical')
  })

  it('offers the exact value to the clipboard, not the rendered form', () => {
    render(
      <Technical copyable copyValue="10.77.0.1/30">
        10.77.0.1
      </Technical>,
    )
    // The rendered text is the short form; what gets copied is the full value.
    expect(screen.getByText('10.77.0.1')).toHaveAttribute('dir', 'ltr')
    expect(screen.getByRole('button')).toBeInTheDocument()
  })
})

/**
 * The panel is usually served over plain HTTP on a private address, where
 * navigator.clipboard does not exist and copying falls back to execCommand
 * over a hidden textarea. That fallback has to survive being inside an open
 * dialog: a dialog traps focus, and a textarea appended to document.body is
 * outside the trap — the trap pulls focus straight back and execCommand runs
 * with no live selection. That is exactly how the pairing-code copy button
 * copied nothing while showing success.
 */
describe('CopyButton fallback', () => {
  const clipboard = Object.getOwnPropertyDescriptor(window.navigator, 'clipboard')

  afterEach(() => {
    if (clipboard) Object.defineProperty(window.navigator, 'clipboard', clipboard)
    else delete (window.navigator as { clipboard?: unknown }).clipboard
  })

  const withoutClipboard = () =>
    Object.defineProperty(window.navigator, 'clipboard', { value: undefined, configurable: true })

  it('builds the fallback selection inside its own container, where a focus trap allows it', async () => {
    withoutClipboard()
    let selectionHost: HTMLElement | null = null
    document.execCommand = vi.fn(() => {
      selectionHost = document.querySelector('textarea')?.parentElement ?? null
      return true
    })

    const { container } = render(
      <div>
        <CopyButton value="pairing-code" />
      </div>,
    )
    fireEvent.click(within(container).getByRole('button'))

    await waitFor(() => expect(document.execCommand).toHaveBeenCalled())
    expect(selectionHost).not.toBeNull()
    expect(container.contains(selectionHost)).toBe(true)
  })

  it('reports failure when the copy is refused, never success', async () => {
    withoutClipboard()
    document.execCommand = vi.fn(() => false)

    const { container } = render(<CopyButton value="pairing-code" />)
    fireEvent.click(within(container).getByRole('button'))

    await waitFor(() =>
      expect(within(container).getByRole('button')).toHaveAccessibleName('Could not copy'),
    )
  })
})
