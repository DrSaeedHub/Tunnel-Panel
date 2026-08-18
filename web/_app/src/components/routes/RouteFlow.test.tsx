import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'

import { RouteFlow, endpointLabel } from './RouteFlow'

// Auto-cleanup only registers itself when vitest runs with globals, which this
// project deliberately does not, so each render is torn down explicitly.
// Without it the second render finds the first one's nodes still mounted.
afterEach(cleanup)

/**
 * The flow indicator carries meaning in its direction: it says traffic moves
 * from the bind address to the destination, and reading order is how it says
 * it. Under RTL an unmirrored arrow reads as the exact opposite — the operator
 * sees traffic flowing from the destination back to this server.
 *
 * These assert the two halves that prevent it: the indicator mirrors, and the
 * addresses inside it do not.
 */
describe('RouteFlow', () => {
  it('reads source-then-destination in the DOM whichever way the page runs', () => {
    render(<RouteFlow bind="203.0.113.10:2044" destination="198.51.100.20:2044" />)

    const flow = screen.getByTestId('route-flow')
    // Mirroring is visual: the DOM order stays source, then destination, so a
    // screen reader announces the flow the right way round in either
    // direction.
    expect(flow.textContent).toBe('203.0.113.10:2044198.51.100.20:2044')
  })

  it('mirrors the indicator under RTL rather than swapping the values', () => {
    render(
      <div dir="rtl" lang="fa">
        <RouteFlow bind="203.0.113.10:2044" destination="198.51.100.20:2044" />
      </div>,
    )

    const flow = screen.getByTestId('route-flow')
    // The container reverses, so the bind address renders on the right and the
    // destination on the left.
    expect(flow.className).toContain('rtl:flex-row-reverse')
    // And the arrowhead turns with it: an arrow still pointing right would say
    // the traffic goes the other way.
    expect(screen.getByTestId('route-flow-arrow')).toHaveClass('icon-directional')
  })

  it('isolates each address from the surrounding direction', () => {
    render(
      <p dir="rtl" lang="fa">
        قانون <RouteFlow bind="203.0.113.10:2044" destination="198.51.100.20:2044" /> فعال است
      </p>,
    )

    for (const value of ['203.0.113.10:2044', '198.51.100.20:2044']) {
      const element = screen.getByText(value)
      // Without this the bidi algorithm reorders the dot-separated parts and
      // the operator reads an address that is not the one stored.
      expect(element).toHaveAttribute('dir', 'ltr')
      expect(element).toHaveClass('technical')
    }
  })

  it('labels the whole indicator for assistive technology', () => {
    render(<RouteFlow bind="203.0.113.10:2044" destination="198.51.100.20:2044" />)
    // The arrow is decorative; the label carries the relationship in words.
    expect(screen.getByLabelText(/203\.0\.113\.10:2044/)).toBeInTheDocument()
    expect(screen.getByTestId('route-flow-arrow')).toHaveAttribute('aria-hidden', 'true')
  })

  it('renders a load-balanced destination with its note', () => {
    render(
      <RouteFlow
        bind="203.0.113.10:2044"
        destination="198.51.100.20:2044"
        destinationNote="+1 more"
      />,
    )
    expect(screen.getByText('+1 more')).toBeInTheDocument()
  })
})

describe('endpointLabel', () => {
  it.each([
    ['a single port', '203.0.113.10', 2044, null, '203.0.113.10:2044'],
    ['a port range', '203.0.113.10', 20000, 20100, '203.0.113.10:20000-20100'],
    // A range end equal to the start is one port, not a range of one: the two
    // must not render differently.
    ['a range of one', '203.0.113.10', 2044, 2044, '203.0.113.10:2044'],
    ['an IPv6 address', '2001:db8::1', 5353, null, '2001:db8::1:5353'],
  ])('renders %s', (_label, address, port, end, expected) => {
    expect(endpointLabel(address, port, end)).toBe(expected)
  })
})
