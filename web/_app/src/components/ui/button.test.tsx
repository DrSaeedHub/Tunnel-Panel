import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { Button } from './button'

/**
 * `asChild` hands the button's props to the caller's own element through Radix
 * `Slot`, which accepts exactly one React element child. Rendering anything
 * beside that child — a loading spinner, say — makes two, and Slot throws.
 *
 * The failure is worse than it sounds: the throw happens during render, so it
 * unmounts the whole tree and the operator gets a blank page rather than a
 * broken button. Every screen with a link-shaped button goes down with it.
 * These tests pin the behaviour on the component every such button goes
 * through.
 */
describe('Button', () => {
  it('renders as the child element without throwing', () => {
    render(
      <Button asChild variant="primary">
        <a href="/tunnels/new">Create tunnel</a>
      </Button>,
    )

    const link = screen.getByRole('link', { name: 'Create tunnel' })
    expect(link).toBeTruthy()
    expect(link.tagName).toBe('A')
    // The variant classes have to reach the child, or it renders unstyled.
    expect(link.className.length).toBeGreaterThan(0)
  })

  it('still renders as a child element while loading', () => {
    render(
      <Button asChild loading>
        <a href="/tunnels">Tunnels</a>
      </Button>,
    )

    const link = screen.getByRole('link', { name: 'Tunnels' })
    expect(link.getAttribute('aria-busy')).toBe('true')
    // An anchor has no disabled attribute; setting one would be invalid HTML.
    expect(link.hasAttribute('disabled')).toBe(false)
  })

  it('shows a spinner and blocks interaction when it renders its own button', () => {
    render(<Button loading>Save</Button>)

    const button = screen.getByRole('button', { name: /Save/ })
    expect(button.tagName).toBe('BUTTON')
    expect((button as HTMLButtonElement).disabled).toBe(true)
    expect(button.getAttribute('aria-busy')).toBe('true')
  })
})
