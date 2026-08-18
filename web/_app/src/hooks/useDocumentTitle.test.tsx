import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render } from '@testing-library/react'
import { readFileSync, readdirSync } from 'node:fs'
import path from 'node:path'

import { FALLBACK_TITLE, useDocumentTitle } from './useDocumentTitle'

afterEach(cleanup)

function Titled({ title }: { title: string | null }) {
  useDocumentTitle(title)
  return <p>page</p>
}

/**
 * The browser tab's title, which is the one piece of a page that survives being
 * navigated away from.
 *
 * NotFoundPage never set one, so a URL matching no route left the previous
 * page's title in the tab: an operator sees "Tunnels" above a page saying the
 * thing was not found, and a bookmark or a restored session records the wrong
 * name. The two detail pages had a narrower version of it — they set the title
 * only once the entity had loaded, so their loading, error and not-found states
 * kept whatever was there before.
 */
describe('useDocumentTitle', () => {
  it('sets the title while the view is on screen', () => {
    render(<Titled title="Tunnels" />)
    expect(document.title).toBe('Tunnels')
  })

  it('restores the previous title when the view goes away', () => {
    document.title = 'Dashboard'
    const view = render(<Titled title="gre-a-1" />)
    expect(document.title).toBe('gre-a-1')
    view.unmount()
    expect(document.title).toBe('Dashboard')
  })

  it('falls back rather than keeping a stale title when there is nothing to say', () => {
    document.title = 'Tunnels'
    render(<Titled title={null} />)
    expect(document.title).toBe(FALLBACK_TITLE)
    expect(document.title).not.toBe('Tunnels')
  })

  it('falls back for a blank title too', () => {
    document.title = 'Settings'
    render(<Titled title="   " />)
    expect(document.title).toBe(FALLBACK_TITLE)
  })
})

/**
 * Every routed page names the tab, through the one mechanism.
 *
 * Six pages each had their own effect and one page had none, which is exactly
 * the shape of defect a shared hook removes: there is no longer a per-page
 * decision to forget. This walks the pages rather than listing them, so a page
 * added later is covered without anyone remembering to add it here.
 */
describe('every page', () => {
  it('sets a document title', () => {
    const dir = path.resolve(__dirname, '..', 'pages')
    const missing: string[] = []
    for (const file of readdirSync(dir)) {
      if (!file.endsWith('.tsx') || file.includes('.test.')) continue
      const body = readFileSync(path.join(dir, file), 'utf8')
      if (!body.includes('useDocumentTitle(')) missing.push(file)
    }
    expect(missing).toEqual([])
  })

  it('does not set the title by hand any more', () => {
    // A stray `document.title = …` would bypass the restore-on-unmount and the
    // fallback, quietly reintroducing the stale-title behaviour on one page.
    const dir = path.resolve(__dirname, '..', 'pages')
    const direct: string[] = []
    for (const file of readdirSync(dir)) {
      if (!file.endsWith('.tsx') || file.includes('.test.')) continue
      const body = readFileSync(path.join(dir, file), 'utf8')
      if (/document\.title\s*=/.test(body)) direct.push(file)
    }
    expect(direct).toEqual([])
  })
})
