import { afterEach, describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider, type Query } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'

import i18n from '@/i18n'
import { PreferencesProvider, usePreferences } from './PreferencesProvider'

afterEach(async () => {
  cleanup()
  try {
    localStorage.clear()
  } catch {
    // Nothing stored, nothing to clear.
  }
  await i18n.changeLanguage('en')
})

function Switcher() {
  const { setLanguage } = usePreferences()
  return (
    <button type="button" onClick={() => setLanguage('fa')}>
      switch
    </button>
  )
}

/**
 * Everything the server says is said in the language the request named. A page
 * that switched language kept every sentence it had already fetched in the old
 * one -- the error under a field, the diagnosis on screen, the settings' own
 * descriptions -- until each happened to be fetched again.
 */
describe('changing the interface language', () => {
  it('fetches what the server said again, in the new language', async () => {
    const client = new QueryClient()
    const invalidate = vi.spyOn(client, 'invalidateQueries')

    render(
      <QueryClientProvider client={client}>
        <PreferencesProvider authenticated={false}>
          <Switcher />
        </PreferencesProvider>
      </QueryClientProvider>,
    )
    // Nothing is refetched just for mounting in the language already in use.
    expect(invalidate).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'switch' }))
    await waitFor(() => expect(invalidate).toHaveBeenCalledTimes(1))
    // By then the requests already carry the new language.
    expect(i18n.language).toBe('fa')

    const { predicate } = invalidate.mock.calls[0][0] as { predicate: (query: Query) => boolean }
    const query = (queryKey: unknown[]) => ({ queryKey }) as unknown as Query
    expect(predicate(query(['settings', 'schema']))).toBe(true)
    expect(predicate(query(['reconcile']))).toBe(true)
    expect(predicate(query(['tunnels', 'list']))).toBe(true)
    // The stored values carry no prose, and refetching them races the save
    // that records the new language.
    expect(predicate(query(['settings']))).toBe(false)
  })
})
