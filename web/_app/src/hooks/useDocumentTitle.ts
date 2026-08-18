import { useEffect } from 'react'

/**
 * Sets the browser tab's title for as long as this view is on screen.
 *
 * Every page did this for itself with a bare effect, which worked for the
 * pages that remembered. NotFoundPage did not, so navigating to a URL that
 * matches no route left the previous page's title in the tab: the operator sees
 * "Tunnels" above a page saying the thing was not found, and a bookmark or a
 * restored session records the wrong name. The two detail pages had a narrower
 * version of the same gap — they set the title only once the entity had loaded,
 * so their own not-found and error states kept whatever was there before.
 *
 * Passing null or an empty string means "nothing specific to say", and the tab
 * falls back to the panel's own name rather than keeping a stale one.
 */
export function useDocumentTitle(title: string | null | undefined) {
  useEffect(() => {
    const previous = document.title
    document.title = title?.trim() ? title : FALLBACK_TITLE
    // Restoring on unmount keeps a dialog or a transient view from leaving its
    // title behind on the page underneath it.
    return () => {
      document.title = previous
    }
  }, [title])
}

/**
 * What the tab says when a view has no title of its own.
 *
 * Deliberately the same neutral word the served index.html carries, so the tab
 * never reveals more about the panel than the page already does — the web path
 * is secret-ish by design and the title is visible in a lot of places a URL is
 * not.
 */
export const FALLBACK_TITLE = 'Panel'
