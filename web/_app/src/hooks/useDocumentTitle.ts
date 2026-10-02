import { useEffect } from 'react'
import { useTranslation } from 'react-i18next'

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
 * falls back to the panel's own name rather than keeping a stale one. That name
 * is said in the operator's language like every other word on the page; the
 * fallback used to be the English word "Panel" whatever the interface was in.
 */
export function useDocumentTitle(title: string | null | undefined) {
  const { t } = useTranslation()
  const fallback = t('app.name')

  useEffect(() => {
    const previous = document.title
    document.title = title?.trim() ? title : fallback
    // Restoring on unmount keeps a dialog or a transient view from leaving its
    // title behind on the page underneath it.
    return () => {
      document.title = previous
    }
  }, [title, fallback])
}
