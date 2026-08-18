// Recovering from assets that no longer exist.
//
// The bundle is content-hashed and ships inside the Go binary, so upgrading the
// panel replaces every chunk name at once. A tab that was already open still
// holds the previous shell, and the moment it needs a route it has not loaded
// yet it asks for a chunk that the new binary does not serve. The import
// rejects, React unmounts the tree, and the operator is left looking at an
// empty <div id="root"> — during an upgrade, which is exactly when they are
// most likely to be watching.
//
// Reloading fixes it, because the fresh document asks for the new asset names.
// So reload — but not without limit. The failing route is still the current URL
// after the reload, so if the asset is genuinely gone rather than merely
// renamed, the same import fails again immediately and a page that reloads on
// every failure never stops. This was not hypothetical: an earlier attempt at
// this file cleared its own guard as soon as the shell mounted, which happens
// before the lazy route resolves, and a live panel reloaded 91 times in a row.
//
// A cooldown is what makes that safe. One recovery attempt per window, recorded
// with the time it happened, so a second failure inside the window shows the
// operator what is wrong instead of reloading, while a genuine upgrade weeks
// later still recovers by itself. Nothing has to remember to reset it.

/** When this tab last reloaded itself to pick up renamed assets. */
const RELOAD_MARK = 'gre-panel:stale-asset-reload-at'

/**
 * How long a recovery attempt suppresses the next one. Long enough that a
 * failing route cannot loop, short enough that a later upgrade in the same
 * long-lived tab still recovers on its own.
 */
export const RELOAD_COOLDOWN_MS = 30_000

/** The slice of Storage this module needs, so a test can supply its own. */
type MarkStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

/**
 * Reports whether an error is a browser failing to fetch a JavaScript chunk,
 * rather than the application throwing.
 *
 * There is no single error type for this: Vite raises `vite:preloadError`, the
 * bare dynamic import rejects with a TypeError whose message differs per
 * browser, and an aborted script tag surfaces as its own kind of failure. The
 * shapes below are the ones that actually reach us.
 */
export function isStaleAssetError(error: unknown): boolean {
  if (!error) return false

  const name = typeof error === 'object' && 'name' in error ? String(error.name) : ''
  if (name === 'ChunkLoadError') return true

  const message =
    error instanceof Error
      ? error.message
      : typeof error === 'string'
        ? error
        : typeof error === 'object' && 'message' in error
          ? String((error as { message: unknown }).message)
          : ''

  return [
    'failed to fetch dynamically imported module',
    'error loading dynamically imported module',
    'failed to load module script',
    'importing a module script failed',
    'unable to preload css',
  ].some((fragment) => message.toLowerCase().includes(fragment))
}

/**
 * Reloads the page to pick up the current asset names, at most once per
 * cooldown window.
 *
 * Returns true when it triggered a reload, and false when this tab reloaded
 * recently — in which case the caller should show the failure rather than loop.
 * `storage`, `reload` and `now` are injectable so this is testable without
 * navigating the test runner. Passing null for storage says there is none,
 * which a default parameter cannot express: an explicit undefined argument
 * takes the default.
 */
export function reloadOnceForStaleAssets(
  storage?: MarkStorage | null,
  reload: () => void = () => window.location.reload(),
  now: number = Date.now(),
): boolean {
  const store = storage === null ? undefined : (storage ?? safeSessionStorage())

  // With nowhere to record the attempt, a reload cannot be bounded, and an
  // unbounded reload is the loop this exists to prevent.
  if (!store) return false
  if (attemptedWithinCooldown(store, now)) return false

  store.setItem(RELOAD_MARK, String(now))
  reload()
  return true
}

/**
 * Reports whether this tab tried to recover from renamed assets a moment ago.
 *
 * React does not preserve the original rejection when a lazy import fails; by
 * the time it reaches an error boundary the message can be an ordinary-looking
 * "Cannot read properties of undefined (reading 'default')", which is far too
 * generic to match on. A recent recovery attempt is the reliable signal that
 * what actually went wrong was the assets, so the boundary can say so.
 */
export function attemptedStaleAssetReload(
  storage?: MarkStorage | null,
  now: number = Date.now(),
): boolean {
  const store = storage === null ? undefined : (storage ?? safeSessionStorage())
  return store ? attemptedWithinCooldown(store, now) : false
}

function attemptedWithinCooldown(store: MarkStorage, now: number): boolean {
  const raw = store.getItem(RELOAD_MARK)
  if (!raw) return false

  const at = Number(raw)
  // A mark that is not a number, or is dated in the future because the clock
  // moved, is treated as spent rather than trusted into a loop.
  if (!Number.isFinite(at)) return true
  return now - at < RELOAD_COOLDOWN_MS
}

/**
 * sessionStorage throws rather than returning null when storage is denied —
 * a hardened browser profile, or a page opened with cookies blocked.
 */
function safeSessionStorage(): Storage | undefined {
  try {
    return window.sessionStorage
  } catch {
    return undefined
  }
}
