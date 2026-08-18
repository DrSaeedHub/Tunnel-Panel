import { describe, expect, it, vi } from 'vitest'

import {
  RELOAD_COOLDOWN_MS,
  attemptedStaleAssetReload,
  isStaleAssetError,
  reloadOnceForStaleAssets,
} from './recovery'

function fakeStorage(seed: Record<string, string> = {}) {
  const map = new Map(Object.entries(seed))
  return {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
    size: () => map.size,
  }
}

describe('isStaleAssetError', () => {
  it('recognises the shapes a browser actually produces for a missing chunk', () => {
    // Each of these is a real message from a browser failing a dynamic import;
    // there is no shared error type, which is why they are matched by text.
    const staleErrors = [
      new Error('Failed to fetch dynamically imported module: /assets/RoutesPage-abc.js'),
      new Error('error loading dynamically imported module'),
      new Error('Failed to load module script: Expected a JavaScript module'),
      new Error('Importing a module script failed.'),
      new Error('Unable to preload CSS for /assets/index-abc.css'),
      Object.assign(new Error('boom'), { name: 'ChunkLoadError' }),
    ]
    for (const error of staleErrors) {
      expect(isStaleAssetError(error), error.message).toBe(true)
    }
  })

  it('does not mistake an ordinary application error for a missing chunk', () => {
    // The distinction matters: treating a real bug as a stale asset would
    // reload the page and hide it.
    expect(isStaleAssetError(new Error("Cannot read properties of null (reading '0')"))).toBe(false)
    expect(isStaleAssetError(new TypeError('x is not a function'))).toBe(false)
    expect(isStaleAssetError(null)).toBe(false)
    expect(isStaleAssetError(undefined)).toBe(false)
  })
})

describe('reloadOnceForStaleAssets', () => {
  it('reloads the first time and refuses for the rest of the cooldown', () => {
    const storage = fakeStorage()
    const reload = vi.fn()
    const t0 = 1_000_000

    expect(reloadOnceForStaleAssets(storage, reload, t0)).toBe(true)
    expect(reload).toHaveBeenCalledTimes(1)

    // The whole point: a page that reloads on every failure is an infinite
    // loop that never shows the operator what went wrong.
    expect(reloadOnceForStaleAssets(storage, reload, t0 + 1)).toBe(false)
    expect(reloadOnceForStaleAssets(storage, reload, t0 + RELOAD_COOLDOWN_MS - 1)).toBe(false)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('does not reload again just because the shell mounted in between', () => {
    // This is the loop that actually happened on a live panel. The failing
    // route is still the current URL after the recovery reload, so the shell
    // mounts, the lazy import fails a second time, and anything that treats a
    // successful mount as "recovered" hands the attempt straight back. That
    // panel reloaded 91 times. Mounting is not evidence of anything, because
    // the shell mounts before the route it cannot load.
    const storage = fakeStorage()
    const reload = vi.fn()
    const t0 = 1_000_000

    for (let i = 0; i < 20; i++) {
      // Time barely advances: reload, mount, fail, repeat.
      reloadOnceForStaleAssets(storage, reload, t0 + i * 100)
    }
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('recovers again from a genuine later upgrade in the same tab', () => {
    const storage = fakeStorage()
    const reload = vi.fn()
    const t0 = 1_000_000

    reloadOnceForStaleAssets(storage, reload, t0)
    expect(reloadOnceForStaleAssets(storage, reload, t0 + 1_000)).toBe(false)

    // A tab left open for hours must not be permanently unable to recover.
    expect(reloadOnceForStaleAssets(storage, reload, t0 + RELOAD_COOLDOWN_MS + 1)).toBe(true)
    expect(reload).toHaveBeenCalledTimes(2)
  })

  it('does not reload at all when there is nowhere to record the attempt', () => {
    // Storage can be denied outright. Reloading without being able to bound it
    // is the loop this guard exists to prevent.
    const reload = vi.fn()
    expect(reloadOnceForStaleAssets(null, reload)).toBe(false)
    expect(reload).not.toHaveBeenCalled()
  })

  it('treats an unreadable mark as spent rather than reloading on it', () => {
    const reload = vi.fn()
    const storage = fakeStorage({ 'gre-panel:stale-asset-reload-at': 'not-a-number' })
    expect(reloadOnceForStaleAssets(storage, reload, 1_000_000)).toBe(false)
    expect(reload).not.toHaveBeenCalled()
  })
})

describe('attemptedStaleAssetReload', () => {
  it('reports a recent recovery attempt, which is how a lost rejection is recognised', () => {
    // React replaces a failed lazy import's rejection with its own error, so
    // the boundary cannot identify it from the message. The attempt this tab
    // just made is the signal that stands in for it.
    const storage = fakeStorage()
    const t0 = 1_000_000

    expect(attemptedStaleAssetReload(storage, t0)).toBe(false)
    reloadOnceForStaleAssets(storage, vi.fn(), t0)
    expect(attemptedStaleAssetReload(storage, t0 + 500)).toBe(true)
    expect(attemptedStaleAssetReload(storage, t0 + RELOAD_COOLDOWN_MS + 1)).toBe(false)
  })
})
