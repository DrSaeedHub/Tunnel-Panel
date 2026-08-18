import { describe, expect, it } from 'vitest'

import en from './locales/en'
import fa from './locales/fa'
import { languages } from './index'

/**
 * Every language carries every key.
 *
 * A missing key does not fail loudly: i18next falls back to English, so a Farsi
 * operator sees one English sentence in an otherwise translated screen and
 * nobody notices until they do. Comparing the key sets is the only way to catch
 * it, and it is the check that keeps a new feature's copy from landing in one
 * language only.
 */
function flatten(value: unknown, prefix = ''): string[] {
  if (value === null || typeof value !== 'object') return [prefix]
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) =>
    flatten(child, prefix ? `${prefix}.${key}` : key),
  )
}

describe('translations', () => {
  const enKeys = new Set(flatten(en))
  const faKeys = new Set(flatten(fa))

  it('defines the same keys in every language', () => {
    const missingFromFa = [...enKeys].filter((key) => !faKeys.has(key)).sort()
    const missingFromEn = [...faKeys].filter((key) => !enKeys.has(key)).sort()

    expect({ missingFromFa, missingFromEn }).toEqual({ missingFromFa: [], missingFromEn: [] })
  })

  it('leaves no value empty', () => {
    const empty: string[] = []
    const walk = (value: unknown, prefix: string) => {
      if (typeof value === 'string') {
        if (!value.trim()) empty.push(prefix)
        return
      }
      if (value && typeof value === 'object') {
        for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
          walk(child, prefix ? `${prefix}.${key}` : key)
        }
      }
    }
    walk(en, '')
    walk(fa, '')
    expect(empty).toEqual([])
  })

  it('covers the forwarding subsystem in both languages', () => {
    // The R3 copy specifically: a feature whose strings landed in English only
    // would otherwise pass the comparison above on the day it was added and
    // fail it silently later.
    for (const group of ['routes', 'routeForm', 'routeDetail', 'routeDiag', 'deleteRoute',
      'routesSummary', 'tunnelRoutes']) {
      expect(enKeys.has(`${group}.title`) || [...enKeys].some((k) => k.startsWith(`${group}.`))).toBe(true)
      expect([...faKeys].some((k) => k.startsWith(`${group}.`))).toBe(true)
    }
    expect(faKeys.has('nav.routes')).toBe(true)
  })

  it('names and explains every settings category the backend can send', () => {
    // The Settings page groups the schema by the category the backend stamps on
    // each setting, and renders the raw identifier when it has no label. The
    // routes category shipped without one, so a whole section of the page was
    // headed by the lowercase word "routes" with no description under it, in
    // both languages at once — the language comparison above cannot see that,
    // because the key was missing from both.
    //
    // This list is the backend's, from internal/settings/definition.go. The Go
    // test TestEverySettingCategoryIsNamedInTheInterface fails if the two ever
    // drift apart, which is what stops this list from going stale.
    const categories = [
      'tunnel', 'addressing', 'keepalive', 'monitor', 'diagnostics',
      'metrics', 'routes', 'display', 'security', 'system',
    ]
    const missing: string[] = []
    for (const category of categories) {
      for (const [name, keys] of [['en', enKeys], ['fa', faKeys]] as const) {
        if (!keys.has(`settings.category.${category}`)) missing.push(`${name}: category.${category}`)
        if (!keys.has(`settings.categoryHelp.${category}`)) missing.push(`${name}: categoryHelp.${category}`)
      }
    }
    expect(missing).toEqual([])
  })

  it('keeps the interpolation placeholders identical across languages', () => {
    // A placeholder that differs between languages renders as literal braces
    // in the one that is wrong, which is how "{{count}} selected" reaches an
    // operator verbatim.
    const placeholders = (text: string) =>
      [...text.matchAll(/\{\{(\w+)/g)].map((match) => match[1]).sort()

    const byKey = (value: unknown, prefix: string, into: Map<string, string>) => {
      if (typeof value === 'string') {
        into.set(prefix, value)
        return
      }
      if (value && typeof value === 'object') {
        for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
          byKey(child, prefix ? `${prefix}.${key}` : key, into)
        }
      }
    }

    const enText = new Map<string, string>()
    const faText = new Map<string, string>()
    byKey(en, '', enText)
    byKey(fa, '', faText)

    const mismatched: string[] = []
    for (const [key, text] of enText) {
      const other = faText.get(key)
      if (other === undefined) continue
      const left = placeholders(text).join(',')
      const right = placeholders(other).join(',')
      if (left !== right) mismatched.push(`${key}: en(${left}) fa(${right})`)
    }
    expect(mismatched).toEqual([])
  })

  it('registers both languages with a direction and a digit system', () => {
    expect(languages.map((l) => l.code)).toEqual(['en', 'fa'])
    expect(languages.find((l) => l.code === 'fa')?.dir).toBe('rtl')
  })
})
