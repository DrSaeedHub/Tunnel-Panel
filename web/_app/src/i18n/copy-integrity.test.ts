import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'

import en from './locales/en'
import fa from './locales/fa'

/**
 * The copy the interface actually renders, checked against the source rather
 * than one screen at a time.
 *
 * Four separate defects turned out to be the same thing: a user-facing string
 * that never went through the translation table. The Settings page headed a
 * whole section with the raw category id `routes`; a lookup setting printed the
 * row number 10 where its label belonged; the tunnel page titled a card with a
 * hardcoded state key so a dead tunnel was labelled "Up"; and two rows of the
 * configuration tab were labelled `oper_state` and `flags`. Every one was
 * invisible to the API, to the type checker and to the suite, and visible
 * immediately to anyone who read the page.
 *
 * Patching the four sites does not stop the fifth. These two checks are about
 * the shape of the source, so they fail on the next one wherever it lands.
 */

const SRC = path.resolve(__dirname, '..')

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry)
    if (statSync(full).isDirectory()) {
      if (entry === 'locales' || entry === 'test') continue
      out.push(...sourceFiles(full))
      continue
    }
    if (!/\.tsx?$/.test(entry) || /\.test\.tsx?$/.test(entry)) continue
    out.push(full)
  }
  return out
}

function resolveKey(bundle: unknown, key: string): unknown {
  return key.split('.').reduce<unknown>((node, part) => {
    if (node && typeof node === 'object' && part in (node as Record<string, unknown>)) {
      return (node as Record<string, unknown>)[part]
    }
    return undefined
  }, bundle)
}

const FILES = sourceFiles(SRC)

describe('interface copy', () => {
  it('has a translation for every key the source asks for', () => {
    // Only fully literal keys can be checked here; a key built from a template
    // is covered by the Go test that walks the settings schema, which is the
    // one place that knows what the dynamic half can be.
    const missing: string[] = []
    for (const file of FILES) {
      const body = readFileSync(file, 'utf8')
      for (const match of body.matchAll(/\bt\(\s*'([A-Za-z][\w.]*)'/g)) {
        const key = match[1]
        for (const [name, bundle] of [['en', en], ['fa', fa]] as const) {
          const value = resolveKey(bundle, key)
          if (typeof value !== 'string' && typeof value !== 'object') {
            missing.push(`${path.relative(SRC, file)}: ${name} has no ${key}`)
          }
        }
      }
    }
    expect([...new Set(missing)].sort()).toEqual([])
  })

  it('never labels anything with a wire identifier', () => {
    // snake_case and SCREAMING_SNAKE are how the API spells its fields, and no
    // label written for a human is ever spelled that way. This is the check
    // that `oper_state` and `flags` would have failed.
    const leaked: string[] = []
    const labelElements = /<(dt|CardTitle|TabsTrigger|th|Label|CardDescription)(\s[^>]*)?>\s*([^<{][^<]*?)\s*<\//g
    const labelProps = /\b(label|title|placeholder|description)=\{?"([^"]+)"\}?/g
    const wireLike = /^[a-z0-9]+(_[a-z0-9]+)+$|^[A-Z0-9]+(_[A-Z0-9]+)+$/

    for (const file of FILES) {
      const body = readFileSync(file, 'utf8')
      const where = path.relative(SRC, file)
      for (const match of body.matchAll(labelElements)) {
        const text = match[3].trim()
        if (wireLike.test(text)) leaked.push(`${where}: <${match[1]}> labelled ${text}`)
      }
      for (const match of body.matchAll(labelProps)) {
        if (wireLike.test(match[2].trim())) leaked.push(`${where}: ${match[1]}="${match[2]}"`)
      }
    }
    expect(leaked.sort()).toEqual([])
  })

  it('never writes a byte-order mark into a source file', () => {
    // A duplicate of the check in scripts/source_hygiene_test.go, which covers
    // Go and shell and the generated bundle as well. It is repeated here
    // because this is the test that already walks every frontend source file,
    // and a BOM is a Windows-tooling accident that lands in exactly these
    // files: Out-File and a bare > redirect both default to UTF-8 with one.
    const withMark: string[] = []
    for (const file of FILES) {
      if (readFileSync(file, 'utf8').charCodeAt(0) === 0xfeff) {
        withMark.push(path.relative(SRC, file))
      }
    }
    expect(withMark.sort()).toEqual([])
  })

  it('never announces one fixed monitor state as if it were the live one', () => {
    // The monitoring card titled itself t('monitor.state.Up'), so it named a
    // state rather than a section and named the wrong one for every tunnel that
    // was not up. The same key had also been glued to the front of the probe
    // interval field, labelling it "Up · Interval".
    //
    // Naming a state is legitimate as a trailing qualifier -- "Loss · Degraded"
    // is the loss at which a tunnel is called degraded, and reads correctly.
    // What is never legitimate is a fixed state standing on its own, because
    // then it is a claim about this tunnel rather than a label. So the key is
    // allowed only where it continues a concatenation.
    const hardcoded: string[] = []
    for (const file of FILES) {
      const body = readFileSync(file, 'utf8')
      for (const match of body.matchAll(/t\(\s*'monitor\.state\.(\w+)'/g)) {
        const before = body.slice(0, match.index ?? 0).trimEnd()
        if (before.endsWith('+')) continue
        hardcoded.push(`${path.relative(SRC, file)}: t('monitor.state.${match[1]}') stands alone`)
      }
    }
    expect(hardcoded.sort()).toEqual([])
  })
})
