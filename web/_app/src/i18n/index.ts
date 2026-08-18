import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

import en from './locales/en'
import fa from './locales/fa'

/**
 * The language registry.
 *
 * Adding a language means adding a resource file and one entry here: no
 * component, layout or style needs to change, because direction, fonts and
 * digits are all derived from the entry rather than hardcoded per language.
 */
export interface LanguageDefinition {
  /** BCP 47 tag, which is also the `display.language` value stored on the backend. */
  code: string
  /** The language's own name, never translated. */
  nativeName: string
  /** Writing direction, applied to the document root. */
  dir: 'ltr' | 'rtl'
  /** The digit system this language conventionally uses, as an initial default. */
  digits: 'latin' | 'persian'
  resources: Record<string, unknown>
}

export const languages: LanguageDefinition[] = [
  { code: 'en', nativeName: 'English', dir: 'ltr', digits: 'latin', resources: en },
  { code: 'fa', nativeName: 'فارسی', dir: 'rtl', digits: 'persian', resources: fa },
]

export const defaultLanguage = 'en'

export function languageOf(code: string | undefined | null): LanguageDefinition {
  if (!code) return languages[0]
  const exact = languages.find((l) => l.code === code)
  if (exact) return exact
  // `fa-IR` should find `fa`.
  const base = code.split('-')[0]
  return languages.find((l) => l.code === base) ?? languages[0]
}

export function directionOf(code: string): 'ltr' | 'rtl' {
  return languageOf(code).dir
}

/** The browser's preference, used until the operator or the backend says otherwise. */
export function detectLanguage(): string {
  if (typeof navigator === 'undefined') return defaultLanguage
  for (const candidate of navigator.languages ?? [navigator.language]) {
    const match = languages.find((l) => l.code === candidate || l.code === candidate.split('-')[0])
    if (match) return match.code
  }
  return defaultLanguage
}

void i18n.use(initReactI18next).init({
  resources: Object.fromEntries(
    languages.map((l) => [l.code, { translation: l.resources }]),
  ),
  lng: detectLanguage(),
  fallbackLng: defaultLanguage,
  interpolation: {
    // React escapes for us; double-escaping mangles apostrophes in the copy.
    escapeValue: false,
  },
  returnNull: false,
})

export default i18n
