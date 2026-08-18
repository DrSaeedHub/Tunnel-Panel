import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

import { api } from '@/lib/api'
import type { SettingsResponse } from '@/lib/types'
import { defaultUnits, type UnitPreferences } from '@/lib/format'
import { detectLanguage, languageOf } from '@/i18n'

export type ThemeChoice = 'system' | 'light' | 'dark'
export type Density = 'comfortable' | 'compact'

export interface Preferences {
  theme: ThemeChoice
  /** The theme actually in force once "system" is resolved. */
  resolvedTheme: 'light' | 'dark'
  language: string
  dir: 'ltr' | 'rtl'
  digits: 'latin' | 'persian'
  calendar: 'gregorian' | 'jalali'
  density: Density
  units: UnitPreferences
}

interface PreferencesContextValue extends Preferences {
  setTheme: (value: ThemeChoice) => void
  setLanguage: (value: string) => void
  setDensity: (value: Density) => void
  /** Writes one display setting through to the backend as well. */
  persist: (key: string, value: unknown) => void
  isSaving: boolean
}

const PreferencesContext = createContext<PreferencesContextValue | null>(null)

const STORAGE_KEY = 'gre-panel:preferences'

interface StoredPreferences {
  theme?: ThemeChoice
  language?: string
  density?: Density
}

/**
 * Preferences that must survive a reload before there is a session.
 *
 * The backend owns these settings, but the login page is rendered before any
 * of them can be fetched, and an operator who chose Farsi should not be shown
 * an English login screen every time.
 */
function readStored(): StoredPreferences {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as StoredPreferences) : {}
  } catch {
    return {}
  }
}

function writeStored(value: StoredPreferences) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(value))
  } catch {
    // A panel in a private window still works; it just forgets.
  }
}

function systemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined' || !window.matchMedia) return 'dark'
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function asString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value ? value : fallback
}

export function PreferencesProvider({
  children,
  authenticated,
}: {
  children: ReactNode
  authenticated: boolean
}) {
  const { i18n } = useTranslation()
  const queryClient = useQueryClient()
  const stored = useMemo(readStored, [])

  const [theme, setThemeState] = useState<ThemeChoice>(stored.theme ?? 'system')
  const [density, setDensityState] = useState<Density>(stored.density ?? 'comfortable')
  const [language, setLanguageState] = useState<string>(stored.language ?? detectLanguage())
  const [systemPreference, setSystemPreference] = useState<'light' | 'dark'>(systemTheme)

  // The backend is the source of truth once there is a session to read it with.
  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get<SettingsResponse>('/settings'),
    enabled: authenticated,
    staleTime: 30_000,
  })

  const remote = settingsQuery.data?.settings

  const saveMutation = useMutation({
    mutationFn: (values: Record<string, unknown>) => api.put<SettingsResponse>('/settings', values),
    onSuccess: (data) => queryClient.setQueryData(['settings'], data),
  })

  // Follow the system only while the operator has not chosen for themselves.
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const media = window.matchMedia('(prefers-color-scheme: light)')
    const listener = () => setSystemPreference(media.matches ? 'light' : 'dark')
    media.addEventListener('change', listener)
    return () => media.removeEventListener('change', listener)
  }, [])

  // A stored backend value wins over the local one: the operator set it on this
  // panel, possibly from another browser.
  useEffect(() => {
    if (!remote) return
    const remoteTheme = asString(remote['display.theme'], '') as ThemeChoice
    if (remoteTheme && remoteTheme !== theme) setThemeState(remoteTheme)
    const remoteLanguage = asString(remote['display.language'], '')
    if (remoteLanguage && remoteLanguage !== language) setLanguageState(remoteLanguage)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [remote])

  const digits = (asString(remote?.['display.digits'], languageOf(language).digits) as
    | 'latin'
    | 'persian')
  const calendar = asString(remote?.['display.calendar'], 'gregorian') as 'gregorian' | 'jalali'

  const units: UnitPreferences = useMemo(
    () => ({
      throughput: asString(remote?.['display.throughput_unit'], defaultUnits.throughput) as
        | 'bytes'
        | 'bits',
      volume: asString(remote?.['display.volume_unit'], defaultUnits.volume) as 'bytes' | 'bits',
      binary: typeof remote?.['display.binary_units'] === 'boolean'
        ? (remote['display.binary_units'] as boolean)
        : defaultUnits.binary,
      digits,
    }),
    [remote, digits],
  )

  const resolvedTheme = theme === 'system' ? systemPreference : theme
  const dir = languageOf(language).dir

  // The document root carries direction, language and theme, so CSS logical
  // properties and the font switch resolve correctly for the whole tree.
  useEffect(() => {
    const root = document.documentElement
    root.setAttribute('dir', dir)
    root.setAttribute('lang', language)
    root.setAttribute('data-theme', resolvedTheme)
    root.setAttribute('data-density', density)
    root.style.colorScheme = resolvedTheme
  }, [dir, language, resolvedTheme, density])

  useEffect(() => {
    if (i18n.language !== language) void i18n.changeLanguage(language)
  }, [i18n, language])

  const persist = useCallback(
    (key: string, value: unknown) => {
      if (!authenticated) return
      saveMutation.mutate({ [key]: value })
    },
    [authenticated, saveMutation],
  )

  const setTheme = useCallback(
    (value: ThemeChoice) => {
      setThemeState(value)
      writeStored({ ...readStored(), theme: value })
      persist('display.theme', value)
    },
    [persist],
  )

  const setLanguage = useCallback(
    (value: string) => {
      setLanguageState(value)
      writeStored({ ...readStored(), language: value })
      persist('display.language', value)
    },
    [persist],
  )

  // Density is a local comfort setting with no backend key, so it stays here.
  const setDensity = useCallback((value: Density) => {
    setDensityState(value)
    writeStored({ ...readStored(), density: value })
  }, [])

  const value: PreferencesContextValue = {
    theme,
    resolvedTheme,
    language,
    dir,
    digits,
    calendar,
    density,
    units,
    setTheme,
    setLanguage,
    setDensity,
    persist,
    isSaving: saveMutation.isPending,
  }

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}

export function usePreferences(): PreferencesContextValue {
  const context = useContext(PreferencesContext)
  if (!context) throw new Error('usePreferences must be used inside PreferencesProvider')
  return context
}
