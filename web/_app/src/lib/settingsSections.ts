import {
  Activity,
  BarChart3,
  Database,
  Globe,
  KeyRound,
  Layers,
  Network,
  Palette,
  Shield,
  SlidersHorizontal,
  Stethoscope,
  Waypoints,
  Wrench,
  type LucideIcon,
} from 'lucide-react'

/**
 * One page of Settings.
 *
 * The schema's backend categories are grouped into pages an operator can name:
 * "monitoring" is one page even though the backend splits it into monitor and
 * keepalive, and addressing carries the pools editor because a pool is where
 * an addressing setting points.
 */
export interface SettingsPageDef {
  /** Stable key; appears in the URL as ?section=<key>. */
  key: string
  Icon: LucideIcon
  /** i18next key for the page name. */
  labelKey: string
  /** Backend schema categories rendered on this page, in order. */
  categories: string[]
  /** Non-schema panels rendered on this page, in order. */
  extras: Array<'density' | 'pools' | 'address' | 'database' | 'account' | 'backup'>
}

/**
 * Ordered by how often an operator actually opens them: daily-look items
 * first, defaults for the two object kinds next, then probing and limits,
 * with server-level plumbing (where the panel serves, the database, the
 * account) at the end where they are looked for rather than stumbled on.
 */
const PAGES: SettingsPageDef[] = [
  { key: 'appearance', Icon: Palette, labelKey: 'settings.category.display', categories: ['display'], extras: ['density'] },
  { key: 'tunnel', Icon: Network, labelKey: 'settings.category.tunnel', categories: ['tunnel'], extras: [] },
  { key: 'routes', Icon: Waypoints, labelKey: 'settings.category.routes', categories: ['routes'], extras: [] },
  { key: 'monitoring', Icon: Activity, labelKey: 'settings.category.monitor', categories: ['monitor', 'keepalive'], extras: [] },
  { key: 'addressing', Icon: Layers, labelKey: 'settings.category.addressing', categories: ['addressing'], extras: ['pools'] },
  { key: 'diagnostics', Icon: Stethoscope, labelKey: 'settings.category.diagnostics', categories: ['diagnostics'], extras: [] },
  { key: 'metrics', Icon: BarChart3, labelKey: 'settings.category.metrics', categories: ['metrics'], extras: [] },
  { key: 'security', Icon: Shield, labelKey: 'settings.category.security', categories: ['security'], extras: [] },
  { key: 'system', Icon: Wrench, labelKey: 'settings.category.system', categories: ['system'], extras: [] },
  { key: 'address', Icon: Globe, labelKey: 'settings.address.title', categories: [], extras: ['address'] },
  { key: 'database', Icon: Database, labelKey: 'settings.database.title', categories: [], extras: ['database'] },
  { key: 'account', Icon: KeyRound, labelKey: 'settings.account.title', categories: [], extras: ['account', 'backup'] },
]

/**
 * The pages, with a generated page appended for any backend category no page
 * claims — a category added to the backend appears here without a change,
 * which is the property the old flat list had and this keeps.
 */
export function settingsPages(schemaCategories: string[]): SettingsPageDef[] {
  const claimed = new Set(PAGES.flatMap((page) => page.categories))
  const orphans = schemaCategories
    .filter((category) => !claimed.has(category))
    .map((category) => ({
      key: `category-${category}`,
      Icon: SlidersHorizontal,
      labelKey: `settings.category.${category}`,
      categories: [category],
      extras: [] as SettingsPageDef['extras'],
    }))
  return [...PAGES, ...orphans]
}
