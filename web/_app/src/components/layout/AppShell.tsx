import { useEffect, useState } from 'react'
import { Link as RouterLink, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import {
  ChevronDown,
  Gauge,
  KeyRound,
  LogOut,
  Moon,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Settings as SettingsIcon,
  Waypoints,
  Sun,
  User as UserIcon,
} from 'lucide-react'

import { cn } from '@/lib/utils'
import { api } from '@/lib/api'
import { settingsPages } from '@/lib/settingsSections'
import {
  MonitorState,
  type RouteHealthState,
  type RouteListResponse,
  type SettingsSchemaResponse,
  type TunnelListResponse,
} from '@/lib/types'
import { useAuth } from '@/providers/AuthProvider'
import { usePreferences } from '@/providers/PreferencesProvider'
import { UpdateProvider } from '@/providers/UpdateProvider'
import { useMonitorSummary } from '@/hooks/useMonitorSummary'
import { Button } from '../ui/button'
import { StatusDot } from '../ui/status'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Tooltip,
} from '../ui/overlay'
import { HealthIndicator } from './HealthIndicator'
import { LiveIndicator } from './LiveIndicator'
import { LanguageMenu } from './LanguageMenu'
import { ShortcutsDialog, useShortcuts } from './ShortcutsDialog'

const NAV_ITEMS: Array<{
  to: string
  labelKey: string
  Icon: typeof Gauge
  end: boolean
  tree?: 'tunnels' | 'routes' | 'settings'
}> = [
  { to: '/', labelKey: 'nav.dashboard', Icon: Gauge, end: true },
  { to: '/tunnels', labelKey: 'nav.tunnels', Icon: Network, end: false, tree: 'tunnels' },
  { to: '/routes', labelKey: 'nav.routes', Icon: Waypoints, end: false, tree: 'routes' },
  { to: '/settings', labelKey: 'nav.settings', Icon: SettingsIcon, end: false, tree: 'settings' },
]

/** Which trees the operator has folded away; open is the default. */
function readTreeState(): Record<string, boolean> {
  try {
    return JSON.parse(localStorage.getItem('gre-panel:tree') ?? '{}') as Record<string, boolean>
  } catch {
    return {}
  }
}

/** How many live objects the navigation tree lists before deferring to the page. */
const TREE_LIMIT = 6

/**
 * The application frame.
 *
 * The sidebar sits directly on the warm canvas; the pages sit on a floating
 * plate with its own top bar. The sidebar is a live tree, not a menu: the
 * tunnels and forwarding rules that exist on this server appear under their
 * sections with their current state, one click from anywhere.
 */
export function AppShell() {
  const { t } = useTranslation()
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('gre-panel:sidebar') === 'collapsed')
  const [shortcutsOpen, setShortcutsOpen] = useState(false)

  // One monitoring subscription for the whole application.
  const monitor = useMonitorSummary(true)

  useShortcuts({ onShowShortcuts: () => setShortcutsOpen(true) })

  useEffect(() => {
    localStorage.setItem('gre-panel:sidebar', collapsed ? 'collapsed' : 'expanded')
  }, [collapsed])

  return (
    // The update check lives here rather than on a page: the shell is what
    // stays mounted as the operator moves between tabs, so the poll, the
    // dialog and the notice are one of each for the whole session rather than
    // one per page visit.
    <UpdateProvider>
      <div className="flex min-h-screen bg-background">
        {/* The <base href> that makes assets resolve under the secret web path
            also makes a bare fragment resolve against the base, so following this
            link would leave the current page for the panel root -- sending a
            keyboard user to the dashboard instead of past the navigation. Move
            the focus here instead. */}
        <a
          href="#main"
          onClick={(event) => {
            const main = document.getElementById('main')
            if (!main) return
            event.preventDefault()
            main.focus()
            main.scrollIntoView({ block: 'start' })
          }}
          className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-2 focus:rounded-full focus:bg-surface focus:px-4 focus:py-2 focus:text-sm focus:shadow-pop"
        >
          {t('nav.skipToContent')}
        </a>

        <Sidebar
          collapsed={collapsed}
          onToggle={() => setCollapsed((v) => !v)}
          monitor={monitor}
          className="hidden lg:flex"
        />

        <div className="flex min-w-0 flex-1 flex-col sm:p-3 lg:p-4 lg:ps-0">
          {/* The plate: everything the pages draw floats on this. On a phone it
              runs edge to edge, the way an app does. */}
          <div className="flex min-w-0 flex-1 flex-col bg-plate sm:rounded-[1.75rem] sm:border sm:border-border/50 sm:shadow-card">
            <TopBar monitor={monitor} onShowShortcuts={() => setShortcutsOpen(true)} />
            {/* tabIndex -1 so the skip link can move focus here; it is not a tab
                stop. The bottom padding under lg clears the tab bar. */}
            <main
              id="main"
              tabIndex={-1}
              className="mx-auto w-full max-w-screen-2xl min-w-0 flex-1 p-4 pb-28 focus:outline-none sm:p-6 sm:pb-28 lg:pb-6"
            >
              <Outlet context={monitor} />
            </main>
          </div>
        </div>

        {/* On a phone the navigation is a thumb-reach tab bar, not a drawer:
            every destination is one tap, the way a native app does it. */}
        <MobileTabBar />

        <ShortcutsDialog open={shortcutsOpen} onOpenChange={setShortcutsOpen} />
      </div>
    </UpdateProvider>
  )
}

/** The phone navigation: four fixed tabs at the bottom edge. */
function MobileTabBar() {
  const { t } = useTranslation()
  return (
    <nav
      className="fixed inset-x-0 bottom-0 z-40 border-t border-border/60 bg-plate/95 backdrop-blur lg:hidden"
      style={{ paddingBottom: 'env(safe-area-inset-bottom)' }}
      aria-label={t('nav.dashboard')}
    >
      <div className="mx-auto grid max-w-md grid-cols-4">
        {NAV_ITEMS.map(({ to, labelKey, Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className="group flex flex-col items-center gap-1 py-2 focus-visible:outline-none"
          >
            {({ isActive }) => (
              <>
                <span
                  className={cn(
                    'grid h-7 w-12 place-items-center rounded-full transition-colors group-focus-visible:ring-2 group-focus-visible:ring-ring',
                    isActive ? 'bg-ink text-ink-foreground shadow-sm' : 'text-muted-foreground',
                  )}
                >
                  <Icon className="size-4" aria-hidden="true" />
                </span>
                <span
                  className={cn(
                    'max-w-full truncate px-1 text-2xs font-medium',
                    isActive ? 'text-foreground' : 'text-muted-foreground',
                  )}
                >
                  {t(labelKey)}
                </span>
              </>
            )}
          </NavLink>
        ))}
      </div>
    </nav>
  )
}

function Sidebar({
  collapsed,
  onToggle,
  className,
  monitor,
}: {
  collapsed: boolean
  onToggle: () => void
  className?: string
  monitor: ReturnType<typeof useMonitorSummary>
}) {
  const { t } = useTranslation()
  const [treeOpen, setTreeOpen] = useState<Record<string, boolean>>(readTreeState)

  const onToggleTree = (key: string) =>
    setTreeOpen((current) => {
      const next = { ...current, [key]: current[key] === false }
      localStorage.setItem('gre-panel:tree', JSON.stringify(next))
      return next
    })

  return (
    <aside
      className={cn(
        'flex-col px-3 py-4 transition-[width] duration-250',
        collapsed ? 'w-[4.75rem] items-center' : 'w-[17rem]',
        className,
      )}
    >
      <div className={cn('flex items-center gap-2.5 px-1 pb-6', collapsed && 'flex-col px-0')}>
        <div className="grid size-10 shrink-0 place-items-center rounded-full bg-ink text-ink-foreground shadow-sm">
          <Network className="size-5" aria-hidden="true" />
        </div>
        {!collapsed ? (
          <div className="min-w-0 flex-1">
            <p className="display truncate text-[15px] font-bold leading-tight">{t('app.name')}</p>
            <p className="truncate text-2xs text-muted-foreground">{t('app.tagline')}</p>
          </div>
        ) : null}
        <Button
          variant="ghost"
          size="iconSm"
          onClick={onToggle}
          aria-label={collapsed ? t('nav.expand') : t('nav.collapse')}
          className="shrink-0"
        >
          {collapsed ? (
            <PanelLeftOpen className="icon-directional size-4" aria-hidden="true" />
          ) : (
            <PanelLeftClose className="icon-directional size-4" aria-hidden="true" />
          )}
        </Button>
      </div>

      <nav
        className={cn('min-h-0 flex-1 space-y-1 overflow-y-auto scrollbar-thin', collapsed && 'w-full')}
        aria-label={t('nav.dashboard')}
      >
        {NAV_ITEMS.map(({ to, labelKey, Icon, end, tree }) => {
          const open = treeOpen[tree ?? ''] !== false
          return (
            <div key={to}>
              <div className="relative">
                <Tooltip content={collapsed ? t(labelKey) : undefined} side="right">
                  <NavLink
                    to={to}
                    end={end}
                    className={({ isActive }) =>
                      cn(
                        'group flex h-10 items-center gap-3 rounded-full px-3.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                        tree && !collapsed && '[padding-inline-end:2.5rem]',
                        collapsed && 'w-10 justify-center gap-0 px-0',
                        isActive
                          ? 'bg-ink text-ink-foreground shadow-sm'
                          : 'text-muted-foreground hover:bg-surface hover:text-foreground hover:shadow-sm',
                      )
                    }
                  >
                    <Icon className="size-4 shrink-0" aria-hidden="true" />
                    {!collapsed ? <span className="truncate">{t(labelKey)}</span> : null}
                    {collapsed ? <span className="sr-only">{t(labelKey)}</span> : null}
                  </NavLink>
                </Tooltip>

                {/* Folds the tree away, for a server with fifty tunnels. */}
                {tree && !collapsed ? (
                  <button
                    type="button"
                    onClick={() => onToggleTree(tree)}
                    aria-expanded={open}
                    aria-label={open ? t('actions.collapse') : t('actions.expand')}
                    className="absolute top-1/2 grid size-6 -translate-y-1/2 place-items-center rounded-full text-current opacity-70 transition-colors hover:bg-surface hover:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring [inset-inline-end:0.5rem]"
                  >
                    <ChevronDown
                      className={cn('size-3.5 transition-transform duration-250', !open && '-rotate-90 rtl:rotate-90')}
                      aria-hidden="true"
                    />
                  </button>
                ) : null}
              </div>

              {/* The live tree: what actually exists on this server, with its
                  current state. The page itself remains the complete list. */}
              {!collapsed && open && tree === 'tunnels' ? <TunnelTree monitor={monitor} /> : null}
              {!collapsed && open && tree === 'routes' ? <RouteTree /> : null}
              {!collapsed && open && tree === 'settings' ? <SettingsTree /> : null}
            </div>
          )
        })}
      </nav>
    </aside>
  )
}

/** Tree rows under Tunnels: each tunnel by name, wearing its monitor state. */
function TunnelTree({ monitor }: { monitor: ReturnType<typeof useMonitorSummary> }) {
  const tunnelsQuery = useQuery({
    queryKey: ['tunnels', 'list'],
    queryFn: () => api.get<TunnelListResponse>('/tunnels'),
    staleTime: 15_000,
  })

  const tunnels = tunnelsQuery.data?.tunnels ?? []
  if (!tunnels.length) return null

  return (
    <TreeRail>
      {tunnels.slice(0, TREE_LIMIT).map(({ tunnel }) => (
        <TreeLeaf key={tunnel.tunnel_id} to={`/tunnels/${tunnel.tunnel_id}`}>
          <StatusDot
            stateId={monitor.byTunnel.get(tunnel.tunnel_id)?.monitor_state_id ?? MonitorState.Unknown}
            className="shrink-0 [&>svg]:size-3"
          />
          <span className="technical truncate text-xs">{tunnel.interface_name}</span>
        </TreeLeaf>
      ))}
    </TreeRail>
  )
}

const ROUTE_DOT_TONE: Record<RouteHealthState, string> = {
  healthy: 'bg-ok',
  impaired: 'bg-warn',
  failed: 'bg-danger',
  inconsistent: 'bg-danger',
  pending: 'bg-neutral',
  disabled: 'bg-muted-foreground/50',
}

/** Tree rows under Port forwarding: each rule by name, wearing its health. */
function RouteTree() {
  const { t } = useTranslation()
  const routesQuery = useQuery({
    queryKey: ['routes', 'list'],
    queryFn: () => api.get<RouteListResponse>('/routes'),
    staleTime: 15_000,
  })

  const routes = routesQuery.data?.routes ?? []
  if (!routes.length) return null

  return (
    <TreeRail>
      {routes.slice(0, TREE_LIMIT).map(({ route, health }) => (
        <TreeLeaf key={route.route_rule_id} to={`/routes/${route.route_rule_id}`}>
          <span
            className={cn('size-2 shrink-0 rounded-full', ROUTE_DOT_TONE[health.state] ?? 'bg-neutral')}
            title={t(`routes.state.${health.state}`)}
            aria-hidden="true"
          />
          <span className="sr-only">{t(`routes.state.${health.state}`)}</span>
          <span className="truncate text-xs">{route.route_rule_title}</span>
        </TreeLeaf>
      ))}
    </TreeRail>
  )
}

/**
 * Tree rows under Settings: one leaf per section page, each with its icon.
 * Active state follows the ?section= parameter, defaulting to the first page.
 */
function SettingsTree() {
  const { t } = useTranslation()
  const location = useLocation()

  const schemaQuery = useQuery({
    queryKey: ['settings', 'schema'],
    queryFn: () => api.get<SettingsSchemaResponse>('/settings/schema'),
    staleTime: 300_000,
  })

  const pages = settingsPages(schemaQuery.data?.categories ?? [])
  const onSettings = location.pathname.startsWith('/settings')
  const current = onSettings
    ? (new URLSearchParams(location.search).get('section') ?? pages[0]?.key)
    : null

  return (
    <TreeRail>
      {pages.map(({ key, Icon, labelKey }) => {
        const active = current === key
        return (
          <RouterLink
            key={key}
            to={`/settings?section=${key}`}
            className={cn(
              'relative flex h-7 min-w-0 items-center gap-2 rounded-e-full ps-4 pe-2 transition-colors',
              'before:absolute before:top-1/2 before:h-px before:w-2.5 before:bg-border/80 before:[inset-inline-start:0]',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              active ? 'font-semibold text-accent' : 'text-muted-foreground hover:bg-surface hover:text-foreground',
            )}
            aria-current={active ? 'page' : undefined}
          >
            <Icon className="size-3.5 shrink-0" aria-hidden="true" />
            <span className="truncate text-xs">{t(labelKey)}</span>
          </RouterLink>
        )
      })}
    </TreeRail>
  )
}

/** The drafting-tree rail: a vertical rule with a tick per leaf, as drawn. */
function TreeRail({ children }: { children: React.ReactNode }) {
  return <div className="ms-[1.65rem] mt-1 space-y-0.5 border-s border-border/80 pb-1">{children}</div>
}

function TreeLeaf({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          'relative flex h-7 min-w-0 items-center gap-2 rounded-e-full ps-4 pe-2 transition-colors',
          'before:absolute before:top-1/2 before:h-px before:w-2.5 before:bg-border/80 before:[inset-inline-start:0]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          isActive ? 'font-semibold text-accent' : 'text-muted-foreground hover:bg-surface hover:text-foreground',
        )
      }
    >
      {children}
    </NavLink>
  )
}

function TopBar({
  monitor,
  onShowShortcuts,
}: {
  monitor: ReturnType<typeof useMonitorSummary>
  onShowShortcuts: () => void
}) {
  const { t } = useTranslation()
  const location = useLocation()

  const title = (() => {
    if (location.pathname === '/') return t('dashboard.title')
    if (location.pathname.startsWith('/tunnels')) return t('tunnels.title')
    if (location.pathname.startsWith('/routes')) return t('routes.title')
    if (location.pathname.startsWith('/settings')) return t('settings.title')
    return t('app.name')
  })()

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-2 border-b border-border/50 bg-plate/90 px-4 backdrop-blur sm:rounded-t-[1.75rem] sm:px-6">
      <h1 className="display min-w-0 flex-1 truncate text-lg font-bold tracking-tight sm:text-xl">{title}</h1>

      <div className="flex items-center gap-1 sm:gap-2">
        <HealthIndicator counts={monitor.counts} />
        <LiveIndicator stream={monitor.stream} />
        <ThemeMenu />
        <LanguageMenu />
        <UserMenu onShowShortcuts={onShowShortcuts} />
      </div>
    </header>
  )
}

function ThemeMenu() {
  const { t } = useTranslation()
  const { theme, resolvedTheme, setTheme } = usePreferences()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('a11y.themeToggle')}>
          {resolvedTheme === 'dark' ? (
            <Moon className="size-4" aria-hidden="true" />
          ) : (
            <Sun className="size-4" aria-hidden="true" />
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        <DropdownMenuLabel>{t('settings.display.theme')}</DropdownMenuLabel>
        {(['system', 'light', 'dark'] as const).map((option) => (
          <DropdownMenuItem
            key={option}
            onSelect={() => setTheme(option)}
            className={cn(theme === option && 'bg-muted')}
          >
            {option === 'system' ? (
              <Gauge className="size-4" aria-hidden="true" />
            ) : option === 'light' ? (
              <Sun className="size-4" aria-hidden="true" />
            ) : (
              <Moon className="size-4" aria-hidden="true" />
            )}
            {t(
              option === 'system'
                ? 'settings.display.themeSystem'
                : option === 'light'
                  ? 'settings.display.themeLight'
                  : 'settings.display.themeDark',
            )}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function UserMenu({ onShowShortcuts }: { onShowShortcuts: () => void }) {
  const { t } = useTranslation()
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('a11y.userMenu')}>
          <UserIcon className="size-4" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        {user ? <DropdownMenuLabel>{user.username}</DropdownMenuLabel> : null}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => navigate('/settings?section=account')}>
          <KeyRound className="size-4" aria-hidden="true" />
          {t('settings.account.title')}
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={onShowShortcuts}>
          <SettingsIcon className="size-4" aria-hidden="true" />
          {t('shortcuts.open')}
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          tone="danger"
          onSelect={() => {
            void logout().then(() => navigate('/login'))
          }}
        >
          <LogOut className="icon-directional size-4" aria-hidden="true" />
          {t('actions.signOut')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
