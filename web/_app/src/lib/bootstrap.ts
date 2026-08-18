/**
 * Runtime configuration injected by the backend into index.html.
 *
 * The panel is served under a secret web path chosen at install time, so the
 * router basename and the API root are only knowable at runtime. The backend
 * writes them into `window.__GRE_PANEL__` and a `<base>` tag; nothing here may
 * assume the panel lives at `/`.
 */
export interface PanelBootstrap {
  /** Panel root, always with a leading and trailing slash: `/abc123/`. */
  base_path: string
  /** API root, no trailing slash: `/abc123/api/v1`. */
  api_base_path: string
  /**
   * The build that served this page. Empty under `vite dev`, where nothing is
   * injected, and empty on a page served by a panel too old to inject it.
   */
  version: string
}

declare global {
  interface Window {
    __GRE_PANEL__?: Partial<PanelBootstrap>
  }
}

function readBootstrap(): PanelBootstrap {
  const injected = typeof window !== 'undefined' ? window.__GRE_PANEL__ : undefined

  // In `vite dev` nothing is injected, so fall back to the dev server's root.
  // This branch never runs in a real deployment, where the backend always
  // injects both values.
  const basePath = normaliseBase(injected?.base_path ?? '/')
  const apiBasePath = injected?.api_base_path ?? `${basePath}api/v1`.replace(/\/{2,}/g, '/')

  return {
    base_path: basePath,
    api_base_path: apiBasePath.replace(/\/$/, ''),
    version: injected?.version ?? '',
  }
}

function normaliseBase(value: string): string {
  if (!value) return '/'
  let out = value.startsWith('/') ? value : `/${value}`
  if (!out.endsWith('/')) out += '/'
  return out
}

export const bootstrap = readBootstrap()

/**
 * Router basename. React Router wants no trailing slash, except at the root
 * where it wants exactly `/`.
 */
export const routerBasename =
  bootstrap.base_path === '/' ? '/' : bootstrap.base_path.replace(/\/$/, '')

/** Absolute URL for an API path such as `/tunnels`. */
export function apiUrl(path: string): string {
  return `${bootstrap.api_base_path}${path.startsWith('/') ? path : `/${path}`}`
}

/** Absolute URL for a panel path such as `/api/docs`, outside the versioned API. */
export function panelUrl(path: string): string {
  return `${bootstrap.base_path}${path.replace(/^\//, '')}`
}

/**
 * The build that served this page, which is not necessarily the build now
 * answering it: updating replaces the binary and restarts it under the open
 * page. The bundle is content-hashed, so the interface in front of the operator
 * stays the old one until it is reloaded, and this is how that is known.
 *
 * Empty when it could not be known, in which case nothing may be concluded from
 * it — never treat empty as "different".
 */
export const servedVersion = bootstrap.version
