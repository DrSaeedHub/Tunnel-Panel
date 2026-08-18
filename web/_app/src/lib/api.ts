import { apiUrl } from './bootstrap'

/**
 * The backend's error envelope, which every failure uses without exception:
 * `{"error":{"code":"...","message":"...","field":"...","details":{}}}`.
 */
export interface ApiErrorBody {
  code: string
  message: string
  field: string
  details: Record<string, unknown>
}

/**
 * A failed request, carrying everything the UI needs to be actionable: the
 * operator-facing message, the machine code, the field a validation error
 * belongs to, and the details panel's contents.
 */
export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly field: string
  readonly details: Record<string, unknown>

  constructor(status: number, body: ApiErrorBody) {
    super(body.message || `Request failed with status ${status}`)
    this.name = 'ApiError'
    this.status = status
    this.code = body.code || 'UNKNOWN'
    this.field = body.field || ''
    this.details = body.details || {}
  }

  /** Per-field validation messages, when the backend returned any. */
  get fieldErrors(): Record<string, string> {
    const out: Record<string, string> = {}
    const fields = this.details['fields']
    if (Array.isArray(fields)) {
      for (const entry of fields) {
        if (entry && typeof entry === 'object') {
          const record = entry as Record<string, unknown>
          const key = typeof record.field === 'string' ? record.field : ''
          const message = typeof record.message === 'string' ? record.message : ''
          if (key && message) out[key] = message
        }
      }
    }
    // Settings validation answers with a flat key/message map instead.
    for (const [key, value] of Object.entries(this.details)) {
      if (key !== 'fields' && typeof value === 'string') out[key] = value
    }
    if (!Object.keys(out).length && this.field) out[this.field] = this.message
    return out
  }
}

/** Thrown when the browser could not reach the panel at all. */
export class NetworkError extends Error {
  /** The underlying fetch failure, kept for the technical-details panel. */
  readonly reason: unknown

  constructor(reason: unknown) {
    super('The panel could not be reached.')
    this.name = 'NetworkError'
    this.reason = reason
  }
}

const CSRF_COOKIE = 'gre_panel_csrf'
const CSRF_HEADER = 'X-CSRF-Token'

/**
 * The CSRF cookie is deliberately readable: the backend compares the header
 * against it, which a cross-site request cannot forge because it cannot read
 * the cookie to echo it.
 */
export function csrfToken(): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]*)`))
  return match ? decodeURIComponent(match[1]) : ''
}

export interface RequestOptions {
  method?: string
  body?: unknown
  signal?: AbortSignal
  /** Query parameters; undefined and empty values are dropped. */
  query?: Record<string, string | number | boolean | undefined | null>
}

/**
 * Notifies the app that a request was rejected for want of a session, so the
 * router can send the operator to the login page while remembering where they
 * were going. Registered by the auth provider rather than imported, to keep
 * this module free of React.
 */
type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null) {
  onUnauthorized = handler
}

/** Endpoints whose 401 is the answer rather than a session problem. */
const SESSION_PROBES = ['/auth/me', '/auth/login', '/auth/refresh', '/auth/logout']

export function buildQuery(query: RequestOptions['query']): string {
  if (!query) return ''
  const params = new URLSearchParams()
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === '') continue
    params.set(key, String(value))
  }
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? 'GET'
  const headers: Record<string, string> = { Accept: 'application/json' }

  if (options.body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && method !== 'HEAD') {
    const token = csrfToken()
    if (token) headers[CSRF_HEADER] = token
  }

  let response: Response
  try {
    response = await fetch(apiUrl(path) + buildQuery(options.query), {
      method,
      headers,
      credentials: 'same-origin',
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    })
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new NetworkError(cause)
  }

  if (response.status === 204) return undefined as T

  const text = await response.text()
  let parsed: unknown = undefined
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = undefined
    }
  }

  if (!response.ok) {
    const envelope = (parsed as { error?: ApiErrorBody } | undefined)?.error
    const error = new ApiError(
      response.status,
      envelope ?? {
        code: response.status === 404 ? 'NOT_FOUND' : 'UNKNOWN',
        message: text || `Request failed with status ${response.status}`,
        field: '',
        details: {},
      },
    )
    if (response.status === 401 && !SESSION_PROBES.some((p) => path.startsWith(p))) {
      onUnauthorized?.()
    }
    throw error
  }

  return parsed as T
}

export const api = {
  get: <T>(path: string, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...options, method: 'GET' }),
  post: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...options, method: 'POST', body }),
  put: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...options, method: 'PUT', body }),
  patch: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...options, method: 'PATCH', body }),
  delete: <T>(path: string, body?: unknown, options?: Omit<RequestOptions, 'method' | 'body'>) =>
    request<T>(path, { ...options, method: 'DELETE', body }),
}
