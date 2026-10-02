import { afterEach, describe, expect, it, vi } from 'vitest'

import i18n from '@/i18n'
import { describeError } from '@/components/ui/feedback'
import { ApiError, NetworkError, api, errorFromResponse } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
})

function answer(status: number, body: string, contentType = 'application/json') {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(body, { status, headers: { 'Content-Type': contentType } })),
  )
}

const t = i18n.t.bind(i18n) as (key: string, options?: Record<string, unknown>) => string

/**
 * What a failed request turns into on screen.
 *
 * A failure without the backend's envelope used to become the English sentence
 * "Request failed with status 502" -- or, worse, the raw body: a reverse proxy's
 * whole HTML error page shown as the message. Neither is something an operator
 * can act on, and neither was ever in their language.
 */
describe('a failed request', () => {
  it('says what the backend said, when it said something', async () => {
    answer(409, JSON.stringify({ error: { code: 'CONFLICT', message: 'gre-a-1 already exists.', field: 'interface_name', details: {} } }))

    const error = await api.get('/tunnels').catch((caught) => caught)
    expect(error).toBeInstanceOf(ApiError)
    expect(describeError(error, t).message).toBe('gre-a-1 already exists.')
    expect(describeError(error, t).code).toBe('CONFLICT')
  })

  it('never shows a body that is not the envelope', async () => {
    answer(502, '<html><body><h1>502 Bad Gateway</h1></body></html>', 'text/html')

    const error = await api.get('/tunnels').catch((caught) => caught)
    const described = describeError(error, t)
    // A gateway answering for a panel that is not there: it could not be reached.
    expect(described.message).toBe(t('errors.network'))
    expect(described.message).not.toMatch(/html|status|502/i)
    // The status is kept, with the technical details.
    expect(described.code).toBe('HTTP 502')
  })

  it('says it in the language the page is in', async () => {
    answer(500, 'internal error')
    const error = await api.get('/tunnels').catch((caught) => caught)

    await i18n.changeLanguage('fa')
    try {
      expect(describeError(error, t).message).toBe('پنل به خطای پیش‌بینی‌نشده‌ای برخورد.')
    } finally {
      await i18n.changeLanguage('en')
    }
  })

  it('reads a response the caller fetched itself the same way', async () => {
    const envelope = new Response(
      JSON.stringify({ error: { code: 'NOT_FOUND', message: 'No such tunnel.', field: '', details: {} } }),
      { status: 404 },
    )
    expect((await errorFromResponse(envelope)).message).toBe('No such tunnel.')

    const bare = await errorFromResponse(new Response('Forbidden', { status: 403 }))
    expect(bare.message).toBe('')
    expect(describeError(bare, t).message).toBe(t('errors.forbidden'))
  })

  it('says the panel could not be reached rather than what fetch threw', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )

    const error = await api.get('/tunnels').catch((caught) => caught)
    expect(error).toBeInstanceOf(NetworkError)
    expect(describeError(error, t).message).toBe(t('errors.network'))
  })
})

describe('every request', () => {
  it('names the language the page is showing', async () => {
    answer(200, '{}')
    await i18n.changeLanguage('fa')
    try {
      await api.get('/tunnels')
    } finally {
      await i18n.changeLanguage('en')
    }

    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit]
    expect((init.headers as Record<string, string>)['X-Panel-Language']).toBe('fa')
  })
})
