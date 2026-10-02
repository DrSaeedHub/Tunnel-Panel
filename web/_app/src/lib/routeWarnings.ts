import type { TFunction } from 'i18next'

import type { Warning } from './types'
import { formatCount } from './format'

/** Codes the backend answers a rule with when it refuses it unless forced. */
export const FORCEABLE_ROUTE_CODES = ['PORT_IN_USE', 'LOOPBACK_DESTINATION'] as const

interface Numbers {
  digits: 'latin' | 'persian'
  language: string
}

// Addresses, ports and process names are left-to-right tokens inside what may
// be a right-to-left sentence. Isolating them keeps "port 8443" from pulling
// the words around it out of order, which is how a count at the start of an
// English sentence ended up at the end of the line in the Persian interface.
const isolate = (value: unknown) => `⁨${String(value ?? '')}⁩`

function detail(warning: Pick<Warning, 'details'>, key: string): unknown {
  return warning.details?.[key]
}

/**
 * One sentence for a rule warning, in the operator's language.
 *
 * The backend's message is English and is the fallback: a warning this table
 * does not know yet is still shown, just untranslated, rather than dropped.
 */
export function describeRouteWarning(warning: Warning, t: TFunction, numbers: Numbers): string {
  const count = (value: unknown) => formatCount(Number(value ?? 0), numbers.digits, numbers.language)
  const base = 'routeWarnings.'
  switch (warning.code) {
    case 'NAT_HIDES_CLIENT_ADDRESS':
    case 'NAT_PRESERVES_CLIENT_ADDRESS':
    case 'BIND_ANY_ADDRESS':
    case 'MSS_CLAMP_RECOMMENDED':
      return t(base + warning.code)
    case 'BIND_ADDRESS_NOT_FOUND':
      return t(base + warning.code, { address: isolate(detail(warning, 'bind_address')) })
    case 'LOOPBACK_DESTINATION_FORCED':
    case 'LOOPBACK_DESTINATION':
      return t(base + warning.code, { address: isolate(detail(warning, 'destination_address')) })
    case 'PORT_IN_USE_FORCED':
    case 'PORT_IN_USE': {
      const name = detail(warning, 'process_name')
      const pid = detail(warning, 'process_id')
      // The phrase comes from the locale like the sentence around it; it is a
      // process name and a PID, so it is isolated as one left-to-right token.
      const process = name
        ? isolate(pid ? t(base + 'processWithId', { name, pid }) : name)
        : t(base + 'unknownProcess')
      return t(base + warning.code, { process, port: isolate(detail(warning, 'port')) })
    }
    case 'IP_FORWARDING_DISABLED': {
      const ipv6 = detail(warning, 'family') === 'ipv6'
      if (detail(warning, 'stage') === 'preview') {
        return t(base + (ipv6 ? 'forwardingPreviewIpv6' : 'forwardingPreview'))
      }
      if (ipv6) return t(base + 'forwardingLiveIpv6')
      const rules = Number(detail(warning, 'enabled_rules') ?? 0)
      return t(base + 'forwardingLive', { count: rules, value: count(rules) })
    }
    case 'VERIFICATION_IP_FORWARDING':
      return t(base + warning.code)
    case 'CONNTRACK_TABLE_FILLING':
      return t(base + warning.code, {
        percent: count(detail(warning, 'percent')),
        used: count(detail(warning, 'count')),
        max: count(detail(warning, 'max')),
      })
    case 'CONNTRACK_MAX_LOW':
      return t(base + (detail(warning, 'managed') ? 'conntrackLowManaged' : warning.code), {
        max: count(detail(warning, 'max')),
      })
  }
  return warning.message
}
