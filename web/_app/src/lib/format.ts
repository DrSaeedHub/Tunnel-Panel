/**
 * Client-side formatting.
 *
 * The API returns raw bytes and raw bytes per second, always. Every unit
 * decision is made here, from the operator's settings, because the same figure
 * is shown as `MB/s` to one operator and `Mbps` to another and the backend must
 * not have to know which. A bare number is never produced: every result carries
 * its unit.
 */

export type UnitBase = 'bytes' | 'bits'

export interface UnitPreferences {
  /** `display.throughput_unit` — how a rate is expressed. */
  throughput: UnitBase
  /** `display.volume_unit` — how a cumulative total is expressed. Independent. */
  volume: UnitBase
  /** `display.binary_units` — MiB (1024) rather than MB (1000). */
  binary: boolean
  /** `display.digits` — Latin or Persian digits for human-facing numbers. */
  digits: 'latin' | 'persian'
}

export const defaultUnits: UnitPreferences = {
  throughput: 'bytes',
  volume: 'bytes',
  binary: true,
  digits: 'latin',
}

const BYTE_UNITS_BINARY = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
const BYTE_UNITS_DECIMAL = ['B', 'kB', 'MB', 'GB', 'TB', 'PB']
const BIT_UNITS_BINARY = ['bit', 'Kibit', 'Mibit', 'Gibit', 'Tibit', 'Pibit']
const BIT_UNITS_DECIMAL = ['bit', 'kbit', 'Mbit', 'Gbit', 'Tbit', 'Pbit']

export interface Scaled {
  /** The scaled number, already rounded for display. */
  value: number
  /** The unit symbol, never omitted. */
  unit: string
  /** Value and unit joined, with digits converted. */
  text: string
}

function scale(raw: number, base: UnitBase, binary: boolean, perSecond: boolean, digits: 'latin' | 'persian'): Scaled {
  const magnitude = base === 'bits' ? raw * 8 : raw
  const step = binary ? 1024 : 1000
  const units =
    base === 'bits'
      ? binary
        ? BIT_UNITS_BINARY
        : BIT_UNITS_DECIMAL
      : binary
        ? BYTE_UNITS_BINARY
        : BYTE_UNITS_DECIMAL

  let index = 0
  let value = Math.abs(magnitude)
  while (value >= step && index < units.length - 1) {
    value /= step
    index += 1
  }
  if (magnitude < 0) value = -value

  // One decimal below 10, none above: enough precision to see change without
  // digits jittering as the number updates.
  const rounded = index === 0 ? Math.round(value) : value < 10 ? Math.round(value * 10) / 10 : Math.round(value)
  const unit = units[index] + (perSecond ? '/s' : '')
  return {
    value: rounded,
    unit,
    text: `${toDigits(formatNumber(rounded), digits)} ${unit}`,
  }
}

/** Formats a rate in bytes per second according to the throughput preference. */
export function formatThroughput(bytesPerSecond: number, prefs: UnitPreferences): Scaled {
  return scale(bytesPerSecond, prefs.throughput, prefs.binary, true, prefs.digits)
}

/** Formats a cumulative byte count according to the volume preference. */
export function formatVolume(bytes: number, prefs: UnitPreferences): Scaled {
  return scale(bytes, prefs.volume, prefs.binary, false, prefs.digits)
}

/** Formats a byte count that is storage rather than traffic, which is always bytes. */
export function formatBytes(bytes: number, prefs: UnitPreferences): Scaled {
  return scale(bytes, 'bytes', prefs.binary, false, prefs.digits)
}

function formatNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : value.toFixed(1)
}

const PERSIAN_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹']

/**
 * Converts Latin digits to the operator's preferred digit system.
 *
 * Technical values never pass through here: an IP address in Persian digits is
 * not an IP address. Only human-facing counts, sizes and dates follow the
 * setting.
 */
export function toDigits(text: string, digits: 'latin' | 'persian'): string {
  if (digits !== 'persian') return text
  return text.replace(/[0-9]/g, (d) => PERSIAN_DIGITS[Number(d)])
}

/** A percentage, with its sign. */
export function formatPercent(value: number, digits: 'latin' | 'persian', decimals = 1): string {
  const rounded = value >= 10 || decimals === 0 ? Math.round(value) : Math.round(value * 10 ** decimals) / 10 ** decimals
  return `${toDigits(formatNumber(rounded), digits)}%`
}

/** A duration in milliseconds, as a latency figure reads. */
export function formatMs(value: number | null | undefined, digits: 'latin' | 'persian'): string | null {
  if (value === null || value === undefined) return null
  const rounded = value < 10 ? Math.round(value * 100) / 100 : value < 100 ? Math.round(value * 10) / 10 : Math.round(value)
  return `${toDigits(String(rounded), digits)} ms`
}

/** An uptime or age in seconds, as the largest two units that fit. */
export function formatDuration(seconds: number, digits: 'latin' | 'persian', labels: DurationLabels): string {
  const total = Math.max(0, Math.floor(seconds))
  const days = Math.floor(total / 86400)
  const hours = Math.floor((total % 86400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const secs = total % 60

  const parts: string[] = []
  if (days) parts.push(`${toDigits(String(days), digits)}${labels.day}`)
  if (hours || days) parts.push(`${toDigits(String(hours), digits)}${labels.hour}`)
  if (!days && (minutes || hours)) parts.push(`${toDigits(String(minutes), digits)}${labels.minute}`)
  if (!days && !hours) parts.push(`${toDigits(String(secs), digits)}${labels.second}`)
  return parts.slice(0, 2).join(' ')
}

export interface DurationLabels {
  day: string
  hour: string
  minute: string
  second: string
}

export interface DateOptions {
  locale: string
  calendar: 'gregorian' | 'jalali'
  digits: 'latin' | 'persian'
  withSeconds?: boolean
}

/**
 * Renders a UTC timestamp in the viewer's timezone.
 *
 * Every timestamp the API sends is UTC; conversion happens here and only here.
 * The Jalali calendar is produced by Intl with the `islamic`-adjacent Persian
 * calendar, which every browser this panel targets supports.
 */
export function formatDateTime(iso: string | null | undefined, options: DateOptions): string {
  if (!iso) return ''
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return ''

  const locale = buildLocale(options)
  try {
    return new Intl.DateTimeFormat(locale, {
      dateStyle: 'medium',
      timeStyle: options.withSeconds ? 'medium' : 'short',
    }).format(date)
  } catch {
    return date.toISOString()
  }
}

export function formatTime(iso: string | null | undefined, options: DateOptions): string {
  if (!iso) return ''
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return ''
  try {
    return new Intl.DateTimeFormat(buildLocale(options), {
      timeStyle: options.withSeconds ? 'medium' : 'short',
    }).format(date)
  } catch {
    return date.toISOString()
  }
}

function buildLocale(options: DateOptions): string {
  const calendar = options.calendar === 'jalali' ? 'persian' : 'gregory'
  const numbering = options.digits === 'persian' ? 'arabext' : 'latn'
  return `${options.locale}-u-ca-${calendar}-nu-${numbering}`
}

/** How long ago, in words, for an event timeline. */
export function formatRelative(iso: string | null | undefined, locale: string): string {
  if (!iso) return ''
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return ''
  const seconds = Math.round((then - Date.now()) / 1000)

  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['second', 60],
    ['minute', 60],
    ['hour', 24],
    ['day', 7],
    ['week', 4.348],
    ['month', 12],
    ['year', Number.POSITIVE_INFINITY],
  ]

  let value = seconds
  for (const [unit, size] of units) {
    if (Math.abs(value) < size) {
      try {
        return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(Math.round(value), unit)
      } catch {
        return iso
      }
    }
    value /= size
  }
  return iso
}

/** An integer for display, with grouping and the preferred digits. */
export function formatCount(value: number, digits: 'latin' | 'persian', locale = 'en'): string {
  try {
    return toDigits(new Intl.NumberFormat(locale === 'fa' ? 'en' : locale).format(value), digits)
  } catch {
    return toDigits(String(value), digits)
  }
}

// ------------------------------------------------------------------- naming

/**
 * The two names a tunnel carries. The interface name is what the kernel calls
 * it and is always present; the display name is what the operator called it and
 * is optional.
 */
export interface NamedTunnel {
  interface_name: string
  display_name?: string | null
}

/**
 * What a tunnel is called in the panel: its display name when it has one, its
 * interface name otherwise.
 *
 * The rule is one-way and applies everywhere a tunnel is named — a row, a menu,
 * a toast, a page title. An operator who named a tunnel "Frankfurt ↔ Singapore"
 * should never have to recognise it as `gre-a-1`. The interface name still
 * appears wherever it is the subject rather than the label: the identity line
 * under the heading, the field on the detail page, the typed delete
 * confirmation.
 */
export function tunnelLabel(tunnel: NamedTunnel): string {
  return tunnel.display_name?.trim() || tunnel.interface_name
}

/**
 * Whether {@link tunnelLabel} would return a display name. Call sites use it to
 * decide the typography: an interface name is a technical value and goes
 * through `Technical`, a display name is prose and does not.
 */
export function hasDisplayName(tunnel: NamedTunnel): boolean {
  return Boolean(tunnel.display_name?.trim())
}
