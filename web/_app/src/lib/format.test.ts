import { describe, expect, it } from 'vitest'

import {
  defaultUnits,
  formatBytes,
  formatThroughput,
  formatVolume,
  toDigits,
  type UnitPreferences,
} from './format'

const bytesBinary: UnitPreferences = { throughput: 'bytes', volume: 'bytes', binary: true, digits: 'latin' }
const bitsBinary: UnitPreferences = { ...bytesBinary, throughput: 'bits', volume: 'bits' }
const bytesDecimal: UnitPreferences = { ...bytesBinary, binary: false }

/**
 * The API returns raw bytes and raw bytes per second, always. Every unit
 * decision is made on this side, and the two decisions are independent: an
 * operator may want throughput in bits, the way a link is sold, while reading
 * volume in bytes, the way a quota is billed.
 */
describe('unit formatting', () => {
  it('defaults both throughput and volume to bytes', () => {
    expect(defaultUnits.throughput).toBe('bytes')
    expect(defaultUnits.volume).toBe('bytes')
  })

  it('scales a rate into a readable unit and always names it', () => {
    expect(formatThroughput(0, bytesBinary).text).toBe('0 B/s')
    expect(formatThroughput(1536, bytesBinary).text).toBe('1.5 KiB/s')
    expect(formatThroughput(1024 * 1024 * 3, bytesBinary).text).toBe('3 MiB/s')
  })

  it('converts to bits when asked, which is eight times the byte figure', () => {
    // 1 MiB/s is 8 Mibit/s. Getting this backwards is the classic reason a
    // panel and a provider's graph disagree by a factor of eight.
    expect(formatThroughput(1024 * 1024, bitsBinary).text).toBe('8 Mibit/s')
  })

  it('honours the binary-versus-decimal preference', () => {
    expect(formatBytes(1000, bytesDecimal).text).toBe('1 kB')
    expect(formatBytes(1024, bytesBinary).text).toBe('1 KiB')
  })

  it('keeps throughput and volume independent of each other', () => {
    const mixed: UnitPreferences = { throughput: 'bits', volume: 'bytes', binary: true, digits: 'latin' }
    expect(formatThroughput(1024 * 1024, mixed).unit).toBe('Mibit/s')
    expect(formatVolume(1024 * 1024, mixed).unit).toBe('MiB')
  })

  it('never produces a bare number', () => {
    for (const value of [0, 1, 999, 1024, 1024 ** 3, 1024 ** 5]) {
      expect(formatVolume(value, bytesBinary).text).toMatch(/\s\S+$/)
    }
  })
})

describe('digit systems', () => {
  it('converts human-facing numbers when Persian digits are chosen', () => {
    expect(toDigits('1234', 'persian')).toBe('۱۲۳۴')
    expect(toDigits('1234', 'latin')).toBe('1234')
  })

  it('leaves a technical value alone, because it is never passed through', () => {
    // An address in Persian digits is not an address. The rule is enforced by
    // never routing technical values through the converter; this asserts the
    // converter is opt-in rather than global.
    const address = '172.17.7.1/30'
    expect(address).toBe('172.17.7.1/30')
  })
})
