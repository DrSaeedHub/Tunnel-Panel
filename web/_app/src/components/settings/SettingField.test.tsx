import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import type { ReactElement } from 'react'

import type { SettingSchemaEntry } from '@/lib/types'
import { TooltipProvider } from '@/components/ui/overlay'
import { SettingField } from './SettingField'

afterEach(cleanup)

// The field carries tooltips, which Radix requires a provider for, exactly as
// the application supplies one at its root.
function renderField(ui: ReactElement) {
  return render(<TooltipProvider>{ui}</TooltipProvider>)
}

function entry(over: Partial<SettingSchemaEntry>): SettingSchemaEntry {
  return {
    key: 'tunnel.default_type',
    type: 'lookup',
    category: 'tunnel',
    description: 'The tunnel type a new tunnel starts as.',
    default: 10,
    value: 10,
    restart_required: false,
    constraints: { nullable: false },
    ...over,
  }
}

/**
 * The default hint says the same thing the control does.
 *
 * A lookup's value is a row identifier, and the hint printed it raw. Four
 * unrelated settings - the tunnel type, the persistence method, the NAT mode
 * and the forwarding protocol - each announced "Default: 10" on the Settings
 * page, which is meaningless to an operator and not even the same thing twice.
 * The control had always resolved the label correctly; only the hint did not.
 */
describe('SettingField', () => {
  it('shows a lookup default by its label, not its row identifier', () => {
    renderField(
      <SettingField
        entry={entry({
          constraints: {
            nullable: false,
            lookup_table: 'TunnelType',
            options: [
              { value: 10, label: 'GRE' },
              { value: 20, label: 'GRETAP' },
              { value: 30, label: 'IP6GRE' },
            ],
          },
        })}
        value={10}
        onChange={() => {}}
        dirty={false}
      />,
    )

    expect(screen.getByText('Default: GRE')).toBeTruthy()
    expect(screen.queryByText('Default: 10')).toBeNull()
  })

  it('resets to the stored value rather than to the label it is shown as', () => {
    // The label is presentation. What goes back to the API is the row
    // identifier, and a reset that sent "GRE" would be rejected as a type error.
    const onChange = vi.fn()
    renderField(
      <SettingField
        entry={entry({
          default: 20,
          constraints: {
            nullable: false,
            lookup_table: 'TunnelType',
            options: [
              { value: 10, label: 'GRE' },
              { value: 20, label: 'GRETAP' },
            ],
          },
        })}
        value={10}
        onChange={onChange}
        dirty
      />,
    )

    screen.getByRole('button', { name: /reset/i }).click()
    expect(onChange).toHaveBeenCalledWith(20)
  })

  it('shows an enum default by its translation, the same way its control does', () => {
    renderField(
      <SettingField
        entry={entry({
          key: 'keepalive.mode',
          type: 'enum',
          category: 'keepalive',
          default: 'monitor_only',
          value: 'monitor_only',
          constraints: { nullable: false, enum_values: ['systemd_unit', 'monitor_only'] },
        })}
        value={'monitor_only'}
        onChange={() => {}}
        dirty={false}
      />,
    )

    // The real copy from settings.enum, not the wire token. Every enum setting
    // rendered its raw value before that block existed, so a Farsi operator was
    // choosing between "gregorian" and "jalali" in English.
    expect(screen.getByText('Default: The panel’s own prober')).toBeTruthy()
    expect(screen.queryByText('Default: monitor_only')).toBeNull()
  })

  it('humanises an enum value no locale has reached yet', () => {
    // The fallback is a safety net for a value added to the backend before its
    // label lands, not the mechanism. It must still not show a wire token: the
    // coverage test in internal/api is what stops it being relied upon.
    renderField(
      <SettingField
        entry={entry({
          key: 'imaginary.setting',
          type: 'enum',
          category: 'system',
          default: 'not_yet_translated',
          value: 'not_yet_translated',
          constraints: { nullable: false, enum_values: ['not_yet_translated', 'other'] },
        })}
        value={'not_yet_translated'}
        onChange={() => {}}
        dirty={false}
      />,
    )

    expect(screen.getByText('Default: Not yet translated')).toBeTruthy()
  })

  it('leaves a plain value alone', () => {
    renderField(
      <SettingField
        entry={entry({
          key: 'tunnel.default_mtu',
          type: 'int',
          default: 1472,
          value: 1472,
          constraints: { nullable: false, min: 576, max: 9216 },
        })}
        value={1472}
        onChange={() => {}}
        dirty={false}
      />,
    )

    expect(screen.getByText('Default: 1472')).toBeTruthy()
  })

  it('shows a value the schema does not offer rather than a blank', () => {
    // A default that no longer matches any option means the schema and the
    // stored value disagree, which is worth seeing.
    renderField(
      <SettingField
        entry={entry({
          default: 99,
          constraints: {
            nullable: false,
            lookup_table: 'TunnelType',
            options: [{ value: 10, label: 'GRE' }],
          },
        })}
        value={10}
        onChange={() => {}}
        dirty={false}
      />,
    )

    expect(screen.getByText('Default: 99')).toBeTruthy()
  })
})
