import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { RotateCcw } from 'lucide-react'

import { Badge } from '../ui/feedback'
import { Field, Input, Switch } from '../ui/form'
import { Tooltip } from '../ui/overlay'

export interface InheritedFieldProps<T> {
  label: React.ReactNode
  description?: React.ReactNode
  /** The global value this field falls back to, already formatted for display. */
  inheritedDisplay: string
  /** `null` means inherit — the same thing the nullable column means. */
  value: T | null
  onChange: (value: T | null) => void
  /**
   * The value an override starts from when the operator switches it on.
   *
   * Undefined when there is nothing sensible to start from — a global setting
   * that is itself null, meaning the criterion is switched off. The override
   * then starts empty and waits for a value, rather than inventing one.
   */
  overrideDefault?: T
  error?: string
  /**
   * Set when overriding is not available, with the reason. The control still
   * shows what is inherited — which is real information — but does not offer a
   * switch that would silently do nothing.
   */
  lockedReason?: string
  children: (props: {
    value: T
    onChange: (value: T) => void
    disabled: boolean
    id: string
    'aria-describedby'?: string
  }) => React.ReactNode
}

/**
 * A per-tunnel override of a global setting.
 *
 * The backend models these as nullable columns where NULL means inherit, and
 * this control is the interaction for exactly that. It shows the inherited
 * value and where it came from, disables the input while inheriting, badges
 * the field once overridden, and offers a way back. The behaviour is identical
 * everywhere it appears, so an operator learns it once.
 */
export function InheritedField<T>({
  label,
  description,
  inheritedDisplay,
  value,
  onChange,
  overrideDefault,
  error,
  lockedReason,
  children,
}: InheritedFieldProps<T>) {
  const { t } = useTranslation()

  // An override with nothing typed into it yet is still an override. The
  // backend's nullable column has only two states — a value, or null meaning
  // inherit — so "switched on but empty" exists only here, and it has to be
  // tracked here. Without it the switch would spring back off the moment it was
  // flipped on a field with no inherited value to start from.
  const [awaitingValue, setAwaitingValue] = useState(false)
  const overridden = value !== null || awaitingValue

  const stopOverriding = () => {
    setAwaitingValue(false)
    onChange(null)
  }

  return (
    <Field
      label={label}
      description={overridden ? description : t('settings.inherited', { value: inheritedDisplay })}
      error={error}
      aside={
        <div className="flex items-center gap-2">
          {lockedReason ? (
            <Tooltip content={lockedReason}>
              <span className="cursor-help text-2xs text-muted-foreground underline decoration-dotted underline-offset-2">
                {t('settings.inheritedOnly')}
              </span>
            </Tooltip>
          ) : null}
          {overridden ? (
            <>
              <Badge tone="accent">{t('settings.overridden')}</Badge>
              <Tooltip content={t('settings.resetToInherited')}>
                <button
                  type="button"
                  onClick={stopOverriding}
                  className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  aria-label={t('settings.resetToInherited')}
                >
                  <RotateCcw className="size-3.5" aria-hidden="true" />
                </button>
              </Tooltip>
            </>
          ) : null}
          {lockedReason ? null : (
            <Tooltip content={t('settings.override')}>
              <span className="inline-flex">
                <Switch
                  checked={overridden}
                  onCheckedChange={(checked) => {
                    if (!checked) {
                      stopOverriding()
                      return
                    }
                    setAwaitingValue(true)
                    // Only seed from the inherited value. Seeding from a
                    // stand-in when there is none is how switching on a
                    // disabled latency threshold handed the operator 0 ms,
                    // which reads as "degraded whenever RTT is at least zero"
                    // and marks the tunnel Degraded for ever.
                    if (overrideDefault !== undefined) onChange(overrideDefault)
                  }}
                  aria-label={t('settings.override')}
                />
              </span>
            </Tooltip>
          )}
        </div>
      }
    >
      {(props) =>
        children({
          // Undefined rather than a stand-in when there is nothing to show, so
          // the input renders empty. It used to render 0 here even while
          // disabled and inheriting, which said the threshold was zero when the
          // description beside it correctly said there was none.
          value: (value ?? overrideDefault) as T,
          onChange: (next) => onChange(next),
          disabled: !overridden,
          id: props.id,
          'aria-describedby': props['aria-describedby'],
        })
      }
    </Field>
  )
}

/** The numeric case, which is what every monitoring override happens to be. */
export function InheritedNumberField({
  label,
  description,
  inheritedValue,
  unit,
  value,
  onChange,
  error,
  min,
  max,
  step,
  lockedReason,
}: {
  label: React.ReactNode
  description?: React.ReactNode
  inheritedValue: number | undefined
  unit?: string
  value: number | null
  onChange: (value: number | null) => void
  error?: string
  min?: number
  max?: number
  step?: number
  lockedReason?: string
}) {
  const inheritedDisplay = inheritedValue === undefined ? '—' : `${inheritedValue}${unit ? ` ${unit}` : ''}`

  return (
    <InheritedField<number>
      label={label}
      description={description}
      inheritedDisplay={inheritedDisplay}
      value={value}
      onChange={onChange}
      // Undefined, not 0, when the global setting is itself null.
      // monitor.degraded_rtt_ms is the only monitoring setting with a nil
      // default — "null disables the latency criterion" — and it is the one
      // where a zero stand-in is not neutral but the most aggressive value the
      // field can take.
      overrideDefault={inheritedValue}
      error={error}
      lockedReason={lockedReason}
    >
      {({ value: current, onChange: set, disabled, id, ...aria }) => (
        <Input
          id={id}
          {...aria}
          type="number"
          inputMode="decimal"
          dir="ltr"
          className="tabular text-start"
          value={Number.isFinite(current) ? current : ''}
          min={min}
          max={max}
          step={step}
          disabled={disabled}
          onChange={(event) => {
            const next = event.target.value === '' ? null : Number(event.target.value)
            set(next as number)
          }}
        />
      )}
    </InheritedField>
  )
}
