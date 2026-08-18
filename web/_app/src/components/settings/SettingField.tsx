import type { TFunction } from 'i18next'
import { useTranslation } from 'react-i18next'
import { RotateCcw } from 'lucide-react'

import type { SettingSchemaEntry } from '@/lib/types'
import { Badge } from '../ui/feedback'
import { Field, Input, Select, Switch, TechnicalInput, Textarea } from '../ui/form'
import { Tooltip } from '../ui/overlay'

/**
 * One setting, rendered from its schema entry.
 *
 * The control is chosen from the declared type, the constraints become the
 * input's bounds, and the description and default come from the backend. A
 * setting added to the backend appears here with no frontend change at all,
 * which is the point: the field list is never hand-written.
 */
export function SettingField({
  entry,
  value,
  onChange,
  error,
  dirty,
}: {
  entry: SettingSchemaEntry
  value: unknown
  onChange: (value: unknown) => void
  error?: string
  dirty: boolean
}) {
  const { t } = useTranslation()
  const label = labelFor(entry.key)

  const aside = (
    <div className="flex items-center gap-1.5">
      {entry.restart_required ? (
        <Tooltip content={t('settings.restartRequired')}>
          <span>
            <Badge tone="warn">{t('settings.restartRequiredShort')}</Badge>
          </span>
        </Tooltip>
      ) : null}
      {dirty ? <Badge tone="accent">•</Badge> : null}
      <Tooltip content={t('actions.resetToDefault')}>
        <button
          type="button"
          onClick={() => onChange(entry.default)}
          className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          aria-label={t('actions.resetToDefault')}
        >
          <RotateCcw className="size-3.5" aria-hidden="true" />
        </button>
      </Tooltip>
    </div>
  )

  const description = (
    <>
      {entry.description}
      {entry.default !== null && entry.default !== undefined ? (
        <span className="block text-2xs opacity-80">
          {/*
            Through the same mapping the control uses, so the two can never
            disagree. A lookup's value is a row identifier, and printing it raw
            made four different settings each announce "Default: 10" — a number
            that means nothing on screen and is not even the same thing twice.
          */}
          {t('settings.default', { value: choiceLabel(entry, entry.default, t) })}
        </span>
      ) : null}
    </>
  )

  return (
    <Field label={label} description={description} error={error} aside={aside}>
      {(props) => {
        switch (entry.type) {
          case 'bool':
            return (
              <div className="flex h-9 items-center">
                <Switch
                  id={props.id}
                  aria-describedby={props['aria-describedby']}
                  checked={value === true}
                  onCheckedChange={(checked) => onChange(checked)}
                />
              </div>
            )

          case 'enum':
          case 'lookup':
            return (
              <Select
                id={props.id}
                value={value === null || value === undefined ? '' : String(value)}
                // The stored value is what goes back to the API — the row
                // identifier for a lookup, the wire token for an enum — however
                // it is labelled on screen.
                onValueChange={(next) => onChange(entry.type === 'lookup' ? Number(next) : next)}
                options={choicesFor(entry, t)}
              />
            )

          case 'int':
          case 'float':
            return (
              <div className="flex items-center gap-2">
                <Input
                  {...props}
                  type="number"
                  dir="ltr"
                  className="tabular text-start"
                  value={value === null || value === undefined ? '' : Number(value)}
                  min={entry.constraints.min}
                  max={entry.constraints.max}
                  step={entry.type === 'float' ? 'any' : 1}
                  onChange={(event) =>
                    onChange(event.target.value === '' ? null : Number(event.target.value))
                  }
                />
                {entry.unit ? <span className="shrink-0 text-2xs text-muted-foreground">{entry.unit}</span> : null}
              </div>
            )

          case 'json':
            return (
              <Textarea
                {...props}
                dir="ltr"
                className="technical min-h-20 text-xs"
                value={typeof value === 'string' ? value : JSON.stringify(value ?? null, null, 2)}
                onChange={(event) => {
                  try {
                    onChange(JSON.parse(event.target.value))
                  } catch {
                    // Kept as text until it parses, so typing does not fight
                    // the operator halfway through an object.
                    onChange(event.target.value)
                  }
                }}
              />
            )

          default:
            return (
              <TechnicalInput
                {...props}
                value={value === null || value === undefined ? '' : String(value)}
                onChange={(event) => onChange(event.target.value)}
              />
            )
        }
      }}
    </Field>
  )
}

/**
 * A readable label from the setting key.
 *
 * The backend sends a description but not a title, and inventing a translated
 * label per key would be exactly the hand-written list this page exists to
 * avoid, so the key's last segment is humanised.
 *
 * The raw key used to be printed beside the label for anyone matching a field
 * against the API. It is gone: a settings page is read by somebody deciding
 * what to change, and `tunnel.default_mtu` next to "Default Mtu" told them
 * nothing they could act on while making every row noisier than the one fact
 * it carries. The key is still what the search box matches, so it remains the
 * way to find a field by its API name — it simply is not printed at rest.
 */
export function labelFor(key: string): React.ReactNode {
  const [, ...rest] = key.split('.')
  const name = rest.join('.').replace(/_/g, ' ')
  return <span className="capitalize">{name}</span>
}

export function displayValue(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

/**
 * The choices a lookup or enum setting offers, as value and label.
 *
 * A lookup carries the rows of its table, resolved by the backend, so a row
 * added there needs no change here. An enum carries its own values, which are
 * wire tokens rather than prose: a locale may name one explicitly, and
 * otherwise the token is humanised. Humanising rather than keeping a list of
 * translations per value is deliberate — this page renders from the backend's
 * schema precisely so that a setting added to the backend needs no frontend
 * change, and a hand-written label per enum value would give that back.
 */
export function choicesFor(
  entry: SettingSchemaEntry,
  t: TFunction,
): { value: string; label: string }[] {
  if (entry.type === 'lookup') {
    return (entry.constraints.options ?? []).map((option) => ({
      value: String(option.value),
      label: option.label,
    }))
  }
  return (entry.constraints.enum_values ?? []).map((option) => ({
    value: option,
    label: t(`settings.enum.${entry.key}.${option}`, { defaultValue: humanise(option) }),
  }))
}

/**
 * How one value of a setting reads on screen.
 *
 * Anything that offers choices is shown by its label, so the default hint says
 * the same thing the control does. Everything else is shown as it is stored: an
 * MTU is a number and reads like one.
 */
export function choiceLabel(entry: SettingSchemaEntry, value: unknown, t: TFunction): string {
  if (entry.type !== 'lookup' && entry.type !== 'enum') {
    return displayValue(value)
  }
  const match = choicesFor(entry, t).find((choice) => choice.value === String(value))
  // No match means the schema and the value disagree, which is worth seeing
  // rather than hiding behind a blank.
  return match ? match.label : displayValue(value)
}

/** `monitor_only` reads as `Monitor only`. */
function humanise(token: string): string {
  const spaced = token.replace(/_/g, ' ')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}
