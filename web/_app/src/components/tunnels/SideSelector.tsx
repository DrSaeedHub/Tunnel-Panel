import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { Info } from 'lucide-react'

import { api } from '@/lib/api'
import type { SideInfo } from '@/lib/types'
import { cn } from '@/lib/utils'
import { Popover, PopoverContent, PopoverTrigger } from '../ui/overlay'
import { Label } from '../ui/form'
import { Skeleton } from '../ui/feedback'

/**
 * The A/B side selector.
 *
 * The explanation comes from the backend's side-info endpoint rather than from
 * copy written here. Both ends of an install then give the operator the same
 * answer, and the text stays correct if the backend's wording changes. The
 * labels for the two slots are configurable on the backend too, so they are
 * read from the same response rather than hardcoded.
 */
export function SideSelector({
  value,
  onChange,
  disabled,
}: {
  value: number
  onChange: (value: number) => void
  disabled?: boolean
}) {
  const { t } = useTranslation()

  const sideInfoQuery = useQuery({
    queryKey: ['tunnels', 'side-info'],
    queryFn: () => api.get<SideInfo>('/tunnels/side-info'),
    staleTime: 600_000,
  })

  const info = sideInfoQuery.data
  const sideIds = info?.tunnel_side_ids ?? { a: 10, b: 20 }

  const options = (info?.sides ?? [
    { slot: 'a', label: 'A', endpoints: '', address_in_subnet: '', name_substitution: '' },
    { slot: 'b', label: 'B', endpoints: '', address_in_subnet: '', name_substitution: '' },
  ]).map((side) => ({
    ...side,
    id: sideIds[side.slot] ?? (side.slot === 'a' ? 10 : 20),
  }))

  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-1.5">
        <Label>{t('tunnel.fields.side')}</Label>
        <Popover>
          <PopoverTrigger asChild>
            <button
              type="button"
              className="rounded-full p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              aria-label={t('tunnel.side.whatIsThis')}
            >
              <Info className="size-3.5" aria-hidden="true" />
            </button>
          </PopoverTrigger>
          <PopoverContent className="w-80 space-y-2">
            {sideInfoQuery.isLoading ? (
              <Skeleton className="h-16" />
            ) : info ? (
              <>
                {/* The backend's canonical text, rendered as written. */}
                <p className="whitespace-pre-line text-xs leading-relaxed">{info.summary}</p>
                <dl className="space-y-1.5 border-t border-border pt-2 text-2xs">
                  {info.sides.map((side) => (
                    <div key={side.slot}>
                      <dt className="font-medium">{side.label}</dt>
                      <dd className="text-muted-foreground">
                        {side.endpoints}
                        {side.address_in_subnet ? ` · ${side.address_in_subnet}` : ''}
                      </dd>
                    </div>
                  ))}
                </dl>
                {(info.identical_on_both_ends ?? []).length ? (
                  <div className="border-t border-border pt-2 text-2xs">
                    <p className="font-medium">{t('tunnel.side.identicalOnBoth')}</p>
                    <p className="text-muted-foreground">{info.identical_on_both_ends.join(' · ')}</p>
                  </div>
                ) : null}
              </>
            ) : (
              <p className="text-xs text-muted-foreground">{t('tunnel.side.loading')}</p>
            )}
          </PopoverContent>
        </Popover>
      </div>

      <div className="grid grid-cols-2 gap-2" role="radiogroup" aria-label={t('tunnel.fields.side')}>
        {options.map((option) => (
          <button
            key={option.slot}
            type="button"
            role="radio"
            aria-checked={value === option.id}
            disabled={disabled}
            onClick={() => onChange(option.id)}
            className={cn(
              'rounded-md border p-3 text-start transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60',
              value === option.id
                ? 'border-accent bg-accent-muted'
                : 'border-border hover:border-input hover:bg-muted',
            )}
          >
            <span className="block text-sm font-medium">{option.label}</span>
            {option.address_in_subnet ? (
              <span className="mt-0.5 block text-2xs text-muted-foreground">{option.address_in_subnet}</span>
            ) : null}
          </button>
        ))}
      </div>
    </div>
  )
}
