import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { ChevronDown, Cpu, HardDrive, Info, MemoryStick, Layers } from 'lucide-react'

import type { CpuUsage, Disk, MetricsSnapshot } from '@/lib/types'
import { formatBytes, formatCount, formatPercent } from '@/lib/format'
import { usePreferences } from '@/providers/PreferencesProvider'
import { cn } from '@/lib/utils'
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card'
import { Meter } from '../ui/feedback'
import { Sparkline } from '../ui/sparkline'
import { Tooltip } from '../ui/overlay'
import { Technical } from '../ui/technical'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '../ui/disclosure'

function overallCpu(snapshot: MetricsSnapshot): CpuUsage | undefined {
  return snapshot.cpu.find((entry) => entry.name === 'cpu') ?? snapshot.cpu[0]
}

function perCore(snapshot: MetricsSnapshot): CpuUsage[] {
  return (snapshot.cpu ?? []).filter((entry) => entry.name !== 'cpu')
}

/** Utilisation drives the accent through neutral, warning and critical. */
function utilisationTone(percent: number, warn = 75, critical = 90): 'accent' | 'warn' | 'danger' {
  if (percent >= critical) return 'danger'
  if (percent >= warn) return 'warn'
  return 'accent'
}

export function CpuCard({ snapshot, history }: { snapshot: MetricsSnapshot; history: number[] }) {
  const { t } = useTranslation()
  const { digits, language } = usePreferences()
  const [expanded, setExpanded] = useState(false)

  const overall = overallCpu(snapshot)
  const cores = perCore(snapshot)
  const usage = overall?.usage_percent ?? 0

  return (
    <Card>
      <CardHeader className="border-b-0 pb-0">
        <CardTitle className="flex items-center gap-2">
          <Cpu className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('dashboard.cpu.title')}
        </CardTitle>
        <span className="readout text-2xl">{formatPercent(usage, digits)}</span>
      </CardHeader>
      <CardContent className="space-y-3 pt-3">
        <Meter value={usage} tone={utilisationTone(usage)} label={t('dashboard.cpu.usage')} />
        <Sparkline values={history} tone={utilisationTone(usage)} max={100} />

        <dl className="grid grid-cols-3 gap-2 text-xs">
          {(
            [
              ['dashboard.cpu.load1', snapshot.load.one],
              ['dashboard.cpu.load5', snapshot.load.five],
              ['dashboard.cpu.load15', snapshot.load.fifteen],
            ] as const
          ).map(([key, value]) => (
            <div key={key}>
              <dt className="text-muted-foreground">{t(key)}</dt>
              <dd className="tabular font-medium">{formatCount(Math.round(value * 100) / 100, digits, language)}</dd>
            </div>
          ))}
        </dl>

        <Collapsible open={expanded} onOpenChange={setExpanded}>
          <CollapsibleTrigger className="group flex w-full items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
            <ChevronDown
              className="size-3.5 transition-transform duration-250 group-data-[state=open]:rotate-180"
              aria-hidden="true"
            />
            {expanded ? t('actions.showLess') : t('dashboard.cpu.cores')}
          </CollapsibleTrigger>
          <CollapsibleContent className="space-y-3 pt-3">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <Stat label={t('dashboard.cpu.user')} value={formatPercent(overall?.user_percent ?? 0, digits)} />
              <Stat label={t('dashboard.cpu.system')} value={formatPercent(overall?.system_percent ?? 0, digits)} />
              <Stat label={t('dashboard.cpu.iowait')} value={formatPercent(overall?.iowait_percent ?? 0, digits)} />
              <Stat
                label={t('dashboard.cpu.steal')}
                value={formatPercent(overall?.steal_percent ?? 0, digits)}
                hint={t('dashboard.cpu.stealHint')}
                // Steal is the figure that explains slowness nothing else
                // accounts for, so it is called out rather than buried.
                emphasise={(overall?.steal_percent ?? 0) > 1}
              />
            </dl>

            {cores.length ? (
              <ul className="space-y-1.5">
                {cores.map((core) => (
                  <li key={core.name} className="flex items-center gap-2">
                    <Technical className="w-12 shrink-0 text-2xs text-muted-foreground">{core.name}</Technical>
                    <Meter value={core.usage_percent} tone={utilisationTone(core.usage_percent)} className="flex-1" />
                    <span className="tabular w-10 shrink-0 text-end text-2xs">
                      {formatPercent(core.usage_percent, digits, 0)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : null}

            <p className="text-2xs text-muted-foreground">
              {t('dashboard.cpu.processes', {
                running: formatCount(snapshot.load.running_entities, digits, language),
                total: formatCount(snapshot.load.total_entities, digits, language),
              })}
            </p>
          </CollapsibleContent>
        </Collapsible>
      </CardContent>
    </Card>
  )
}

export function MemoryCard({ snapshot, history }: { snapshot: MetricsSnapshot; history: number[] }) {
  const { t } = useTranslation()
  const { digits, units } = usePreferences()
  const [expanded, setExpanded] = useState(false)

  const memory = snapshot.memory
  const percent = memory.used_percent

  return (
    <Card>
      <CardHeader className="border-b-0 pb-0">
        <CardTitle className="flex items-center gap-2">
          <MemoryStick className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('dashboard.memory.title')}
        </CardTitle>
        <span className="readout text-2xl">{formatPercent(percent, digits)}</span>
      </CardHeader>
      <CardContent className="space-y-3 pt-3">
        <Meter value={percent} tone={utilisationTone(percent, 80, 92)} label={t('dashboard.memory.used')} />
        <Sparkline values={history} tone={utilisationTone(percent, 80, 92)} max={100} />

        <dl className="grid grid-cols-2 gap-2 text-xs">
          <Stat label={t('dashboard.memory.used')} value={formatBytes(memory.used_bytes, units).text} />
          <Stat
            label={t('dashboard.memory.available')}
            value={formatBytes(memory.available_bytes, units).text}
            hint={t('dashboard.memory.availableHint')}
          />
        </dl>

        <Collapsible open={expanded} onOpenChange={setExpanded}>
          <CollapsibleTrigger className="group flex w-full items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
            <ChevronDown
              className="size-3.5 transition-transform duration-250 group-data-[state=open]:rotate-180"
              aria-hidden="true"
            />
            {expanded ? t('actions.showLess') : t('actions.showMore')}
          </CollapsibleTrigger>
          <CollapsibleContent className="pt-3">
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <Stat label={t('dashboard.memory.total')} value={formatBytes(memory.total_bytes, units).text} />
              <Stat label={t('dashboard.memory.free')} value={formatBytes(memory.free_bytes, units).text} />
              <Stat label={t('dashboard.memory.buffers')} value={formatBytes(memory.buffers_bytes, units).text} />
              <Stat label={t('dashboard.memory.cached')} value={formatBytes(memory.cached_bytes, units).text} />
            </dl>
          </CollapsibleContent>
        </Collapsible>
      </CardContent>
    </Card>
  )
}

export function SwapCard({ snapshot }: { snapshot: MetricsSnapshot }) {
  const { t } = useTranslation()
  const { digits, units } = usePreferences()
  const swap = snapshot.swap

  // No swap is a valid configuration, not a broken card: it is stated plainly
  // and de-emphasised rather than drawn as an empty gauge.
  if (!swap.configured || swap.total_bytes === 0) {
    return (
      <Card className="opacity-70">
        <CardHeader className="border-b-0 pb-0">
          <CardTitle className="flex items-center gap-2">
            <Layers className="size-4 text-muted-foreground" aria-hidden="true" />
            {t('dashboard.swap.title')}
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-3">
          <p className="text-sm text-muted-foreground">{t('dashboard.swap.notConfigured')}</p>
          <p className="mt-1 text-xs text-muted-foreground">{t('dashboard.swap.notConfiguredHint')}</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="border-b-0 pb-0">
        <CardTitle className="flex items-center gap-2">
          <Layers className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('dashboard.swap.title')}
        </CardTitle>
        <span className="readout text-2xl">{formatPercent(swap.used_percent, digits)}</span>
      </CardHeader>
      <CardContent className="space-y-3 pt-3">
        <Meter
          value={swap.used_percent}
          tone={utilisationTone(swap.used_percent, 50, 80)}
          label={t('dashboard.swap.used')}
        />
        <dl className="grid grid-cols-2 gap-2 text-xs">
          <Stat label={t('dashboard.swap.used')} value={formatBytes(swap.used_bytes, units).text} />
          <Stat label={t('dashboard.memory.total')} value={formatBytes(swap.total_bytes, units).text} />
        </dl>
      </CardContent>
    </Card>
  )
}

export function DiskCard({
  snapshot,
  warnPercent,
  criticalPercent,
}: {
  snapshot: MetricsSnapshot
  warnPercent: number
  criticalPercent: number
}) {
  const { t } = useTranslation()
  const { digits, units } = usePreferences()
  const [showPseudo, setShowPseudo] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)

  const disks = (snapshot.disks ?? []).filter((disk) => showPseudo || !disk.is_pseudo)

  return (
    <Card>
      <CardHeader className="border-b-0 pb-0">
        <CardTitle className="flex items-center gap-2">
          <HardDrive className="size-4 text-muted-foreground" aria-hidden="true" />
          {t('dashboard.disk.title')}
        </CardTitle>
        <button
          type="button"
          onClick={() => setShowPseudo((v) => !v)}
          className="text-2xs text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
        >
          {showPseudo ? t('dashboard.disk.hidePseudo') : t('dashboard.disk.showPseudo')}
        </button>
      </CardHeader>
      <CardContent className="space-y-3 pt-3">
        {disks.map((disk) => (
          <DiskRow
            key={disk.mount_point}
            disk={disk}
            expanded={expanded === disk.mount_point}
            onToggle={() => setExpanded((current) => (current === disk.mount_point ? null : disk.mount_point))}
            warnPercent={warnPercent}
            criticalPercent={criticalPercent}
            digits={digits}
            unitsText={(value: number) => formatBytes(value, units).text}
            t={t}
          />
        ))}
        {!disks.length ? <p className="text-xs text-muted-foreground">{t('states.empty')}</p> : null}
      </CardContent>
    </Card>
  )
}

function DiskRow({
  disk,
  expanded,
  onToggle,
  warnPercent,
  criticalPercent,
  digits,
  unitsText,
  t,
}: {
  disk: Disk
  expanded: boolean
  onToggle: () => void
  warnPercent: number
  criticalPercent: number
  digits: 'latin' | 'persian'
  unitsText: (value: number) => string
  t: (key: string, options?: Record<string, unknown>) => string
}) {
  const tone = utilisationTone(disk.used_percent, warnPercent, criticalPercent)

  return (
    <div className="space-y-1.5">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between gap-2 text-start"
        aria-expanded={expanded}
      >
        <Technical className="truncate text-xs">{disk.mount_point}</Technical>
        <span className="flex shrink-0 items-center gap-2 text-2xs text-muted-foreground">
          <span className="tabular">
            {unitsText(disk.used_bytes)} / {unitsText(disk.total_bytes)}
          </span>
          <span className={cn('tabular font-medium', tone === 'warn' && 'text-warn', tone === 'danger' && 'text-danger')}>
            {formatPercent(disk.used_percent, digits, 0)}
          </span>
        </span>
      </button>
      <Meter value={disk.used_percent} tone={tone} label={disk.mount_point} />
      {tone !== 'accent' ? (
        <p className={cn('text-2xs', tone === 'warn' ? 'text-warn' : 'text-danger')}>
          {tone === 'warn' ? t('dashboard.disk.nearingWarn') : t('dashboard.disk.nearingCritical')}
        </p>
      ) : null}
      {expanded ? (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-1 rounded-md bg-surface-sunken p-2 text-2xs">
          <Stat label={t('dashboard.disk.device')} value={<Technical>{disk.device}</Technical>} />
          <Stat label={t('dashboard.disk.filesystem')} value={<Technical>{disk.fs_type}</Technical>} />
          <Stat label={t('dashboard.disk.available')} value={unitsText(disk.available_bytes)} />
          <Stat
            label={t('dashboard.disk.inodes')}
            value={formatPercent(disk.inodes_used_percent, digits, 0)}
          />
        </dl>
      ) : null}
    </div>
  )
}

function Stat({
  label,
  value,
  hint,
  emphasise,
}: {
  label: React.ReactNode
  value: React.ReactNode
  hint?: string
  emphasise?: boolean
}) {
  return (
    <div>
      <dt className="flex items-center gap-1 text-muted-foreground">
        {label}
        {hint ? (
          <Tooltip content={hint}>
            <button type="button" className="text-muted-foreground hover:text-foreground" aria-label={hint}>
              <Info className="size-3" aria-hidden="true" />
            </button>
          </Tooltip>
        ) : null}
      </dt>
      <dd className={cn('tabular font-medium', emphasise && 'text-warn')}>{value}</dd>
    </div>
  )
}
