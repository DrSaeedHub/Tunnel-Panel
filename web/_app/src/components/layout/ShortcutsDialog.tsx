import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

import { Dialog, DialogBody, DialogContent, DialogHeader, DialogTitle } from '../ui/overlay'

const SHORTCUTS = [
  { keys: ['/'], labelKey: 'shortcuts.search' },
  { keys: ['c'], labelKey: 'shortcuts.create' },
  { keys: ['g', 'd'], labelKey: 'shortcuts.dashboard' },
  { keys: ['g', 't'], labelKey: 'shortcuts.tunnels' },
  { keys: ['g', 's'], labelKey: 'shortcuts.settings' },
  { keys: ['?'], labelKey: 'shortcuts.help' },
  { keys: ['Esc'], labelKey: 'shortcuts.close' },
]

/**
 * Global keyboard shortcuts.
 *
 * They are ignored while the operator is typing, so `c` in a search box does
 * not open the create form, and they are discoverable through the overlay
 * rather than being folklore.
 */
export function useShortcuts({ onShowShortcuts }: { onShowShortcuts: () => void }) {
  const navigate = useNavigate()

  useEffect(() => {
    let pendingG = false
    let pendingTimer: number | undefined

    const isTyping = (target: EventTarget | null) => {
      const element = target as HTMLElement | null
      if (!element) return false
      const tag = element.tagName
      return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || element.isContentEditable
    }

    const handler = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return
      if (isTyping(event.target)) return

      if (pendingG) {
        pendingG = false
        if (pendingTimer) window.clearTimeout(pendingTimer)
        if (event.key === 'd') {
          event.preventDefault()
          navigate('/')
          return
        }
        if (event.key === 't') {
          event.preventDefault()
          navigate('/tunnels')
          return
        }
        if (event.key === 's') {
          event.preventDefault()
          navigate('/settings')
          return
        }
      }

      switch (event.key) {
        case 'g':
          pendingG = true
          pendingTimer = window.setTimeout(() => {
            pendingG = false
          }, 1200)
          break
        case '/': {
          const search = document.querySelector<HTMLInputElement>('[data-shortcut="search"]')
          if (search) {
            event.preventDefault()
            search.focus()
            search.select()
          }
          break
        }
        case 'c': {
          const create = document.querySelector<HTMLElement>('[data-shortcut="create"]')
          if (create) {
            event.preventDefault()
            create.click()
          }
          break
        }
        case '?':
          event.preventDefault()
          onShowShortcuts()
          break
        default:
          break
      }
    }

    window.addEventListener('keydown', handler)
    return () => {
      window.removeEventListener('keydown', handler)
      if (pendingTimer) window.clearTimeout(pendingTimer)
    }
  }, [navigate, onShowShortcuts])
}

export function ShortcutsDialog({
  open,
  onOpenChange,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const { t } = useTranslation()

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('shortcuts.title')}</DialogTitle>
        </DialogHeader>
        <DialogBody>
          <dl className="space-y-2">
            {SHORTCUTS.map((shortcut) => (
              <div key={shortcut.labelKey} className="flex items-center justify-between gap-4">
                <dt className="text-sm text-muted-foreground">{t(shortcut.labelKey)}</dt>
                <dd className="flex shrink-0 gap-1">
                  {shortcut.keys.map((key) => (
                    <kbd
                      key={key}
                      dir="ltr"
                      className="technical rounded border border-border bg-muted px-1.5 py-0.5 text-2xs"
                    >
                      {key}
                    </kbd>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
