import { Languages } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { languages } from '@/i18n'
import { usePreferences } from '@/providers/PreferencesProvider'
import { cn } from '@/lib/utils'
import { Button } from '../ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '../ui/overlay'

/**
 * The language switcher, built from the language registry.
 *
 * Adding a language adds an entry here automatically — there is no list of
 * languages in this component to keep in sync.
 */
export function LanguageMenu() {
  const { t } = useTranslation()
  const { language, setLanguage } = usePreferences()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label={t('a11y.languageToggle')}>
          <Languages className="size-4" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        {languages.map((entry) => (
          <DropdownMenuItem
            key={entry.code}
            onSelect={() => setLanguage(entry.code)}
            className={cn(language === entry.code && 'bg-muted')}
          >
            {/* The name of a language is always written in that language. */}
            <span lang={entry.code} dir={entry.dir}>
              {entry.nativeName}
            </span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
