import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Database, Upload } from 'lucide-react'

import { Button } from '@/components/ui/button'

/**
 * Where the restore page is announced.
 *
 * The page exists at /restore and nothing linked to it, so the only way to
 * reach it was to already know it was there — and the panel is served under a
 * secret prefix, so it is not a URL anyone could guess. A feature nobody can
 * find is a feature nobody has.
 *
 * Downloading is deliberately not a button here. The link it produces carries
 * every password hash in the database, and issuing one needs the CLI, where the
 * operator is already root on the box and the warning has somewhere to sit.
 */
export function DatabaseSection() {
  const { t } = useTranslation()

  return (
    <section id="settings-database" className="rounded-lg border p-6">
      <div className="mb-4 flex items-start gap-3">
        <Database className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
        <div>
          <h2 className="display text-lg font-bold">
            {t('settings.database.title', { defaultValue: 'Database' })}
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {t('settings.database.description', {
              defaultValue:
                'Everything this panel knows — accounts, tunnels, forwarding rules and where it serves — lives in one file.',
            })}
          </p>
        </div>
      </div>

      <div className="space-y-4 text-sm">
        <div>
          <h3 className="font-medium">
            {t('settings.database.restoreTitle', { defaultValue: 'Restore from a file' })}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {t('settings.database.restoreBody', {
              defaultValue:
                'Upload a .db file from your computer. Its tunnels and forwarding rules are applied to this server once the panel restarts, and you will be signed out.',
            })}
          </p>
          <Button asChild variant="secondary" className="mt-3">
            <Link to="/restore">
              <Upload className="size-4" aria-hidden />
              {t('settings.database.restoreAction', { defaultValue: 'Open the restore page' })}
            </Link>
          </Button>
        </div>

        <div>
          <h3 className="font-medium">
            {t('settings.database.downloadTitle', { defaultValue: 'Download a copy' })}
          </h3>
          <p className="mt-1 text-muted-foreground">
            {t('settings.database.downloadBody', {
              defaultValue:
                'Run tnp backup on the server. It prints a link that works for 15 minutes. The file contains every password hash, so the link is deliberately short-lived and is issued from the server rather than from here.',
            })}
          </p>
          <code dir="ltr" className="technical mt-2 inline-block rounded bg-muted px-2 py-1 text-xs">
            tnp backup
          </code>
        </div>
      </div>
    </section>
  )
}
