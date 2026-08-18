import { cn } from '@/lib/utils'

import emptyLog from '@/assets/illustrations/empty-log.png'
import emptyLogDark from '@/assets/illustrations/empty-log-dark.png'
import emptyRoutes from '@/assets/illustrations/empty-routes.png'
import emptyRoutesDark from '@/assets/illustrations/empty-routes-dark.png'
import emptySearch from '@/assets/illustrations/empty-search.png'
import emptySearchDark from '@/assets/illustrations/empty-search-dark.png'
import emptyTunnels from '@/assets/illustrations/empty-tunnels.png'
import emptyTunnelsDark from '@/assets/illustrations/empty-tunnels-dark.png'
import notFound from '@/assets/illustrations/not-found.png'
import notFoundDark from '@/assets/illustrations/not-found-dark.png'

/**
 * The drawings an empty state stands behind.
 *
 * Each one ships as a pair, because the set is line art: the day version is
 * dark ink on nothing, and on the night desk that ink would disappear into the
 * plate. The pair is one drawing rendered against both grounds rather than two
 * different pictures, so the night version is the same illustration with its
 * lightness inverted and its hues held in place -- a CSS invert() would have
 * swung the ultramarine round to orange.
 *
 * `ratio` is the drawing's own aspect, and it is what reserves the box before
 * the image decodes. Without it every empty state would jump by the height of
 * its illustration on first paint. `size` caps the width per drawing rather
 * than across the set, because these are not all the same shape: the upright
 * one would stand three times the height of the wide ones at a shared width.
 */
const ART = {
  'empty-tunnels': { light: emptyTunnels, dark: emptyTunnelsDark, ratio: 640 / 297, size: 'max-w-[17rem]' },
  'empty-routes': { light: emptyRoutes, dark: emptyRoutesDark, ratio: 640 / 270, size: 'max-w-[18rem]' },
  'empty-search': { light: emptySearch, dark: emptySearchDark, ratio: 640 / 434, size: 'max-w-[14rem]' },
  'empty-log': { light: emptyLog, dark: emptyLogDark, ratio: 457 / 640, size: 'max-w-[7rem]' },
  'not-found': { light: notFound, dark: notFoundDark, ratio: 640 / 168, size: 'max-w-[19rem]' },
} as const

export type IllustrationName = keyof typeof ART

/**
 * Purely decorative, and hidden from assistive technology on purpose.
 *
 * Every one of these drawings restates something the empty state already says
 * in words -- that there are no tunnels, that the filter matched nothing. Alt
 * text here would make a screen reader announce the same sentence twice, so
 * the picture is marked as the ornament it is, exactly like the section
 * drawing on the login page.
 *
 * The two sources hang off custom properties rather than off two <img> tags,
 * so only the variant the current theme names is ever fetched.
 */
export function Illustration({
  name,
  className,
}: {
  name: IllustrationName
  className?: string
}) {
  const art = ART[name]
  return (
    <div
      aria-hidden="true"
      className={cn('illustration w-full', art.size, className)}
      style={
        {
          aspectRatio: art.ratio,
          '--art-light': `url(${art.light})`,
          '--art-dark': `url(${art.dark})`,
        } as React.CSSProperties
      }
    />
  )
}
