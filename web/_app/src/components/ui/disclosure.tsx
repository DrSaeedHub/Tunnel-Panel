import { forwardRef } from 'react'
import * as CollapsiblePrimitive from '@radix-ui/react-collapsible'
import * as TabsPrimitive from '@radix-ui/react-tabs'
import { ChevronDown } from 'lucide-react'

import { cn } from '@/lib/utils'

export const Collapsible = CollapsiblePrimitive.Root
export const CollapsibleTrigger = CollapsiblePrimitive.Trigger
export const CollapsibleContent = CollapsiblePrimitive.Content

/**
 * A titled disclosure panel with a chevron that rotates as it opens.
 *
 * The chevron points down when closed in both directions — it indicates
 * vertical movement, not reading order, so it is not one of the icons that
 * mirrors under RTL.
 */
export function DisclosurePanel({
  title,
  description,
  children,
  defaultOpen = false,
  open,
  onOpenChange,
  aside,
  className,
  contentClassName,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  children: React.ReactNode
  defaultOpen?: boolean
  open?: boolean
  onOpenChange?: (open: boolean) => void
  aside?: React.ReactNode
  className?: string
  contentClassName?: string
}) {
  return (
    <Collapsible
      defaultOpen={defaultOpen}
      open={open}
      onOpenChange={onOpenChange}
      className={cn('card-surface overflow-hidden', className)}
    >
      <div className="flex items-center justify-between gap-2 p-[var(--card-padding)]">
        <CollapsibleTrigger className="group flex min-w-0 flex-1 items-center gap-2 text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded-md">
          <ChevronDown
            className="size-4 shrink-0 text-muted-foreground transition-transform duration-250 group-data-[state=closed]:-rotate-90 rtl:group-data-[state=closed]:rotate-90"
            aria-hidden="true"
          />
          <span className="min-w-0">
            <span className="block truncate text-sm font-medium">{title}</span>
            {description ? (
              <span className="block truncate text-xs text-muted-foreground">{description}</span>
            ) : null}
          </span>
        </CollapsibleTrigger>
        {aside}
      </div>
      <CollapsibleContent
        className={cn('overflow-hidden border-t border-border p-[var(--card-padding)]', contentClassName)}
      >
        {children}
      </CollapsibleContent>
    </Collapsible>
  )
}

export const Tabs = TabsPrimitive.Root

export const TabsList = forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.List
    ref={ref}
    className={cn(
      'inline-flex items-center gap-1 overflow-x-auto rounded-full border border-border/60 bg-surface-sunken p-1 scrollbar-thin',
      className,
    )}
    {...props}
  />
))
TabsList.displayName = 'TabsList'

export const TabsTrigger = forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      // The active tab wears the ink pill — the segmented control from the
      // instrument voice, not a faint background swap.
      'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-3.5 py-1.5 text-sm font-medium text-muted-foreground transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring data-[state=active]:bg-ink data-[state=active]:text-ink-foreground data-[state=active]:shadow-sm',
      className,
    )}
    {...props}
  />
))
TabsTrigger.displayName = 'TabsTrigger'

export const TabsContent = forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn('mt-4 focus-visible:outline-none', className)}
    {...props}
  />
))
TabsContent.displayName = 'TabsContent'
