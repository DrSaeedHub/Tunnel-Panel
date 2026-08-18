import { forwardRef } from 'react'
import { Slot } from '@radix-ui/react-slot'
import { cva, type VariantProps } from 'class-variance-authority'
import { Loader2 } from 'lucide-react'

import { cn } from '@/lib/utils'

const buttonVariants = cva(
  // Pills, pressed like keys: the only transform is a 1px settle on :active,
  // and colour carries every other state.
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-sm font-medium transition-[background-color,border-color,color,transform] duration-150 active:translate-y-px focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        // The primary action wears the ink slab: near-black by day, paper by
        // night. The accent stays reserved for selection and links.
        primary: 'bg-ink text-ink-foreground shadow-sm hover:bg-ink/90',
        secondary: 'border border-border bg-surface shadow-sm hover:bg-muted',
        ghost: 'hover:bg-muted',
        // Destructive is visually distinct from every reversible action, so
        // delete never reads like disable.
        danger: 'bg-danger text-danger-foreground shadow-sm hover:bg-danger/90',
        dangerOutline: 'border border-danger/50 text-danger hover:bg-danger-muted',
        link: 'text-accent underline-offset-4 hover:underline',
      },
      size: {
        sm: 'h-8 px-3.5 text-xs',
        // md matches the input height, so a field and its button sit flush.
        md: 'h-10 px-5',
        lg: 'h-11 px-6',
        icon: 'size-9 p-0',
        iconSm: 'size-7 p-0',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
)

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean
  /** Shows a spinner and blocks interaction; a submitting form never double-fires. */
  loading?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, loading = false, disabled, children, ...props }, ref) => {
    const shared = {
      ref,
      className: cn(buttonVariants({ variant, size }), className),
      'aria-busy': loading || undefined,
      ...props,
    }

    // Slot merges these props onto the caller's own element, and it accepts
    // exactly one React element child. Adding a spinner beside that child makes
    // two, which throws and takes the whole page down with it -- so a button
    // rendered as something else keeps its child untouched. `disabled` is left
    // off too: the child may be an anchor, which has no such attribute.
    if (asChild) {
      return <Slot {...shared}>{children}</Slot>
    }

    return (
      <button {...shared} disabled={disabled || loading}>
        {loading ? <Loader2 className="size-4 animate-spin" aria-hidden="true" /> : null}
        {children}
      </button>
    )
  },
)
Button.displayName = 'Button'

export { buttonVariants }
