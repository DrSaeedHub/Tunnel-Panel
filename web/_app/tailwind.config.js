/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class', '[data-theme="dark"]'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Every colour is a CSS variable so the two themes are one set of
        // tokens rather than two sets of classes.
        border: 'hsl(var(--border) / <alpha-value>)',
        input: 'hsl(var(--input) / <alpha-value>)',
        ring: 'hsl(var(--ring) / <alpha-value>)',
        background: 'hsl(var(--background) / <alpha-value>)',
        foreground: 'hsl(var(--foreground) / <alpha-value>)',
        // The content plate the pages sit on, one step lighter than the canvas.
        plate: 'hsl(var(--plate) / <alpha-value>)',
        surface: {
          DEFAULT: 'hsl(var(--surface) / <alpha-value>)',
          raised: 'hsl(var(--surface-raised) / <alpha-value>)',
          sunken: 'hsl(var(--surface-sunken) / <alpha-value>)',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted) / <alpha-value>)',
          foreground: 'hsl(var(--muted-foreground) / <alpha-value>)',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent) / <alpha-value>)',
          foreground: 'hsl(var(--accent-foreground) / <alpha-value>)',
          muted: 'hsl(var(--accent-muted) / <alpha-value>)',
        },
        // The inverted instrument slab (near-black by day, paper by night).
        ink: {
          DEFAULT: 'hsl(var(--ink) / <alpha-value>)',
          foreground: 'hsl(var(--ink-foreground) / <alpha-value>)',
          muted: 'hsl(var(--ink-muted) / <alpha-value>)',
        },
        // Semantic status colours. Reserved strictly for state, never used
        // decoratively, and never the only signal.
        ok: {
          DEFAULT: 'hsl(var(--ok) / <alpha-value>)',
          foreground: 'hsl(var(--ok-foreground) / <alpha-value>)',
          muted: 'hsl(var(--ok-muted) / <alpha-value>)',
        },
        warn: {
          DEFAULT: 'hsl(var(--warn) / <alpha-value>)',
          foreground: 'hsl(var(--warn-foreground) / <alpha-value>)',
          muted: 'hsl(var(--warn-muted) / <alpha-value>)',
        },
        danger: {
          DEFAULT: 'hsl(var(--danger) / <alpha-value>)',
          foreground: 'hsl(var(--danger-foreground) / <alpha-value>)',
          muted: 'hsl(var(--danger-muted) / <alpha-value>)',
        },
        neutral: {
          DEFAULT: 'hsl(var(--neutral) / <alpha-value>)',
          foreground: 'hsl(var(--neutral-foreground) / <alpha-value>)',
          muted: 'hsl(var(--neutral-muted) / <alpha-value>)',
        },
      },
      borderRadius: {
        xl: 'calc(var(--radius) + 0.25rem)',
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 6px)',
        sm: 'calc(var(--radius) - 10px)',
      },
      boxShadow: {
        card: 'var(--shadow-card)',
        slab: 'var(--shadow-slab)',
        pop: 'var(--shadow-pop)',
      },
      fontFamily: {
        sans: ['var(--font-ui)', 'system-ui', 'sans-serif'],
        display: ['var(--font-display)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'scale-in': {
          from: { opacity: '0', transform: 'scale(0.97)' },
          to: { opacity: '1', transform: 'scale(1)' },
        },
        // Dialogs are centred with translate(-50%,-50%); a scale keyframe that
        // omits the translate overwrites it mid-animation, so the dialog
        // appeared at the corner and then snapped to centre. The translate has
        // to live inside the keyframe.
        'dialog-in': {
          from: { opacity: '0', transform: 'translate(-50%, -50%) scale(0.97)' },
          to: { opacity: '1', transform: 'translate(-50%, -50%) scale(1)' },
        },
        'slide-in': {
          from: { opacity: '0', transform: 'translateY(-0.35rem)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: { '100%': { transform: 'translateX(100%)' } },
        // A single highlight that resolves, never a loop: a steady state must
        // not animate.
        'pulse-once': {
          '0%': { backgroundColor: 'hsl(var(--accent) / 0.16)' },
          '100%': { backgroundColor: 'transparent' },
        },
      },
      animation: {
        'fade-in': 'fade-in 150ms ease-out',
        'scale-in': 'scale-in 150ms ease-out',
        'dialog-in': 'dialog-in 150ms ease-out',
        'slide-in': 'slide-in 250ms ease-out',
        shimmer: 'shimmer 1.6s infinite',
        'pulse-once': 'pulse-once 900ms ease-out 1',
      },
    },
  },
  plugins: [],
}
