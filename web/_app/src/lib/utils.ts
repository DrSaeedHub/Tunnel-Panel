import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** Merges Tailwind classes, letting later classes win over earlier ones. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** Clamps a number into a range. */
export function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max)
}

/** A stable identifier for a list key when the API gives no natural one. */
export function keyOf(...parts: (string | number | null | undefined)[]) {
  return parts.filter((p) => p !== null && p !== undefined).join(':')
}
