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

/**
 * Isolates a sentence the backend wrote where it is interpolated into one of
 * this interface's own: the string-level form of `<bdi>`. Between U+2068 FIRST
 * STRONG ISOLATE and U+2069 POP DIRECTIONAL ISOLATE the text takes the
 * direction of its own first strong character, so a Farsi reason inside an
 * English line, or an English one inside a Farsi line, keeps its word order and
 * leaves the words around it in theirs.
 */
export function isolateText(value: unknown): string {
  return `⁨${String(value ?? '')}⁩`
}

/** A stable identifier for a list key when the API gives no natural one. */
export function keyOf(...parts: (string | number | null | undefined)[]) {
  return parts.filter((p) => p !== null && p !== undefined).join(':')
}
