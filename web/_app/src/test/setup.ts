import '@testing-library/jest-dom/vitest'

// Components under test call `useTranslation`, so i18next has to be initialised
// before any of them render. Importing the real configuration keeps the tests
// honest: a missing key shows up as the key itself rather than as a stub.
import '@/i18n'

// jsdom implements no scrolling at all, so any component that keeps a view
// pinned to its newest line -- the streaming probe output does -- throws during
// its effect and takes the whole render down with it. Stubbing it here rather
// than making the component defensive keeps the gap where it belongs: in the
// environment, not in the product.
if (typeof Element !== 'undefined' && !Element.prototype.scrollTo) {
  Element.prototype.scrollTo = () => {}
}
