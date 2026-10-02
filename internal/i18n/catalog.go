package i18n

import "fmt"

// farsi holds every Persian sentence, keyed by the English it replaces.
//
// It is filled from the catalog files beside this one, one per area of the
// panel (fa_route.go, fa_tunnel.go, ...), so the people working on different
// areas never edit the same file. Two files may carry the same English, since
// the same sentence can be said in two places, but only with the same Persian.
var farsi = map[string]string{}

func register(entries map[string]string) {
	for english, persian := range entries {
		if existing, ok := farsi[english]; ok && existing != persian {
			panic(fmt.Sprintf("i18n: two Persian sentences for %q: %q and %q", english, existing, persian))
		}
		farsi[english] = persian
	}
}
