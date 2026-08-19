// Package sourcelist keeps the named address sets a forwarding rule allows
// traffic from.
//
// The problem it solves is repetition. A relay that should only serve one
// mobile operator needs several hundred ranges; a second relay that should
// serve the same operator needs the same several hundred. Written into each
// rule they are two copies that drift, and editing the operator's ranges means
// editing every rule that mentions them. Written once here, a rule points at
// the list and the ranges have one home.
//
// The lists are ordinary rows. The two the panel ships with are marked as
// built-in so that seeding can tell them from an operator's own, but nothing
// else treats them differently: they can be edited, added to, or deleted, and a
// deleted one is not put back on the next start.
package sourcelist

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

// MaxEntries bounds one list. It is high enough for a country's ranges and low
// enough that a mistake -- a pasted log file, a wrong URL -- is refused rather
// than stored.
const MaxEntries = 65536

// MaxNameLength bounds the name an operator gives a list.
const MaxNameLength = 60

// ParseEntries reads addresses and ranges out of whatever an operator pasted or
// uploaded.
//
// It is deliberately forgiving about the shape of the input and strict about
// the values in it. Lists come from a text box, from a file exported by some
// other tool, and from copying a page in a browser, so the separators vary and
// the comments come along for the ride. What comes out is normalised, masked
// and deduplicated, in the order it was first seen, because an operator who
// pasted a list in a deliberate order should get it back that way.
func ParseEntries(text string) ([]netip.Prefix, []string) {
	var out []netip.Prefix
	var bad []string
	seen := map[string]bool{}

	for _, field := range fields(text) {
		prefix, err := ParseOne(field)
		if err != nil {
			if len(bad) < 20 {
				bad = append(bad, field)
			}
			continue
		}
		if seen[prefix.String()] {
			continue
		}
		seen[prefix.String()] = true
		out = append(out, prefix)
	}
	return out, bad
}

// ParseOne accepts the two forms an operator writes: a bare address, meaning
// that one host, and a CIDR range. The result is always masked, so 10.0.0.5/8
// is stored as the 10.0.0.0/8 it actually means rather than as a range whose
// text implies a host it does not match.
func ParseOne(text string) (netip.Prefix, error) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return netip.Prefix{}, fmt.Errorf("empty")
	}
	if strings.Contains(trimmed, "/") {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	address, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(address, address.BitLen()), nil
}

// fields splits pasted text into candidate entries.
//
// Newlines, commas, semicolons and spaces all separate, because every one of
// them turns up in a list somebody exported from something. A `#` or `//`
// starts a comment: lists downloaded from anywhere carry a header, and refusing
// the whole paste over it would be a poor trade.
func fields(text string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if cut := strings.IndexAny(line, "#;"); cut >= 0 {
			line = line[:cut]
		}
		if cut := strings.Index(line, "//"); cut >= 0 {
			line = line[:cut]
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			if field != "" {
				out = append(out, field)
			}
		}
	}
	return out
}

// Slugify derives the identifier the generated ruleset uses for a list.
//
// It has to be a legal nftables set name and it has to be stable, so it is
// derived once when the list is created and never again: renaming a list must
// not rename a kernel object that installed rules are pointing at. The
// identifier is carried in the name so two lists that slugify the same way
// still get different sets.
func Slugify(id int64, name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && b.String()[b.Len()-1] != '_':
			b.WriteByte('_')
		}
		if b.Len() >= 16 {
			break
		}
	}
	slug := strings.Trim(b.String(), "_")
	if slug == "" {
		slug = "list"
	}
	return fmt.Sprintf("src_%d_%s", id, slug)
}

// ValidateName reports why a name cannot be used, or nil.
func ValidateName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("a source list needs a name")
	}
	if len([]rune(trimmed)) > MaxNameLength {
		return fmt.Errorf("a source list name may be at most %d characters", MaxNameLength)
	}
	return nil
}
