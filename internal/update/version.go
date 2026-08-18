// Package update answers the two questions the panel could not answer about
// itself: whether the release host is serving something newer than this build,
// and installing it when an operator asks.
//
// Neither is done here directly. The check reads the release host's own index
// over HTTPS, and the install goes through `tnp update`, which goes through the
// installer — the same path an operator would take from a shell, so a panel
// that updated itself and a panel that was updated by hand end up in exactly
// the same state. What this package adds is the plumbing that makes that
// possible from inside a request: a cached check that never blocks the caller
// on the network, and a launcher that starts the installer outside the panel's
// own service so the restart in the middle of it does not kill the update.
package update

import (
	"strconv"
	"strings"
)

// Version is a release tag broken into the parts that can be compared.
//
// The project tags every commit vMAJOR.MINOR.PATCH, and an untagged build
// stamps itself 0.0.0-<short sha>. The second is why Pre matters here: a build
// that did not come from a tag must never be told that a release is "newer",
// because it is not the same lineage — it may well contain work that no release
// has yet.
type Version struct {
	Major int
	Minor int
	Patch int
	// Pre is whatever followed the first hyphen, empty for a plain release tag.
	Pre string
	// Raw is the string this was parsed from, with the leading v kept, so a
	// value can be shown back to an operator exactly as the release names it.
	Raw string
}

// ParseVersion reads vMAJOR.MINOR.PATCH, with or without the v, and with an
// optional -suffix. Anything else is not a version this panel can reason about
// and is reported as such rather than guessed at.
func ParseVersion(s string) (Version, bool) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return Version{}, false
	}

	body := strings.TrimPrefix(raw, "v")
	pre := ""
	if cut := strings.IndexAny(body, "-+"); cut >= 0 {
		pre = body[cut+1:]
		body = body[:cut]
	}

	parts := strings.Split(body, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	numbers := make([]int, 3)
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return Version{}, false
		}
		numbers[i] = n
	}
	return Version{Major: numbers[0], Minor: numbers[1], Patch: numbers[2], Pre: pre, Raw: raw}, true
}

// IsRelease reports whether this is a plain release tag: something the CI
// release job could have published, rather than a local or untagged build.
func (v Version) IsRelease() bool {
	return v.Pre == "" && (v.Major > 0 || v.Minor > 0 || v.Patch > 0)
}

// Less orders two versions. A prerelease sorts before the release it leads to,
// which is the semantic version rule and also the useful one here: v0.2.0-rc1
// is older than v0.2.0.
func (v Version) Less(other Version) bool {
	switch {
	case v.Major != other.Major:
		return v.Major < other.Major
	case v.Minor != other.Minor:
		return v.Minor < other.Minor
	case v.Patch != other.Patch:
		return v.Patch < other.Patch
	case v.Pre == other.Pre:
		return false
	case v.Pre == "":
		// A release is newer than any prerelease of the same numbers.
		return false
	case other.Pre == "":
		return true
	default:
		return v.Pre < other.Pre
	}
}

// Newer reports whether latest is a release this build should be offered.
//
// It answers false whenever the question cannot be settled — an unparseable
// tag, or a running build that did not come from a release — because the cost
// of a wrong "yes" here is an operator being nagged to install something that
// is not newer, or being sent backwards from a build they made themselves.
func Newer(current, latest string) bool {
	from, ok := ParseVersion(current)
	if !ok || !from.IsRelease() {
		return false
	}
	to, ok := ParseVersion(latest)
	if !ok {
		return false
	}
	return from.Less(to)
}
