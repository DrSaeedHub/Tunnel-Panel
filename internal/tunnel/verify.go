package tunnel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/validate"
)

// Verification check names. They are stable so the frontend can render each one
// with its own explanation.
const (
	CheckLinkExists    = "link_exists"
	CheckLinkType      = "link_type"
	CheckParameters    = "parameters"
	CheckAddresses     = "addresses"
	CheckFlags         = "flags"
	CheckUnitEnabled   = "unit_enabled"
	CheckUnitActive    = "unit_active"
	CheckPeerReachable = "peer_reachable"
)

// VerifyCheck is the outcome of one verification step.
type VerifyCheck struct {
	Name     string `json:"name"`
	Ok       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	// Fatal reports whether failing this check fails the apply. The peer
	// reachability probe is the one check that is reported and not fatal (§9.3).
	Fatal bool `json:"fatal"`
	// Skipped marks a check that could not be run at all, which is neither a
	// pass nor a failure and must never be presented as either.
	Skipped bool `json:"skipped,omitempty"`
}

// VerifyReport is everything checked after an apply (§9.3).
type VerifyReport struct {
	Ok       bool          `json:"ok"`
	Checks   []VerifyCheck `json:"checks"`
	Failures []string      `json:"failures,omitempty"`
	// OperState is reported for information. It is never used to decide health:
	// a working GRE tunnel reports UNKNOWN, and treating that as failure is the
	// single most common way to get this wrong (§2).
	OperState string `json:"oper_state,omitempty"`
}

// Warnings turns the non-fatal outcomes into response warnings.
func (r VerifyReport) Warnings() []validate.Warning {
	var out []validate.Warning
	for _, check := range r.Checks {
		if check.Fatal || check.Ok {
			continue
		}
		code := "PEER_NOT_REACHABLE"
		if check.Name != CheckPeerReachable {
			code = "VERIFICATION_" + strings.ToUpper(check.Name)
		}
		out = append(out, validate.Warning{Code: code, Message: check.Detail})
	}
	return out
}

func (r *VerifyReport) add(ctx context.Context, check VerifyCheck) {
	r.Checks = append(r.Checks, check)
	if check.Fatal && !check.Ok && !check.Skipped {
		detail := check.Detail
		if detail == "" {
			detail = i18n.T(ctx, "%s: expected %s, found %s", check.Name, check.Expected, check.Actual)
		}
		r.Failures = append(r.Failures, detail)
	}
}

// Verify confirms against the kernel that a tunnel is really what was asked
// for (§9.3).
//
// Nothing here trusts a return code. The legacy script printed
// "installed and active" for a unit that had never started, and this function
// is the direct answer to that: if the kernel does not agree, the apply failed,
// whatever the commands reported.
func (s *Service) Verify(ctx context.Context, rec Record) VerifyReport {
	var report VerifyReport
	desiredSpec := SpecOf(rec)
	desiredAddresses := AddressesOf(rec)

	observed, err := s.links.Get(ctx, rec.InterfaceName)
	if err != nil {
		report.add(ctx, VerifyCheck{
			Name: CheckLinkExists, Fatal: true,
			Detail:   i18n.T(ctx, "the interface %s does not exist", rec.InterfaceName),
			Expected: rec.InterfaceName, Actual: i18n.T(ctx, "absent"),
		})
		report.Ok = false
		return report
	}
	report.OperState = observed.OperState
	report.add(ctx, VerifyCheck{Name: CheckLinkExists, Ok: true, Fatal: true, Actual: rec.InterfaceName})

	// 1. The type matches what was requested. The detail is written for the
	// case it is in: phrasing a passing check as a mismatch made the report
	// read as though something were wrong when nothing was.
	typeMatches := observed.Kind == desiredSpec.Kind
	typeDetail := i18n.T(ctx, "the interface %s is of type %s, as requested",
		rec.InterfaceName, observed.Kind)
	if !typeMatches {
		typeDetail = i18n.T(ctx, "the interface %s is of type %s, but %s was requested",
			rec.InterfaceName, observed.Kind, desiredSpec.Kind)
	}
	report.add(ctx, VerifyCheck{
		Name: CheckLinkType, Ok: typeMatches, Fatal: true,
		Expected: desiredSpec.Kind, Actual: observed.Kind,
		Detail: typeDetail,
	})

	// 2. Every requested parameter matches the actual one.
	for _, check := range parameterChecks(ctx, desiredSpec, observed) {
		report.add(ctx, check)
	}

	// 3. Every requested address is present with the right prefix length.
	report.add(ctx, addressCheck(ctx, desiredAddresses, observed))

	// 4. The flags include UP and LOWER_UP. Operational state is deliberately not
	// part of the decision.
	report.add(ctx, flagCheck(ctx, rec, observed))

	// 5. For systemd persistence the unit must be enabled and active, or the
	// tunnel will not come back after a reboot and the panel would be reporting
	// exactly the zombie state this whole design exists to prevent.
	if rec.PersistenceTypeID == model.PersistenceTypeSystemd && s.store.SystemdAvailable() {
		unit := persist.UnitName(rec.InterfaceName)

		enabled, state, err := s.store.IsEnabled(ctx, unit)
		// Same rule as the type check above: the consequence is only stated when
		// it applies. Telling an operator that an enabled unit "would not return
		// after a reboot" is worse than saying nothing.
		enabledOk := err == nil && enabled
		enabledDetail := i18n.T(ctx, "the unit %s is enabled, so the tunnel returns after a reboot", unit)
		if !enabledOk {
			enabledDetail = i18n.T(ctx, "the unit %s is %s, so the tunnel would not return after a reboot",
				unit, orUnknown(ctx, state))
		}
		// Expected stays systemd's own word, because Actual is what systemctl
		// printed and the two are read side by side.
		report.add(ctx, VerifyCheck{
			Name: CheckUnitEnabled, Ok: enabledOk, Fatal: true,
			Expected: "enabled", Actual: state,
			Detail: enabledDetail,
		})

		active, state, err := s.store.IsActive(ctx, unit)
		report.add(ctx, VerifyCheck{
			Name: CheckUnitActive, Ok: err == nil && active, Fatal: true,
			Expected: "active", Actual: state,
			Detail: i18n.T(ctx, "the unit %s is %s", unit, orUnknown(ctx, state)),
		})
	}

	// 6. A short peer probe, reported and never fatal: the far end may
	// legitimately not be configured yet.
	report.add(ctx, s.peerCheck(ctx, rec))

	report.Ok = len(report.Failures) == 0
	return report
}

// The parameters the parameter check compares, each of which is named in its
// own sentence when it does not match.
const (
	paramLocal = iota
	paramRemote
	paramTtl
	paramHopLimit
	paramMtu
	paramIKey
	paramOKey
)

// mismatchClause says that one parameter is not what was asked for. Each
// parameter has a sentence of its own rather than a label dropped into a shared
// one, because the word order around the name is not the same in every
// language.
func mismatchClause(ctx context.Context, param int, actual, expected string) string {
	actual, expected = orNone(ctx, actual), orNone(ctx, expected)
	switch param {
	case paramLocal:
		return i18n.T(ctx, "local endpoint is %s, not %s", actual, expected)
	case paramRemote:
		return i18n.T(ctx, "remote endpoint is %s, not %s", actual, expected)
	case paramTtl:
		return i18n.T(ctx, "TTL is %s, not %s", actual, expected)
	case paramHopLimit:
		return i18n.T(ctx, "hop limit is %s, not %s", actual, expected)
	case paramMtu:
		return i18n.T(ctx, "MTU is %s, not %s", actual, expected)
	case paramIKey:
		return i18n.T(ctx, "inbound key is %s, not %s", actual, expected)
	default:
		return i18n.T(ctx, "outbound key is %s, not %s", actual, expected)
	}
}

// parameterChecks compares each requested attribute against the live one.
func parameterChecks(ctx context.Context, desired link.TunnelSpec, observed link.Link) []VerifyCheck {
	actual := observed.Tunnel
	if actual == nil {
		return []VerifyCheck{{
			Name: CheckParameters, Fatal: true,
			Detail:   i18n.T(ctx, "the interface exists but reports no tunnel attributes at all"),
			Expected: i18n.T(ctx, "tunnel attributes"), Actual: i18n.T(ctx, "none"),
		}}
	}

	type comparison struct {
		param            int
		expected, actual string
	}
	// An IPv6 tunnel carries a hop limit rather than a TTL, and it is the same
	// octet. link.TunnelArgs writes the hop limit when one is set and falls back
	// to the TTL, and the reader maps the kernel's hoplimit back onto Ttl — so
	// the value to compare against is the one that was actually written. Using
	// the desired TTL made an IPv6 tunnel with a hop limit impossible to create:
	// the apply succeeded, verification compared two different fields, and the
	// whole thing rolled back.
	expectedTtl := desired.Ttl
	ttlParam := paramTtl
	if link.IsIPv6Kind(desired.Kind) {
		ttlParam = paramHopLimit
		if desired.HopLimit != nil {
			expectedTtl = *desired.HopLimit
		}
	}

	comparisons := []comparison{
		{paramLocal, desired.Local, actual.Local},
		{paramRemote, desired.Remote, actual.Remote},
		{ttlParam, itoa(int64(expectedTtl)), itoa(int64(actual.Ttl))},
		{paramMtu, itoa(int64(desired.Mtu)), itoa(int64(observed.MTU))},
		{paramIKey, keyText(desired.IKey), keyText(actual.IKey)},
		{paramOKey, keyText(desired.OKey), keyText(actual.OKey)},
	}

	var mismatches []string
	for _, c := range comparisons {
		if c.expected != c.actual {
			mismatches = append(mismatches, mismatchClause(ctx, c.param, c.actual, c.expected))
		}
	}
	if len(mismatches) == 0 {
		return []VerifyCheck{{
			Name: CheckParameters, Ok: true, Fatal: true, Detail: i18n.T(ctx, "every parameter matches"),
		}}
	}
	return []VerifyCheck{{
		Name: CheckParameters, Fatal: true,
		Detail: i18n.T(ctx, "the interface exists but %s",
			strings.Join(mismatches, clauseSeparator(i18n.Language(ctx)))),
		Expected: describeSpec(desired), Actual: describeActual(observed),
	}}
}

func addressCheck(ctx context.Context, desired []link.Address, observed link.Link) VerifyCheck {
	var missing []string
	for _, want := range desired {
		found := false
		for _, have := range observed.Addresses {
			if have.Address == want.Address && have.PrefixLength == want.PrefixLength {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, want.String())
		}
	}
	if len(missing) == 0 {
		return VerifyCheck{
			Name: CheckAddresses, Ok: true, Fatal: true,
			Detail: i18n.T(ctx, "all %d address(es) are present with the right prefix length", len(desired)),
		}
	}
	return VerifyCheck{
		Name: CheckAddresses, Fatal: true,
		Detail:   i18n.T(ctx, "missing from the interface: %s", strings.Join(missing, ", ")),
		Expected: addressText(desired), Actual: addressText(observed.Addresses),
	}
}

// flagCheck implements the rule that catches out most GRE tooling: health comes
// from the UP and LOWER_UP flags, never from the operational state. A healthy
// point-to-point tunnel device reports UNKNOWN, and requiring UP would fail
// every working tunnel there is (§2, §9.3).
func flagCheck(ctx context.Context, rec Record, observed link.Link) VerifyCheck {
	if !rec.IsEnabled {
		return VerifyCheck{
			Name: CheckFlags, Ok: !observed.IsUp, Fatal: true,
			Expected: i18n.T(ctx, "not up"), Actual: flagText(ctx, observed),
			Detail: i18n.T(ctx, "this tunnel is configured to be down"),
		}
	}
	ok := observed.IsUp && observed.IsLowerUp
	detail := i18n.T(ctx, "the flags are %s and the operational state is %s, which is normal for a "+
		"point-to-point tunnel", flagText(ctx, observed), orUnknown(ctx, observed.OperState))
	if !ok {
		detail = i18n.T(ctx, "the flags are %s; both UP and LOWER_UP are required", flagText(ctx, observed))
	}
	return VerifyCheck{
		Name: CheckFlags, Ok: ok, Fatal: true,
		Expected: i18n.T(ctx, "UP and LOWER_UP"), Actual: flagText(ctx, observed), Detail: detail,
	}
}

// peerProbeBudget is the whole time the reachability probe may take. It is
// short on purpose: the legacy status check blocked for twelve seconds on every
// tunnel, which made the status view unusable.
const peerProbeBudget = 2 * time.Second

// peerProbeCount is how many packets the probe sends.
const peerProbeCount = 3

func (s *Service) peerCheck(ctx context.Context, rec Record) VerifyCheck {
	if len(rec.Addresses) == 0 {
		return VerifyCheck{
			Name: CheckPeerReachable, Skipped: true,
			Detail: i18n.T(ctx, "this tunnel has no address, so there is nothing to probe from"),
		}
	}
	primary := rec.Addresses[0]
	target := derefString(primary.PeerAddress)
	if target == "" {
		return VerifyCheck{
			Name: CheckPeerReachable, Skipped: true,
			Detail: i18n.T(ctx, "no peer address is recorded for this tunnel, so there is nothing to probe"),
		}
	}
	prober := s.peerProber()
	if prober == nil {
		return VerifyCheck{
			Name: CheckPeerReachable, Skipped: true,
			Detail: i18n.T(ctx, "no prober is configured, so peer reachability was not checked"),
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, peerProbeBudget)
	defer cancel()

	result, err := prober.Probe(probeCtx, primary.Address, target, peerProbeCount, peerProbeBudget)
	switch {
	case err != nil:
		return VerifyCheck{
			Name: CheckPeerReachable, Skipped: true,
			Detail: i18n.T(ctx, "the peer could not be probed: %s", err),
		}
	case result.Received > 0:
		return VerifyCheck{
			Name: CheckPeerReachable, Ok: true,
			Detail: i18n.T(ctx, "%d of %d probes to %s were answered", result.Received, result.Sent, target),
		}
	default:
		// Not fatal, and deliberately so: the other end may simply not be
		// configured yet, which is the normal state halfway through setting up a
		// tunnel between two servers.
		return VerifyCheck{
			Name: CheckPeerReachable,
			Detail: i18n.T(ctx, "none of the %d probes to %s were answered. That is expected while the "+
				"other end is not configured yet; if it is configured, check that the keys, the MTU and "+
				"the addresses match on both servers.", result.Sent, target),
		}
	}
}

// verifyDown checks the far simpler post-condition of taking a tunnel down.
func (s *Service) verifyDown(ctx context.Context, rec Record) VerifyReport {
	var report VerifyReport
	observed, err := s.links.Get(ctx, rec.InterfaceName)
	if err != nil {
		report.add(ctx, VerifyCheck{
			Name: CheckLinkExists, Ok: true, Fatal: true,
			Detail: i18n.T(ctx, "the interface is gone, which satisfies being down"),
		})
		report.Ok = true
		return report
	}
	report.OperState = observed.OperState
	report.add(ctx, VerifyCheck{
		Name: CheckFlags, Ok: !observed.IsUp, Fatal: true,
		Expected: i18n.T(ctx, "not up"), Actual: flagText(ctx, observed),
		Detail: i18n.T(ctx, "the interface is still up"),
	})
	report.Ok = len(report.Failures) == 0
	return report
}

func flagText(ctx context.Context, l link.Link) string {
	if len(l.Flags) == 0 {
		return i18n.T(ctx, "none")
	}
	return strings.Join(l.Flags, ",")
}

func keyText(key *uint32) string {
	if key == nil {
		return ""
	}
	return fmt.Sprintf("%d", *key)
}

func orNone(ctx context.Context, s string) string {
	if s == "" {
		return i18n.T(ctx, "unset")
	}
	return s
}

func orUnknown(ctx context.Context, s string) string {
	if s == "" {
		return i18n.T(ctx, "unknown")
	}
	return s
}

// keyOrUnset is a key as it appears in the one-line descriptions below. They
// are written in the syntax of `ip link`, which stays the same whatever the
// language around it.
func keyOrUnset(key *uint32) string {
	if key == nil {
		return "unset"
	}
	return keyText(key)
}

func describeSpec(spec link.TunnelSpec) string {
	return fmt.Sprintf("%s local %s remote %s ttl %d mtu %d ikey %s okey %s",
		spec.Kind, spec.Local, spec.Remote, spec.Ttl, spec.Mtu, keyOrUnset(spec.IKey), keyOrUnset(spec.OKey))
}

func describeActual(observed link.Link) string {
	if observed.Tunnel == nil {
		return observed.Kind
	}
	return fmt.Sprintf("%s local %s remote %s ttl %d mtu %d ikey %s okey %s",
		observed.Kind, observed.Tunnel.Local, observed.Tunnel.Remote, observed.Tunnel.Ttl, observed.MTU,
		keyOrUnset(observed.Tunnel.IKey), keyOrUnset(observed.Tunnel.OKey))
}

// clauseSeparator joins independent clauses -- the parameters that do not
// match, the checks that failed -- with the punctuation of the language they
// are said in.
func clauseSeparator(lang string) string {
	if lang == i18n.Farsi {
		return "؛ "
	}
	return "; "
}
