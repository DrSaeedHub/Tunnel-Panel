package validate

import (
	"context"

	"github.com/drs/gre-panel/internal/i18n"
	"github.com/drs/gre-panel/internal/link"
)

// Encapsulation sizes in bytes (§7.6).
const (
	// GreBaseHeader is the GRE header with no optional fields.
	GreBaseHeader = 4
	// GreKeyField, GreChecksumField and GreSequenceField are the optional GRE
	// header fields, each four bytes when present.
	GreKeyField      = 4
	GreChecksumField = 4
	GreSequenceField = 4
	// OuterIPv4Header and OuterIPv6Header are the outer delivery headers.
	OuterIPv4Header = 20
	OuterIPv6Header = 40
)

// MtuBounds are the accepted MTU range (§7.3).
const (
	MinMtu = 576
	MaxMtu = 9216
)

// OverheadInput is the subset of a tunnel that decides its encapsulation
// overhead.
type OverheadInput struct {
	Kind     string
	HasKey   bool
	Checksum bool
	Sequence bool
}

// Overhead computes the encapsulation cost of a tunnel in bytes (§7.6).
//
// For IPv4 GRE with a key and neither checksum nor sequence numbers this is
// 20 + 4 + 4 = 28, so the correct MTU over a 1500-byte underlay is 1472 — which
// is what the legacy script hardcoded, and is right.
func Overhead(in OverheadInput) int {
	total := GreBaseHeader
	if in.HasKey {
		total += GreKeyField
	}
	if in.Checksum {
		total += GreChecksumField
	}
	if in.Sequence {
		total += GreSequenceField
	}
	if link.IsIPv6Kind(in.Kind) {
		return total + OuterIPv6Header
	}
	return total + OuterIPv4Header
}

// OverheadOf computes the overhead of a request. A checksum or sequence number
// on either direction costs the field, because the header carrying it is the
// same header in both cases.
func OverheadOf(in TunnelInput) int {
	return Overhead(OverheadInput{
		Kind:     in.Kind(),
		HasKey:   in.HasKey(),
		Checksum: in.HasInputChecksum || in.HasOutputChecksum,
		Sequence: in.HasInputSequence || in.HasOutputSequence,
	})
}

// MtuAdvice reports the computed recommendation alongside the operator's
// choice. The recommendation is never applied silently: overriding an explicit
// choice would be exactly the kind of hidden policy this panel avoids (§7.6).
type MtuAdvice struct {
	// Requested is the MTU the operator asked for.
	Requested int `json:"requested"`
	// Overhead is the encapsulation cost in bytes.
	Overhead int `json:"overhead"`
	// UnderlayMtu is the MTU of the interface the tunnel egresses through, or 0
	// when it could not be determined.
	UnderlayMtu int `json:"underlay_mtu"`
	// UnderlayDevice names that interface.
	UnderlayDevice string `json:"underlay_device,omitempty"`
	// Recommended is UnderlayMtu - Overhead, or 0 when the underlay is unknown.
	Recommended int `json:"recommended"`
	// Matches reports whether the requested MTU equals the recommendation.
	Matches bool `json:"matches"`
	// Breakdown explains the overhead term by term, for display.
	Breakdown []MtuTerm `json:"breakdown"`
}

// MtuTerm is one component of the overhead.
type MtuTerm struct {
	Name  string `json:"name"`
	Bytes int    `json:"bytes"`
}

// AdviseMtu computes the advisory for a request against the observed underlay.
func AdviseMtu(in TunnelInput, underlayDevice string, underlayMtu int) MtuAdvice {
	overhead := OverheadOf(in)
	advice := MtuAdvice{
		Requested:      int(in.Mtu),
		Overhead:       overhead,
		UnderlayMtu:    underlayMtu,
		UnderlayDevice: underlayDevice,
		Breakdown:      overheadBreakdown(in),
	}
	if underlayMtu > overhead {
		advice.Recommended = underlayMtu - overhead
		advice.Matches = advice.Recommended == advice.Requested
	}
	return advice
}

// overheadBreakdown names the terms in English. They are marked for translation
// and said in the operator's language by said, once there is a request to take
// the language from.
func overheadBreakdown(in TunnelInput) []MtuTerm {
	outer := MtuTerm{Name: i18n.N("outer IPv4 header"), Bytes: OuterIPv4Header}
	if in.IsIPv6() {
		outer = MtuTerm{Name: i18n.N("outer IPv6 header"), Bytes: OuterIPv6Header}
	}
	terms := []MtuTerm{outer, {Name: i18n.N("GRE base header"), Bytes: GreBaseHeader}}
	if in.HasKey() {
		terms = append(terms, MtuTerm{Name: i18n.N("GRE key"), Bytes: GreKeyField})
	}
	if in.HasInputChecksum || in.HasOutputChecksum {
		terms = append(terms, MtuTerm{Name: i18n.N("GRE checksum"), Bytes: GreChecksumField})
	}
	if in.HasInputSequence || in.HasOutputSequence {
		terms = append(terms, MtuTerm{Name: i18n.N("GRE sequence number"), Bytes: GreSequenceField})
	}
	return terms
}

// said returns the advice with its breakdown named in the language ctx
// carries.
func (a MtuAdvice) said(ctx context.Context) MtuAdvice {
	terms := make([]MtuTerm, len(a.Breakdown))
	for i, term := range a.Breakdown {
		terms[i] = MtuTerm{Name: i18n.Tr(ctx, term.Name), Bytes: term.Bytes}
	}
	a.Breakdown = terms
	return a
}

// Warning turns a mismatched advisory into the warning the response carries.
// It returns false when the requested MTU is the recommended one.
//
// With no request to take a language from, the warning is said in the panel's
// own.
func (a MtuAdvice) Warning() (Warning, bool) { return a.warning(context.Background()) }

// warning is Warning said in the language ctx carries.
func (a MtuAdvice) warning(ctx context.Context) (Warning, bool) {
	if a.Recommended == 0 || a.Matches {
		return Warning{}, false
	}
	message := i18n.T(ctx, "The MTU %d is above the %d computed from the %s underlay MTU of %d minus %d "+
		"bytes of encapsulation overhead, so packets at the tunnel MTU will need fragmenting or will be "+
		"dropped. The value you chose has been kept.",
		a.Requested, a.Recommended, a.UnderlayDevice, a.UnderlayMtu, a.Overhead)
	if a.Requested < a.Recommended {
		message = i18n.T(ctx, "The MTU %d is below the %d computed from the %s underlay MTU of %d minus %d "+
			"bytes of encapsulation overhead, so the tunnel will carry smaller packets than the path "+
			"allows. The value you chose has been kept.",
			a.Requested, a.Recommended, a.UnderlayDevice, a.UnderlayMtu, a.Overhead)
	}
	return Warning{
		Code:    WarnMtuAdvisory,
		Field:   "mtu",
		Message: message,
		Details: map[string]any{
			"requested":       a.Requested,
			"recommended":     a.Recommended,
			"overhead":        a.Overhead,
			"underlay_mtu":    a.UnderlayMtu,
			"underlay_device": a.UnderlayDevice,
		},
	}, true
}
