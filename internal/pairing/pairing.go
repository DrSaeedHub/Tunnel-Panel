// Package pairing encodes a tunnel's parameters into a short, versioned string
// that can be carried to the other server (§14).
//
// Each server is configured independently, so parameter mismatch between the
// two ends is the main human-error risk: the tunnel comes up locally, reports
// itself healthy, and carries nothing. A pairing code removes the transcription
// step entirely.
//
// The code carries configuration, not a credential. The GRE key it contains is
// not a security boundary — GRE has no authentication — but it is still
// configuration for a specific pair of hosts and should not be posted publicly.
package pairing

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"strings"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

// Version is the current code version. The prefix is part of the string so a
// future format can be recognised and rejected clearly rather than decoded into
// nonsense.
const Version = 1

// Prefix is the literal that starts every version 1 code.
const Prefix = "v1."

// maxDecodedSize bounds what a code may expand to, so a hostile code cannot be
// a decompression bomb.
const maxDecodedSize = 64 * 1024

// PairAddress is one address of the tunnel subnet, carried as both ends'
// addresses so flipping the side needs no arithmetic and cannot get the
// allocation scheme wrong.
type PairAddress struct {
	AddressA     string `json:"a"`
	AddressB     string `json:"b"`
	PrefixLength int    `json:"len"`
	IsPrimary    bool   `json:"primary,omitempty"`
}

// Payload is what a pairing code carries. The field names are short because the
// whole point is a string an operator can copy in one go.
type Payload struct {
	Version      int   `json:"v"`
	TunnelTypeID int64 `json:"type"`
	// TunnelSideID is the side of the server that produced the code. Decoding
	// flips it.
	TunnelSideID int64  `json:"side"`
	Name         string `json:"name,omitempty"`
	// IsNameTemplated reports that the name came from the naming template, so
	// the receiving server should render its own rather than copying this one.
	IsNameTemplated bool   `json:"tmpl,omitempty"`
	TunnelNumber    *int64 `json:"num,omitempty"`

	LocalEndpoint  string `json:"local"`
	RemoteEndpoint string `json:"remote"`

	Ttl  int64  `json:"ttl"`
	Tos  string `json:"tos,omitempty"`
	Mtu  int64  `json:"mtu"`
	IKey *int64 `json:"ikey,omitempty"`
	OKey *int64 `json:"okey,omitempty"`

	HasInputChecksum  bool `json:"icsum,omitempty"`
	HasOutputChecksum bool `json:"ocsum,omitempty"`
	HasInputSequence  bool `json:"iseq,omitempty"`
	HasOutputSequence bool `json:"oseq,omitempty"`

	IsPathMtuDiscovery bool `json:"pmtu,omitempty"`
	IsIgnoreDf         bool `json:"idf,omitempty"`

	HopLimit   *int64 `json:"hop,omitempty"`
	EncapLimit *int64 `json:"encap,omitempty"`

	// AddressPoolID is the pool on the server that produced the code. Pool ids
	// are rows in one server's database and mean nothing on the other, so the
	// receiving end resolves the pool by its range instead and this is carried
	// only for a reader looking at a decoded code.
	AddressPoolID *int64 `json:"pool,omitempty"`
	// AddressPoolCidr, AddressPoolTitle and AddressPoolPrefixLength describe
	// that pool in terms both servers can agree on: the range it hands out, how
	// big the subnets are, and what its operator called it. They are what lets
	// the far end match its own pool, or offer to create the same one.
	AddressPoolCidr         string `json:"pool_cidr,omitempty"`
	AddressPoolTitle        string `json:"pool_title,omitempty"`
	AddressPoolPrefixLength int    `json:"pool_len,omitempty"`

	Addresses []PairAddress `json:"addr,omitempty"`
}

// Encode renders a payload as a pairing code: JSON, gzipped, prefixed with a
// CRC over the JSON, and base64url encoded (§14).
func Encode(p Payload) (string, error) {
	p.Version = Version

	body, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encoding the pairing payload: %w", err)
	}

	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return "", fmt.Errorf("preparing to compress the pairing payload: %w", err)
	}
	if _, err := writer.Write(body); err != nil {
		return "", fmt.Errorf("compressing the pairing payload: %w", err)
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("finishing the pairing payload: %w", err)
	}

	// The checksum covers the JSON rather than the compressed bytes, so it
	// verifies what is actually used and catches a corrupt decompression too.
	framed := make([]byte, 4, 4+compressed.Len())
	binary.BigEndian.PutUint32(framed, crc32.ChecksumIEEE(body))
	framed = append(framed, compressed.Bytes()...)

	return Prefix + base64.RawURLEncoding.EncodeToString(framed), nil
}

// Decode parses a pairing code. A code of an unknown version or with a bad
// checksum is rejected with a message that says which (§14).
func Decode(code string) (Payload, error) {
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return Payload{}, fmt.Errorf("the pairing code is empty")
	}

	version, body, found := strings.Cut(trimmed, ".")
	if !found {
		return Payload{}, fmt.Errorf("this does not look like a pairing code: it should start with %q", Prefix)
	}
	if version != strings.TrimSuffix(Prefix, ".") {
		return Payload{}, fmt.Errorf("this pairing code is version %q, and this panel understands %q. "+
			"Update the panel on whichever server produced it, or copy the parameters by hand",
			version, strings.TrimSuffix(Prefix, "."))
	}

	framed, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		// Accept the padded form too: some clipboards and chat clients add it.
		framed, err = base64.URLEncoding.DecodeString(body)
		if err != nil {
			return Payload{}, fmt.Errorf("the pairing code is not valid: it was truncated or altered in transit")
		}
	}
	if len(framed) < 5 {
		return Payload{}, fmt.Errorf("the pairing code is too short to be complete")
	}

	want := binary.BigEndian.Uint32(framed[:4])
	reader, err := gzip.NewReader(bytes.NewReader(framed[4:]))
	if err != nil {
		return Payload{}, fmt.Errorf("the pairing code is not valid: its contents could not be read")
	}
	defer reader.Close()

	decoded, err := io.ReadAll(io.LimitReader(reader, maxDecodedSize+1))
	if err != nil {
		return Payload{}, fmt.Errorf("the pairing code is not valid: its contents could not be read")
	}
	if len(decoded) > maxDecodedSize {
		return Payload{}, fmt.Errorf("the pairing code expands to more than %d bytes and was refused", maxDecodedSize)
	}

	if got := crc32.ChecksumIEEE(decoded); got != want {
		return Payload{}, fmt.Errorf("the pairing code failed its checksum, so it was truncated or "+
			"altered in transit. Copy it again in full (expected %08x, got %08x)", want, got)
	}

	var p Payload
	if err := json.Unmarshal(decoded, &p); err != nil {
		return Payload{}, fmt.Errorf("the pairing code does not contain a tunnel: %w", err)
	}
	if p.Version != Version {
		return Payload{}, fmt.Errorf("the pairing code declares version %d, and this panel understands %d",
			p.Version, Version)
	}
	if model.TunnelTypeKind(p.TunnelTypeID) == "" {
		return Payload{}, fmt.Errorf("the pairing code names tunnel type %d, which this panel does not know",
			p.TunnelTypeID)
	}
	if model.SideSlot(p.TunnelSideID) == "" {
		return Payload{}, fmt.Errorf("the pairing code names side %d, which is not one of the two ends",
			p.TunnelSideID)
	}
	return p, nil
}

// Flipped returns the create payload for the other end: the same tunnel seen
// from the far side (§14).
//
// The slot decides exactly three things, and all three are mirrored here: the
// endpoints swap, the address taken from the subnet swaps, and the {side}
// substitution changes. Everything else — type, keys, MTU, TTL, the checksum
// and sequence flags — is copied unchanged, because it must be identical on
// both ends or the tunnel comes up and carries nothing (§5.4).
func (p Payload) Flipped() validate.TunnelInput {
	side := model.OppositeSide(p.TunnelSideID)

	in := validate.TunnelInput{
		TunnelTypeID:   p.TunnelTypeID,
		TunnelSideID:   side,
		TunnelNumber:   p.TunnelNumber,
		LocalEndpoint:  p.RemoteEndpoint,
		RemoteEndpoint: p.LocalEndpoint,
		Ttl:            p.Ttl,
		Tos:            p.Tos,
		Mtu:            p.Mtu,
		IKey:           p.IKey,
		OKey:           p.OKey,

		HasInputChecksum:  p.HasInputChecksum,
		HasOutputChecksum: p.HasOutputChecksum,
		HasInputSequence:  p.HasInputSequence,
		HasOutputSequence: p.HasOutputSequence,

		IsPathMtuDiscovery: p.IsPathMtuDiscovery,
		IsIgnoreDf:         p.IsIgnoreDf,

		HopLimit:   p.HopLimit,
		EncapLimit: p.EncapLimit,
		// The pool is deliberately not carried across: the id belongs to the
		// other server's database. The receiving end matches the range against
		// its own pools and fills this in itself.
		IsEnabled: true,
	}
	// A name that came from a template is regenerated by the receiving server
	// from its own settings; a name the operator chose by hand is not copied
	// either, because it belongs to the other host.
	if !p.IsNameTemplated {
		in.InterfaceName = p.Name
	}

	for _, addr := range p.Addresses {
		own, peer := addr.AddressB, addr.AddressA
		if side == model.TunnelSideA {
			own, peer = addr.AddressA, addr.AddressB
		}
		in.Addresses = append(in.Addresses, validate.AddressInput{
			Address:      own,
			PrefixLength: addr.PrefixLength,
			PeerAddress:  peer,
			IsPrimary:    addr.IsPrimary,
		})
	}
	return in
}

// Summary is a human-readable description of a decoded code, shown next to the
// prefilled form so the operator can see what they are about to create.
type Summary struct {
	TunnelType     string `json:"tunnel_type"`
	FromSide       string `json:"from_side"`
	ToSide         string `json:"to_side"`
	LocalEndpoint  string `json:"local_endpoint"`
	RemoteEndpoint string `json:"remote_endpoint"`
	Mtu            int64  `json:"mtu"`
	Ttl            int64  `json:"ttl"`
	IKey           string `json:"ikey"`
	OKey           string `json:"okey"`
}

// Summarise describes the flipped tunnel.
func (p Payload) Summarise() Summary {
	return Summary{
		TunnelType:     model.TunnelTypeKind(p.TunnelTypeID),
		FromSide:       strings.ToUpper(model.SideSlot(p.TunnelSideID)),
		ToSide:         strings.ToUpper(model.SideSlot(model.OppositeSide(p.TunnelSideID))),
		LocalEndpoint:  p.RemoteEndpoint,
		RemoteEndpoint: p.LocalEndpoint,
		Mtu:            p.Mtu,
		Ttl:            p.Ttl,
		IKey:           validate.FormatGreKey(p.IKey),
		OKey:           validate.FormatGreKey(p.OKey),
	}
}
