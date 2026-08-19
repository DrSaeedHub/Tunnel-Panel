package sourcelist

import (
	"strings"
	"testing"
)

// Lists arrive from a text box, from a file some other tool exported, and from
// copying a page in a browser. The separators vary and the comments come along
// for the ride, so the parser is forgiving about shape and strict about values.
func TestPastedTextIsReadHoweverItIsSeparated(t *testing.T) {
	text := `
# Iranian mobile, exported 2026-08-19
5.22.0.0/20
5.22.16.0/20, 5.22.32.0/20
	2.144.0.0/14   2.176.0.0/12
185.112.32.0/22 // a trailing note
`

	prefixes, bad := ParseEntries(text)
	if len(bad) != 0 {
		t.Fatalf("rejected %v from a paste that is entirely valid", bad)
	}
	got := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		got = append(got, prefix.String())
	}
	want := []string{
		"5.22.0.0/20", "5.22.16.0/20", "5.22.32.0/20",
		"2.144.0.0/14", "2.176.0.0/12", "185.112.32.0/22",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("parsed %v, want %v in the order they were written", got, want)
	}
}

// A bare address is one host and a range is a range, and both are stored the
// same way so nothing downstream has to handle two shapes.
func TestABareAddressBecomesASingleHostRange(t *testing.T) {
	prefixes, bad := ParseEntries("192.0.2.7\n2001:db8::1")
	if len(bad) != 0 {
		t.Fatalf("rejected %v", bad)
	}
	if len(prefixes) != 2 {
		t.Fatalf("parsed %d entries, want 2", len(prefixes))
	}
	if got := prefixes[0].String(); got != "192.0.2.7/32" {
		t.Errorf("the IPv4 host is %q, want 192.0.2.7/32", got)
	}
	if got := prefixes[1].String(); got != "2001:db8::1/128" {
		t.Errorf("the IPv6 host is %q, want 2001:db8::1/128", got)
	}
}

// A range written with host bits set means the range, and storing the text as
// typed would describe a network that does not match the address in it.
func TestARangeIsStoredMasked(t *testing.T) {
	prefixes, _ := ParseEntries("10.0.0.5/8")
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/8" {
		t.Errorf("parsed %v, want the masked 10.0.0.0/8", prefixes)
	}
}

// One range written twice is one range. Lists are pasted together from several
// sources and the overlap is the normal case, not the exception.
func TestDuplicatesCollapseAndRubbishIsReported(t *testing.T) {
	prefixes, bad := ParseEntries("10.0.0.0/8\n10.0.0.0/8\nnot-an-address\n10.0.0.0/8")
	if len(prefixes) != 1 {
		t.Errorf("parsed %v, want the one range", prefixes)
	}
	if len(bad) != 1 || bad[0] != "not-an-address" {
		t.Errorf("rejected %v, want exactly the entry that is not an address", bad)
	}
}

// The slug names a kernel object, so it has to be legal, stable and unique.
func TestSlugsAreLegalAndUnique(t *testing.T) {
	cases := map[string]string{
		"MCI":                  "src_1_mci",
		"Hamrah-e Aval":        "src_1_hamrah_e_aval",
		"خانه":                 "src_1_list",
		"  spaces  and  more ": "src_1_spaces_and_more",
	}
	for name, want := range cases {
		if got := Slugify(1, name); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", name, got, want)
		}
	}

	// Two lists that slugify the same way still get different sets, because the
	// identifier is in the name.
	if Slugify(1, "MCI") == Slugify(2, "MCI") {
		t.Error("two lists with the same name share one set name")
	}
	// And the slug is only ever legal characters for an nftables identifier.
	for _, r := range Slugify(7, "MCI / MTN — همه") {
		if !(r == '_' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			t.Errorf("slug contains %q, which nftables will not parse", r)
		}
	}
}
