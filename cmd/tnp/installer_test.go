package main

import "testing"

// An offline bundle's release base is a path on the machine it was extracted
// to, or a file:// URL pointing at the same thing — either way, a directory
// that will never hold anything newer than what shipped in the bundle. update
// treats both as local and reaches for the real release host instead;
// anything else is assumed to already be a network host.
func TestIsLocalReleaseBase(t *testing.T) {
	local := []string{
		"/root/temp/tunnel-panel-v0.1.0-ubuntu24.04-amd64-bootstrap/dist/release",
		"/opt/bundles/dist/release",
		"file:///root/bundle/dist/release",
	}
	for _, base := range local {
		if !isLocalReleaseBase(base) {
			t.Errorf("isLocalReleaseBase(%q) = false, want true", base)
		}
	}

	remote := []string{
		DefaultReleaseBase,
		"https://github.com/DrSaeedHub/Tunnel-Panel/releases/download",
		"https://example.com/mirror/dist/release",
	}
	for _, base := range remote {
		if isLocalReleaseBase(base) {
			t.Errorf("isLocalReleaseBase(%q) = true, want false", base)
		}
	}
}
