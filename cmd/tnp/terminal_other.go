//go:build !unix

package main

import (
	"errors"
	"os"
)

// The CLI manages a systemd service on a Linux host, so it is only ever built
// for Linux. These stubs exist so that `go build ./...` and `go vet ./...` work
// on a developer's Windows or other non-unix workstation instead of failing on
// a package that machine could not run anyway.

func isTerminal(uintptr) bool { return false }

func readPasswordNoEcho(*os.File) (string, error) {
	return "", errors.New("reading a password without echo is not supported on this platform")
}
