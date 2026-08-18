//go:build unix

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// The terminal handling is done with golang.org/x/sys/unix directly rather than
// with golang.org/x/term.
//
// x/term would be one import and it is the obvious choice; what it costs here
// is not. Adding it pulls a newer golang.org/x/sys through the module graph,
// and x/sys is what the netlink layer this panel depends on is built against —
// upgrading it to get a password prompt is a large blast radius for a small
// convenience. The two ioctls below are the whole of what x/term would have
// provided.

// isTerminal reports whether a file descriptor is a terminal, by asking for its
// terminal attributes: a pipe or a file has none.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
	return err == nil
}

// readPasswordNoEcho reads a line with echo turned off, restoring the previous
// terminal state whatever happens — including on a signal, because leaving an
// operator's shell with echo disabled is a genuinely unpleasant thing to do.
func readPasswordNoEcho(file *os.File) (string, error) {
	fd := int(file.Fd())
	before, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("this is not a terminal, so a password cannot be typed here: %w", err)
	}

	quiet := *before
	quiet.Lflag &^= unix.ECHO
	// ECHONL keeps the newline visible when the operator presses Enter, so the
	// cursor moves on and the prompt does not look stuck.
	quiet.Lflag |= unix.ECHONL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", fmt.Errorf("turning echo off failed: %w", err)
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, before) //nolint:errcheck // best effort restore

	line, err := bufio.NewReader(file).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
