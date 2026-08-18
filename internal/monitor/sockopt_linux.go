//go:build linux

package monitor

import "golang.org/x/sys/unix"

// setDontFragment turns path MTU discovery on or off for a socket.
//
// IP_PMTUDISC_DO sets the Don't-Fragment bit on every outgoing packet, so a
// packet larger than a link on the path is rejected with an ICMP error instead
// of being fragmented. That rejection is the signal the path MTU probe binary
// searches on (§13.2).
func setDontFragment(fd int, on bool) error {
	value := unix.IP_PMTUDISC_WANT
	if on {
		value = unix.IP_PMTUDISC_DO
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, value)
}
