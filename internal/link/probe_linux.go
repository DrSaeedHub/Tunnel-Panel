//go:build linux

package link

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// probeNetlink opens and immediately closes a netlink route socket. Opening one
// is the only honest test that netlink is usable: the capability can be missing
// in a container even though the binary supports it.
func probeNetlink() error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("opening a netlink route socket: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		return fmt.Errorf("closing the netlink probe socket: %w", err)
	}
	return nil
}
