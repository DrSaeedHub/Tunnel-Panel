//go:build !linux

package link

import "errors"

// probeNetlink always fails off Linux. The panel manages Linux kernel tunnels
// and is only deployed there; this file exists so the tree still builds and
// vets on a developer's machine.
func probeNetlink() error {
	return errors.New("netlink is only available on Linux")
}
