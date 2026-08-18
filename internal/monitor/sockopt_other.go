//go:build !linux

package monitor

import "errors"

// setDontFragment is unavailable off Linux. The panel is only deployed there;
// this file exists so the tree still builds and tests on a developer machine.
func setDontFragment(fd int, on bool) error {
	return errors.New("setting the Don't-Fragment bit is only supported on Linux")
}
