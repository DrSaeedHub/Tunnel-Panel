//go:build !linux

package metrics

import "errors"

// statfs is unavailable off Linux. The panel is only deployed there; this file
// exists so the tree still builds and tests on a developer machine.
func statfs(mountPoint string) (filesystemUsage, error) {
	return filesystemUsage{}, errors.New("disk usage is only measurable on Linux")
}
