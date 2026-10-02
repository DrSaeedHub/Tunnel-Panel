//go:build !linux

package metrics

import (
	"context"

	"github.com/drs/gre-panel/internal/i18n"
)

// statfs is unavailable off Linux. The panel is only deployed there; this file
// exists so the tree still builds and tests on a developer machine.
func statfs(mountPoint string) (filesystemUsage, error) {
	return filesystemUsage{}, i18n.Errorf(context.Background(), "disk usage is only measurable on Linux")
}
