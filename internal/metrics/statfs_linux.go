//go:build linux

package metrics

import (
	"context"

	"golang.org/x/sys/unix"

	"github.com/drs/gre-panel/internal/i18n"
)

// statfs measures one mount point.
func statfs(mountPoint string) (filesystemUsage, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(mountPoint, &fs); err != nil {
		return filesystemUsage{}, i18n.Errorf(context.Background(), "%s could not be measured: %w", mountPoint, err)
	}
	blockSize := uint64(fs.Bsize)
	return filesystemUsage{
		TotalBytes:     fs.Blocks * blockSize,
		FreeBytes:      fs.Bfree * blockSize,
		AvailableBytes: fs.Bavail * blockSize,
		InodesTotal:    fs.Files,
		InodesFree:     fs.Ffree,
	}, nil
}
