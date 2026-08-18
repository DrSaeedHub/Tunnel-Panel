//go:build linux

package metrics

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// statfs measures one mount point.
func statfs(mountPoint string) (filesystemUsage, error) {
	var fs unix.Statfs_t
	if err := unix.Statfs(mountPoint, &fs); err != nil {
		return filesystemUsage{}, fmt.Errorf("%s could not be measured: %w", mountPoint, err)
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
