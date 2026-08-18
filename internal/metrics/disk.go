package metrics

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// pseudoFilesystems are the kernel's own filesystems: real enough to appear in
// /proc/mounts, but not disks anyone is trying to keep an eye on (§11.1).
var pseudoFilesystems = map[string]bool{
	"autofs": true, "bpf": true, "binfmt_misc": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true, "efivarfs": true,
	"fuse.gvfsd-fuse": true, "fusectl": true, "hugetlbfs": true, "mqueue": true,
	"nsfs": true, "overlay": true, "proc": true, "pstore": true, "ramfs": true,
	"securityfs": true, "selinuxfs": true, "squashfs": true, "sysfs": true,
	"tmpfs": true, "tracefs": true,
}

// IsPseudoFilesystem reports whether a filesystem type is one of the kernel's
// own rather than storage.
func IsPseudoFilesystem(fstype string) bool {
	if pseudoFilesystems[fstype] {
		return true
	}
	// Every cgroup variant, whatever it is called on this kernel.
	return strings.HasPrefix(fstype, "cgroup")
}

// Mount is one entry of the kernel's mount table.
type Mount struct {
	Device     string `json:"device"`
	MountPoint string `json:"mount_point"`
	FsType     string `json:"fs_type"`
	Options    string `json:"options"`

	// DeviceID is the kernel's own identity for the filesystem — major:minor
	// from /proc/self/mountinfo — and it is what decides whether two entries are
	// the same storage. Empty when only /proc/mounts was available, which does
	// not carry it.
	DeviceID string `json:"device_id,omitempty"`
	// FsRoot is which part of that filesystem is mounted here: "/" for the
	// filesystem itself, a subdirectory for a bind mount of a subtree.
	FsRoot string `json:"fs_root,omitempty"`
}

// Disk is one mount with its usage.
type Disk struct {
	Mount
	// IsPseudo marks a kernel filesystem, so the interface can hide it by
	// default while the full list stays retrievable.
	IsPseudo bool `json:"is_pseudo"`

	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`

	InodesTotal   uint64  `json:"inodes_total"`
	InodesUsed    uint64  `json:"inodes_used"`
	InodesFree    uint64  `json:"inodes_free"`
	InodesPercent float64 `json:"inodes_used_percent"`

	// Error explains a mount that could not be measured, which happens for an
	// unreachable network mount and must not fail the whole reading.
	Error string `json:"error,omitempty"`
}

// Mounts reads the kernel's mount table, one entry per filesystem.
//
// It prefers /proc/self/mountinfo, because that is the only one of the two that
// says which filesystem a mount belongs to. /proc/mounts gives a path and a
// source string, and a bind mount of a subtree has a different path and the
// same source, so nothing there distinguishes "another filesystem" from
// "another view of the one already counted".
//
// That is not a hypothetical. The panel's own unit sets ProtectSystem=full with
// ReadWritePaths, which systemd implements with bind mounts, so the panel runs
// in a mount namespace where its root filesystem appears ten times over — at /,
// /boot, /etc, /etc/sysctl.d, /etc/systemd/network, /etc/systemd/system, /tmp,
// /usr, /var/lib/gre-panel and /var/tmp. Every one is ext4 rather than a
// pseudo filesystem, so hiding pseudo filesystems does not touch them, and
// statfs answers identically for all ten because they are one superblock. The
// dashboard listed eleven disks on a machine with two.
func (r *Reader) Mounts() ([]Mount, error) {
	mounts, err := r.mountInfo()
	if err != nil {
		// A kernel or a fixture without mountinfo still gets the older reading,
		// with the older limitation: no device identity means no way to tell a
		// bind mount from a filesystem, so only the identical path is collapsed.
		mounts, err = r.procMounts()
		if err != nil {
			return nil, err
		}
	}
	return collapseByFilesystem(mounts), nil
}

// mountInfo parses /proc/self/mountinfo, which carries the major:minor device
// number and the subtree that is mounted.
//
// Its shape is: mount ID, parent ID, major:minor, root, mount point, options,
// zero or more optional fields, a "-" separator, then the filesystem type, the
// source and the super options. The optional fields are why the separator has
// to be found rather than the tail indexed from the front.
func (r *Reader) mountInfo() ([]Mount, error) {
	file, err := os.Open(r.path("proc", "self", "mountinfo"))
	if err != nil {
		return nil, fmt.Errorf("reading the mount table: %w", err)
	}
	defer file.Close()

	var out []Mount
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 {
			continue
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 0 || separator+2 >= len(fields) {
			continue
		}
		mount := Mount{
			DeviceID:   fields[2],
			FsRoot:     unescapeMount(fields[3]),
			MountPoint: unescapeMount(fields[4]),
			Options:    fields[5],
			FsType:     fields[separator+1],
			Device:     unescapeMount(fields[separator+2]),
		}
		out = append(out, mount)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading the mount table: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("reading the mount table: no usable entries")
	}
	return out, nil
}

// procMounts parses /proc/mounts, which is the fallback.
func (r *Reader) procMounts() ([]Mount, error) {
	file, err := os.Open(r.path("proc", "mounts"))
	if err != nil {
		return nil, fmt.Errorf("reading the mount table: %w", err)
	}
	defer file.Close()

	var out []Mount
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		mount := Mount{
			Device:     unescapeMount(fields[0]),
			MountPoint: unescapeMount(fields[1]),
			FsType:     fields[2],
		}
		if len(fields) > 3 {
			mount.Options = fields[3]
		}
		out = append(out, mount)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading the mount table: %w", err)
	}
	return out, nil
}

// collapseByFilesystem keeps one entry per filesystem.
//
// Identity is the device number when there is one, so every view of a
// filesystem — the filesystem itself and any bind mount of any subtree of it —
// collapses to a single entry, and two tmpfs instances stay separate because
// the kernel gives them different minor numbers. Without a device number the
// most it can do is what it did before: collapse an identical path.
//
// The entry kept is the most canonical view of the filesystem: the one mounting
// its root, then the shortest path, then the first alphabetically so the
// reading does not depend on the order the kernel happened to list them in.
// That is what makes / win over /etc and /usr.
func collapseByFilesystem(mounts []Mount) []Mount {
	// First, one entry per path. A filesystem can be mounted over another at the
	// same point — /proc/sys/fs/binfmt_misc is an autofs with a binfmt_misc on
	// top of it — and only the last one mounted is the one anybody can see, so
	// it is the only one statfs can answer for.
	visible := map[string]int{}
	var topmost []Mount
	for _, mount := range mounts {
		if at, seen := visible[mount.MountPoint]; seen {
			topmost[at] = mount
			continue
		}
		visible[mount.MountPoint] = len(topmost)
		topmost = append(topmost, mount)
	}

	// Then, one entry per filesystem.
	best := map[string]int{}
	var out []Mount
	for _, mount := range topmost {
		key := mount.DeviceID
		if key == "" {
			key = "path:" + mount.MountPoint
		}
		at, seen := best[key]
		if !seen {
			best[key] = len(out)
			out = append(out, mount)
			continue
		}
		if moreCanonical(mount, out[at]) {
			out[at] = mount
		}
	}
	return out
}

// moreCanonical reports whether a is the better representative of a filesystem
// than b.
func moreCanonical(a, b Mount) bool {
	aRoot, bRoot := a.FsRoot == "/", b.FsRoot == "/"
	if aRoot != bRoot {
		return aRoot
	}
	if len(a.MountPoint) != len(b.MountPoint) {
		return len(a.MountPoint) < len(b.MountPoint)
	}
	return a.MountPoint < b.MountPoint
}

// unescapeMount decodes the octal escapes /proc/mounts uses for spaces and
// other awkward characters in a path.
func unescapeMount(value string) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+3 < len(value) {
			var code int
			if _, err := fmt.Sscanf(value[i+1:i+4], "%03o", &code); err == nil {
				b.WriteByte(byte(code))
				i += 3
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return b.String()
}

// Disks reads every mount and measures it.
//
// A mount that cannot be measured is reported with its error rather than
// dropped: an operator whose network mount has hung wants to see that, not a
// list that quietly got shorter.
func (r *Reader) Disks() ([]Disk, error) {
	mounts, err := r.Mounts()
	if err != nil {
		return nil, err
	}

	out := make([]Disk, 0, len(mounts))
	for _, mount := range mounts {
		disk := Disk{Mount: mount, IsPseudo: IsPseudoFilesystem(mount.FsType)}
		usage, err := statfs(mount.MountPoint)
		if err != nil {
			disk.Error = err.Error()
			out = append(out, disk)
			continue
		}

		disk.TotalBytes = usage.TotalBytes
		disk.AvailableBytes = usage.AvailableBytes
		disk.UsedBytes = saturatingSub(usage.TotalBytes, usage.FreeBytes)
		if disk.TotalBytes > 0 {
			// Usage is measured against what a non-root user can actually have:
			// the reserved blocks are not available, so counting them as free
			// would report a full disk as having room.
			usable := disk.UsedBytes + disk.AvailableBytes
			if usable > 0 {
				disk.UsedPercent = float64(disk.UsedBytes) / float64(usable) * 100
			}
		}

		disk.InodesTotal = usage.InodesTotal
		disk.InodesFree = usage.InodesFree
		disk.InodesUsed = saturatingSub(usage.InodesTotal, usage.InodesFree)
		if disk.InodesTotal > 0 {
			disk.InodesPercent = float64(disk.InodesUsed) / float64(disk.InodesTotal) * 100
		}
		out = append(out, disk)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].MountPoint < out[j].MountPoint })
	return out, nil
}

// FilterDisks drops the kernel's own filesystems when asked to.
func FilterDisks(disks []Disk, hidePseudo bool) []Disk {
	if !hidePseudo {
		return disks
	}
	out := make([]Disk, 0, len(disks))
	for _, disk := range disks {
		if disk.IsPseudo {
			continue
		}
		out = append(out, disk)
	}
	return out
}

// filesystemUsage is what statfs reports, in bytes and inodes.
type filesystemUsage struct {
	TotalBytes     uint64
	FreeBytes      uint64
	AvailableBytes uint64
	InodesTotal    uint64
	InodesFree     uint64
}
