// Package metrics reads this server's own health from /proc and /sys (§11).
//
// It parses the kernel's own files rather than adding a system-stats
// dependency, and it returns raw bytes and bytes per second throughout. Unit
// conversion — bytes against bits, binary against decimal — is presentation and
// belongs to the frontend, driven by the display settings. Nothing here returns
// a pre-formatted string.
package metrics

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Reader reads the kernel's files. Root is "/" in production and a fixture
// directory in tests, which is what makes the parsers testable against
// recorded output rather than against whatever machine happens to run them.
type Reader struct {
	Root string
}

// NewReader returns a reader rooted at the real filesystem.
func NewReader() *Reader { return &Reader{Root: "/"} }

func (r *Reader) path(parts ...string) string {
	root := r.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

// ---------------------------------------------------------------- CPU

// CPUTimes is one line of /proc/stat: cumulative jiffies in each state.
type CPUTimes struct {
	Name      string `json:"name"`
	User      uint64 `json:"user"`
	Nice      uint64 `json:"nice"`
	System    uint64 `json:"system"`
	Idle      uint64 `json:"idle"`
	Iowait    uint64 `json:"iowait"`
	Irq       uint64 `json:"irq"`
	Softirq   uint64 `json:"softirq"`
	Steal     uint64 `json:"steal"`
	Guest     uint64 `json:"guest"`
	GuestNice uint64 `json:"guest_nice"`
}

// Total is every jiffy accounted for.
//
// Guest time is already included in User, and guest-nice in Nice, so adding
// them again would inflate the denominator and understate utilisation.
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.Iowait + c.Irq + c.Softirq + c.Steal
}

// Busy is everything except idling.
func (c CPUTimes) Busy() uint64 { return c.Total() - c.Idle - c.Iowait }

// CPUUsage is utilisation over one sampling interval, as a percentage.
type CPUUsage struct {
	Name string `json:"name"`
	// UsagePercent is everything that was not idle or waiting on I/O.
	UsagePercent  float64 `json:"usage_percent"`
	UserPercent   float64 `json:"user_percent"`
	SystemPercent float64 `json:"system_percent"`
	IowaitPercent float64 `json:"iowait_percent"`
	// StealPercent is time the hypervisor gave to somebody else. It matters on
	// a virtual private server, where it is the difference between "this server
	// is busy" and "this server is being starved".
	StealPercent float64 `json:"steal_percent"`
	IdlePercent  float64 `json:"idle_percent"`
}

// CPU reads /proc/stat. The first entry is the aggregate, the rest per core.
func (r *Reader) CPU() ([]CPUTimes, error) {
	file, err := os.Open(r.path("proc", "stat"))
	if err != nil {
		return nil, fmt.Errorf("reading CPU times: %w", err)
	}
	defer file.Close()

	var out []CPUTimes
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		times := CPUTimes{Name: fields[0]}
		values := make([]uint64, 0, 10)
		for _, field := range fields[1:] {
			v, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				v = 0
			}
			values = append(values, v)
		}
		// Older kernels report fewer columns; anything absent stays zero.
		assign := []*uint64{
			&times.User, &times.Nice, &times.System, &times.Idle, &times.Iowait,
			&times.Irq, &times.Softirq, &times.Steal, &times.Guest, &times.GuestNice,
		}
		for i := range assign {
			if i < len(values) {
				*assign[i] = values[i]
			}
		}
		out = append(out, times)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading CPU times: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no CPU lines in %s", r.path("proc", "stat"))
	}
	return out, nil
}

// CPUDelta computes utilisation between two consecutive readings.
//
// Utilisation is only ever a difference: the cumulative totals since boot say
// nothing about what the machine is doing now, and reporting them as a
// percentage would show a number that barely moves whatever happens (§11.1).
func CPUDelta(previous, current []CPUTimes) []CPUUsage {
	byName := make(map[string]CPUTimes, len(previous))
	for _, p := range previous {
		byName[p.Name] = p
	}

	out := make([]CPUUsage, 0, len(current))
	for _, now := range current {
		before, ok := byName[now.Name]
		if !ok {
			out = append(out, CPUUsage{Name: now.Name})
			continue
		}
		total := float64(now.Total()) - float64(before.Total())
		if total <= 0 {
			out = append(out, CPUUsage{Name: now.Name})
			continue
		}
		share := func(a, b uint64) float64 {
			d := float64(a) - float64(b)
			if d < 0 {
				return 0
			}
			return d / total * 100
		}
		usage := CPUUsage{
			Name:          now.Name,
			UserPercent:   share(now.User+now.Nice, before.User+before.Nice),
			SystemPercent: share(now.System+now.Irq+now.Softirq, before.System+before.Irq+before.Softirq),
			IowaitPercent: share(now.Iowait, before.Iowait),
			StealPercent:  share(now.Steal, before.Steal),
			IdlePercent:   share(now.Idle, before.Idle),
		}
		usage.UsagePercent = share(now.Busy(), before.Busy())
		out = append(out, usage)
	}
	return out
}

// LoadAverage is /proc/loadavg.
type LoadAverage struct {
	One             float64 `json:"one"`
	Five            float64 `json:"five"`
	Fifteen         float64 `json:"fifteen"`
	RunningEntities int     `json:"running_entities"`
	TotalEntities   int     `json:"total_entities"`
}

// Load reads the load averages.
func (r *Reader) Load() (LoadAverage, error) {
	raw, err := os.ReadFile(r.path("proc", "loadavg"))
	if err != nil {
		return LoadAverage{}, fmt.Errorf("reading the load average: %w", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 3 {
		return LoadAverage{}, fmt.Errorf("the load average file is not in the expected form")
	}

	out := LoadAverage{}
	out.One, _ = strconv.ParseFloat(fields[0], 64)
	out.Five, _ = strconv.ParseFloat(fields[1], 64)
	out.Fifteen, _ = strconv.ParseFloat(fields[2], 64)
	if len(fields) >= 4 {
		if running, total, ok := strings.Cut(fields[3], "/"); ok {
			out.RunningEntities, _ = strconv.Atoi(running)
			out.TotalEntities, _ = strconv.Atoi(total)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- memory

// Memory is the memory picture, in bytes.
type Memory struct {
	TotalBytes     uint64 `json:"total_bytes"`
	FreeBytes      uint64 `json:"free_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	BuffersBytes   uint64 `json:"buffers_bytes"`
	CachedBytes    uint64 `json:"cached_bytes"`

	// UsedBytes is total minus available, which is the figure that means what
	// an operator expects. Total minus free would count the page cache as used
	// and report a healthy Linux machine as nearly out of memory (§11.1).
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`

	// UnavailableBytes is the naive total-minus-free figure, exposed so the
	// interface can show the breakdown rather than leaving the difference
	// unexplained.
	UnavailableBytes   uint64  `json:"unavailable_bytes"`
	UnavailablePercent float64 `json:"unavailable_percent"`
}

// Swap is the swap picture.
type Swap struct {
	// Configured reports whether this machine has any swap at all, so the
	// interface can say "none configured" rather than showing a misleading 0%.
	Configured  bool    `json:"configured"`
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// MemoryInfo reads /proc/meminfo and derives both memory and swap.
func (r *Reader) MemoryInfo() (Memory, Swap, error) {
	values, err := r.parseMeminfo()
	if err != nil {
		return Memory{}, Swap{}, err
	}

	memory := Memory{
		TotalBytes:     values["MemTotal"],
		FreeBytes:      values["MemFree"],
		AvailableBytes: values["MemAvailable"],
		BuffersBytes:   values["Buffers"],
		CachedBytes:    values["Cached"],
	}
	// MemAvailable has been in the kernel since 3.14, but deriving it keeps the
	// figure sane on anything older rather than reporting everything as used.
	if memory.AvailableBytes == 0 {
		memory.AvailableBytes = memory.FreeBytes + memory.BuffersBytes + memory.CachedBytes
	}
	if memory.TotalBytes > 0 {
		memory.UsedBytes = saturatingSub(memory.TotalBytes, memory.AvailableBytes)
		memory.UsedPercent = float64(memory.UsedBytes) / float64(memory.TotalBytes) * 100
		memory.UnavailableBytes = saturatingSub(memory.TotalBytes, memory.FreeBytes)
		memory.UnavailablePercent = float64(memory.UnavailableBytes) / float64(memory.TotalBytes) * 100
	}

	swap := Swap{TotalBytes: values["SwapTotal"], FreeBytes: values["SwapFree"]}
	swap.Configured = swap.TotalBytes > 0
	if swap.Configured {
		swap.UsedBytes = saturatingSub(swap.TotalBytes, swap.FreeBytes)
		swap.UsedPercent = float64(swap.UsedBytes) / float64(swap.TotalBytes) * 100
	}
	return memory, swap, nil
}

// parseMeminfo returns every /proc/meminfo key in bytes.
func (r *Reader) parseMeminfo() (map[string]uint64, error) {
	file, err := os.Open(r.path("proc", "meminfo"))
	if err != nil {
		return nil, fmt.Errorf("reading memory information: %w", err)
	}
	defer file.Close()

	out := map[string]uint64{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, rest, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		value, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		// Every value is in kibibytes unless it says otherwise.
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			value *= 1024
		}
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading memory information: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable lines in %s", r.path("proc", "meminfo"))
	}
	return out, nil
}

func saturatingSub(a, b uint64) uint64 {
	if b > a {
		return 0
	}
	return a - b
}
