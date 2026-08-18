package rules

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Socket states as the kernel numbers them in /proc/net/tcp. Only LISTEN
// matters here: a socket in any other state is a connection, not a service
// holding a port.
const tcpStateListen = "0A"

// Listener is one socket holding a local port, together with the process that
// owns it.
//
// Naming the process is the whole point. "Port 8080 is in use" sends an
// operator hunting; "port 8080 is held by nginx (pid 812)" ends the question.
type Listener struct {
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	// Inode is the socket inode, which is what maps a socket to the process
	// holding it through that process's file descriptors.
	Inode int64 `json:"inode"`
	// ProcessName and ProcessID are empty and zero when no process could be
	// attributed — which happens for a socket in another network namespace, or
	// when the panel is not running as root.
	ProcessName string `json:"process_name,omitempty"`
	ProcessID   int    `json:"process_id,omitempty"`
	// Uid owns the socket.
	Uid int `json:"uid"`
}

// Describe renders the listener the way an error message names it.
func (l Listener) Describe() string {
	where := fmt.Sprintf("%s:%d", l.Address, l.Port)
	if l.IsAnyAddress() {
		where = fmt.Sprintf("every local address on port %d", l.Port)
	}
	switch {
	case l.ProcessName != "" && l.ProcessID != 0:
		return fmt.Sprintf("%s (pid %d) is listening on %s/%s", l.ProcessName, l.ProcessID, l.Protocol, where)
	case l.ProcessName != "":
		return fmt.Sprintf("%s is listening on %s/%s", l.ProcessName, l.Protocol, where)
	}
	return fmt.Sprintf("a process this panel cannot identify is listening on %s/%s", l.Protocol, where)
}

// IsAnyAddress reports whether the socket is bound to every local address, in
// which case it holds the port on all of them.
func (l Listener) IsAnyAddress() bool { return isUnspecified(l.Address) }

// Covers reports whether this listener holds the given address and port. A
// socket bound to the unspecified address holds the port on every address, so
// it covers any bind address; and a rule binding every address collides with a
// listener on any single one.
func (l Listener) Covers(address string, port int) bool {
	if l.Port != port {
		return false
	}
	if l.IsAnyAddress() || isUnspecified(address) {
		return true
	}
	want, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	got, err := netip.ParseAddr(l.Address)
	if err != nil {
		return false
	}
	return want.Unmap() == got.Unmap()
}

// SocketReader reads the kernel's socket table. Root is "/" in production and a
// fixture directory in tests, which is what makes the parser testable against
// recorded kernel output rather than against whatever host happens to run it.
type SocketReader struct {
	Root string
}

// NewSocketReader returns a reader rooted at the real filesystem.
func NewSocketReader() *SocketReader { return &SocketReader{Root: "/"} }

func (r *SocketReader) path(parts ...string) string {
	root := r.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

// procNetFile names one of the kernel's socket tables and the protocol it
// holds.
type procNetFile struct {
	name     string
	protocol Protocol
	ipv6     bool
}

func socketTables() []procNetFile {
	return []procNetFile{
		{"tcp", ProtocolTCP, false},
		{"tcp6", ProtocolTCP, true},
		{"udp", ProtocolUDP, false},
		{"udp6", ProtocolUDP, true},
	}
}

// Listeners returns every socket holding a local port.
//
// It reads the kernel's tables directly rather than shelling out to ss or
// netstat: the answer is needed on a request path, the format is stable, and a
// parser is testable against a recorded file in a way a subprocess is not.
//
// A table that cannot be read is skipped rather than failing the whole call: a
// host without IPv6 has no /proc/net/tcp6, and refusing to validate anything
// because of that would be worse than validating what is there.
func (r *SocketReader) Listeners() ([]Listener, error) {
	inodes := r.socketInodes()

	var out []Listener
	var firstErr error
	for _, table := range socketTables() {
		listeners, err := r.readTable(table)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		for _, l := range listeners {
			if owner, ok := inodes[l.Inode]; ok {
				l.ProcessID = owner.pid
				l.ProcessName = owner.name
			}
			out = append(out, l)
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// ListenerOn returns the listener holding an address and port, if there is one.
func (r *SocketReader) ListenerOn(protocol Protocol, address string, port int) (Listener, bool, error) {
	listeners, err := r.Listeners()
	if err != nil {
		return Listener{}, false, err
	}
	for _, l := range listeners {
		if protocol != ProtocolBoth && l.Protocol != protocol {
			continue
		}
		if l.Covers(address, port) {
			return l, true, nil
		}
	}
	return Listener{}, false, nil
}

// readTable parses one /proc/net socket table.
//
// The format is fixed-width-ish columns with the local address as
// hex-encoded network data: "0100007F:1F90" is 127.0.0.1:8080, with the IPv4
// address in host byte order per 32-bit word.
func (r *SocketReader) readTable(table procNetFile) ([]Listener, error) {
	f, err := os.Open(r.path("proc", "net", table.name))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Listener
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false // the header row
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		// UDP sockets have no LISTEN state: an unconnected UDP socket is bound
		// and receiving, which is exactly what a DNAT would steal.
		if table.protocol == ProtocolTCP && fields[3] != tcpStateListen {
			continue
		}
		address, port, err := parseProcAddress(fields[1], table.ipv6)
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(fields[7])
		inode, _ := strconv.ParseInt(fields[9], 10, 64)
		out = append(out, Listener{
			Protocol: table.protocol, Address: address, Port: port,
			Inode: inode, Uid: uid,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading /proc/net/%s: %w", table.name, err)
	}
	return out, nil
}

// parseProcAddress decodes one "ADDRESS:PORT" field of a socket table.
func parseProcAddress(field string, ipv6 bool) (string, int, error) {
	hexAddr, hexPort, ok := strings.Cut(field, ":")
	if !ok {
		return "", 0, fmt.Errorf("%q is not an address:port pair", field)
	}
	port, err := strconv.ParseUint(hexPort, 16, 32)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not a port: %w", hexPort, err)
	}

	raw, err := decodeHex(hexAddr)
	if err != nil {
		return "", 0, err
	}
	// The kernel prints each 32-bit word in host byte order, which on every
	// platform this runs on is little-endian, so each group of four bytes is
	// reversed. An IPv6 address is four such words.
	expected := 4
	if ipv6 {
		expected = 16
	}
	if len(raw) != expected {
		return "", 0, fmt.Errorf("%q is not a %d-byte address", hexAddr, expected)
	}
	for word := 0; word < len(raw); word += 4 {
		raw[word], raw[word+3] = raw[word+3], raw[word]
		raw[word+1], raw[word+2] = raw[word+2], raw[word+1]
	}

	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "", 0, fmt.Errorf("%q is not an address", hexAddr)
	}
	return addr.Unmap().String(), int(port), nil
}

func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("%q is not hex-encoded", s)
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("%q is not hex-encoded: %w", s, err)
		}
		out[i] = byte(v)
	}
	return out, nil
}

// owner is the process holding a socket.
type owner struct {
	pid  int
	name string
}

// socketInodes maps socket inodes to the processes holding them, by walking
// every process's file descriptors and reading the ones that are sockets.
//
// Anything unreadable is skipped: a process that exits mid-walk, or one owned
// by another user when the panel is not root, simply goes unattributed. The
// port conflict is still reported; only the name is missing.
func (r *SocketReader) socketInodes() map[int64]owner {
	out := map[int64]owner{}
	entries, err := os.ReadDir(r.path("proc"))
	if err != nil {
		return out
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		fds, err := os.ReadDir(r.path("proc", entry.Name(), "fd"))
		if err != nil {
			continue
		}
		name := r.processName(entry.Name())
		for _, fd := range fds {
			target, err := os.Readlink(r.path("proc", entry.Name(), "fd", fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok {
				continue
			}
			if existing, taken := out[inode]; !taken || supersedes(pid, name, existing) {
				out[inode] = owner{pid: pid, name: name}
			}
		}
	}
	return out
}

// supersedes reports whether a newly found holder of a socket describes it
// better than the one already recorded.
//
// A socket can be held by more than one process, and the case that matters here
// is socket activation: systemd opens the listening socket, hands it to the
// service, and keeps its own descriptor. Both then appear in /proc, and which
// one is found first is directory order — on Ubuntu 24.04 that is pid 1, so
// the port ends up attributed to "systemd".
//
// That is not cosmetic. The panel refuses to forward the live SSH port and
// finds that port by looking for the sshd process holding it (§6.3.1), so an
// SSH socket attributed to systemd leaves the port unprotected on exactly the
// distributions that socket-activate it by default. The supervisor therefore
// yields to anything more specific.
func supersedes(pid int, name string, existing owner) bool {
	if !isSupervisor(existing.pid, existing.name) {
		return false
	}
	return !isSupervisor(pid, name)
}

// isSupervisor recognises the process that hands sockets to other processes
// rather than serving them itself.
func isSupervisor(pid int, name string) bool {
	if pid == 1 {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "systemd", "init", "inetd", "xinetd", "systemd-socket-proxyd":
		return true
	}
	return false
}

// socketInode extracts the inode from a "socket:[12345]" symlink target.
func socketInode(target string) (int64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inode, err := strconv.ParseInt(target[len(prefix):len(target)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// processName reads a process's command name, preferring the full command line
// so that a service running under an interpreter is named by what it is running
// rather than as "python3".
func (r *SocketReader) processName(pid string) string {
	if raw, err := os.ReadFile(r.path("proc", pid, "comm")); err == nil {
		if name := strings.TrimSpace(string(raw)); name != "" {
			return name
		}
	}
	raw, err := os.ReadFile(r.path("proc", pid, "cmdline"))
	if err != nil {
		return ""
	}
	fields := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(fields) == 0 {
		return ""
	}
	return filepath.Base(fields[0])
}

// SshPorts returns the TCP ports the running sshd is listening on.
//
// The safety invariant is that the live SSH port is never DNAT'd, and the live
// port is whatever sshd actually bound — not 22. An installation that moved SSH
// to 2222 and left something else on 22 would otherwise be protected on the
// wrong port and locked out on the right one (§6.3.1).
func (r *SocketReader) SshPorts() ([]int, error) {
	listeners, err := r.Listeners()
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var out []int
	for _, l := range listeners {
		if l.Protocol != ProtocolTCP || !isSshProcess(l.ProcessName) || seen[l.Port] {
			continue
		}
		seen[l.Port] = true
		out = append(out, l.Port)
	}
	return out, nil
}

// isSshProcess recognises the SSH daemon by the names it runs under. Both the
// classic sshd and the socket-activated sshd-session of OpenSSH 9.8 count.
func isSshProcess(name string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(name)))
	switch base {
	case "sshd", "sshd-session", "dropbear":
		return true
	}
	return false
}
