package rules

import (
	"fmt"
	"testing"
)

// fixtureSockets reads the recorded /proc under testdata, so the parser is
// tested against real kernel output rather than against whatever host happens
// to run the suite.
//
// The recorded host has sshd on port 22 over both families, nginx on
// 127.0.0.10:8080, the panel itself on 10.0.113.10:8443, and WireGuard on
// UDP 51820, plus one established connection that is not a listener and one
// process whose file descriptors are not sockets.
func fixtureSockets() *SocketReader { return &SocketReader{Root: "testdata"} }

func TestListenersAreParsedAndAttributed(t *testing.T) {
	listeners, err := fixtureSockets().Listeners()
	if err != nil {
		t.Fatalf("Listeners returned an unexpected error: %v", err)
	}

	type want struct {
		protocol Protocol
		address  string
		port     int
		process  string
		pid      int
	}
	expected := []want{
		{ProtocolTCP, "0.0.0.0", 22, "sshd", 812},
		{ProtocolTCP, "127.0.0.10", 8080, "nginx", 1044},
		{ProtocolTCP, "10.0.113.10", 8443, "gre-panel", 3300},
		{ProtocolTCP, "::", 22, "sshd", 812},
		{ProtocolUDP, "0.0.0.0", 51820, "wg-quick", 2201},
	}
	if len(listeners) != len(expected) {
		t.Fatalf("got %d listeners, want %d: %+v", len(listeners), len(expected), listeners)
	}
	for i, w := range expected {
		got := listeners[i]
		if got.Protocol != w.protocol || got.Address != w.address || got.Port != w.port {
			t.Errorf("listener %d = %s %s:%d, want %s %s:%d",
				i, got.Protocol, got.Address, got.Port, w.protocol, w.address, w.port)
		}
		if got.ProcessName != w.process || got.ProcessID != w.pid {
			t.Errorf("listener %d is attributed to %q (pid %d), want %q (pid %d)",
				i, got.ProcessName, got.ProcessID, w.process, w.pid)
		}
	}
}

// TestEstablishedConnectionsAreNotListeners is the difference between "a
// service holds this port" and "somebody is connected". Only the first blocks a
// forwarding rule.
func TestEstablishedConnectionsAreNotListeners(t *testing.T) {
	listeners, err := fixtureSockets().Listeners()
	if err != nil {
		t.Fatalf("Listeners returned an unexpected error: %v", err)
	}
	for _, l := range listeners {
		if l.Inode == 33999 {
			t.Errorf("an established connection was reported as a listener: %+v", l)
		}
	}
}

func TestListenerOnFindsTheOwningProcess(t *testing.T) {
	r := fixtureSockets()

	// A socket bound to one address is found on that address.
	l, found, err := r.ListenerOn(ProtocolTCP, "127.0.0.10", 8080)
	if err != nil || !found {
		t.Fatalf("ListenerOn(127.0.0.10:8080) = %v, %v, %v; want the nginx socket", l, found, err)
	}
	if l.ProcessName != "nginx" {
		t.Errorf("the listener on 127.0.0.10:8080 is %q, want nginx", l.ProcessName)
	}
	if got := l.Describe(); got != "nginx (pid 1044) is listening on tcp/127.0.0.10:8080" {
		t.Errorf("Describe = %q", got)
	}

	// A socket bound to every address holds the port on every address, so a
	// rule binding one specific address still collides with it.
	l, found, err = r.ListenerOn(ProtocolTCP, "10.0.113.99", 22)
	if err != nil || !found {
		t.Fatalf("a rule on port 22 must collide with sshd bound to every address")
	}
	if l.ProcessName != "sshd" {
		t.Errorf("the listener on port 22 is %q, want sshd", l.ProcessName)
	}

	// And a rule binding every address collides with a socket on one of them.
	if _, found, _ = r.ListenerOn(ProtocolTCP, "0.0.0.0", 8080); !found {
		t.Error("a rule binding every address must collide with the listener on 127.0.0.10:8080")
	}

	// A different address with nothing on it is free.
	if _, found, _ = r.ListenerOn(ProtocolTCP, "10.0.113.10", 9999); found {
		t.Error("port 9999 is free on the recorded host but was reported as taken")
	}
	// A UDP socket does not hold the TCP port of the same number.
	if _, found, _ = r.ListenerOn(ProtocolTCP, "0.0.0.0", 51820); found {
		t.Error("a UDP listener was reported as holding the TCP port of the same number")
	}
	if _, found, _ = r.ListenerOn(ProtocolUDP, "0.0.0.0", 51820); !found {
		t.Error("the UDP listener on 51820 was not found")
	}
	// "Both" collides with a listener of either protocol, because it generates
	// rules for both.
	if _, found, _ = r.ListenerOn(ProtocolBoth, "0.0.0.0", 51820); !found {
		t.Error("a rule for both protocols must collide with the UDP listener")
	}
}

// TestSshPortsComeFromTheRunningDaemon covers the invariant's input: the port
// to protect is whatever sshd actually bound, never an assumed 22.
func TestSshPortsComeFromTheRunningDaemon(t *testing.T) {
	ports, err := fixtureSockets().SshPorts()
	if err != nil {
		t.Fatalf("SshPorts returned an unexpected error: %v", err)
	}
	if fmt.Sprint(ports) != fmt.Sprint([]int{22}) {
		t.Errorf("SshPorts = %v, want [22] read from the running daemon", ports)
	}

	// The daemon name is what identifies it, so a moved SSH port is protected
	// and an unrelated service on 22 is not mistaken for one.
	for name, want := range map[string]bool{
		"sshd": true, "sshd-session": true, "dropbear": true,
		"/usr/sbin/sshd": true, "nginx": false, "": false, "ssh-agent": false,
	} {
		if got := isSshProcess(name); got != want {
			t.Errorf("isSshProcess(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestProcAddressDecoding(t *testing.T) {
	cases := []struct {
		field   string
		ipv6    bool
		address string
		port    int
	}{
		{"0100007F:1F90", false, "127.0.0.1", 8080},
		{"00000000:0016", false, "0.0.0.0", 22},
		{"0A71000A:20FB", false, "10.0.113.10", 8443},
		{"00000000000000000000000000000000:0016", true, "::", 22},
		{"B80D0120000000000000000001000000:01BB", true, "2001:db8::1", 443},
	}
	for _, tc := range cases {
		address, port, err := parseProcAddress(tc.field, tc.ipv6)
		if err != nil {
			t.Errorf("parseProcAddress(%q) returned an error: %v", tc.field, err)
			continue
		}
		if address != tc.address || port != tc.port {
			t.Errorf("parseProcAddress(%q) = %s:%d, want %s:%d", tc.field, address, port, tc.address, tc.port)
		}
	}

	for _, bad := range []string{"", "nonsense", "ZZ:0016", "0100007F", "0100007F:ZZZZ", "0100:0016"} {
		if _, _, err := parseProcAddress(bad, false); err == nil {
			t.Errorf("parseProcAddress(%q) accepted a malformed field", bad)
		}
	}
}

// TestUnreadableSocketTablesDoNotFailTheWholeRead covers a host with no IPv6:
// there is no /proc/net/tcp6, and refusing to validate anything because of that
// would be worse than validating what is there.
func TestUnreadableSocketTablesDoNotFailTheWholeRead(t *testing.T) {
	r := &SocketReader{Root: t.TempDir()}
	listeners, err := r.Listeners()
	if err != nil {
		t.Errorf("a root with no socket tables at all returned an error: %v", err)
	}
	if len(listeners) != 0 {
		t.Errorf("got %d listeners from an empty root", len(listeners))
	}
}

// TestASocketActivatedServiceIsAttributedToTheService is the defect a real host
// found: on a distribution that socket-activates SSH, both systemd and sshd
// hold the listening socket, and /proc yields pid 1 first.
//
// Attributing the port to "systemd" is not a cosmetic error. The panel refuses
// to forward the live SSH port by finding the sshd process holding it, so an
// SSH socket credited to systemd leaves port 22 unprotected on exactly the
// distributions that ship socket activation by default — Ubuntu 24.04 among
// them, which is what this panel is installed on.
func TestASocketActivatedServiceIsAttributedToTheService(t *testing.T) {
	listeners, err := fixtureSockets().Listeners()
	if err != nil {
		t.Fatalf("Listeners returned an unexpected error: %v", err)
	}

	for _, listener := range listeners {
		if listener.Port != 22 {
			continue
		}
		if listener.ProcessName != "sshd" {
			t.Errorf("the SSH listener on %s is attributed to %q (pid %d); systemd holds the "+
				"socket too and must yield to the service it handed it to",
				listener.Address, listener.ProcessName, listener.ProcessID)
		}
		if listener.ProcessID != 812 {
			t.Errorf("the SSH listener is attributed to pid %d, want sshd's 812", listener.ProcessID)
		}
	}
}

// TestTheLiveSshPortIsFoundThroughSocketActivation is the same defect stated as
// the safety invariant it protects.
func TestTheLiveSshPortIsFoundThroughSocketActivation(t *testing.T) {
	ports, err := fixtureSockets().SshPorts()
	if err != nil {
		t.Fatalf("SshPorts returned an unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 22 {
		t.Fatalf("the live SSH port was found as %v, want [22]. A host whose SSH socket is "+
			"held by systemd must still have its SSH port protected.", ports)
	}
}
