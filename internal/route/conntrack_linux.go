//go:build linux

package route

import (
	"context"
	"fmt"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NetlinkConntrack reads connection tracking through the netfilter netlink
// interface, which is what §5.3 asks for: a dump rather than a parse of a text
// file the kernel renders one line at a time.
//
// It also carries what the text file does not — a flow's start time, so its age
// is reported rather than left blank.
type NetlinkConntrack struct{}

// Name identifies the implementation.
func (n *NetlinkConntrack) Name() string { return "netlink" }

// Available reports whether the table can be dumped here. It probes rather than
// assumes: the conntrack module may not be loaded, and running unprivileged or
// in a restricted namespace fails the same way.
func (n *NetlinkConntrack) Available() (bool, string) {
	if _, err := netlink.ConntrackTableList(netlink.ConntrackTable, unix.AF_INET); err != nil {
		return false, "connection tracking could not be dumped over netlink: " + err.Error()
	}
	return true, ""
}

// Flows dumps both address families.
//
// A family that cannot be dumped is skipped rather than failing the whole call:
// a host without IPv6 conntrack still relays IPv4, and refusing to report any
// connections because of that would be worse than reporting the ones there are.
func (n *NetlinkConntrack) Flows(ctx context.Context) ([]Flow, error) {
	var out []Flow
	var firstErr error

	for _, family := range []netlink.InetFamily{unix.AF_INET, unix.AF_INET6} {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		dumped, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, entry := range dumped {
			if flow, ok := flowFromNetlink(entry); ok {
				out = append(out, flow)
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, fmt.Errorf("dumping connection tracking: %w", firstErr)
	}
	return out, nil
}

// tcpStateNames are the connection tracking states, in the kernel's own order,
// so a state is reported by the name an operator would see from the conntrack
// tool rather than as a number.
var tcpStateNames = []string{
	"NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT",
	"LAST_ACK", "TIME_WAIT", "CLOSE", "SYN_SENT2",
}

// flowFromNetlink converts one dumped flow.
//
// The original tuple is the client reaching the relay, and the reply tuple's
// source is where the traffic was actually sent — which is the destination the
// DNAT chose, not the one the rule names, so a load-balanced rule shows which
// destination took each connection.
func flowFromNetlink(entry *netlink.ConntrackFlow) (Flow, bool) {
	if entry == nil {
		return Flow{}, false
	}
	protocol := ""
	switch entry.Forward.Protocol {
	case unix.IPPROTO_TCP:
		protocol = "tcp"
	case unix.IPPROTO_UDP:
		protocol = "udp"
	default:
		return Flow{}, false
	}

	flow := Flow{
		Protocol:      protocol,
		SourceAddress: entry.Forward.SrcIP.String(),
		SourcePort:    int(entry.Forward.SrcPort),
		BindAddress:   entry.Forward.DstIP.String(),
		BindPort:      int(entry.Forward.DstPort),
		// The reply comes back from wherever the packet was sent.
		DestinationAddress: entry.Reverse.SrcIP.String(),
		DestinationPort:    int(entry.Reverse.SrcPort),

		TxBytes:   entry.Forward.Bytes,
		TxPackets: entry.Forward.Packets,
		RxBytes:   entry.Reverse.Bytes,
		RxPackets: entry.Reverse.Packets,

		TimeoutSeconds: int(entry.TimeOut),
		Mark:           entry.Mark,
	}
	if entry.TimeStart > 0 {
		flow.AgeSeconds = time.Since(time.Unix(0, int64(entry.TimeStart))).Seconds()
	}
	if info, ok := entry.ProtoInfo.(*netlink.ProtoInfoTCP); ok && info != nil {
		if int(info.State) < len(tcpStateNames) {
			flow.State = tcpStateNames[info.State]
		}
	}
	return flow, true
}

// SelectConntrack returns the best reader this host can serve.
//
// netlink is preferred because dumping the table is markedly cheaper than
// parsing the kernel's text rendering of it, which matters precisely on the
// busy relay where the figures are most wanted. The /proc listing is the
// fallback, and a host with neither is reported as such rather than as a host
// with no connections.
func SelectConntrack() ConntrackReader {
	nl := &NetlinkConntrack{}
	if ok, _ := nl.Available(); ok {
		return nl
	}
	return NewProcConntrack()
}
