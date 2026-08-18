package link

import (
	"strconv"
	"strings"
)

// This file is the single place that builds `ip` command lines. Both the
// command-line link manager and the systemd unit renderer use it, which is what
// makes the two paths provably equivalent: the unit file runs exactly the argv
// the fallback manager would have run (§9.4).
//
// Every function returns an argv slice. No function anywhere in this package
// returns a shell string (§17.6).

// CreateArgs builds the `ip link add` invocation for a tunnel.
//
// Two attributes are always stated explicitly rather than left to a default,
// because iproute2 and the netlink path disagree about what the default is and
// the two implementations must produce identical links from one specification:
//
//   - path MTU discovery, which iproute2 turns on when the keyword is absent
//     and the netlink path leaves off;
//   - the type of service, where "inherit" is the kernel's flag value 1 and
//     iproute2 defaults to 0, which means a fixed TOS of zero instead.
//
// Both differences were found by building the same tunnel through each path on
// a real kernel and comparing what came back.
func CreateArgs(ipBin string, spec TunnelSpec) []string {
	argv := []string{ipBin, "link", "add", "name", spec.Name, "type", spec.Kind}

	if spec.Local != "" {
		argv = append(argv, "local", spec.Local)
	}
	if spec.Remote != "" {
		argv = append(argv, "remote", spec.Remote)
	}

	if IsIPv6Kind(spec.Kind) {
		hop := spec.Ttl
		if spec.HopLimit != nil {
			hop = *spec.HopLimit
		}
		argv = append(argv, "hoplimit", ttlWord(hop))
	} else {
		argv = append(argv, "ttl", ttlWord(spec.Ttl))
	}

	argv = append(argv, "tos", tosWord(spec.Tos))
	if spec.IKey != nil {
		argv = append(argv, "ikey", strconv.FormatUint(uint64(*spec.IKey), 10))
	}
	if spec.OKey != nil {
		argv = append(argv, "okey", strconv.FormatUint(uint64(*spec.OKey), 10))
	}
	if spec.HasInputChecksum {
		argv = append(argv, "icsum")
	}
	if spec.HasOutputChecksum {
		argv = append(argv, "ocsum")
	}
	if spec.HasInputSequence {
		argv = append(argv, "iseq")
	}
	if spec.HasOutputSequence {
		argv = append(argv, "oseq")
	}

	// IPv6 tunnel modes have no pmtudisc keyword; the encapsulation limit plays
	// the equivalent role there.
	if !IsIPv6Kind(spec.Kind) {
		if spec.IsPathMtuDiscovery {
			argv = append(argv, "pmtudisc")
		} else {
			argv = append(argv, "nopmtudisc")
		}
		if spec.IsIgnoreDf {
			argv = append(argv, "ignore-df")
		}
	} else {
		if spec.EncapLimit != nil {
			argv = append(argv, "encaplimit", strconv.Itoa(*spec.EncapLimit))
		}
		if spec.TrafficClass != "" && spec.TrafficClass != "inherit" {
			argv = append(argv, "tclass", spec.TrafficClass)
		}
		if spec.FlowLabel != "" && spec.FlowLabel != "inherit" {
			argv = append(argv, "flowlabel", spec.FlowLabel)
		}
	}

	if spec.FwMark != nil {
		argv = append(argv, "fwmark", strconv.FormatUint(uint64(*spec.FwMark), 10))
	}
	if spec.BindDevice != "" {
		argv = append(argv, "dev", spec.BindDevice)
	}
	return argv
}

// tosWord renders the type of service, defaulting to "inherit".
func tosWord(tos string) string {
	if strings.TrimSpace(tos) == "" {
		return "inherit"
	}
	return tos
}

// ttlWord renders a TTL, spelling zero as the kernel's "inherit".
func ttlWord(ttl int) string {
	if ttl <= 0 {
		return "inherit"
	}
	return strconv.Itoa(ttl)
}

// DeleteArgs builds `ip link del <name>`.
func DeleteArgs(ipBin, name string) []string {
	return []string{ipBin, "link", "del", name}
}

// SetMTUArgs builds `ip link set dev <name> mtu <mtu>`.
func SetMTUArgs(ipBin, name string, mtu int) []string {
	return []string{ipBin, "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)}
}

// SetTxQueueLenArgs builds `ip link set dev <name> txqueuelen <n>`.
func SetTxQueueLenArgs(ipBin, name string, length int) []string {
	return []string{ipBin, "link", "set", "dev", name, "txqueuelen", strconv.Itoa(length)}
}

// SetUpArgs builds `ip link set dev <name> up`.
func SetUpArgs(ipBin, name string) []string {
	return []string{ipBin, "link", "set", "dev", name, "up"}
}

// SetDownArgs builds `ip link set dev <name> down`.
func SetDownArgs(ipBin, name string) []string {
	return []string{ipBin, "link", "set", "dev", name, "down"}
}

// AddAddressArgs builds `ip addr add <addr>/<len> [peer <peer>] dev <name>`.
// The peer is named only when the prefix length leaves no room for it in the
// subnet; see Address.NeedsExplicitPeer.
func AddAddressArgs(ipBin, name string, addr Address) []string {
	argv := []string{ipBin, "addr", "add", addr.String()}
	if addr.NeedsExplicitPeer() {
		argv = append(argv, "peer", addr.Peer)
	}
	return append(argv, "dev", name)
}

// DelAddressArgs builds `ip addr del <addr>/<len> [peer <peer>] dev <name>`.
func DelAddressArgs(ipBin, name string, addr Address) []string {
	argv := []string{ipBin, "addr", "del", addr.String()}
	if addr.NeedsExplicitPeer() {
		argv = append(argv, "peer", addr.Peer)
	}
	return append(argv, "dev", name)
}
