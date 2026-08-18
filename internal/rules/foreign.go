package rules

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// ForeignRule is a redirecting rule outside the panel's namespace.
//
// The panel never touches one. It reports them because a DNAT installed by
// Docker, firewalld or a hand-written script in a built-in chain can take a
// packet before the panel's own rule ever sees it, and the symptom — a rule
// that is installed, verified and does nothing — is otherwise unexplainable
// (§6.2, §9).
type ForeignRule struct {
	Table string `json:"table"`
	Chain string `json:"chain"`
	Text  string `json:"text"`

	// Protocol, Address and the ports are what could be read out of the rule.
	// They are best-effort: a rule using a set, a mark or an ipset match will
	// leave them empty, and an unparsed rule is still reported rather than
	// dropped, because an operator reading the text can see what the parser
	// could not.
	Protocol string `json:"protocol,omitempty"`
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port,omitempty"`
	PortEnd  int    `json:"port_end,omitempty"`

	// Manager names the software that appears to own the rule, when the chain
	// it lives in gives it away.
	Manager string `json:"manager,omitempty"`
}

// Describe renders the rule the way a report names it.
func (f ForeignRule) Describe() string {
	where := f.Chain
	if f.Table != "" {
		where = f.Table + "/" + f.Chain
	}
	if f.Manager != "" {
		return fmt.Sprintf("%s in %s, which belongs to %s", strings.TrimSpace(f.Text), where, f.Manager)
	}
	return fmt.Sprintf("%s in %s", strings.TrimSpace(f.Text), where)
}

// Ports returns the range this rule claims.
func (f ForeignRule) Ports() PortRange { return PortRange{Port: f.Port, End: f.PortEnd} }

// Shadows reports whether this foreign rule could take traffic the given rule
// expects.
//
// It errs towards saying yes. A foreign rule whose port could not be read is
// treated as not overlapping, because reporting every DNAT on the host against
// every panel rule would bury the real collisions; but where the ports do
// overlap and the addresses are compatible, it is reported even if the protocol
// could not be determined.
func (f ForeignRule) Shadows(spec RouteSpec) bool {
	if f.Port == 0 {
		return false
	}
	if !portRangesIntersect(f.Ports(), spec.BindPorts) {
		return false
	}
	if f.Protocol != "" && spec.Protocol != ProtocolBoth &&
		!strings.EqualFold(f.Protocol, string(spec.Protocol)) {
		return false
	}
	return addressesIntersect(f.Address, spec.BindAddress)
}

// portRangesIntersect reports whether two ranges share a port.
func portRangesIntersect(a, b PortRange) bool {
	aEnd, bEnd := a.Port, b.Port
	if a.IsRange() {
		aEnd = a.End
	}
	if b.IsRange() {
		bEnd = b.End
	}
	return a.Port <= bEnd && b.Port <= aEnd
}

// addressesIntersect reports whether two bind addresses can receive the same
// packet. Either one meaning "any local address" covers the other.
func addressesIntersect(a, b string) bool {
	if isUnspecified(a) || isUnspecified(b) {
		return true
	}
	left, err := netip.ParseAddr(strings.TrimSpace(a))
	if err != nil {
		return true // unparsed: reported rather than silently dismissed
	}
	right, err := netip.ParseAddr(strings.TrimSpace(b))
	if err != nil {
		return true
	}
	return left.Unmap() == right.Unmap()
}

// ForeignView is what a backend can see of the rest of the host's netfilter
// configuration.
type ForeignView struct {
	// Readable reports whether the system ruleset could be read at all. A host
	// that refuses the read is reported as unknown rather than as clean: saying
	// "no foreign rules" because the listing failed is exactly the kind of
	// false assurance this panel exists to avoid.
	Readable bool   `json:"readable"`
	Detail   string `json:"detail,omitempty"`

	Rules []ForeignRule `json:"rules"`
	// Managers names the other software found managing netfilter here, derived
	// from the chains and tables it creates.
	Managers []string `json:"managers,omitempty"`
}

// ShadowsOf returns the foreign rules that could take traffic from one rule.
func (v ForeignView) ShadowsOf(spec RouteSpec) []ForeignRule {
	var out []ForeignRule
	for _, rule := range v.Rules {
		if rule.Shadows(spec) {
			out = append(out, rule)
		}
	}
	return out
}

// managerChains recognises the software that owns a chain by the name it gives
// it. These are the tools that routinely manage netfilter on a server this
// panel would be installed on, and each of them installs DNAT rules in the
// built-in chains.
var managerChains = []struct {
	prefix  string
	manager string
}{
	{"DOCKER", "Docker"},
	{"KUBE-", "Kubernetes"},
	{"CNI-", "a container network plugin"},
	{"cali-", "Calico"},
	{"LIBVIRT_", "libvirt"},
	{"ufw-", "ufw"},
	{"ufw6-", "ufw"},
	{"f2b-", "fail2ban"},
	{"FIREWALLD", "firewalld"},
	{"PRE_public", "firewalld"},
	{"POST_public", "firewalld"},
	{"PREROUTING_direct", "firewalld"},
	{"OUTPUT_direct", "firewalld"},
	{"POSTROUTING_direct", "firewalld"},
	{"SHOREWALL", "Shorewall"},
	{"MINIUPNPD", "miniupnpd"},
}

// managerOf names the software owning a chain, or "" when nothing is
// recognised. A rule in a built-in chain has no owner to name: that is exactly
// the case where an operator has to look at it themselves.
func managerOf(chain string) string {
	trimmed := strings.TrimSpace(chain)
	for _, entry := range managerChains {
		if strings.HasPrefix(trimmed, entry.prefix) {
			return entry.manager
		}
	}
	return ""
}

// managerNames collects the distinct managers in a set of rules, sorted so the
// report is stable.
func managerNames(rules []ForeignRule) []string {
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.Manager != "" {
			seen[rule.Manager] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// isRedirecting reports whether a line of rule text sends traffic somewhere
// else. Only those can shadow the panel: an accept or a drop in a nat chain
// changes nothing about where a packet goes.
func isRedirecting(lower string) bool {
	return strings.Contains(lower, "dnat") || strings.Contains(lower, "redirect")
}

// ---------------------------------------------------------------- nftables

// ParseNftForeign reads `nft list ruleset` and returns every redirecting rule
// outside the panel's own table.
//
// The panel's table is skipped by name rather than by content: a rule of the
// panel's is not foreign even when it looks exactly like one that is. Which
// table a line belongs to is tracked by counting braces rather than by assuming
// one level of nesting, because a table also holds counter, set and map blocks
// of its own — and treating one of those closing braces as the table's own is
// how the panel came to report its own rules as somebody else's.
func ParseNftForeign(out string) []ForeignRule {
	var found []ForeignRule
	table, family, chain := "", "", ""
	depth := 0

	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A rule can carry balanced braces of its own — an address set, or the
		// map a load-balanced dnat renders as — so nesting is the difference
		// between the two counts rather than the presence of either.
		delta := strings.Count(line, "{") - strings.Count(line, "}")

		switch {
		case depth == 0:
			if strings.HasPrefix(line, "table ") {
				// "table <family> <name> {"
				if fields := strings.Fields(strings.TrimSuffix(line, "{")); len(fields) >= 3 {
					family, table = fields[1], fields[2]
				}
			}

		case depth == 1:
			// Inside a table: a chain opens one, and so do the counter, set and
			// map blocks, which hold no rules and are simply descended past.
			if delta > 0 && strings.HasPrefix(line, "chain ") {
				chain = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "chain "), "{"))
			}

		case chain != "" && delta == 0:
			// A line inside a chain. The chain's own type and policy lines land
			// here too and are filtered out by not redirecting anything.
			if table != TableName && isRedirecting(strings.ToLower(line)) {
				rule := ForeignRule{
					Table: strings.TrimSpace(family + " " + table), Chain: chain,
					Text: line, Manager: managerOf(chain),
				}
				rule.Protocol, rule.Address, rule.Port, rule.PortEnd = parseNftMatch(line)
				found = append(found, rule)
			}
		}

		depth += delta
		if depth < 2 {
			chain = ""
		}
		if depth < 1 {
			table, family, depth = "", "", 0
		}
	}
	return found
}

// parseNftMatch pulls the protocol, destination address and destination port
// out of an nftables rule as nft prints it.
func parseNftMatch(line string) (protocol, address string, port, portEnd int) {
	fields := strings.Fields(line)
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "daddr":
			// Preceded by the family keyword: "ip daddr <address>".
			if i+1 < len(fields) && address == "" {
				address = strings.Trim(fields[i+1], ",")
			}
		case "dport":
			if i+1 < len(fields) && port == 0 {
				port, portEnd = parsePortToken(fields[i+1])
			}
			if i > 0 && protocol == "" {
				if candidate := strings.ToLower(fields[i-1]); candidate == "tcp" || candidate == "udp" {
					protocol = candidate
				}
			}
		}
	}
	// A rule can name the protocol without matching a port, e.g.
	// "meta l4proto tcp".
	if protocol == "" {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, " tcp "):
			protocol = "tcp"
		case strings.Contains(lower, " udp "):
			protocol = "udp"
		}
	}
	if address != "" {
		if _, err := netip.ParsePrefix(address); err == nil {
			address = strings.SplitN(address, "/", 2)[0]
		} else if _, err := netip.ParseAddr(address); err != nil {
			address = "" // a set reference or a variable, not an address
		}
	}
	return protocol, address, port, portEnd
}

// parsePortToken reads "8080" or "20000-20100" as nft prints them.
func parsePortToken(token string) (int, int) {
	trimmed := strings.Trim(token, "{},")
	if start, end, ok := strings.Cut(trimmed, "-"); ok {
		first, err1 := strconv.Atoi(strings.TrimSpace(start))
		second, err2 := strconv.Atoi(strings.TrimSpace(end))
		if err1 != nil || err2 != nil {
			return 0, 0
		}
		return first, second
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, 0
	}
	return value, 0
}

// ---------------------------------------------------------------- iptables

// ParseIptablesForeign reads `iptables-save -t nat` and returns every
// redirecting rule outside the panel's own chains.
func ParseIptablesForeign(out, table string) []ForeignRule {
	var found []ForeignRule
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chain := fields[1]
		if IsPanelChain(chain) {
			continue
		}
		if !isRedirecting(strings.ToLower(line)) {
			continue
		}
		// A jump into one of the panel's own chains is the panel's rule, not a
		// foreign one, even though it lives in a built-in chain.
		if target, ok := iptablesTarget(fields); ok && IsPanelChain(target) {
			continue
		}

		rule := ForeignRule{Table: table, Chain: chain, Text: line, Manager: managerOf(chain)}
		rule.Protocol, rule.Address, rule.Port, rule.PortEnd = parseIptablesMatch(fields)
		found = append(found, rule)
	}
	return found
}

// iptablesTarget returns the -j target of a rule.
func iptablesTarget(fields []string) (string, bool) {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "-j" {
			return fields[i+1], true
		}
	}
	return "", false
}

// parseIptablesMatch pulls the protocol, destination address and destination
// port out of an iptables rule as iptables-save prints it.
func parseIptablesMatch(fields []string) (protocol, address string, port, portEnd int) {
	for i := 0; i < len(fields)-1; i++ {
		switch fields[i] {
		case "-p", "--protocol":
			protocol = strings.ToLower(fields[i+1])
		case "-d", "--destination":
			address = fields[i+1]
		case "--dport", "--destination-port":
			// iptables spells a range with a colon: "--dport 20000:20100".
			token := fields[i+1]
			if start, end, ok := strings.Cut(token, ":"); ok {
				first, err1 := strconv.Atoi(start)
				second, err2 := strconv.Atoi(end)
				if err1 == nil && err2 == nil {
					port, portEnd = first, second
				}
				continue
			}
			if value, err := strconv.Atoi(token); err == nil {
				port = value
			}
		}
	}
	if protocol == "all" {
		protocol = ""
	}
	if address != "" {
		if prefix, err := netip.ParsePrefix(address); err == nil {
			if prefix.Bits() != prefix.Addr().BitLen() {
				// A whole subnet rather than one host: reported, but not treated
				// as claiming a specific address.
				return protocol, "", port, portEnd
			}
			address = prefix.Addr().String()
		} else if _, err := netip.ParseAddr(address); err != nil {
			address = ""
		}
	}
	return protocol, address, port, portEnd
}
