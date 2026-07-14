package audit

import (
	"regexp"
	"strings"
	"time"
)

// firewallRule is the normalized host-firewall unit consumed by workload
// checks. Family is ipv4, ipv6, or any; source is "any" or a restricted CIDR.
type firewallRule struct {
	Family, Protocol, Port, Source, Action, Origin, Raw string
}

func collectHostFirewall(cmd Commander) panelUFW {
	var inactive panelUFW
	var active panelUFW
	if cmd.Exists("ufw") {
		r := cmd.Run(12*time.Second, "ufw", "status", "verbose")
		if r.Err == nil && !r.Truncated {
			f := parsePanelUFW(r.Stdout)
			if f.active {
				active = f
			}
			inactive = f
		}
	}
	// UFW and products such as Hiddify can both install rules into the same
	// effective nftables INPUT path.  UFW's summary intentionally omits rules
	// inserted by other managers, so merge the live nftables view instead of
	// returning as soon as an active UFW frontend is found.
	if active.available && cmd.Exists("nft") {
		r := cmd.Run(15*time.Second, "nft", "list", "ruleset")
		if r.Err == nil && !r.Truncated {
			nft := parseNFTFirewall(r.Stdout)
			active.rules = append(active.rules, nft.rules...)
			active.backend = "ufw+nftables"
			for family, deny := range nft.defaultDenyByFamily {
				active.defaultDenyByFamily[family] = active.defaultDenyByFamily[family] || deny
			}
			active.defaultDeny = active.defaultDeny || nft.defaultDeny
		}
		return active
	}
	if active.available {
		return active
	}
	if cmd.Exists("firewall-cmd") {
		state := cmd.Run(8*time.Second, "firewall-cmd", "--state")
		if strings.TrimSpace(state.Stdout) == "running" {
			if f := collectFirewalld(cmd); f.available {
				return f
			}
		}
	}
	if cmd.Exists("nft") {
		r := cmd.Run(15*time.Second, "nft", "list", "ruleset")
		if r.Err == nil && !r.Truncated {
			return parseNFTFirewall(r.Stdout)
		}
	}
	if cmd.Exists("iptables-save") || cmd.Exists("ip6tables-save") {
		f := panelUFW{available: true, active: true, backend: "iptables", defaultDenyByFamily: map[string]bool{}}
		for _, spec := range []struct{ command, family string }{{"iptables-save", "ipv4"}, {"ip6tables-save", "ipv6"}} {
			if !cmd.Exists(spec.command) {
				continue
			}
			r := cmd.Run(12*time.Second, spec.command)
			if r.Err == nil && !r.Truncated {
				rules, deny := parseIPTablesFirewall(r.Stdout, spec.family)
				f.rules = append(f.rules, rules...)
				f.defaultDenyByFamily[spec.family] = deny
				f.defaultDeny = f.defaultDeny || deny
				f.lines = append(f.lines, lines(r.Stdout)...)
			}
		}
		return f
	}
	return inactive
}

func collectFirewalld(cmd Commander) panelUFW {
	zonesResult := cmd.Run(10*time.Second, "firewall-cmd", "--get-active-zones")
	if zonesResult.Err != nil || zonesResult.Truncated {
		return panelUFW{}
	}
	f := panelUFW{available: true, active: true, backend: "firewalld", defaultDenyByFamily: map[string]bool{}}
	servicePorts := map[string]string{"ssh": "22", "http": "80", "https": "443"}
	for _, zone := range parseFirewalldActiveZones(zonesResult.Stdout) {
		detail := cmd.Run(10*time.Second, "firewall-cmd", "--zone="+zone, "--list-all")
		if detail.Err != nil || detail.Truncated {
			return panelUFW{}
		}
		f.lines = append(f.lines, lines(detail.Stdout)...)
		restricted := false
		for _, line := range lines(detail.Stdout) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "sources:") && strings.TrimSpace(strings.TrimPrefix(trimmed, "sources:")) != "" {
				restricted = true
			}
			if strings.HasPrefix(trimmed, "target:") && strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(trimmed, "target:")), "DROP") {
				f.defaultDeny = true
				f.defaultDenyByFamily["any"] = true
			}
		}
		analysis := parseFirewalldZone(detail.Stdout)
		source := "any"
		if restricted {
			source = "zone-sources"
		}
		for _, item := range analysis.ports {
			parts := strings.SplitN(item, "/", 2)
			if len(parts) != 2 || !validPort(parts[0]) {
				continue
			}
			f.rules = append(f.rules, firewallRule{Family: "any", Protocol: parts[1], Port: parts[0], Source: source, Action: "allow", Origin: "firewalld-zone", Raw: item})
		}
		for _, service := range analysis.services {
			if port := servicePorts[service]; port != "" {
				f.rules = append(f.rules, firewallRule{Family: "any", Protocol: "tcp", Port: port, Source: source, Action: "allow", Origin: "firewalld-zone", Raw: service})
			}
		}
	}
	return f
}

func parseUFWRules(input []string) []firewallRule {
	var out []firewallRule
	for _, line := range input {
		idx := strings.Index(line, "ALLOW IN")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(line[:idx])
		family := "ipv4"
		if strings.Contains(target, "(v6)") || strings.Contains(line, "Anywhere (v6)") {
			family = "ipv6"
		}
		target = strings.TrimSpace(strings.ReplaceAll(target, "(v6)", ""))
		port, protocol := target, "any"
		if parts := strings.SplitN(target, "/", 2); len(parts) == 2 {
			port, protocol = parts[0], strings.ToLower(parts[1])
		}
		if !validPort(port) {
			continue
		}
		source := strings.TrimSpace(line[idx+len("ALLOW IN"):])
		if strings.HasPrefix(source, "Anywhere") {
			source = "any"
		}
		out = append(out, firewallRule{Family: family, Protocol: protocol, Port: port, Source: source, Action: "allow", Origin: "ufw-user", Raw: line})
	}
	return out
}

func parseNFTFirewall(output string) panelUFW {
	f := panelUFW{available: true, active: true, backend: "nftables", lines: lines(output), defaultDenyByFamily: map[string]bool{}}
	collectNFTDefaultPolicies(&f, output)
	f.rules = parseNFTHookRules(f.lines, "input")
	if len(f.rules) > 0 {
		return f
	}
	// Keep accepting compact single-line fixtures and unusual nft renderers.
	// Real multi-line rulesets take the input-chain-only path above.
	ruleRE := regexp.MustCompile(`(?i)\b(tcp|udp)\s+dport\s+([0-9]+)\b([^\n]*?)\b(accept|drop|reject)\b`)
	for _, line := range f.lines {
		m := ruleRE.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		family := "any"
		lower := strings.ToLower(line)
		if strings.Contains(lower, " ip6 ") || strings.Contains(lower, "ip6 saddr") {
			family = "ipv6"
		} else if strings.Contains(lower, " ip ") || strings.Contains(lower, "ip saddr") {
			family = "ipv4"
		}
		source := "any"
		if s := regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+saddr\s+([^\s]+)`).FindStringSubmatch(line); len(s) > 1 {
			source = s[1]
		}
		outcome := strings.ToLower(m[4])
		if outcome == "accept" {
			outcome = "allow"
		} else {
			outcome = "deny"
		}
		f.rules = append(f.rules, firewallRule{Family: family, Protocol: strings.ToLower(m[1]), Port: m[2], Source: source, Action: outcome, Origin: "nft-unknown", Raw: line})
	}
	return f
}

type nftInputChain struct {
	family, table, name string
	baseInput           bool
	lines               []string
}

// parseNFTInputRules follows only base chains with hook input and chains they
// jump or go to. Parsing every accept statement in a ruleset would mistake
// OUTPUT, FORWARD, Docker NAT, and unrelated tables for host ingress policy.
func parseNFTInputRules(input []string) []firewallRule { return parseNFTHookRules(input, "input") }

func parseNFTHookRules(input []string, hook string) []firewallRule {
	tableRE := regexp.MustCompile(`(?i)^table\s+(ip|ip6|inet)\s+([^\s{]+)\s*\{`)
	chainRE := regexp.MustCompile(`(?i)^chain\s+([^\s{]+)\s*\{`)
	tableFamily, tableName := "", ""
	var current *nftInputChain
	chains := map[string]*nftInputChain{}
	for _, raw := range input {
		trimmed := strings.TrimSpace(raw)
		if current == nil {
			if m := tableRE.FindStringSubmatch(trimmed); len(m) > 2 {
				tableFamily = map[string]string{"ip": "ipv4", "ip6": "ipv6", "inet": "any"}[strings.ToLower(m[1])]
				tableName = m[2]
				continue
			}
			if tableFamily != "" {
				if m := chainRE.FindStringSubmatch(trimmed); len(m) > 1 {
					current = &nftInputChain{family: tableFamily, table: tableName, name: m[1]}
					current.baseInput = strings.Contains(strings.ToLower(trimmed), "hook "+hook)
					chains[nftChainKey(tableFamily, tableName, m[1])] = current
					continue
				}
				if trimmed == "}" {
					tableFamily, tableName = "", ""
				}
			}
			continue
		}
		if trimmed == "}" {
			current = nil
			continue
		}
		current.lines = append(current.lines, trimmed)
		if strings.Contains(strings.ToLower(trimmed), "hook "+hook) {
			current.baseInput = true
		}
	}

	jumpRE := regexp.MustCompile(`(?i)\b(?:jump|goto)\s+([^\s;]+)`)
	reachable := map[string]bool{}
	var visit func(*nftInputChain)
	visit = func(chain *nftInputChain) {
		key := nftChainKey(chain.family, chain.table, chain.name)
		if reachable[key] {
			return
		}
		reachable[key] = true
		for _, line := range chain.lines {
			for _, match := range jumpRE.FindAllStringSubmatch(line, -1) {
				if next := chains[nftChainKey(chain.family, chain.table, match[1])]; next != nil {
					visit(next)
				}
			}
		}
	}
	for _, chain := range chains {
		if chain.baseInput {
			visit(chain)
		}
	}

	portSets := parseNFTPortSets(strings.Join(input, "\n"))
	var out []firewallRule
	for key := range reachable {
		chain := chains[key]
		origin := "nft-reachable"
		if chain.baseInput {
			origin = "nft-" + hook
		}
		for _, line := range chain.lines {
			out = append(out, parseNFTRuleLine(line, chain.family, origin, portSets)...)
		}
	}
	return out
}

func nftChainKey(family, table, chain string) string {
	return family + "\x00" + table + "\x00" + chain
}

type nftPortSet struct {
	ports   []string
	actions map[string]string
}

// parseNFTPortSets supports the common nftables set/map forms used by UFW
// companions and container stacks. It deliberately extracts only numeric
// inet_service ports; unknown expressions stay unknown instead of being
// promoted to public allows.
func parseNFTPortSets(input string) map[string]nftPortSet {
	sets := map[string]nftPortSet{}
	blockRE := regexp.MustCompile(`(?is)\b(?:set|map)\s+([A-Za-z0-9_.-]+)\s*\{.*?\belements\s*=\s*\{(.*?)\}`)
	entryRE := regexp.MustCompile(`\b([0-9]{1,5})\b\s*(?::\s*(accept|drop|reject))?`)
	for _, block := range blockRE.FindAllStringSubmatch(input, -1) {
		set := nftPortSet{actions: map[string]string{}}
		for _, entry := range entryRE.FindAllStringSubmatch(block[2], -1) {
			if !validPort(entry[1]) {
				continue
			}
			set.ports = append(set.ports, entry[1])
			if entry[2] != "" {
				set.actions[entry[1]] = strings.ToLower(entry[2])
			}
		}
		if len(set.ports) > 0 {
			sets[block[1]] = set
		}
	}
	return sets
}

func parseNFTRuleLine(line, family, origin string, portSets map[string]nftPortSet) []firewallRule {
	line = expandNFTPortSet(line, portSets)
	ruleRE := regexp.MustCompile(`(?i)\b(tcp|udp)\s+dport\s+(\{[^}]+\}|[0-9]+)(?:\s|$)([^\n]*?)\b(accept|drop|reject)\b`)
	m := ruleRE.FindStringSubmatch(line)
	if len(m) == 0 {
		return nil
	}
	source := "any"
	if s := regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+saddr\s+([^\s]+)`).FindStringSubmatch(line); len(s) > 1 {
		source = s[1]
	} else if d := regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+daddr\s+([^\s]+)`).FindStringSubmatch(line); len(d) > 1 {
		// Multicast/broadcast destination rules are not equivalent to a public
		// unicast allow, even when their source is unrestricted.
		source = "destination:" + d[1]
	}
	action := strings.ToLower(m[4])
	if action == "accept" {
		action = "allow"
	} else {
		action = "deny"
	}
	ports := strings.Split(strings.Trim(m[2], "{} "), ",")
	var out []firewallRule
	for _, port := range ports {
		port = strings.TrimSpace(port)
		if validPort(port) {
			out = append(out, firewallRule{Family: family, Protocol: strings.ToLower(m[1]), Port: port, Source: source, Action: action, Origin: origin, Raw: line})
		}
	}
	return out
}

func expandNFTPortSet(line string, portSets map[string]nftPortSet) string {
	pattern := regexp.MustCompile(`(?i)\b(tcp|udp)\s+dport\s+(vmap\s+)?@([A-Za-z0-9_.-]+)`)
	match := pattern.FindStringSubmatch(line)
	if len(match) != 4 {
		return line
	}
	set, ok := portSets[match[3]]
	if !ok || len(set.ports) == 0 {
		return line
	}
	// Verdict maps can contain mixed actions. Expand only uniform maps; a
	// mixed map is intentionally left unresolved rather than guessing.
	action := ""
	for _, port := range set.ports {
		if set.actions[port] == "" {
			continue
		}
		if action == "" {
			action = set.actions[port]
		} else if action != set.actions[port] {
			return line
		}
	}
	if action == "" {
		return strings.Replace(line, match[0], match[1]+" dport { "+strings.Join(set.ports, ", ")+" }", 1)
	}
	replacement := match[1] + " dport { " + strings.Join(set.ports, ", ") + " } " + action
	return strings.Replace(line, match[0], replacement, 1)
}

func collectNFTDefaultPolicies(f *panelUFW, output string) {
	collectNFTHookDefaultPolicies(f.defaultDenyByFamily, output, "input")
	for _, deny := range f.defaultDenyByFamily {
		f.defaultDeny = f.defaultDeny || deny
	}
}

func collectNFTHookDefaultPolicies(target map[string]bool, output, hook string) {
	tableFamily := ""
	tableRE := regexp.MustCompile(`(?i)^table\s+(ip|ip6|inet)\s+`)
	policyRE := regexp.MustCompile(`(?i)hook\s+` + regexp.QuoteMeta(hook) + `\b.*\bpolicy\s+(drop|reject)\b`)
	for _, line := range lines(output) {
		trimmed := strings.TrimSpace(line)
		if m := tableRE.FindStringSubmatch(trimmed); len(m) > 1 {
			tableFamily = map[string]string{"ip": "ipv4", "ip6": "ipv6", "inet": "any"}[strings.ToLower(m[1])]
		}
		if policyRE.MatchString(trimmed) {
			target[tableFamily] = true
		}
	}
}

func parseIPTablesFirewall(output, family string) ([]firewallRule, bool) {
	defaultDeny := regexp.MustCompile(`(?m)^:INPUT\s+(DROP|REJECT)\b`).MatchString(output)
	var out []firewallRule
	for _, line := range lines(output) {
		if !strings.HasPrefix(line, "-A INPUT ") || !containsAny(line, "-j ACCEPT", "-j DROP", "-j REJECT") {
			continue
		}
		fields := strings.Fields(line)
		value := func(flag, fallback string) string {
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == flag {
					return fields[i+1]
				}
			}
			return fallback
		}
		port := value("--dport", "")
		if !validPort(port) {
			continue
		}
		action := "deny"
		if value("-j", "") == "ACCEPT" {
			action = "allow"
		}
		source := value("-s", "any")
		if source == "0.0.0.0/0" || source == "::/0" {
			source = "any"
		}
		out = append(out, firewallRule{Family: family, Protocol: value("-p", "any"), Port: port, Source: source, Action: action, Origin: "iptables-input", Raw: line})
	}
	return out, defaultDeny
}

func firewallDisposition(f panelUFW, port, protocol string) string {
	return firewallDispositionFamily(f, port, protocol, "any")
}

func firewallDispositionFamily(f panelUFW, port, protocol, family string) string {
	if !f.available {
		return "unknown"
	}
	if !f.active {
		return "inactive"
	}
	rules := f.rules
	if len(rules) == 0 && len(f.lines) > 0 {
		rules = parseUFWRules(f.lines)
	}
	restricted := false
	for _, rule := range rules {
		if family != "any" && rule.Family != "any" && rule.Family != family {
			continue
		}
		if rule.Port != port || (rule.Protocol != "any" && rule.Protocol != protocol) {
			continue
		}
		if rule.Action != "allow" {
			continue
		}
		if rule.Source == "any" {
			return "allow-anywhere"
		}
		restricted = true
	}
	if restricted {
		return "allow-restricted"
	}
	if defaultDenyForFamily(f, family) {
		return "blocked-by-default"
	}
	return "no-explicit-rule"
}

func defaultDenyForFamily(f panelUFW, family string) bool {
	if len(f.defaultDenyByFamily) == 0 {
		return f.defaultDeny
	}
	if f.defaultDenyByFamily["any"] {
		return true
	}
	if family == "any" {
		return f.defaultDenyByFamily["ipv4"] && f.defaultDenyByFamily["ipv6"]
	}
	return f.defaultDenyByFamily[family]
}

func listenerAddressFamily(address string) string {
	if address == "*" || address == "::" || address == "0.0.0.0" {
		return "any"
	}
	if strings.Contains(address, ":") && !strings.Contains(address, ".") {
		return "ipv6"
	}
	return "ipv4"
}

func firewallEvidenceSource(f panelUFW) string {
	if f.backend == "" {
		return "host firewall"
	}
	return f.backend
}
