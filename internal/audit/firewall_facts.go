package audit

import (
	"regexp"
	"strings"
	"time"
)

// firewallRule is the normalized host-firewall unit consumed by workload
// checks. Family is ipv4, ipv6, or any; source is "any" or a restricted CIDR.
type firewallRule struct {
	Family, Protocol, Port, Source, Action, Raw string
}

func collectHostFirewall(cmd Commander) panelUFW {
	var inactive panelUFW
	if cmd.Exists("ufw") {
		r := cmd.Run(12*time.Second, "ufw", "status", "verbose")
		if r.Err == nil && !r.Truncated {
			f := parsePanelUFW(r.Stdout)
			if f.active {
				return f
			}
			inactive = f
		}
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
		f := panelUFW{available: true, active: true, backend: "iptables"}
		for _, spec := range []struct{ command, family string }{{"iptables-save", "ipv4"}, {"ip6tables-save", "ipv6"}} {
			if !cmd.Exists(spec.command) {
				continue
			}
			r := cmd.Run(12*time.Second, spec.command)
			if r.Err == nil && !r.Truncated {
				rules, deny := parseIPTablesFirewall(r.Stdout, spec.family)
				f.rules = append(f.rules, rules...)
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
	f := panelUFW{available: true, active: true, backend: "firewalld"}
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
			f.rules = append(f.rules, firewallRule{Family: "any", Protocol: parts[1], Port: parts[0], Source: source, Action: "allow", Raw: item})
		}
		for _, service := range analysis.services {
			if port := servicePorts[service]; port != "" {
				f.rules = append(f.rules, firewallRule{Family: "any", Protocol: "tcp", Port: port, Source: source, Action: "allow", Raw: service})
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
		out = append(out, firewallRule{Family: family, Protocol: protocol, Port: port, Source: source, Action: "allow", Raw: line})
	}
	return out
}

func parseNFTFirewall(output string) panelUFW {
	f := panelUFW{available: true, active: true, backend: "nftables", lines: lines(output)}
	f.defaultDeny = regexp.MustCompile(`(?i)hook\s+input[^\n]*policy\s+drop`).MatchString(output)
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
		f.rules = append(f.rules, firewallRule{Family: family, Protocol: strings.ToLower(m[1]), Port: m[2], Source: source, Action: outcome, Raw: line})
	}
	return f
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
		out = append(out, firewallRule{Family: family, Protocol: value("-p", "any"), Port: port, Source: source, Action: action, Raw: line})
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
	if f.defaultDeny {
		return "blocked-by-default"
	}
	return "no-explicit-rule"
}

func listenerAddressFamily(address string) string {
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
