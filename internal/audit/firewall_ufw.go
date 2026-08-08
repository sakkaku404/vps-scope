package audit

import (
	"regexp"
	"strings"
)

func parsePanelUFW(output string) hostFirewallSnapshot {
	defaultDeny := regexp.MustCompile(`(?mi)^Default:\s+deny \(incoming\)`).MatchString(output)
	policy := "unknown"
	if defaultDeny {
		policy = "deny"
	} else if regexp.MustCompile(`(?mi)^Default:\s+allow \(incoming\)`).MatchString(output) {
		policy = "allow"
	}
	f := hostFirewallSnapshot{available: true, active: regexp.MustCompile(`(?mi)^Status:\s+active\s*$`).MatchString(output), defaultDeny: defaultDeny, defaultDenyByFamily: map[string]bool{"any": defaultDeny}, defaultPolicyByFamily: map[string]string{"any": policy}, lines: lines(output), backend: "ufw"}
	f.rules = parseUFWRules(f.lines)
	return f
}

func parseUFWRules(input []string) []firewallRule {
	var out []firewallRule
	actionRE := regexp.MustCompile(`\s+(ALLOW|DENY|REJECT) IN\s+`)
	for _, line := range input {
		match := actionRE.FindStringSubmatchIndex(line)
		if len(match) < 4 {
			continue
		}
		target := strings.TrimSpace(line[:match[0]])
		action := "allow"
		if strings.ToUpper(line[match[2]:match[3]]) != "ALLOW" {
			action = "deny"
		}
		family := "ipv4"
		if strings.Contains(target, "(v6)") || strings.Contains(line, "Anywhere (v6)") {
			family = "ipv6"
		}
		target = strings.TrimSpace(strings.ReplaceAll(target, "(v6)", ""))
		if target == "Anywhere" {
			source := strings.TrimSpace(line[match[1]:])
			if strings.HasPrefix(source, "Anywhere") {
				source = "any"
			}
			out = append(out, firewallRule{Family: family, Protocol: "any", Port: "any", Source: source, Action: action, Origin: "ufw-user", Raw: line})
			continue
		}
		port, protocol := target, "any"
		if parts := strings.SplitN(target, "/", 2); len(parts) == 2 {
			port, protocol = parts[0], strings.ToLower(parts[1])
		}
		if !validPort(port) {
			continue
		}
		source := strings.TrimSpace(line[match[1]:])
		if strings.HasPrefix(source, "Anywhere") {
			source = "any"
		}
		out = append(out, firewallRule{Family: family, Protocol: protocol, Port: port, Source: source, Action: action, Origin: "ufw-user", Raw: line})
	}
	return out
}
