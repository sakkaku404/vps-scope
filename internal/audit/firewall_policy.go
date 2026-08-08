package audit

import "strings"

func firewallDisposition(f hostFirewallSnapshot, port, protocol string) string {
	return firewallDispositionFamily(f, port, protocol, "any")
}

func firewallDispositionFamily(f hostFirewallSnapshot, port, protocol, family string) string {
	if !f.available {
		if f.collectionErr != nil {
			return "unknown"
		}
		return "inactive"
	}
	if !f.active {
		return "inactive"
	}
	rules := f.rules
	if len(rules) == 0 && len(f.lines) > 0 {
		rules = parseUFWRules(f.lines)
	}
	restricted, conditional := false, false
	orderedRules := f.backend == "iptables" || f.backend == "nftables" || f.backend == "ufw"
	for _, rule := range rules {
		if family != "any" && rule.Family != "any" && rule.Family != family {
			continue
		}
		if rule.Port != "any" && rule.Port != port || rule.Protocol != "any" && rule.Protocol != protocol {
			continue
		}
		if rule.Action != "allow" {
			if orderedRules && rule.Action == "deny" && rule.Source == "any" && !rule.Conditional {
				if conditional {
					return "conditional-unknown"
				}
				if restricted {
					return "allow-restricted"
				}
				return "blocked-by-explicit-rule"
			}
			continue
		}
		if rule.InputInterface == "lo" || rule.InputInterface == "lo+" {
			continue
		}
		if rule.Conditional {
			conditional = true
			continue
		}
		if rule.Source == "any" {
			return "allow-anywhere"
		}
		restricted = true
	}
	policy := defaultFirewallPolicyForFamily(f, family)
	if policy == "allow" {
		return "allow-anywhere"
	}
	if conditional {
		return "conditional-unknown"
	}
	if restricted {
		return "allow-restricted"
	}
	switch policy {
	case "deny":
		return "blocked-by-default"
	case "allow":
		return "allow-anywhere"
	}
	return "no-explicit-rule"
}

func setDefaultFirewallPolicy(f *hostFirewallSnapshot, family, policy string) {
	if f.defaultPolicyByFamily == nil {
		f.defaultPolicyByFamily = map[string]string{}
	}
	if f.defaultDenyByFamily == nil {
		f.defaultDenyByFamily = map[string]bool{}
	}
	f.defaultPolicyByFamily[family] = policy
	f.defaultDenyByFamily[family] = policy == "deny"
	f.defaultDeny = false
	for _, deny := range f.defaultDenyByFamily {
		f.defaultDeny = f.defaultDeny || deny
	}
}

func mergeDefaultFirewallPolicy(f *hostFirewallSnapshot, family, policy string) {
	existing := f.defaultPolicyByFamily[family]
	if existing == "" {
		setDefaultFirewallPolicy(f, family, policy)
		return
	}
	if existing == policy {
		return
	}
	// Multiple base chains are all traversed. A deny policy on any of them
	// blocks unmatched traffic; otherwise conflicting or unknown evidence is
	// retained as unknown rather than optimistically calling it allowed.
	if existing == "deny" || policy == "deny" {
		setDefaultFirewallPolicy(f, family, "deny")
		return
	}
	setDefaultFirewallPolicy(f, family, "unknown")
}

func defaultFirewallPolicyForFamily(f hostFirewallSnapshot, family string) string {
	if policy := f.defaultPolicyByFamily["any"]; policy != "" {
		return policy
	}
	if family != "any" {
		if policy := f.defaultPolicyByFamily[family]; policy != "" {
			return policy
		}
		if len(f.defaultPolicyByFamily) == 0 && f.defaultDenyByFamily[family] {
			return "deny"
		}
		if len(f.defaultPolicyByFamily) == 0 && len(f.defaultDenyByFamily) == 0 && f.defaultDeny {
			return "deny"
		}
		return "unknown"
	}
	v4, v6 := f.defaultPolicyByFamily["ipv4"], f.defaultPolicyByFamily["ipv6"]
	if v4 != "" && v4 == v6 {
		return v4
	}
	if v4 == "deny" && v6 == "deny" {
		return "deny"
	}
	if len(f.defaultPolicyByFamily) == 0 && f.defaultDeny {
		return "deny"
	}
	return "unknown"
}

func defaultDenyForFamily(f hostFirewallSnapshot, family string) bool {
	if len(f.defaultPolicyByFamily) > 0 {
		return defaultFirewallPolicyForFamily(f, family) == "deny"
	}
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
	if address == "*" {
		return "any"
	}
	if address == "::" {
		return "ipv6"
	}
	if strings.Contains(address, ":") && !strings.Contains(address, ".") {
		return "ipv6"
	}
	return "ipv4"
}

func firewallEvidenceSource(f hostFirewallSnapshot) string {
	if f.backend == "" {
		return "host firewall"
	}
	return f.backend
}
