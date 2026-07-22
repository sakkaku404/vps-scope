package audit

import (
	"fmt"
	"regexp"
	"strings"
)

// iptablesChain keeps the ordered filter-table program. Host INPUT rules often
// jump into a user chain; reading only "-A INPUT" can therefore mistake a
// publicly allowed management port for one protected by the default DROP
// policy. The walker below follows reachable user chains and deliberately
// marks conditions it cannot prove instead of guessing.
type iptablesChain struct {
	policy string
	rules  []string
}

func parseIPTablesFirewall(output, family string) ([]firewallRule, bool) {
	rules, policy, _ := parseIPTablesFirewallDetailed(output, family)
	return rules, policy == "deny"
}

func parseIPTablesFirewallDetailed(output, family string) ([]firewallRule, string, int) {
	chains := map[string]*iptablesChain{}
	hasTables := strings.Contains(output, "*")
	inFilter := !hasTables
	for _, line := range lines(output) {
		switch {
		case strings.HasPrefix(line, "*"):
			inFilter = strings.EqualFold(strings.TrimSpace(line), "*filter")
			continue
		case strings.EqualFold(strings.TrimSpace(line), "COMMIT"):
			inFilter = !hasTables
			continue
		}
		if !inFilter {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.HasPrefix(fields[0], ":") {
			name := strings.TrimPrefix(fields[0], ":")
			chain := ensureIPTablesChain(chains, name)
			chain.policy = normalizeFirewallPolicy(fields[1])
			continue
		}
		if len(fields) >= 3 && fields[0] == "-P" && fields[1] == "INPUT" {
			ensureIPTablesChain(chains, "INPUT").policy = normalizeFirewallPolicy(fields[2])
			continue
		}
		if len(fields) >= 3 && fields[0] == "-A" {
			ensureIPTablesChain(chains, fields[1]).rules = append(ensureIPTablesChain(chains, fields[1]).rules, line)
		}
	}
	input := chains["INPUT"]
	if input == nil {
		return nil, "unknown", 1
	}
	policy := input.policy
	if policy == "" {
		policy = "unknown"
	}

	var out []firewallRule
	unresolved := 0
	visiting := map[string]bool{}
	visitedBroadly := map[string]bool{}
	visitedConditionally := map[string]bool{}
	var walk func(string, bool, int)
	walk = func(name string, inheritedConditional bool, depth int) {
		if depth > 64 {
			unresolved++
			return
		}
		chain := chains[name]
		if chain == nil {
			unresolved++
			return
		}
		if visiting[name] {
			unresolved++
			return
		}
		// A broad visit subsumes later conditional visits. A conditional visit
		// cannot subsume a later unconditional path to the same chain.
		if visitedBroadly[name] || inheritedConditional && visitedConditionally[name] {
			return
		}
		if !inheritedConditional {
			visitedBroadly[name] = true
		} else {
			visitedConditionally[name] = true
		}
		visiting[name] = true
		defer delete(visiting, name)

		for _, raw := range chain.rules {
			clean := stripIPTablesComment(raw)
			fields := strings.Fields(clean)
			target, gotoTarget := iptablesTarget(fields)
			if target == "" {
				continue
			}
			upperTarget := strings.ToUpper(target)
			if next := chains[target]; next != nil {
				_ = next
				walk(target, inheritedConditional || iptablesRuleHasPacketConditions(fields), depth+1)
				if gotoTarget && !iptablesRuleHasPacketConditions(fields) && !inheritedConditional {
					return
				}
				continue
			}
			if upperTarget == "RETURN" {
				if !inheritedConditional && !iptablesRuleHasPacketConditions(fields) {
					return
				}
				continue
			}
			if upperTarget != "ACCEPT" && upperTarget != "DROP" && upperTarget != "REJECT" {
				continue
			}
			rules, understood := parseIPTablesTerminalRule(clean, family, name, inheritedConditional)
			if !understood {
				unresolved++
				continue
			}
			out = append(out, rules...)
			for _, rule := range rules {
				if !rule.Conditional && rule.Protocol == "any" && rule.Port == "any" && rule.Source == "any" {
					return
				}
			}
		}
	}
	walk("INPUT", false, 0)
	return out, policy, unresolved
}

func ensureIPTablesChain(chains map[string]*iptablesChain, name string) *iptablesChain {
	if chains[name] == nil {
		chains[name] = &iptablesChain{}
	}
	return chains[name]
}

func normalizeFirewallPolicy(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "ACCEPT", "ALLOW":
		return "allow"
	case "DROP", "REJECT", "DENY":
		return "deny"
	default:
		return "unknown"
	}
}

var iptablesCommentRE = regexp.MustCompile(`(?i)\s+-m\s+comment\s+--comment\s+(?:"(?:[^"\\]|\\.)*"|'[^']*'|\S+)`)

func stripIPTablesComment(line string) string {
	return iptablesCommentRE.ReplaceAllString(line, "")
}

func iptablesTarget(fields []string) (target string, gotoTarget bool) {
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "-j", "--jump":
			return fields[i+1], false
		case "-g", "--goto":
			return fields[i+1], true
		}
	}
	return "", false
}

func iptablesRuleHasPacketConditions(fields []string) bool {
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "-j", "--jump", "-g", "--goto":
			i++
		case "-c":
			i += 2
		default:
			return true
		}
	}
	return false
}

func parseIPTablesTerminalRule(line, family, chain string, inheritedConditional bool) ([]firewallRule, bool) {
	fields := strings.Fields(line)
	target, _ := iptablesTarget(fields)
	action := "deny"
	if strings.EqualFold(target, "ACCEPT") {
		action = "allow"
	}
	rule := firewallRule{Family: family, Protocol: "any", Port: "any", Source: "any", Action: action, Origin: "iptables-reachable", Raw: line, Chain: chain, Conditional: inheritedConditional}
	if chain == "INPUT" {
		rule.Origin = "iptables-input"
	}
	ports := []string{"any"}
	for i := 2; i < len(fields); i++ {
		value := func() (string, bool) {
			if i+1 >= len(fields) {
				return "", false
			}
			i++
			return fields[i], true
		}
		switch fields[i] {
		case "-j", "--jump", "-g", "--goto":
			if _, ok := value(); !ok {
				return nil, false
			}
		case "-p", "--protocol":
			v, ok := value()
			if !ok {
				return nil, false
			}
			rule.Protocol = strings.ToLower(strings.TrimPrefix(v, "!"))
			if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "all" {
				rule.Conditional = true
			}
			if rule.Protocol == "all" {
				rule.Protocol = "any"
			}
		case "-s", "--source":
			v, ok := value()
			if !ok {
				return nil, false
			}
			rule.Source = normalizeFirewallAddress(v)
		case "-d", "--destination":
			v, ok := value()
			if !ok {
				return nil, false
			}
			v = normalizeFirewallAddress(v)
			if v != "any" {
				rule.Destination, rule.Conditional = v, true
			}
		case "-i", "--in-interface":
			v, ok := value()
			if !ok {
				return nil, false
			}
			rule.InputInterface, rule.Conditional = v, true
		case "--dport", "--destination-port", "--ctorigdstport":
			v, ok := value()
			if !ok || !validPort(v) {
				return nil, false
			}
			ports = []string{v}
		case "--dports":
			v, ok := value()
			if !ok {
				return nil, false
			}
			ports = nil
			for _, port := range strings.Split(v, ",") {
				if !validPort(port) {
					return nil, false
				}
				ports = append(ports, port)
			}
		case "--ctstate", "--state":
			v, ok := value()
			if !ok {
				return nil, false
			}
			states := strings.ToUpper(v)
			if !strings.Contains(states, "NEW") {
				return nil, true
			}
		case "-m", "--match":
			v, ok := value()
			if !ok {
				return nil, false
			}
			switch strings.ToLower(v) {
			case "tcp", "udp", "multiport", "conntrack", "state", "comment":
			default:
				rule.Conditional = true
			}
		case "--syn":
			// A positive SYN match is expected for a new TCP connection.
		case "-c":
			if _, ok := value(); !ok {
				return nil, false
			}
			if _, ok := value(); !ok {
				return nil, false
			}
		case "!":
			rule.Conditional = true
		case "--sport", "--source-port", "--sports", "--tcp-flags", "--tcp-option", "--icmp-type", "--icmpv6-type":
			if _, ok := value(); !ok {
				return nil, false
			}
			rule.Conditional = true
		default:
			if strings.HasPrefix(fields[i], "-") {
				rule.Conditional = true
			}
		}
	}
	if len(ports) == 0 {
		return nil, false
	}
	out := make([]firewallRule, 0, len(ports))
	for _, port := range ports {
		copy := rule
		copy.Port = port
		out = append(out, copy)
	}
	return out, true
}

func normalizeFirewallAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "0.0.0.0/0" || value == "::/0" || value == "anywhere" {
		return "any"
	}
	return value
}

func iptablesParseError(family string, unresolved int) error {
	if unresolved == 0 {
		return nil
	}
	return fmt.Errorf("%d reachable %s iptables rules or chains were not understood", unresolved, family)
}
