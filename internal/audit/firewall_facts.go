package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// firewallRule is the normalized host-firewall unit consumed by workload
// checks. Family is ipv4, ipv6, or any; source is "any" or a restricted CIDR.
// Conditional is set when a reachable rule contains an interface, destination,
// negation, match extension, or inherited chain condition that the host-local
// listener evidence cannot prove applies to arbitrary Internet traffic. Such a
// rule must produce UNKNOWN rather than a false allow or false block.
type firewallRule struct {
	Family, Protocol, Port, Source, Action, Origin, Raw string
	Chain, InputInterface, Destination                  string
	Conditional                                         bool
}

// hostFirewallSnapshot is the historical name of the normalized host-firewall snapshot.
// It now covers UFW, nftables, iptables and firewalld; keeping the internal
// name avoids report-schema churn while the collector and policy model live in
// this firewall-specific file.
type hostFirewallSnapshot struct {
	available, active, defaultDeny bool
	defaultDenyByFamily            map[string]bool
	defaultPolicyByFamily          map[string]string
	lines                          []string
	backend                        string
	rules                          []firewallRule
	collectionErr                  error
}

func collectHostFirewall(cmd Commander) hostFirewallSnapshot {
	return collectHostFirewallFromProgram(cmd, newFirewallProgram(cmd))
}

func collectHostFirewallFromProgram(cmd Commander, program *firewallProgram) hostFirewallSnapshot {
	var inactive hostFirewallSnapshot
	var active hostFirewallSnapshot
	var collectionErr error
	if cmd.Exists("ufw") {
		r := cmd.Run(12*time.Second, "ufw", "status", "verbose")
		if r.Err != nil || r.Truncated {
			collectionErr = fmt.Errorf("ufw status verbose: %s", commandError(r))
		} else {
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
	if active.available {
		r, exists := program.nftRuleset()
		if !exists {
			active.collectionErr = collectionErr
			return active
		}
		if r.Err == nil && !r.Truncated {
			nft := parseNFTFirewall(r.Stdout)
			active.rules = append(active.rules, nft.rules...)
			active.backend = "ufw+nftables"
			// UFW owns the documented host INPUT default. The live nftables
			// ruleset is merged for direct workload rules, but its generated
			// base-chain policy must not replace UFW's user-facing default.
			active.collectionErr = errors.Join(active.collectionErr, nft.collectionErr)
		} else {
			active.collectionErr = fmt.Errorf("nft list ruleset: %s", commandError(r))
		}
		return active
	}
	if cmd.Exists("firewall-cmd") {
		state := cmd.Run(8*time.Second, "firewall-cmd", "--state")
		if state.Err != nil || state.Truncated {
			collectionErr = fmt.Errorf("firewall-cmd --state: %s", commandError(state))
		}
		if strings.TrimSpace(state.Stdout) == "running" {
			if f := collectFirewalld(cmd); f.available {
				f.collectionErr = collectionErr
				return f
			} else if f.collectionErr != nil {
				collectionErr = f.collectionErr
			}
		}
	}
	if r, exists := program.nftRuleset(); exists {
		if r.Err == nil && !r.Truncated {
			f := parseNFTFirewall(r.Stdout)
			f.collectionErr = collectionErr
			return f
		}
		collectionErr = fmt.Errorf("nft list ruleset: %s", commandError(r))
	}
	_, ipv4SaveExists := program.iptablesSave("ipv4")
	_, ipv6SaveExists := program.iptablesSave("ipv6")
	if ipv4SaveExists || ipv6SaveExists {
		f := hostFirewallSnapshot{backend: "iptables", defaultDenyByFamily: map[string]bool{}, defaultPolicyByFamily: map[string]string{}}
		for _, spec := range []struct{ command, family string }{{"iptables-save", "ipv4"}, {"ip6tables-save", "ipv6"}} {
			r, exists := program.iptablesSave(spec.family)
			if !exists {
				continue
			}
			if r.Err == nil && !r.Truncated {
				f.available, f.active = true, true
				rules, policy, unresolved := parseIPTablesFirewallDetailed(r.Stdout, spec.family)
				f.rules = append(f.rules, rules...)
				setDefaultFirewallPolicy(&f, spec.family, policy)
				collectionErr = errors.Join(collectionErr, iptablesParseError(spec.family, unresolved))
				f.lines = append(f.lines, lines(r.Stdout)...)
			} else {
				collectionErr = fmt.Errorf("%s: %s", spec.command, commandError(r))
			}
		}
		f.collectionErr = collectionErr
		if f.available {
			return f
		}
	}
	// Minimal Debian/Ubuntu installations occasionally retain iptables itself
	// without iptables-save. Keep that backend observable rather than calling
	// it absent merely because the richer exporter is unavailable.
	if cmd.Exists("iptables") {
		r := cmd.Run(12*time.Second, "iptables", "-S")
		if r.Err == nil && !r.Truncated {
			rules, policy, unresolved := parseIPTablesFirewallDetailed(r.Stdout, "ipv4")
			f := hostFirewallSnapshot{available: true, active: true, defaultDenyByFamily: map[string]bool{}, defaultPolicyByFamily: map[string]string{}, backend: "iptables", rules: rules, lines: lines(r.Stdout)}
			setDefaultFirewallPolicy(&f, "ipv4", policy)
			f.collectionErr = errors.Join(collectionErr, iptablesParseError("ipv4", unresolved))
			return f
		}
		collectionErr = fmt.Errorf("iptables -S: %s", commandError(r))
	}
	inactive.collectionErr = collectionErr
	return inactive
}

func parseNFTFirewall(output string) hostFirewallSnapshot {
	f := hostFirewallSnapshot{available: true, active: true, backend: "nftables", lines: lines(output), defaultDenyByFamily: map[string]bool{}, defaultPolicyByFamily: map[string]string{}}
	collectNFTDefaultPolicies(&f, output)
	var unresolved int
	f.rules, unresolved = parseNFTHookRulesDetailed(f.lines, "input")
	if unresolved > 0 {
		f.collectionErr = fmt.Errorf("%d reachable nftables input accept/jump expressions were not understood", unresolved)
	}
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

// parseNFTHookRules follows only base chains for the selected hook and chains
// they jump or go to. Parsing every accept statement in a ruleset would mix
// unrelated paths such as OUTPUT, FORWARD, and Docker NAT into one policy.
func parseNFTHookRules(input []string, hook string) []firewallRule {
	rules, _ := parseNFTHookRulesDetailed(input, hook)
	return rules
}

func parseNFTHookRulesDetailed(input []string, hook string) ([]firewallRule, int) {
	tableRE := regexp.MustCompile(`(?i)^table\s+(ip|ip6|inet)\s+([^\s{]+)\s*\{`)
	chainRE := regexp.MustCompile(`(?i)^chain\s+([^\s{]+)\s*\{`)
	tableFamily, tableName := "", ""
	var current *nftInputChain
	chains := map[string]*nftInputChain{}
	var chainOrder []*nftInputChain
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
					chainOrder = append(chainOrder, current)
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

	jumpRE := regexp.MustCompile(`(?i)\b(jump|goto)\s+([^\s;]+)`)
	unresolved := 0
	portSets := parseNFTPortSets(strings.Join(input, "\n"))
	var out []firewallRule
	var visit func(*nftInputChain, bool, map[string]bool, int)
	visit = func(chain *nftInputChain, inheritedConditional bool, visiting map[string]bool, depth int) {
		key := nftChainKey(chain.family, chain.table, chain.name)
		if depth > 64 || visiting[key] {
			unresolved++
			return
		}
		visiting[key] = true
		defer delete(visiting, key)
		origin := "nft-reachable"
		if chain.baseInput {
			origin = "nft-" + hook
		}
		for _, line := range chain.lines {
			if match := jumpRE.FindStringSubmatch(line); len(match) > 2 {
				next := chains[nftChainKey(chain.family, chain.table, match[2])]
				if next == nil {
					unresolved++
					continue
				}
				prefix := strings.TrimSpace(line[:strings.Index(strings.ToLower(line), strings.ToLower(match[0]))])
				conditional := inheritedConditional || nftJumpHasPacketConditions(prefix)
				visit(next, conditional, visiting, depth+1)
				if strings.EqualFold(match[1], "goto") && !conditional {
					return
				}
				continue
			}
			if regexp.MustCompile(`(?i)^return\b`).MatchString(strings.TrimSpace(line)) && !inheritedConditional {
				return
			}
			parsed := parseNFTRuleLine(line, chain.family, origin, portSets)
			if len(parsed) == 0 {
				if rule, ok := parseNFTAllPortRule(line, chain.family, origin); ok {
					parsed = []firewallRule{rule}
				} else if nftPotentialExposureExpression(line) {
					unresolved++
				}
			}
			for i := range parsed {
				parsed[i].Chain = chain.name
				parsed[i].Conditional = parsed[i].Conditional || inheritedConditional
			}
			out = append(out, parsed...)
			for _, rule := range parsed {
				if rule.Port == "any" && rule.Protocol == "any" && rule.Source == "any" && !rule.Conditional {
					return
				}
			}
		}
	}
	baseByFamily := map[string]int{}
	for _, chain := range chainOrder {
		if chain.baseInput {
			baseByFamily[chain.family]++
			visit(chain, false, map[string]bool{}, 0)
		}
	}
	if baseByFamily["any"] > 1 || baseByFamily["ipv4"] > 1 || baseByFamily["ipv6"] > 1 ||
		baseByFamily["any"] > 0 && (baseByFamily["ipv4"] > 0 || baseByFamily["ipv6"] > 0) {
		// Base-chain priority and cross-table verdict interaction cannot be
		// reconstructed safely from a flattened text summary.
		unresolved++
	}
	return out, unresolved
}

func nftJumpHasPacketConditions(prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	return prefix != "" && !strings.HasPrefix(strings.ToLower(prefix), "counter")
}

func nftPotentialExposureExpression(line string) bool {
	lower := strings.ToLower(line)
	if !regexp.MustCompile(`\baccept\b`).MatchString(lower) {
		return false
	}
	return !containsAny(lower,
		"type filter hook", " policy ",
		"ct state established", "ct state related", "ct state { established",
		`iif "lo"`, `iifname "lo"`, "icmp type", "icmpv6 type",
	)
}

func parseNFTAllPortRule(line, family, origin string) (firewallRule, bool) {
	lower := strings.ToLower(line)
	actionMatch := regexp.MustCompile(`\b(accept|drop|reject)\b`).FindStringSubmatch(lower)
	if len(actionMatch) == 0 ||
		strings.Contains(lower, "type filter hook") || strings.Contains(lower, " policy ") ||
		containsAny(lower, "ct state established", "ct state related", "ct state { established", "iif \"lo\"", "iifname \"lo\"", "icmp type", "icmpv6 type") {
		return firewallRule{}, false
	}
	if strings.Contains(lower, " dport ") {
		return firewallRule{}, false
	}
	protocol := "any"
	if regexp.MustCompile(`\b(?:meta\s+l4proto|ip\s+protocol)\s+tcp\b`).MatchString(lower) {
		protocol = "tcp"
	} else if regexp.MustCompile(`\b(?:meta\s+l4proto|ip\s+protocol)\s+udp\b`).MatchString(lower) {
		protocol = "udp"
	}
	source := "any"
	if match := regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+saddr\s+([^\s]+)`).FindStringSubmatch(line); len(match) > 1 {
		source = match[1]
	}
	action := "deny"
	if actionMatch[1] == "accept" {
		action = "allow"
	}
	rule := firewallRule{Family: family, Protocol: protocol, Port: "any", Source: source, Action: action, Origin: origin, Raw: line}
	applyNFTRuleConditions(&rule, line)
	return rule, true
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
			rule := firewallRule{Family: family, Protocol: strings.ToLower(m[1]), Port: port, Source: source, Action: action, Origin: origin, Raw: line}
			applyNFTRuleConditions(&rule, line)
			out = append(out, rule)
		}
	}
	return out
}

func applyNFTRuleConditions(rule *firewallRule, line string) {
	lower := strings.ToLower(line)
	if match := regexp.MustCompile(`(?i)\biif(?:name)?\s+(!=\s+)?("[^"]+"|[^\s;]+)`).FindStringSubmatch(line); len(match) > 2 {
		rule.InputInterface = strings.Trim(match[2], `"`)
		rule.Conditional = true
		if strings.TrimSpace(match[1]) != "" {
			rule.Conditional = true
		}
	}
	if match := regexp.MustCompile(`(?i)\b(?:ip|ip6)\s+daddr\s+([^\s;]+)`).FindStringSubmatch(line); len(match) > 1 {
		rule.Destination = match[1]
		rule.Conditional = true
	}
	// Source restrictions are represented explicitly and can be classified as
	// allow-restricted. Other packet predicates need interface/address context
	// that the current listener snapshot does not prove.
	if containsAny(lower,
		" != ", " meta mark ", " ct mark ", " meta skuid ", " meta cgroup ",
		" fib ", " socket ", " ipsec ", " limit rate ", " meter ", " quota ",
		" hour ", " day ", " oif ", " oifname ",
	) {
		rule.Conditional = true
	}
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

func collectNFTDefaultPolicies(f *hostFirewallSnapshot, output string) {
	collectNFTHookPolicies(f, output, "input")
}

func collectNFTHookDefaultPolicies(target map[string]bool, output, hook string) {
	temporary := hostFirewallSnapshot{defaultDenyByFamily: map[string]bool{}, defaultPolicyByFamily: map[string]string{}}
	collectNFTHookPolicies(&temporary, output, hook)
	for family, deny := range temporary.defaultDenyByFamily {
		target[family] = target[family] || deny
	}
}

func collectNFTHookPolicies(f *hostFirewallSnapshot, output, hook string) {
	if f.defaultDenyByFamily == nil {
		f.defaultDenyByFamily = map[string]bool{}
	}
	if f.defaultPolicyByFamily == nil {
		f.defaultPolicyByFamily = map[string]string{}
	}
	tableFamily := ""
	tableRE := regexp.MustCompile(`(?i)^table\s+(ip|ip6|inet)\s+`)
	hookRE := regexp.MustCompile(`(?i)\bhook\s+` + regexp.QuoteMeta(hook) + `\b`)
	policyRE := regexp.MustCompile(`(?i)\bpolicy\s+(accept|drop|reject)\b`)
	seenHook := false
	for _, line := range lines(output) {
		trimmed := strings.TrimSpace(line)
		if m := tableRE.FindStringSubmatch(trimmed); len(m) > 1 {
			tableFamily = map[string]string{"ip": "ipv4", "ip6": "ipv6", "inet": "any"}[strings.ToLower(m[1])]
		}
		if !hookRE.MatchString(trimmed) {
			continue
		}
		seenHook = true
		family := tableFamily
		if family == "" {
			if m := regexp.MustCompile(`(?i)\btable\s+(ip|ip6|inet)\s+`).FindStringSubmatch(trimmed); len(m) > 1 {
				family = map[string]string{"ip": "ipv4", "ip6": "ipv6", "inet": "any"}[strings.ToLower(m[1])]
			}
		}
		if family == "" {
			family = "any"
		}
		policy := "allow" // nft base chains default to accept without policy.
		if m := policyRE.FindStringSubmatch(trimmed); len(m) > 1 {
			policy = normalizeFirewallPolicy(m[1])
		}
		mergeDefaultFirewallPolicy(f, family, policy)
	}
	if !seenHook {
		// With no INPUT base chain, nftables is not filtering host-local input.
		mergeDefaultFirewallPolicy(f, "any", "allow")
	}
}
