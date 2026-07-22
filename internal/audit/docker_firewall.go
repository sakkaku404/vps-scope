package audit

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// dockerFirewallFacts models the forwarding path used by published container
// ports. Host INPUT policy alone cannot describe this path: Docker commonly
// DNATs traffic and accepts it through FORWARD after DOCKER-USER.
type dockerFirewallFacts struct {
	Available           bool
	AvailableByFamily   map[string]bool
	Backend             string
	UserChain           bool
	ForwardHook         bool
	DefaultDropByFamily map[string]bool
	Rules               []firewallRule
	Error               string
}

func (f dockerFirewallFacts) clone() dockerFirewallFacts {
	out := f
	out.Rules = append([]firewallRule(nil), f.Rules...)
	out.DefaultDropByFamily = map[string]bool{}
	out.AvailableByFamily = map[string]bool{}
	for family, value := range f.DefaultDropByFamily {
		out.DefaultDropByFamily[family] = value
	}
	for family, value := range f.AvailableByFamily {
		out.AvailableByFamily[family] = value
	}
	return out
}

func collectDockerFirewall(cmd Commander) dockerFirewallFacts {
	f := dockerFirewallFacts{DefaultDropByFamily: map[string]bool{}, AvailableByFamily: map[string]bool{}}
	for _, spec := range []struct{ command, family string }{{"iptables-save", "ipv4"}, {"ip6tables-save", "ipv6"}} {
		if !cmd.Exists(spec.command) {
			continue
		}
		r := cmd.Run(15*time.Second, spec.command)
		if r.Err != nil || r.Truncated {
			f.Error = spec.command + ": " + commandError(r)
			continue
		}
		available, userChain, forwardHook, defaultDrop, rules := parseDockerIPTables(r.Stdout, spec.family)
		if available {
			f.Available = true
			f.AvailableByFamily[spec.family] = true
			f.Backend = "iptables"
			f.UserChain = f.UserChain || userChain
			f.ForwardHook = f.ForwardHook || forwardHook
			f.DefaultDropByFamily[spec.family] = defaultDrop
			f.Rules = append(f.Rules, rules...)
		}
	}
	if f.Available {
		return f
	}
	if !cmd.Exists("nft") {
		return f
	}
	r := cmd.Run(20*time.Second, "nft", "list", "ruleset")
	if r.Err != nil || r.Truncated {
		f.Error = "nft: " + commandError(r)
		return f
	}
	rules, unresolved := parseNFTHookRulesDetailed(lines(r.Stdout), "forward")
	if len(rules) == 0 && !regexp.MustCompile(`(?i)hook\s+forward`).MatchString(r.Stdout) {
		return f
	}
	f.Available, f.Backend, f.ForwardHook = true, "nftables", true
	f.AvailableByFamily["ipv4"] = true
	f.AvailableByFamily["ipv6"] = true
	f.UserChain = regexp.MustCompile(`(?i)chain\s+(?:DOCKER-USER|docker-user|docker_user)\b`).MatchString(r.Stdout)
	f.Rules = rules
	if unresolved > 0 {
		f.Error = fmt.Sprintf("%d reachable nftables forward accept/jump expressions were not understood", unresolved)
	}
	collectNFTHookDefaultPolicies(f.DefaultDropByFamily, r.Stdout, "forward")
	return f
}

func parseDockerIPTables(output, family string) (available, userChain, forwardHook, defaultDrop bool, rules []firewallRule) {
	available = strings.Contains(output, ":DOCKER") || strings.Contains(output, "-A DOCKER")
	userChain = strings.Contains(output, ":DOCKER-USER ") || strings.Contains(output, "-A DOCKER-USER ")
	forwardHook = strings.Contains(output, "-A FORWARD") && containsAny(output, "DOCKER-USER", "DOCKER-FORWARD", "-j DOCKER")
	defaultDrop = regexp.MustCompile(`(?m)^:FORWARD\s+(DROP|REJECT)\b`).MatchString(output)
	for _, line := range lines(output) {
		if !strings.HasPrefix(line, "-A DOCKER-USER ") || !containsAny(line, "-j ACCEPT", "-j DROP", "-j REJECT", "-j RETURN") {
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
		port, origin := value("--ctorigdstport", ""), "docker-user-original"
		if !validPort(port) {
			port, origin = value("--dport", "any"), "docker-user-translated"
			if port != "any" && !validPort(port) {
				continue
			}
		}
		action := strings.ToLower(value("-j", ""))
		if action == "accept" {
			action = "allow"
		} else if action == "drop" || action == "reject" {
			action = "deny"
		} else if action != "return" {
			continue
		}
		source := value("-s", "any")
		if source == "0.0.0.0/0" || source == "::/0" {
			source = "any"
		}
		parsed, understood := parseIPTablesTerminalRule(stripIPTablesComment(line), family, "DOCKER-USER", false)
		conditional := !understood
		if len(parsed) > 0 {
			conditional = parsed[0].Conditional
		}
		// Original-destination matching is the reliable way to constrain a
		// published host port in DOCKER-USER. A normal --dport observes the
		// translated container port after DNAT.
		rules = append(rules, firewallRule{Family: family, Protocol: strings.ToLower(value("-p", "any")), Port: port, Source: source, Action: action, Origin: origin, Raw: line, Chain: "DOCKER-USER", Conditional: conditional})
	}
	return
}

func dockerForwardDisposition(f dockerFirewallFacts, hostPort, targetPort, protocol, family string) string {
	if !f.Available || !f.ForwardHook {
		return "unknown"
	}
	if family != "any" && len(f.AvailableByFamily) > 0 && !f.AvailableByFamily[family] {
		return "unknown"
	}
	restricted, conditional := false, false
	for _, rule := range f.Rules {
		port := targetPort
		if rule.Origin == "docker-user-original" {
			port = hostPort
		}
		if (rule.Port != "any" && rule.Port != port) || (rule.Protocol != "any" && rule.Protocol != protocol) || (rule.Family != "any" && rule.Family != family) {
			continue
		}
		if rule.Conditional {
			conditional = true
			continue
		}
		if rule.Action == "return" {
			break
		}
		if rule.Action == "deny" && rule.Source == "any" {
			if restricted {
				return "restricted-by-docker-user"
			}
			return "blocked-by-docker-user"
		}
		if rule.Action == "allow" && rule.Source == "any" {
			return "allowed-by-docker-user"
		}
		if rule.Action == "allow" {
			restricted = true
		}
	}
	if conditional {
		return "conditional-unknown"
	}
	if f.UserChain {
		return "docker-user-fallthrough"
	}
	return "docker-forward-unfiltered"
}

func checkDockerFirewallPath(ctx *Context, containers []dockerInspect) model.Finding {
	facts := ctx.Facts.DockerFirewall()
	f := model.Finding{ID: "DOCKER-002", Category: "docker", Status: model.Pass, Facts: map[string]string{}}
	published, public, bypasses, unknown := 0, 0, 0, 0
	hostFirewall := ctx.Facts.UFW()
	for _, container := range containers {
		name := strings.TrimPrefix(container.Name, "/")
		for target, bindings := range container.NetworkSettings.Ports {
			protocol := "tcp"
			if parts := strings.SplitN(target, "/", 2); len(parts) == 2 {
				protocol = strings.ToLower(parts[1])
			}
			for _, binding := range bindings {
				published++
				scope := classifyAddress(binding.HostIP)
				if scope != "public" && scope != "public-wildcard" {
					f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "forward_path", Value: fmt.Sprintf("container=%s host=%s:%s/%s target=%s scope=%s judgment=not-publicly-published", name, binding.HostIP, binding.HostPort, protocol, target, scope)})
					continue
				}
				public++
				family := listenerAddressFamily(binding.HostIP)
				targetPort := strings.SplitN(target, "/", 2)[0]
				forward := dockerForwardDisposition(facts, binding.HostPort, targetPort, protocol, family)
				host := firewallDispositionFamily(hostFirewall, binding.HostPort, protocol, family)
				judgment := "docker-published-path-visible"
				if forward == "unknown" || forward == "conditional-unknown" {
					unknown++
					judgment = "forwarding-path-unavailable"
				} else if (host == "blocked-by-default" || host == "blocked-by-explicit-rule" || host == "no-explicit-rule") && containsAny(forward, "fallthrough", "unfiltered", "allowed") {
					bypasses++
					judgment = "docker-forward-may-bypass-host-input-policy"
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect + forwarding firewall", Key: "forward_path", Value: fmt.Sprintf("container=%s host=%s:%s/%s target=%s scope=%s input=%s forward=%s judgment=%s cloud_firewall=unknown", name, binding.HostIP, binding.HostPort, protocol, target, scope, host, forward, judgment)})
			}
		}
	}
	f.Facts["published_ports"] = fmt.Sprint(published)
	f.Facts["public_published_ports"] = fmt.Sprint(public)
	f.Facts["input_policy_bypass_paths"] = fmt.Sprint(bypasses)
	f.Facts["unknown_forward_paths"] = fmt.Sprint(unknown)
	f.Facts["forward_backend"] = facts.Backend
	f.Facts["docker_user_chain"] = fmt.Sprint(facts.UserChain)
	var families []string
	for family, available := range facts.AvailableByFamily {
		if available {
			families = append(families, family)
		}
	}
	sort.Strings(families)
	f.Facts["forward_families"] = strings.Join(families, ",")
	if published == 0 {
		return notApplicable("DOCKER-002", "docker", "docker inspect", "no published container ports")
	}
	if bypasses > 0 {
		f.Status, f.Severity = model.Risk, model.Medium
	} else if unknown > 0 {
		f.Status, f.Unavailable, f.Error = model.Unknown, true, "Docker forwarding policy could not be established"
	}
	sort.Slice(f.Evidence, func(i, j int) bool { return f.Evidence[i].Value < f.Evidence[j].Value })
	if public > 0 {
		f = withIncompleteEvidence(f, "host firewall discovery", hostFirewall.collectionErr)
		if facts.Error != "" {
			f = withIncompleteEvidence(f, "Docker forwarding firewall discovery", fmt.Errorf("%s", facts.Error))
		}
	}
	return f
}
