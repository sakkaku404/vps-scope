package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// firewallAuditSnapshot freezes every input used by FW-001 and FW-002. The
// evaluators never re-read UFW configuration or take a second socket sample.
type firewallAuditSnapshot struct {
	Host             hostFirewallSnapshot
	Listeners        []Listener
	ListenerErr      error
	UFWIPv6Enabled   bool
	UFWIPv6ConfigErr error
}

func collectFirewallAuditSnapshot(ctx *Context) firewallAuditSnapshot {
	host := ctx.Facts.HostFirewall()
	listeners, listenerErr := ctx.Facts.Listeners()
	snapshot := firewallAuditSnapshot{Host: host, Listeners: listeners, ListenerErr: listenerErr}
	if host.backend != "ufw" && !strings.HasPrefix(host.backend, "ufw+") {
		return snapshot
	}
	data, err := readSmall("/etc/default/ufw", 1<<20)
	if err != nil {
		snapshot.UFWIPv6ConfigErr = fmt.Errorf("read /etc/default/ufw: %w", err)
		return snapshot
	}
	for _, line := range lines(data) {
		if strings.EqualFold(strings.TrimSpace(line), "IPV6=yes") {
			snapshot.UFWIPv6Enabled = true
			break
		}
	}
	return snapshot
}

func evaluateFirewallBase(snapshot firewallAuditSnapshot) model.Finding {
	normalized := snapshot.Host
	if !normalized.available {
		if normalized.collectionErr != nil {
			return unknown("FW-001", "firewall", "host firewall discovery", normalized.collectionErr.Error())
		}
		return model.Finding{ID: "FW-001", Category: "firewall", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Source: "command lookup", Value: "ufw, firewalld, nft, and iptables-save not found"}}}
	}
	f := model.Finding{ID: "FW-001", Category: "firewall", Facts: map[string]string{
		"backend": normalized.backend, "active": strconv.FormatBool(normalized.active),
		"default_deny_incoming": strconv.FormatBool(normalized.defaultDeny),
		"normalized_rules":      strconv.Itoa(len(normalized.rules)),
	}}
	isUFW := normalized.backend == "ufw" || strings.HasPrefix(normalized.backend, "ufw+")
	emptyNFT := normalized.backend == "nftables" && len(normalized.lines) == 0
	if !normalized.active || emptyNFT || isUFW && !normalized.defaultDeny {
		f.Status, f.Severity = model.Risk, model.High
	} else if normalized.defaultDeny {
		f.Status = model.Pass
	} else {
		f.Status = model.Info
	}
	for i, line := range normalized.lines {
		if i >= 60 {
			break
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: firewallEvidenceSource(normalized), Value: line})
	}
	if len(f.Evidence) == 0 {
		for _, rule := range normalized.rules {
			if len(f.Evidence) >= 60 {
				break
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: "normalized host firewall", Value: rule.Raw})
		}
	}
	return withIncompleteEvidence(f, "host firewall discovery", normalized.collectionErr)
}

func evaluateFirewallExposure(snapshot firewallAuditSnapshot) model.Finding {
	normalized := snapshot.Host
	if !normalized.available {
		return withIncompleteEvidence(notApplicable("FW-002", "firewall", "backend", "no readable active host-firewall backend"), "host firewall discovery", normalized.collectionErr)
	}
	f := model.Finding{ID: "FW-002", Category: "firewall", Status: model.Pass, Facts: map[string]string{"backend": normalized.backend}}
	type ruleGroup struct {
		protocol, port, source string
		families, origins      map[string]bool
	}
	groups := map[string]*ruleGroup{}
	unrestricted := 0
	for _, rule := range normalized.rules {
		if rule.Action != "allow" || !includeFirewallExposureRule(normalized.backend, rule) {
			continue
		}
		key := strings.Join([]string{rule.Protocol, rule.Port, rule.Source}, "\x00")
		group := groups[key]
		if group == nil {
			group = &ruleGroup{protocol: rule.Protocol, port: rule.Port, source: rule.Source, families: map[string]bool{}, origins: map[string]bool{}}
			groups[key] = group
		}
		group.families[rule.Family] = true
		group.origins[rule.Origin] = true
	}
	groupKeys := make([]string, 0, len(groups))
	for key := range groups {
		groupKeys = append(groupKeys, key)
	}
	sort.Strings(groupKeys)
	for _, key := range groupKeys {
		group := groups[key]
		if group.port == "any" && group.source == "any" {
			unrestricted++
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: firewallEvidenceSource(normalized), Key: "allow_rule", Value: fmt.Sprintf("port=%s/%s families=%s source=%s origin=%s", group.port, group.protocol, sortedBoolKeys(group.families), group.source, sortedBoolKeys(group.origins))})
	}
	for _, line := range normalized.lines {
		idx := strings.Index(line, "ALLOW IN")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(line[:idx])
		from := strings.TrimSpace(line[idx+len("ALLOW IN"):])
		if (target == "Anywhere" || target == "Anywhere (v6)") && strings.HasPrefix(from, "Anywhere") && len(groups) == 0 {
			unrestricted++
		}
	}
	hasIPv6Listener := false
	livePublic := map[string]bool{}
	if snapshot.ListenerErr == nil {
		for _, listener := range snapshot.Listeners {
			if listener.Scope != "public" && listener.Scope != "public-wildcard" {
				continue
			}
			protocol := strings.TrimSuffix(strings.TrimSuffix(listener.Protocol, "6"), "4")
			livePublic[listener.Port+"/"+protocol] = true
			if strings.Contains(listener.Address, ":") || listener.Address == "*" {
				hasIPv6Listener = true
			}
		}
	}
	stale := map[string]bool{}
	if snapshot.ListenerErr == nil {
		for _, group := range groups {
			if group.source != "any" || !validPort(group.port) {
				continue
			}
			live := livePublic[group.port+"/"+group.protocol]
			if group.protocol == "any" {
				live = livePublic[group.port+"/tcp"] || livePublic[group.port+"/udp"]
			}
			if !live {
				stale[group.port+"/"+group.protocol] = true
			}
		}
	}
	staleKeys := make([]string, 0, len(stale))
	for key := range stale {
		staleKeys = append(staleKeys, key)
	}
	sort.Strings(staleKeys)
	for _, key := range staleKeys {
		f.Evidence = append(f.Evidence, model.Evidence{Source: firewallEvidenceSource(normalized) + " + ss", Key: "stale_allow_rule", Value: key + " has no matching public listener"})
	}
	f.Facts["allow_in_rules"] = strconv.Itoa(len(groups))
	f.Facts["unrestricted_all_port_rules"] = strconv.Itoa(unrestricted)
	f.Facts["ipv6_enabled"] = strconv.FormatBool(snapshot.UFWIPv6Enabled)
	f.Facts["public_ipv6_listener"] = strconv.FormatBool(hasIPv6Listener)
	f.Facts["stale_allow_rules"] = strconv.Itoa(len(staleKeys))
	isUFW := normalized.backend == "ufw" || strings.HasPrefix(normalized.backend, "ufw+")
	if unrestricted > 0 || (isUFW && hasIPv6Listener && snapshot.UFWIPv6ConfigErr == nil && !snapshot.UFWIPv6Enabled) {
		f.Status, f.Severity = model.Risk, model.High
	} else if len(staleKeys) > 0 {
		f.Status, f.Severity = model.Risk, model.Medium
	} else if !normalized.defaultDeny {
		f.Status = model.Info
	}
	if snapshot.ListenerErr != nil {
		f = withIncompleteEvidence(f, "public listener inventory", snapshot.ListenerErr)
	}
	if isUFW && hasIPv6Listener && snapshot.UFWIPv6ConfigErr != nil {
		f = withIncompleteEvidence(f, "UFW IPv6 configuration", snapshot.UFWIPv6ConfigErr)
		if f.Status == model.Pass {
			f.Status, f.Unavailable, f.Error = model.Unknown, true, "UFW IPv6 coverage could not be determined"
		}
	}
	return withIncompleteEvidence(f, "host firewall discovery", normalized.collectionErr)
}
