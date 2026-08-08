package audit

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type routeRecord struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
	Table       any    `json:"table"`
	Type        string `json:"type"`
}

type ruleRecord struct {
	Priority any    `json:"priority"`
	Table    any    `json:"table"`
	FWMark   string `json:"fwmark"`
	From     string `json:"from"`
	To       string `json:"to"`
}

type egressSnapshot struct {
	IPv4Defaults []string
	IPv6Defaults []string
	RuleCount    int
	MarkedRules  int
	DNSServers   []string
	Error        error
}

func checkProxyEgress(ctx *Context) model.Finding {
	if ctx.Profile.Effective != "proxy" && ctx.Profile.Effective != "mixed" && (ctx.Policy == nil || ctx.Policy.Egress.Empty()) {
		return notApplicable("WORK-016", "workloads", "routing policy", "proxy or mixed workload context was not detected")
	}
	snapshot := collectEgressSnapshot(ctx)
	if snapshot.Error != nil {
		return unknown("WORK-016", "workloads", "ip route/rule + resolv.conf", snapshot.Error.Error())
	}
	f := model.Finding{ID: "WORK-016", Category: "workloads", Status: model.Info, Facts: map[string]string{
		"ipv4_default_interfaces": strings.Join(snapshot.IPv4Defaults, ","),
		"ipv6_default_interfaces": strings.Join(snapshot.IPv6Defaults, ","),
		"policy_rules":            strconv.Itoa(snapshot.RuleCount),
		"marked_policy_rules":     strconv.Itoa(snapshot.MarkedRules),
		"dns_servers":             strconv.Itoa(len(snapshot.DNSServers)),
	}}
	f.Evidence = append(f.Evidence,
		model.Evidence{Source: "ip -j -4 route show table all", Key: "default_interfaces", Value: valueOr(strings.Join(snapshot.IPv4Defaults, ","), "none")},
		model.Evidence{Source: "ip -j -6 route show table all", Key: "default_interfaces", Value: valueOr(strings.Join(snapshot.IPv6Defaults, ","), "none")},
		model.Evidence{Source: "ip -j rule show", Key: "routing_policy", Value: fmt.Sprintf("rules=%d marked_rules=%d", snapshot.RuleCount, snapshot.MarkedRules)},
		model.Evidence{Source: "/etc/resolv.conf", Key: "resolver_scope", Value: dnsScopeSummary(snapshot.DNSServers)},
	)
	if ctx.Policy == nil || ctx.Policy.Egress.Empty() {
		return f
	}
	mismatches := 0
	if len(ctx.Policy.Egress.IPv4Interfaces) > 0 && !sameStrings(snapshot.IPv4Defaults, ctx.Policy.Egress.IPv4Interfaces) {
		mismatches++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "audit policy + IPv4 routes", Key: "mismatch", Value: fmt.Sprintf("expected_interfaces=%s actual_interfaces=%s", strings.Join(ctx.Policy.Egress.IPv4Interfaces, ","), valueOr(strings.Join(snapshot.IPv4Defaults, ","), "none"))})
	}
	if len(ctx.Policy.Egress.IPv6Interfaces) > 0 && !sameStrings(snapshot.IPv6Defaults, ctx.Policy.Egress.IPv6Interfaces) {
		mismatches++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "audit policy + IPv6 routes", Key: "mismatch", Value: fmt.Sprintf("expected_interfaces=%s actual_interfaces=%s", strings.Join(ctx.Policy.Egress.IPv6Interfaces, ","), valueOr(strings.Join(snapshot.IPv6Defaults, ","), "none"))})
	}
	if ctx.Policy.Egress.RequireSamePath && len(snapshot.IPv4Defaults) > 0 && len(snapshot.IPv6Defaults) > 0 && !sameStrings(snapshot.IPv4Defaults, snapshot.IPv6Defaults) {
		mismatches++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "audit policy + routes", Key: "mismatch", Value: "IPv4 and IPv6 default interfaces differ while require_same_path=true"})
	}
	if !dnsModeMatches(ctx.Policy.Egress.DNSMode, snapshot.DNSServers) {
		mismatches++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "audit policy + resolv.conf", Key: "mismatch", Value: "resolver scope does not match dns_mode=" + ctx.Policy.Egress.DNSMode})
	}
	if mismatches == 0 {
		f.Status = model.Pass
	} else {
		f.Status, f.Severity = model.Risk, model.High
	}
	f.Facts["egress_policy_mismatches"] = strconv.Itoa(mismatches)
	return f
}

func collectEgressSnapshot(ctx *Context) egressSnapshot {
	var snapshot egressSnapshot
	if !ctx.Commander.Exists("ip") {
		snapshot.Error = fmt.Errorf("ip command not found")
		return snapshot
	}
	for _, spec := range []struct {
		family string
		target *[]string
	}{{"-4", &snapshot.IPv4Defaults}, {"-6", &snapshot.IPv6Defaults}} {
		r := ctx.Commander.Run(8*time.Second, "ip", "-j", spec.family, "route", "show", "table", "all")
		if r.Err != nil || r.Truncated {
			snapshot.Error = fmt.Errorf("ip %s route: %s", spec.family, commandError(r))
			return snapshot
		}
		var routes []routeRecord
		if err := json.Unmarshal([]byte(r.Stdout), &routes); err != nil {
			snapshot.Error = fmt.Errorf("parse ip %s route JSON: %w", spec.family, err)
			return snapshot
		}
		devices := map[string]bool{}
		for _, route := range routes {
			if (route.Destination == "default" || route.Destination == "0.0.0.0/0" || route.Destination == "::/0") && route.Device != "" && route.Type != "unreachable" && route.Type != "blackhole" {
				devices[route.Device] = true
			}
		}
		*spec.target = sortedKeys(devices)
	}
	rules := ctx.Commander.Run(8*time.Second, "ip", "-j", "rule", "show")
	if rules.Err != nil || rules.Truncated {
		snapshot.Error = fmt.Errorf("ip rule: %s", commandError(rules))
		return snapshot
	}
	var decoded []ruleRecord
	if err := json.Unmarshal([]byte(rules.Stdout), &decoded); err != nil {
		snapshot.Error = fmt.Errorf("parse ip rule JSON: %w", err)
		return snapshot
	}
	snapshot.RuleCount = len(decoded)
	for _, rule := range decoded {
		if strings.TrimSpace(rule.FWMark) != "" {
			snapshot.MarkedRules++
		}
	}
	resolv, err := ctx.Facts.ReadSmall("/etc/resolv.conf", 128<<10)
	if err != nil {
		snapshot.Error = fmt.Errorf("read resolv.conf: %w", err)
		return snapshot
	}
	for _, line := range lines(resolv) {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") && net.ParseIP(fields[1]) != nil {
			snapshot.DNSServers = append(snapshot.DNSServers, fields[1])
		}
	}
	snapshot.DNSServers = uniqueStrings(snapshot.DNSServers)
	return snapshot
}

func dnsScopeSummary(servers []string) string {
	counts := map[string]int{}
	for _, server := range servers {
		counts[classifyAddress(server)]++
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, " ")
}

func dnsModeMatches(mode string, servers []string) bool {
	if mode == "" || mode == "system" {
		return true
	}
	if len(servers) == 0 {
		return false
	}
	for _, server := range servers {
		scope := classifyAddress(server)
		if mode == "loopback-only" && scope != "loopback" {
			return false
		}
		if mode == "private-only" && scope != "loopback" && scope != "private" {
			return false
		}
	}
	return true
}

func sameStrings(left, right []string) bool {
	a := append([]string(nil), left...)
	b := append([]string(nil), right...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, "\x00") == strings.Join(b, "\x00")
}
