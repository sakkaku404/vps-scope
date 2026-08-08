package audit

import (
	"fmt"
	"strings"
	"time"
)

func collectFirewalld(cmd Commander) hostFirewallSnapshot {
	zonesResult := cmd.Run(10*time.Second, "firewall-cmd", "--get-active-zones")
	if zonesResult.Err != nil || zonesResult.Truncated {
		return hostFirewallSnapshot{collectionErr: fmt.Errorf("firewall-cmd --get-active-zones: %s", commandError(zonesResult))}
	}
	f := hostFirewallSnapshot{available: true, active: true, backend: "firewalld", defaultDenyByFamily: map[string]bool{}, defaultPolicyByFamily: map[string]string{}}
	servicePorts := map[string]string{"ssh": "22", "http": "80", "https": "443"}
	for _, zone := range parseFirewalldActiveZones(zonesResult.Stdout) {
		detail := cmd.Run(10*time.Second, "firewall-cmd", "--zone="+zone, "--list-all")
		if detail.Err != nil || detail.Truncated {
			return hostFirewallSnapshot{collectionErr: fmt.Errorf("firewall-cmd --zone=%s --list-all: %s", zone, commandError(detail))}
		}
		f.lines = append(f.lines, lines(detail.Stdout)...)
		restricted := false
		zonePolicy := "deny"
		for _, line := range lines(detail.Stdout) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "sources:") && strings.TrimSpace(strings.TrimPrefix(trimmed, "sources:")) != "" {
				restricted = true
			}
			if strings.HasPrefix(trimmed, "target:") {
				target := strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(trimmed, "target:")))
				if target == "ACCEPT" {
					zonePolicy = "allow"
				} else if target != "DEFAULT" && target != "DROP" && target != "REJECT" {
					zonePolicy = "unknown"
				}
			}
		}
		mergeDefaultFirewallPolicy(&f, "any", zonePolicy)
		analysis := parseFirewalldZone(detail.Stdout)
		source := "any"
		if restricted {
			source = "zone-sources"
		}
		if analysis.unrestricted {
			f.rules = append(f.rules, firewallRule{Family: "any", Protocol: "any", Port: "any", Source: source, Action: "allow", Origin: "firewalld-zone", Raw: "unrestricted active zone"})
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
