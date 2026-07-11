package audit

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func checkNetwork(ctx *Context) []model.Finding {
	if !ctx.Commander.Exists("ss") {
		return []model.Finding{unknown("NET-001", "network", "ss", "command not found"), unknown("NET-002", "network", "ss", "command not found")}
	}
	r := ctx.Commander.Run(15*time.Second, "ss", "-H", "-lntup")
	if r.Err != nil && r.Stdout == "" {
		// Process metadata may need root, but listeners usually remain available without -p.
		r = ctx.Commander.Run(15*time.Second, "ss", "-H", "-lntu")
	}
	if r.Err != nil {
		return []model.Finding{unknown("NET-001", "network", "ss -H -lntu[p]", commandError(r)), unknown("NET-002", "network", "ss -H -lntu[p]", commandError(r))}
	}
	listeners := parseListeners(r.Stdout)
	f := model.Finding{ID: "NET-001", Category: "network", Status: model.Info, Facts: map[string]string{}}
	counts := map[string]int{}
	for _, listener := range listeners {
		counts[listener.Scope]++
		value := fmt.Sprintf("%s %s:%s scope=%s", listener.Protocol, listener.Address, listener.Port, listener.Scope)
		if listener.Process != "" {
			value += " process=" + truncate(listener.Process, 160)
		}
		if len(f.Evidence) < 80 {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Value: value})
		}
	}
	for key, count := range counts {
		f.Facts[key] = strconv.Itoa(count)
	}
	f.Facts["total"] = strconv.Itoa(len(listeners))
	return []model.Finding{f, checkUnexpectedListeners(ctx, listeners), checkActiveConnections(ctx)}
}

func checkUnexpectedListeners(ctx *Context, listeners []Listener) model.Finding {
	f := model.Finding{ID: "NET-002", Category: "network", Status: model.Pass, Facts: map[string]string{}}
	unexpected := 0
	seen := map[string]bool{}
	for _, listener := range listeners {
		if listener.Scope != "public" && listener.Scope != "public-wildcard" {
			continue
		}
		proto := strings.TrimSuffix(strings.TrimSuffix(listener.Protocol, "6"), "4")
		key := listener.Port + "/" + proto
		if seen[key+"\x00"+listener.Process] {
			continue
		}
		seen[key+"\x00"+listener.Process] = true
		if expectedListener(ctx, listener, key) {
			continue
		}
		unexpected++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ss + profile policy", Key: "unexpected_public_listener", Value: fmt.Sprintf("%s %s:%s process=%s profile=%s", proto, listener.Address, listener.Port, truncate(listener.Process, 180), ctx.Profile.Effective)})
	}
	f.Facts["unexpected_public_listeners"] = strconv.Itoa(unexpected)
	if unexpected > 0 {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return f
}

func expectedListener(ctx *Context, listener Listener, key string) bool {
	if ctx.ExpectedPublic[key] {
		return true
	}
	process := strings.ToLower(listener.Process)
	port, _ := strconv.Atoi(listener.Port)
	if (port == 68 || port == 546) && containsAny(process, "dhcp", "dhclient", "dhcpcd", "systemd-network") {
		return true
	}
	// Time daemons commonly bind UDP/123 on every local address while their
	// own access policy controls whether they serve remote clients. Treat the
	// listener as expected infrastructure; firewall and daemon configuration
	// remain independent evidence instead of a generic port-count alarm.
	if port == 123 && strings.HasPrefix(strings.ToLower(listener.Protocol), "udp") && containsAny(process, "ntpd", "chronyd", "systemd-timesyncd") {
		return true
	}
	if strings.Contains(process, "sshd") {
		return true
	}
	switch ctx.Profile.Effective {
	case "web":
		return containsAny(process, "nginx", "caddy", "apache2")
	case "proxy":
		return containsAny(process, "sing-box", "xray", "sui", "s-ui", "x-ui", "hysteria", "tuic", "trojan", "ss-server", "outline-ss-server", "marzban", "hiddify")
	case "mixed":
		return containsAny(process, "nginx", "caddy", "apache2", "sing-box", "xray", "sui", "s-ui", "x-ui", "hysteria", "tuic", "trojan", "ss-server", "outline-ss-server", "marzban", "hiddify")
	}
	return false
}

func checkFirewall(ctx *Context) []model.Finding {
	findings := checkFirewallBase(ctx)
	return append(findings, checkFirewallExposure(ctx))
}

func checkFirewallBase(ctx *Context) []model.Finding {
	f := model.Finding{ID: "FW-001", Category: "firewall", Facts: map[string]string{}}
	if ctx.Commander.Exists("ufw") {
		r := ctx.Commander.Run(15*time.Second, "ufw", "status", "verbose")
		if r.Err != nil {
			return []model.Finding{unknown("FW-001", "firewall", "ufw status verbose", commandError(r))}
		}
		text := r.Stdout
		active := regexp.MustCompile(`(?mi)^Status:\s+active\s*$`).MatchString(text)
		defaultDeny := regexp.MustCompile(`(?mi)^Default:\s+deny \(incoming\)`).MatchString(text)
		f.Facts["backend"] = "ufw"
		f.Facts["active"] = strconv.FormatBool(active)
		f.Facts["default_deny_incoming"] = strconv.FormatBool(defaultDeny)
		useActiveFirewalld := !active && firewalldRunning(ctx)
		if useActiveFirewalld {
			// UFW may be installed but intentionally unused. Prefer the active backend.
			f = model.Finding{ID: "FW-001", Category: "firewall", Facts: map[string]string{}}
		} else if !active || !defaultDeny {
			f.Status, f.Severity = model.Risk, model.High
		} else {
			f.Status = model.Pass
		}
		if !useActiveFirewalld {
			for i, line := range lines(text) {
				if i >= 60 {
					break
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ufw status verbose", Value: line})
			}
			return []model.Finding{f}
		}
	}
	if ctx.Commander.Exists("firewall-cmd") {
		state := ctx.Commander.Run(10*time.Second, "firewall-cmd", "--state")
		f.Facts["backend"] = "firewalld"
		f.Facts["active"] = strconv.FormatBool(strings.TrimSpace(state.Stdout) == "running")
		f.Evidence = append(f.Evidence, model.Evidence{Source: "firewall-cmd --state", Value: strings.TrimSpace(state.Stdout + " " + state.Stderr)})
		if strings.TrimSpace(state.Stdout) != "running" {
			f.Status, f.Severity = model.Risk, model.High
			return []model.Finding{f}
		}
		zones := ctx.Commander.Run(12*time.Second, "firewall-cmd", "--get-active-zones")
		if zones.Err != nil {
			return []model.Finding{unknown("FW-001", "firewall", "firewall-cmd --get-active-zones", commandError(zones))}
		}
		activeZones := parseFirewalldActiveZones(zones.Stdout)
		f.Facts["active_zones"] = strconv.Itoa(len(activeZones))
		f.Evidence = append(f.Evidence, model.Evidence{Source: "firewall-cmd --get-active-zones", Value: truncate(zones.Stdout, 1200)})
		if len(activeZones) == 0 {
			f.Status = model.Info
		} else {
			f.Status = model.Pass
		}
		return []model.Finding{f}
	}
	if ctx.Commander.Exists("nft") {
		r := ctx.Commander.Run(20*time.Second, "nft", "list", "ruleset")
		if r.Err != nil {
			return []model.Finding{unknown("FW-001", "firewall", "nft list ruleset", commandError(r))}
		}
		if strings.TrimSpace(r.Stdout) == "" {
			f.Status, f.Severity = model.Risk, model.High
			f.Evidence = []model.Evidence{{Source: "nft list ruleset", Value: "empty ruleset"}}
		} else {
			// Rules exist, but a generic parser cannot safely claim they protect every path.
			f.Status = model.Info
			f.Facts["backend"] = "nftables"
			for i, line := range lines(r.Stdout) {
				if i >= 60 {
					break
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: "nft list ruleset", Value: line})
			}
		}
		return []model.Finding{f}
	}
	if ctx.Commander.Exists("iptables") {
		r := ctx.Commander.Run(15*time.Second, "iptables", "-S", "INPUT")
		if r.Err != nil {
			return []model.Finding{unknown("FW-001", "firewall", "iptables -S INPUT", commandError(r))}
		}
		f.Status = model.Info
		f.Facts["backend"] = "iptables"
		for i, line := range lines(r.Stdout) {
			if i >= 60 {
				break
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: "iptables -S INPUT", Value: line})
		}
		return []model.Finding{f}
	}
	f.Status, f.Severity = model.Risk, model.High
	f.Evidence = []model.Evidence{{Source: "command lookup", Value: "ufw, firewalld, nft, and iptables not found"}}
	return []model.Finding{f}
}

func checkFirewallExposure(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("ufw") || !ufwRunning(ctx) {
		if ctx.Commander.Exists("firewall-cmd") {
			return checkFirewalldExposure(ctx)
		}
		return notApplicable("FW-002", "firewall", "backend", "detailed exposure parser currently supports UFW and firewalld")
	}
	r := ctx.Commander.Run(15*time.Second, "ufw", "status", "verbose")
	if r.Err != nil {
		return unknown("FW-002", "firewall", "ufw status verbose", commandError(r))
	}
	f := model.Finding{ID: "FW-002", Category: "firewall", Status: model.Pass, Facts: map[string]string{}}
	allowRules, unrestricted := 0, 0
	for _, line := range lines(r.Stdout) {
		idx := strings.Index(line, "ALLOW IN")
		if idx < 0 {
			continue
		}
		allowRules++
		target := strings.TrimSpace(line[:idx])
		from := strings.TrimSpace(line[idx+len("ALLOW IN"):])
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ufw status verbose", Key: "allow_rule", Value: line})
		if (target == "Anywhere" || target == "Anywhere (v6)") && strings.HasPrefix(from, "Anywhere") {
			unrestricted++
		}
	}
	ipv6Enabled := false
	if data, err := readSmall("/etc/default/ufw", 1<<20); err == nil {
		for _, line := range lines(data) {
			if strings.EqualFold(strings.TrimSpace(line), "IPV6=yes") {
				ipv6Enabled = true
			}
		}
	}
	hasIPv6Listener := false
	if ctx.Commander.Exists("ss") {
		ss := ctx.Commander.Run(12*time.Second, "ss", "-H", "-lntu")
		for _, listener := range parseListeners(ss.Stdout) {
			if strings.Contains(listener.Address, ":") && (listener.Scope == "public" || listener.Scope == "public-wildcard") {
				hasIPv6Listener = true
			}
		}
	}
	f.Facts["allow_in_rules"] = strconv.Itoa(allowRules)
	f.Facts["unrestricted_all_port_rules"] = strconv.Itoa(unrestricted)
	f.Facts["ipv6_enabled"] = strconv.FormatBool(ipv6Enabled)
	f.Facts["public_ipv6_listener"] = strconv.FormatBool(hasIPv6Listener)
	if unrestricted > 0 || (hasIPv6Listener && !ipv6Enabled) {
		f.Status, f.Severity = model.Risk, model.High
	}
	return f
}

func ufwRunning(ctx *Context) bool {
	if !ctx.Commander.Exists("ufw") {
		return false
	}
	r := ctx.Commander.Run(10*time.Second, "ufw", "status")
	return regexp.MustCompile(`(?mi)^Status:\s+active\s*$`).MatchString(r.Stdout)
}

func firewalldRunning(ctx *Context) bool {
	if !ctx.Commander.Exists("firewall-cmd") {
		return false
	}
	r := ctx.Commander.Run(10*time.Second, "firewall-cmd", "--state")
	return strings.TrimSpace(r.Stdout) == "running"
}

func checkFirewalldExposure(ctx *Context) model.Finding {
	state := ctx.Commander.Run(10*time.Second, "firewall-cmd", "--state")
	if strings.TrimSpace(state.Stdout) != "running" {
		return model.Finding{ID: "FW-002", Category: "firewall", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Source: "firewall-cmd --state", Value: strings.TrimSpace(state.Stdout + " " + state.Stderr)}}}
	}
	zonesResult := ctx.Commander.Run(12*time.Second, "firewall-cmd", "--get-active-zones")
	if zonesResult.Err != nil {
		return unknown("FW-002", "firewall", "firewall-cmd --get-active-zones", commandError(zonesResult))
	}
	zones := parseFirewalldActiveZones(zonesResult.Stdout)
	f := model.Finding{ID: "FW-002", Category: "firewall", Status: model.Pass, Facts: map[string]string{"active_zones": strconv.Itoa(len(zones))}}
	unrestricted, exposedItems := 0, 0
	for _, zone := range zones {
		detail := ctx.Commander.Run(12*time.Second, "firewall-cmd", "--zone="+zone, "--list-all")
		if detail.Err != nil {
			return unknown("FW-002", "firewall", "firewall-cmd --zone="+zone+" --list-all", commandError(detail))
		}
		analysis := parseFirewalldZone(detail.Stdout)
		exposedItems += len(analysis.services) + len(analysis.ports)
		if analysis.unrestricted {
			unrestricted++
		}
		for _, line := range lines(detail.Stdout) {
			if len(f.Evidence) >= 80 {
				break
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: "firewall-cmd --zone=" + zone + " --list-all", Value: line})
		}
	}
	f.Facts["allowed_services_and_ports"] = strconv.Itoa(exposedItems)
	f.Facts["unrestricted_accept_zones_or_rules"] = strconv.Itoa(unrestricted)
	if unrestricted > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	return f
}

func parseFirewalldActiveZones(output string) []string {
	var zones []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		zone := strings.Fields(line)
		if len(zone) > 0 {
			zones = append(zones, zone[0])
		}
	}
	sort.Strings(zones)
	return zones
}

type firewalldZone struct {
	services, ports []string
	unrestricted    bool
}

func parseFirewalldZone(output string) firewalldZone {
	var zone firewalldZone
	for _, line := range lines(output) {
		lowerLine := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lowerLine, "rule ") && strings.Contains(lowerLine, "accept") && !strings.Contains(lowerLine, " service ") && !strings.Contains(lowerLine, " port ") && !strings.Contains(lowerLine, " protocol ") {
			zone.unrestricted = true
		}
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "target":
			zone.unrestricted = strings.EqualFold(value, "ACCEPT")
		case "services":
			zone.services = strings.Fields(value)
		case "ports":
			zone.ports = strings.Fields(value)
		case "rich rules":
			lower := strings.ToLower(value)
			if strings.Contains(lower, "accept") && !strings.Contains(lower, " service ") && !strings.Contains(lower, " port ") && !strings.Contains(lower, " protocol ") {
				zone.unrestricted = true
			}
		}
	}
	return zone
}

func checkAuth(ctx *Context) []model.Finding {
	return []model.Finding{checkFailedLogins(ctx), checkSudoAudit(ctx), checkIntrusionPrevention(ctx)}
}

func checkFailedLogins(ctx *Context) model.Finding {
	f := model.Finding{ID: "AUTH-001", Category: "auth", Status: model.Info, Facts: map[string]string{}}
	var text, source string
	if ctx.Commander.Exists("journalctl") {
		r := ctx.Commander.Run(25*time.Second, "journalctl", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat", "-u", "ssh.service", "-u", "sshd.service")
		if r.Err == nil || r.Stdout != "" {
			text, source = r.Stdout, "journalctl -u ssh.service -u sshd.service"
		}
	}
	if text == "" {
		for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if data, err := readSmall(path, 100<<20); err == nil {
				text, source = data, path
				break
			}
		}
	}
	if source == "" {
		return unknown("AUTH-001", "auth", "journal/auth log", "no readable SSH authentication log source")
	}
	failedPasswordRE := regexp.MustCompile(`(?i)failed (?:password|publickey)`)
	invalidUserRE := regexp.MustCompile(`(?i)invalid user`)
	pamFailureRE := regexp.MustCompile(`(?i)authentication failure`)
	maxAttemptsRE := regexp.MustCompile(`(?i)maximum authentication attempts exceeded`)
	ipRE := regexp.MustCompile(`(?i)(?:from\s+|rhost=)([0-9a-fA-F:.]+)`)
	anyIPRE := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	users := map[string]int{}
	ips := map[string]int{}
	failedPassword, invalidUser, pamFailure, maxAttempts := 0, 0, 0, 0
	userRE := regexp.MustCompile(`(?i)(?:for invalid user|for user|for)\s+([^ ]+)`)
	for _, line := range lines(text) {
		matched := false
		if failedPasswordRE.MatchString(line) {
			failedPassword++
			matched = true
		}
		if invalidUserRE.MatchString(line) {
			invalidUser++
			matched = true
		}
		if pamFailureRE.MatchString(line) {
			pamFailure++
			matched = true
		}
		if maxAttemptsRE.MatchString(line) {
			maxAttempts++
			matched = true
		}
		if !matched {
			continue
		}
		if m := ipRE.FindStringSubmatch(line); len(m) > 1 {
			ips[m[1]]++
		} else if candidate := anyIPRE.FindString(line); candidate != "" {
			ips[candidate]++
		}
		if m := userRE.FindStringSubmatch(line); len(m) > 1 {
			users[m[1]]++
		}
	}
	// Categories can overlap on the same attempt, so expose each count rather
	// than adding them into a misleading single total.
	f.Facts["failed_password_or_key"] = strconv.Itoa(failedPassword)
	f.Facts["invalid_user_lines"] = strconv.Itoa(invalidUser)
	f.Facts["pam_auth_failure_lines"] = strconv.Itoa(pamFailure)
	f.Facts["max_attempt_lines"] = strconv.Itoa(maxAttempts)
	f.Facts["unique_sources"] = strconv.Itoa(len(ips))
	f.Facts["targeted_users"] = strconv.Itoa(len(users))
	f.Evidence = []model.Evidence{
		{Source: source, Key: "failed_password_or_key", Value: strconv.Itoa(failedPassword)},
		{Source: source, Key: "invalid_user_lines", Value: strconv.Itoa(invalidUser)},
		{Source: source, Key: "pam_auth_failure_lines", Value: strconv.Itoa(pamFailure)},
		{Source: source, Key: "max_attempt_lines", Value: strconv.Itoa(maxAttempts)},
		{Source: source, Key: "unique_sources", Value: strconv.Itoa(len(ips))},
	}
	for _, entry := range topCounts(ips, 10) {
		f.Evidence = append(f.Evidence, model.Evidence{Source: source, Key: "source_count", Value: entry})
	}
	return f
}

func topCounts(values map[string]int, limit int) []string {
	type pair struct {
		key   string
		count int
	}
	var pairs []pair
	for key, count := range values {
		pairs = append(pairs, pair{key, count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].count > pairs[j].count
	})
	var out []string
	for i, p := range pairs {
		if i >= limit {
			break
		}
		out = append(out, fmt.Sprintf("%s=%d", p.key, p.count))
	}
	return out
}

func checkSudoAudit(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("journalctl") {
		return unknown("AUTH-002", "auth", "journalctl", "command not found")
	}
	r := ctx.Commander.Run(15*time.Second, "journalctl", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat", "_COMM=sudo")
	if r.Err != nil {
		return unknown("AUTH-002", "auth", "journalctl _COMM=sudo", commandError(r))
	}
	count := len(lines(r.Stdout))
	status := model.Pass
	if count == 0 {
		status = model.Info
	}
	return model.Finding{ID: "AUTH-002", Category: "auth", Status: status,
		Facts:    map[string]string{"sudo_journal_lines": strconv.Itoa(count)},
		Evidence: []model.Evidence{{Source: "journalctl _COMM=sudo", Key: "lines", Value: strconv.Itoa(count)}}}
}

func checkIntrusionPrevention(ctx *Context) model.Finding {
	f := model.Finding{ID: "AUTH-003", Category: "auth", Status: model.Info, Facts: map[string]string{}}
	fail2banInstalled := ctx.Commander.Exists("fail2ban-client")
	crowdSecInstalled := ctx.Commander.Exists("cscli")
	f.Facts["fail2ban_installed"] = strconv.FormatBool(fail2banInstalled)
	f.Facts["crowdsec_installed"] = strconv.FormatBool(crowdSecInstalled)
	if !fail2banInstalled && !crowdSecInstalled {
		f.NotApplicable = true
		f.Evidence = []model.Evidence{{Source: "command lookup", Value: "neither fail2ban-client nor cscli is installed"}}
		return f
	}

	protected := false
	if fail2banInstalled {
		active := ctx.Commander.Run(8*time.Second, "systemctl", "is-active", "fail2ban")
		isActive := strings.TrimSpace(active.Stdout) == "active"
		f.Facts["fail2ban_active"] = strconv.FormatBool(isActive)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "fail2ban", Value: strings.TrimSpace(active.Stdout + " " + active.Stderr)})
		if isActive {
			status := ctx.Commander.Run(12*time.Second, "fail2ban-client", "status")
			if status.Err == nil {
				hasSSHD := regexp.MustCompile(`(?i)jail list:.*\bsshd\b`).MatchString(status.Stdout)
				f.Facts["fail2ban_sshd_jail"] = strconv.FormatBool(hasSSHD)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "fail2ban-client status", Value: truncate(status.Stdout, 600)})
				protected = protected || hasSSHD
			} else {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "fail2ban-client status", Key: "unavailable", Value: commandError(status)})
			}
		}
	}
	if crowdSecInstalled {
		active := ctx.Commander.Run(8*time.Second, "systemctl", "is-active", "crowdsec")
		isActive := strings.TrimSpace(active.Stdout) == "active"
		f.Facts["crowdsec_active"] = strconv.FormatBool(isActive)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "crowdsec", Value: strings.TrimSpace(active.Stdout + " " + active.Stderr)})
		if isActive {
			bouncers := ctx.Commander.Run(12*time.Second, "cscli", "bouncers", "list", "-o", "json")
			hasBouncer := bouncers.Err == nil && crowdSecHasBouncer(bouncers.Stdout)
			f.Facts["crowdsec_bouncer_configured"] = strconv.FormatBool(hasBouncer)
			if bouncers.Err == nil {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "cscli bouncers list", Key: "configured", Value: strconv.FormatBool(hasBouncer)})
			} else {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "cscli bouncers list", Key: "unavailable", Value: commandError(bouncers)})
			}
			protected = protected || hasBouncer
		}
	}
	if protected {
		f.Status = model.Pass
	} else {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return f
}

func crowdSecHasBouncer(output string) bool {
	trimmed := strings.TrimSpace(output)
	return trimmed != "" && trimmed != "[]" && trimmed != "null"
}

func checkUpdates(ctx *Context) []model.Finding {
	return []model.Finding{checkPendingUpdates(ctx), checkUnattended(ctx)}
}

func checkPendingUpdates(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("apt-get") {
		return unknown("UPD-001", "updates", "apt-get", "command not found")
	}
	r := ctx.Commander.Run(45*time.Second, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
	if r.Err != nil && r.Stdout == "" {
		return unknown("UPD-001", "updates", "apt-get -s upgrade", commandError(r))
	}
	regular, security, phased := 0, 0, 0
	var packages []string
	for _, line := range lines(r.Stdout) {
		if !strings.HasPrefix(line, "Inst ") {
			if strings.Contains(strings.ToLower(line), "phased") {
				phased++
			}
			continue
		}
		regular++
		if containsAny(strings.ToLower(line), "-security", "security.ubuntu.com", "debian-security") {
			security++
		}
		fields := strings.Fields(line)
		if len(fields) > 1 {
			packages = append(packages, fields[1])
		}
	}
	f := model.Finding{ID: "UPD-001", Category: "updates", Status: model.Pass,
		Facts: map[string]string{"pending_total": strconv.Itoa(regular), "pending_security": strconv.Itoa(security), "phased_mentions": strconv.Itoa(phased)}}
	if security > 0 {
		f.Status, f.Severity = model.Risk, model.High
	} else if regular > 0 {
		f.Status = model.Info
	}
	f.Evidence = []model.Evidence{{Source: "apt-get -s upgrade", Key: "pending_total", Value: strconv.Itoa(regular)}, {Source: "apt-get -s upgrade", Key: "pending_security", Value: strconv.Itoa(security)}}
	for i, pkg := range packages {
		if i >= 30 {
			break
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "apt-get -s upgrade", Key: "package", Value: pkg})
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "/var/run/reboot-required", Value: "present"})
		if f.Status == model.Pass {
			f.Status, f.Severity = model.Risk, model.Medium
		}
	}
	return f
}

func checkUnattended(ctx *Context) model.Finding {
	f := model.Finding{ID: "UPD-002", Category: "updates", Status: model.Pass}
	installed := false
	if ctx.Commander.Exists("dpkg-query") {
		r := ctx.Commander.Run(8*time.Second, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
		installed = r.Err == nil && strings.Contains(r.Stdout, "install ok installed")
	}
	timer := ctx.Commander.Run(8*time.Second, "systemctl", "is-enabled", "apt-daily-upgrade.timer")
	enabled := strings.TrimSpace(timer.Stdout) == "enabled" || strings.TrimSpace(timer.Stdout) == "static"
	f.Evidence = []model.Evidence{{Source: "dpkg-query", Key: "unattended-upgrades_installed", Value: strconv.FormatBool(installed)}, {Source: "systemctl is-enabled", Key: "apt-daily-upgrade.timer", Value: strings.TrimSpace(timer.Stdout)}}
	if !installed || !enabled {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return f
}
