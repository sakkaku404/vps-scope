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
	return []model.Finding{f, checkUnexpectedListeners(ctx, listeners)}
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
	if (port == 68 || port == 546) && containsAny(process, "dhcp", "dhcpcd", "systemd-network") {
		return true
	}
	if strings.Contains(process, "sshd") {
		return true
	}
	switch ctx.Profile.Effective {
	case "web":
		return containsAny(process, "nginx", "caddy", "apache2")
	case "proxy":
		return containsAny(process, "sing-box", "sui", "s-ui", "x-ui", "hysteria")
	case "mixed":
		return containsAny(process, "nginx", "caddy", "apache2", "sing-box", "sui", "s-ui", "x-ui", "hysteria")
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
		if !active || !defaultDeny {
			f.Status, f.Severity = model.Risk, model.High
		} else {
			f.Status = model.Pass
		}
		for i, line := range lines(text) {
			if i >= 60 {
				break
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ufw status verbose", Value: line})
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
	f.Evidence = []model.Evidence{{Source: "command lookup", Value: "ufw, nft, and iptables not found"}}
	return []model.Finding{f}
}

func checkFirewallExposure(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("ufw") {
		return notApplicable("FW-002", "firewall", "backend", "detailed exposure parser currently supports UFW")
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

func checkAuth(ctx *Context) []model.Finding {
	return []model.Finding{checkFailedLogins(ctx), checkSudoAudit(ctx), checkFail2ban(ctx)}
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

func checkFail2ban(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("fail2ban-client") {
		return model.Finding{ID: "AUTH-003", Category: "auth", Status: model.Info, NotApplicable: true,
			Evidence: []model.Evidence{{Source: "command lookup", Value: "fail2ban-client not installed"}}}
	}
	active := ctx.Commander.Run(8*time.Second, "systemctl", "is-active", "fail2ban")
	if strings.TrimSpace(active.Stdout) != "active" {
		return model.Finding{ID: "AUTH-003", Category: "auth", Status: model.Risk, Severity: model.Medium,
			Evidence: []model.Evidence{{Source: "systemctl is-active fail2ban", Value: strings.TrimSpace(active.Stdout + " " + active.Stderr)}}}
	}
	status := ctx.Commander.Run(12*time.Second, "fail2ban-client", "status")
	if status.Err != nil {
		return unknown("AUTH-003", "auth", "fail2ban-client status", commandError(status))
	}
	hasSSHD := regexp.MustCompile(`(?i)jail list:.*\bsshd\b`).MatchString(status.Stdout)
	f := model.Finding{ID: "AUTH-003", Category: "auth", Status: model.Pass,
		Evidence: []model.Evidence{{Source: "systemctl", Key: "fail2ban", Value: "active"}, {Source: "fail2ban-client status", Value: truncate(status.Stdout, 600)}}}
	if !hasSSHD {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return f
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
