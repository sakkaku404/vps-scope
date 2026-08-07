package audit

import (
	"errors"
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
	snapshot := collectNetworkSnapshot(ctx)
	policy := networkPolicyFromContext(ctx)
	return []model.Finding{
		evaluateListenerInventory(snapshot),
		evaluateUnexpectedListeners(snapshot, policy),
		evaluateActiveConnections(snapshot),
		checkExternalObservation(),
	}
}

func checkExternalObservation() model.Finding {
	return model.Finding{
		ID: "NET-004", Category: "network", Status: model.Info, NotApplicable: true,
		Facts:    map[string]string{"observation": "not imported"},
		Evidence: []model.Evidence{{Source: "external probe", Value: "no operator-supplied second-vantage observation is attached"}},
	}
}

func checkUnexpectedListeners(ctx *Context, listeners []Listener) model.Finding {
	runtimeExpected, runtimeExpectedErr := runtimeExpectedPublicListeners(ctx)
	return evaluateUnexpectedListeners(networkSnapshot{
		Listeners: listeners, RuntimeExpected: runtimeExpected, RuntimeExpectedErr: runtimeExpectedErr,
	}, networkPolicyFromContext(ctx))
}

func runtimeExpectedPublicListeners(ctx *Context) (map[string]bool, error) {
	out := map[string]bool{}
	if !ctx.Commander.Exists("wg") {
		return out, nil
	}
	r := ctx.Commander.Run(8*time.Second, "wg", "show", "all", "listen-port")
	if r.Err != nil || r.Truncated {
		return out, fmt.Errorf("wg listen-port inventory: %s", commandError(r))
	}
	for _, line := range lines(r.Stdout) {
		fields := strings.Fields(line)
		if len(fields) < 2 || !validPort(fields[len(fields)-1]) {
			return nil, fmt.Errorf("wg listen-port inventory returned malformed output")
		}
		out[fields[len(fields)-1]+"/udp"] = true
	}
	return out, nil
}

func expectedListener(ctx *Context, listener Listener, key string) bool {
	return expectedListenerForPolicy(networkPolicyFromContext(ctx), listener, key)
}

func checkFirewall(ctx *Context) []model.Finding {
	snapshot := collectFirewallAuditSnapshot(ctx)
	return []model.Finding{evaluateFirewallBase(snapshot), evaluateFirewallExposure(snapshot)}
}

func checkFirewallExposure(ctx *Context) model.Finding {
	return evaluateFirewallExposure(collectFirewallAuditSnapshot(ctx))
}

func includeFirewallExposureRule(backend string, rule firewallRule) bool {
	switch rule.Origin {
	case "ufw-user", "firewalld-zone", "iptables-input", "iptables-reachable", "nft-input", "nft-unknown":
		return true
	case "nft-reachable":
		if backend == "nftables" {
			return true
		}
		// When UFW is active, the live nftables graph is merged specifically
		// to expose rules installed outside UFW. Do not re-list UFW's generated
		// internal chains, but retain independent workload/user chains.
		return backend == "ufw+nftables" && !strings.HasPrefix(strings.ToLower(rule.Chain), "ufw-")
	default:
		return false
	}
}

func sortedBoolKeys(values map[string]bool) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
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

// sshFailureJournalPattern makes journald perform the broad text filter before
// output reaches the bounded command collector. A busy SSH daemon can emit
// hundreds of thousands of successful-login records in a week; fetching that
// full stream would turn an otherwise readable failed-login inventory into an
// avoidable UNKNOWN result.
const sshFailureJournalPattern = `[Ff]ailed (password|publickey)|[Ii]nvalid user|[Aa]uthentication failure|[Mm]aximum authentication attempts exceeded`

const (
	sshFailureJournalWindow    = 48 * time.Hour
	sshFailureJournalMaxSlices = 8
)

var (
	failedPasswordRE  = regexp.MustCompile(`(?i)failed (?:password|publickey)`)
	invalidUserRE     = regexp.MustCompile(`(?i)invalid user`)
	pamFailureRE      = regexp.MustCompile(`(?i)authentication failure`)
	maxAttemptsRE     = regexp.MustCompile(`(?i)maximum authentication attempts exceeded`)
	sshFailureIPRE    = regexp.MustCompile(`(?i)(?:from\s+|rhost=)([0-9a-fA-F:.]+)`)
	sshFailureAnyIPRE = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	sshFailureUserRE  = regexp.MustCompile(`(?i)(?:for invalid user|for user|for)\s+([^ ]+)`)
)

type failedLoginActivity struct {
	failedPassword, invalidUser, pamFailure, maxAttempts int
	ips, users                                           map[string]int
}

func newFailedLoginActivity() failedLoginActivity {
	return failedLoginActivity{ips: map[string]int{}, users: map[string]int{}}
}

func (a *failedLoginActivity) add(text string) {
	for _, line := range lines(text) {
		matched := false
		if failedPasswordRE.MatchString(line) {
			a.failedPassword++
			matched = true
		}
		if invalidUserRE.MatchString(line) {
			a.invalidUser++
			matched = true
		}
		if pamFailureRE.MatchString(line) {
			a.pamFailure++
			matched = true
		}
		if maxAttemptsRE.MatchString(line) {
			a.maxAttempts++
			matched = true
		}
		if !matched {
			continue
		}
		if m := sshFailureIPRE.FindStringSubmatch(line); len(m) > 1 {
			a.ips[m[1]]++
		} else if candidate := sshFailureAnyIPRE.FindString(line); candidate != "" {
			a.ips[candidate]++
		}
		if m := sshFailureUserRE.FindStringSubmatch(line); len(m) > 1 {
			a.users[m[1]]++
		}
	}
}

type sshJournalWindow struct{ since, until time.Time }

func journalTimestamp(value time.Time) string {
	// journalctl accepts this portable, explicit-UTC form on the supported
	// Debian/Ubuntu systemd releases. RFC3339's T...Z form is rejected by some
	// Debian builds even though Go normally uses it for machine timestamps.
	return value.UTC().Truncate(time.Second).Format("2006-01-02 15:04:05 UTC")
}

func sshFailureJournalWindows(now time.Time, lookback time.Duration) []sshJournalWindow {
	if lookback <= sshFailureJournalWindow {
		return []sshJournalWindow{{since: now.Add(-lookback), until: now}}
	}
	slices := int((lookback + sshFailureJournalWindow - 1) / sshFailureJournalWindow)
	if slices > sshFailureJournalMaxSlices {
		slices = sshFailureJournalMaxSlices
	}
	start := now.Add(-lookback)
	width := lookback / time.Duration(slices)
	windows := make([]sshJournalWindow, 0, slices)
	for index := 0; index < slices; index++ {
		end := start.Add(width)
		if index == slices-1 {
			end = now
		}
		windows = append(windows, sshJournalWindow{since: start, until: end})
		start = end
	}
	return windows
}

func journalNoMatches(r CommandResult) bool {
	return !r.Truncated && r.Code == 1 && strings.TrimSpace(r.Stdout) == "" && strings.TrimSpace(r.Stderr) == ""
}

func collectSSHFailureJournal(ctx *Context) (failedLoginActivity, int, error) {
	activity := newFailedLoginActivity()
	if ctx.LogSince <= sshFailureJournalWindow {
		r := ctx.Commander.Run(25*time.Second, "journalctl", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service")
		if (r.Err != nil || r.Truncated) && !journalNoMatches(r) {
			return activity, 0, fmt.Errorf("journalctl SSH units: %s", commandError(r))
		}
		activity.add(r.Stdout)
		return activity, 1, nil
	}
	windows := sshFailureJournalWindows(ctx.Now(), ctx.LogSince)
	for index, window := range windows {
		args := []string{"--since", journalTimestamp(window.since), "--until", journalTimestamp(window.until), "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"}
		r := ctx.Commander.Run(15*time.Second, "journalctl", args...)
		if (r.Err != nil || r.Truncated) && !journalNoMatches(r) {
			return activity, index + 1, fmt.Errorf("journalctl SSH units slice %d/%d: %s", index+1, len(windows), commandError(r))
		}
		activity.add(r.Stdout)
	}
	return activity, len(windows), nil
}

func checkFailedLogins(ctx *Context) model.Finding {
	f := model.Finding{ID: "AUTH-001", Category: "auth", Status: model.Info, Facts: map[string]string{}}
	activity := newFailedLoginActivity()
	var source string
	var journalErr error
	if ctx.Commander.Exists("journalctl") {
		var slices int
		activity, slices, journalErr = collectSSHFailureJournal(ctx)
		if journalErr == nil {
			suffix := ""
			if slices != 1 {
				suffix = "s"
			}
			source = fmt.Sprintf("journalctl filtered SSH units (%d slice%s)", slices, suffix)
		} else {
			// Do not count a journal prefix as a complete lookback window. A
			// traditional log file can still provide independent full evidence.
			activity = newFailedLoginActivity()
		}
	}
	if source == "" {
		for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if data, err := readSmall(path, 100<<20); err == nil {
				activity.add(data)
				source = path
				break
			}
		}
	}
	if source == "" {
		if journalErr != nil {
			return unknown("AUTH-001", "auth", "journalctl SSH units", journalErr.Error())
		}
		return unknown("AUTH-001", "auth", "journal/auth log", "no readable SSH authentication log source")
	}
	// Categories can overlap on the same attempt, so expose each count rather
	// than adding them into a misleading single total.
	f.Facts["failed_password_or_key"] = strconv.Itoa(activity.failedPassword)
	f.Facts["invalid_user_lines"] = strconv.Itoa(activity.invalidUser)
	f.Facts["pam_auth_failure_lines"] = strconv.Itoa(activity.pamFailure)
	f.Facts["max_attempt_lines"] = strconv.Itoa(activity.maxAttempts)
	f.Facts["unique_sources"] = strconv.Itoa(len(activity.ips))
	f.Facts["targeted_users"] = strconv.Itoa(len(activity.users))
	f.Evidence = []model.Evidence{
		{Source: source, Key: "failed_password_or_key", Value: strconv.Itoa(activity.failedPassword)},
		{Source: source, Key: "invalid_user_lines", Value: strconv.Itoa(activity.invalidUser)},
		{Source: source, Key: "pam_auth_failure_lines", Value: strconv.Itoa(activity.pamFailure)},
		{Source: source, Key: "max_attempt_lines", Value: strconv.Itoa(activity.maxAttempts)},
		{Source: source, Key: "unique_sources", Value: strconv.Itoa(len(activity.ips))},
	}
	for _, entry := range topCounts(activity.ips, 10) {
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
	if r.Err != nil || r.Truncated {
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
	knownUnprotected := false
	var discoveryErr error
	if fail2banInstalled {
		active := ctx.Commander.Run(8*time.Second, "systemctl", "is-active", "fail2ban")
		if active.Truncated || (active.Err != nil && active.Code != 3) {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("systemctl is-active fail2ban: %s", commandError(active)))
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "fail2ban_unavailable", Value: commandError(active)})
		} else if isActive := strings.TrimSpace(active.Stdout) == "active"; isActive {
			f.Facts["fail2ban_active"] = "true"
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "fail2ban", Value: "active"})
			status := ctx.Commander.Run(12*time.Second, "fail2ban-client", "status")
			if status.Err == nil && !status.Truncated {
				hasSSHD := regexp.MustCompile(`(?i)jail list:.*\bsshd\b`).MatchString(status.Stdout)
				f.Facts["fail2ban_sshd_jail"] = strconv.FormatBool(hasSSHD)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "fail2ban-client status", Value: truncate(status.Stdout, 600)})
				protected = protected || hasSSHD
				knownUnprotected = knownUnprotected || !hasSSHD
			} else {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("fail2ban-client status: %s", commandError(status)))
				f.Evidence = append(f.Evidence, model.Evidence{Source: "fail2ban-client status", Key: "unavailable", Value: commandError(status)})
			}
		} else {
			f.Facts["fail2ban_active"] = "false"
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "fail2ban", Value: valueOr(strings.TrimSpace(active.Stdout), "inactive")})
			knownUnprotected = true
		}
	}
	if crowdSecInstalled {
		active := ctx.Commander.Run(8*time.Second, "systemctl", "is-active", "crowdsec")
		if active.Truncated || (active.Err != nil && active.Code != 3) {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("systemctl is-active crowdsec: %s", commandError(active)))
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "crowdsec_unavailable", Value: commandError(active)})
		} else if isActive := strings.TrimSpace(active.Stdout) == "active"; isActive {
			f.Facts["crowdsec_active"] = "true"
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "crowdsec", Value: "active"})
			bouncers := ctx.Commander.Run(12*time.Second, "cscli", "bouncers", "list", "-o", "json")
			if bouncers.Err == nil && !bouncers.Truncated {
				hasBouncer := crowdSecHasBouncer(bouncers.Stdout)
				f.Facts["crowdsec_bouncer_configured"] = strconv.FormatBool(hasBouncer)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "cscli bouncers list", Key: "configured", Value: strconv.FormatBool(hasBouncer)})
				protected = protected || hasBouncer
				knownUnprotected = knownUnprotected || !hasBouncer
			} else {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("cscli bouncers list: %s", commandError(bouncers)))
				f.Evidence = append(f.Evidence, model.Evidence{Source: "cscli bouncers list", Key: "unavailable", Value: commandError(bouncers)})
			}
		} else {
			f.Facts["crowdsec_active"] = "false"
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: "crowdsec", Value: valueOr(strings.TrimSpace(active.Stdout), "inactive")})
			knownUnprotected = true
		}
	}
	if protected {
		f.Status = model.Pass
	} else if knownUnprotected {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return withIncompleteEvidence(f, "intrusion-prevention discovery", discoveryErr)
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
	if r.Truncated || r.Err != nil {
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
	installedKnown := false
	var discoveryErr error
	if ctx.Commander.Exists("dpkg-query") {
		r := ctx.Commander.Run(8*time.Second, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
		if r.Err != nil || r.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("dpkg-query unattended-upgrades: %s", commandError(r)))
		} else {
			installedKnown = true
			installed = strings.Contains(r.Stdout, "install ok installed")
		}
	} else {
		discoveryErr = errors.Join(discoveryErr, errors.New("dpkg-query command not found"))
	}
	timerState := "unavailable"
	enabled := false
	enabledKnown := false
	if ctx.Commander.Exists("systemctl") {
		timer := ctx.Commander.Run(8*time.Second, "systemctl", "is-enabled", "apt-daily-upgrade.timer")
		timerState = strings.TrimSpace(timer.Stdout)
		if timer.Err != nil || timer.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("systemctl is-enabled apt-daily-upgrade.timer: %s", commandError(timer)))
		} else {
			enabledKnown = true
			enabled = timerState == "enabled" || timerState == "static"
		}
	} else {
		discoveryErr = errors.Join(discoveryErr, errors.New("systemctl command not found"))
	}
	f.Evidence = []model.Evidence{{Source: "dpkg-query", Key: "unattended-upgrades_installed", Value: strconv.FormatBool(installed)}, {Source: "systemctl is-enabled", Key: "apt-daily-upgrade.timer", Value: timerState}}
	if (installedKnown && !installed) || (enabledKnown && !enabled) {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return withIncompleteEvidence(f, "automatic security update discovery", discoveryErr)
}
