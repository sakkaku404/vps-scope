package audit

import (
	"fmt"
	"regexp"
	"sort"
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
	interfaces, installed, err := ctx.Facts.WireGuardInterfaces()
	if !installed {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, iface := range interfaces {
		if iface.Port != "0" {
			out[iface.Port+"/udp"] = true
		}
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
	snapshot := collectAuthAuditSnapshot(ctx)
	return []model.Finding{
		evaluateFailedLogins(snapshot.FailedLogins),
		evaluateSudoAudit(snapshot.Sudo),
		evaluateIntrusionPrevention(snapshot.Intrusion),
	}
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
	windows := sshFailureJournalWindows(ctx.evidenceTime(), ctx.LogSince)
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

func checkIntrusionPrevention(ctx *Context) model.Finding {
	return evaluateIntrusionPrevention(collectIntrusionPreventionSnapshot(ctx))
}

func crowdSecHasBouncer(output string) bool {
	trimmed := strings.TrimSpace(output)
	return trimmed != "" && trimmed != "[]" && trimmed != "null"
}

func checkUpdates(ctx *Context) []model.Finding {
	snapshot := collectUpdateAuditSnapshot(ctx)
	return []model.Finding{evaluatePendingUpdates(snapshot), evaluateUnattended(snapshot)}
}
