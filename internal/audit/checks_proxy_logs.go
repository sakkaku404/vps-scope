package audit

import (
	"regexp"
	"strconv"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// checkProxyLogSignals is kept separate from configuration policy: it only
// classifies operational activity and deliberately never treats a count as a
// vulnerability on its own.
func checkProxyLogSignals(ctx *Context) model.Finding {
	units := proxyServiceUnits(ctx)
	if len(units) == 0 {
		return notApplicable("WORK-010", "workloads", "systemd", "no supported proxy systemd service found")
	}
	if !ctx.Commander.Exists("journalctl") {
		return unknown("WORK-010", "workloads", "journalctl", "command not found")
	}
	args := []string{"--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat"}
	for _, unit := range units {
		args = append(args, "-u", unit)
	}
	r := ctx.Commander.Run(25*time.Second, "journalctl", args...)
	// A non-zero journalctl exit can still carry a prefix of the selected
	// units. That prefix is not a complete log window, so never publish its
	// counts as a normal operational conclusion.
	if r.Truncated || r.Err != nil {
		return unknown("WORK-010", "workloads", "journalctl proxy units", commandError(r))
	}
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"authentication", regexp.MustCompile(`(?i)\b(auth|authentication|unauthorized|invalid user|bad password)\b`)},
		{"tls", regexp.MustCompile(`(?i)\b(tls|certificate|x509)\b.{0,80}\b(error|fail|expired|invalid)\b`)},
		{"dns", regexp.MustCompile(`(?i)\b(dns|resolver|resolve)\b.{0,80}\b(error|fail|timeout|refused)\b`)},
		{"routing", regexp.MustCompile(`(?i)\b(route|routing|outbound)\b.{0,80}\b(error|fail|unreachable|refused)\b`)},
		{"handshake", regexp.MustCompile(`(?i)\b(handshake)\b.{0,80}\b(error|fail|timeout|invalid)\b`)},
		{"fatal", regexp.MustCompile(`(?i)\b(panic|fatal|segmentation fault)\b`)},
		{"panel_login_failure", regexp.MustCompile(`(?i)\b(login|sign[ -]?in|auth(?:entication)?)\b.{0,100}\b(fail|invalid|wrong|denied|unauthori[sz]ed|bad password)\b`)},
		{"api_unauthorized", regexp.MustCompile(`(?i)\b(api|rpc|clash|v2ray)\b.{0,100}\b(unauthori[sz]ed|forbidden|denied|401|403|invalid token)\b`)},
		{"subscription_abuse", regexp.MustCompile(`(?i)\b(subscription|subscribe|sub link|/sub/)\b.{0,100}\b(unauthori[sz]ed|forbidden|denied|invalid|expired|401|403|404)\b`)},
		{"rate_limit", regexp.MustCompile(`(?i)\b(rate.?limit|too many requests|http[^0-9]*429)\b`)},
		{"web_probe", regexp.MustCompile(`(?i)\b(wp-login|phpmyadmin|\.env|\.git/config|cgi-bin|path traversal|malformed request)\b`)},
	}
	counts := map[string]int{}
	for _, line := range lines(r.Stdout) {
		for _, pattern := range patterns {
			if pattern.re.MatchString(line) {
				counts[pattern.name]++
			}
		}
	}
	f := model.Finding{ID: "WORK-010", Category: "workloads", Status: model.Info, Facts: map[string]string{"units": strconv.Itoa(len(units))}}
	suspicious := 0
	for _, pattern := range patterns {
		count := counts[pattern.name]
		if pattern.name == "panel_login_failure" || pattern.name == "api_unauthorized" || pattern.name == "subscription_abuse" || pattern.name == "rate_limit" || pattern.name == "web_probe" {
			suspicious += count
		}
		f.Facts[pattern.name+"_signals"] = strconv.Itoa(count)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl proxy units", Key: pattern.name, Value: strconv.Itoa(count)})
	}
	f.Facts["suspicious_activity_signals"] = strconv.Itoa(suspicious)
	return f
}
