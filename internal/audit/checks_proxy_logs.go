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
	if r.Truncated || (r.Err != nil && r.Stdout == "") {
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
	for _, pattern := range patterns {
		count := counts[pattern.name]
		f.Facts[pattern.name+"_signals"] = strconv.Itoa(count)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl proxy units", Key: pattern.name, Value: strconv.Itoa(count)})
	}
	return f
}
