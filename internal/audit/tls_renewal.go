package audit

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// tlsRenewalFacts separates the existence of automation from proof that it has
// recently worked. A timer alone is not treated as a successful renewal.
type tlsRenewalFacts struct {
	Schedules      int
	SuccessSignals int
	FailureSignals int
	ReloadHooks    int
	LastOutcome    string
	Methods        []string
	Evidence       []model.Evidence
	DiscoveryError error
}

func collectTLSRenewalFacts(ctx *Context) tlsRenewalFacts {
	return collectTLSRenewalFactsWithDiscovery(ctx, discoverExistingFiles)
}

type renewalFileDiscovery func(maxMatches int, patterns ...string) ([]string, error)

func collectTLSRenewalFactsWithDiscovery(ctx *Context, discover renewalFileDiscovery) tlsRenewalFacts {
	f := tlsRenewalFacts{}
	methods := map[string]bool{}
	if ctx.Commander.Exists("systemctl") {
		for _, timer := range []string{"certbot.timer", "acme.timer", "acme-renew.timer", "lego.timer"} {
			r := ctx.Commander.Run(6*time.Second, "systemctl", "is-enabled", timer)
			if strings.TrimSpace(r.Stdout) != "enabled" {
				continue
			}
			f.Schedules++
			methods[renewalMethod(timer)] = true
			show := ctx.Commander.Run(6*time.Second, "systemctl", "show", timer, "--property=LastTriggerUSec,NextElapseUSecRealtime")
			v := parseKeyValues(show.Stdout)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl", Key: timer, Value: fmt.Sprintf("enabled last_trigger=%s next=%s", valueOrUnknown(v["LastTriggerUSec"]), valueOrUnknown(v["NextElapseUSecRealtime"]))})
		}
		for _, service := range []string{"certbot.service", "acme.service", "acme-renew.service", "lego.service", "caddy.service"} {
			r := ctx.Commander.Run(6*time.Second, "systemctl", "show", service, "--property=LoadState,ActiveState,Result,ExecMainStatus,ActiveEnterTimestamp,ExecReload")
			v := parseKeyValues(r.Stdout)
			if v["LoadState"] != "loaded" {
				continue
			}
			methods[renewalMethod(service)] = true
			result := strings.TrimSpace(v["Result"])
			exit := strings.TrimSpace(v["ExecMainStatus"])
			// A running Caddy service is not, by itself, proof that an ACME
			// renewal completed. Only explicit renewal journal signals count.
			if service != "caddy.service" {
				if result == "success" && (exit == "" || exit == "0") {
					f.SuccessSignals++
					f.LastOutcome = "success"
				} else if result != "" && result != "success" {
					f.FailureSignals++
					f.LastOutcome = "failure"
				}
				if strings.TrimSpace(v["ExecReload"]) != "" && strings.TrimSpace(v["ExecReload"]) != "{}" {
					f.ReloadHooks++
				}
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl", Key: service, Value: fmt.Sprintf("active=%s result=%s exit_status=%s last_active=%s reload_hook=%t", valueOrUnknown(v["ActiveState"]), valueOrUnknown(result), valueOrUnknown(exit), valueOrUnknown(v["ActiveEnterTimestamp"]), strings.TrimSpace(v["ExecReload"]) != "")})
		}
	}
	cronPaths, discoveryErr := discover(512, "/etc/cron.d/*", "/etc/cron.daily/*", "/var/spool/cron/crontabs/*")
	f.DiscoveryError = errors.Join(f.DiscoveryError, discoveryErr)
	for _, path := range cronPaths {
		data, err := readSmall(path, 1<<20)
		if err != nil {
			f.DiscoveryError = errors.Join(f.DiscoveryError, fmt.Errorf("%s: %w", path, err))
			continue
		}
		method := renewalCommandMethod(data)
		if method == "" {
			continue
		}
		f.Schedules++
		methods[method] = true
		// Report only the schedule file and implementation name; command lines
		// may contain account identifiers, DNS credentials, or hook arguments.
		f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: "renewal_schedule", Value: "detected method=" + method})
	}
	for _, pattern := range []string{"/etc/letsencrypt/renewal-hooks/deploy/*", "/etc/letsencrypt/renewal-hooks/post/*"} {
		hookPaths, hookErr := discover(256, pattern)
		f.DiscoveryError = errors.Join(f.DiscoveryError, hookErr)
		for _, path := range hookPaths {
			f.ReloadHooks++
			f.Evidence = append(f.Evidence, model.Evidence{Source: filepath.Dir(path), Key: "renewal_reload_hook", Value: filepath.Base(path)})
		}
	}
	// Journal evidence is reduced to counts. Raw ACME logs can contain domain
	// names, account URLs, and provider-specific identifiers.
	if ctx.Commander.Exists("journalctl") {
		r := ctx.Commander.Run(8*time.Second, "journalctl", "--since", "30 days ago", "-u", "certbot.service", "-u", "acme.service", "-u", "acme-renew.service", "-u", "lego.service", "-u", "caddy.service", "--no-pager", "-o", "cat")
		if r.Err == nil && !r.Truncated {
			success, failure, last := renewalJournalSummary(r.Stdout)
			f.SuccessSignals += success
			f.FailureSignals += failure
			if last != "" {
				f.LastOutcome = last
			}
			if success+failure > 0 {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl (30 days, content withheld)", Key: "renewal_signals", Value: fmt.Sprintf("success=%d failure=%d", success, failure)})
			}
		}
	}
	for method := range methods {
		if method != "" {
			f.Methods = append(f.Methods, method)
		}
	}
	sort.Strings(f.Methods)
	return f
}

func renewalMethod(name string) string {
	name = strings.ToLower(name)
	for _, method := range []string{"certbot", "lego", "caddy"} {
		if strings.Contains(name, method) {
			return method
		}
	}
	return "acme-client"
}

func renewalCommandMethod(data string) string {
	lower := strings.ToLower(data)
	for _, method := range []string{"certbot", "acme.sh", "lego"} {
		if regexp.MustCompile(`(^|[^a-z0-9_.-])` + regexp.QuoteMeta(method) + `([^a-z0-9_.-]|$)`).MatchString(lower) {
			return method
		}
	}
	return ""
}

func renewalJournalSignals(data string) (success, failure int) {
	success, failure, _ = renewalJournalSummary(data)
	return success, failure
}

func renewalJournalSummary(data string) (success, failure int, last string) {
	for _, line := range strings.Split(strings.ToLower(data), "\n") {
		switch {
		case strings.Contains(line, "renew") && (strings.Contains(line, "success") || strings.Contains(line, "not due for renewal")):
			success++
			last = "success"
		case strings.Contains(line, "renew") && (strings.Contains(line, "fail") || strings.Contains(line, "error")):
			failure++
			last = "failure"
		}
	}
	return success, failure, last
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return strings.TrimSpace(value)
}
