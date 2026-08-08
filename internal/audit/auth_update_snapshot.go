package audit

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// authAuditSnapshot freezes the command and file evidence used by AUTH-001
// through AUTH-003. The evaluators below do not execute commands or read the
// host, which keeps policy decisions deterministic and fixture-friendly.
type authAuditSnapshot struct {
	FailedLogins failedLoginSnapshot
	Sudo         sudoAuditSnapshot
	Intrusion    intrusionPreventionSnapshot
}

type failedLoginSnapshot struct {
	Activity failedLoginActivity
	Source   string
	Err      error
}

type sudoAuditSnapshot struct {
	Available bool
	Result    CommandResult
}

type intrusionServiceSnapshot struct {
	Installed       bool
	ActiveKnown     bool
	Active          bool
	ActiveValue     string
	ProtectionKnown bool
	Protected       bool
	Detail          string
	Err             error
}

type intrusionPreventionSnapshot struct {
	Fail2ban intrusionServiceSnapshot
	CrowdSec intrusionServiceSnapshot
}

func collectAuthAuditSnapshot(ctx *Context) authAuditSnapshot {
	return authAuditSnapshot{
		FailedLogins: collectFailedLoginSnapshot(ctx),
		Sudo:         collectSudoAuditSnapshot(ctx),
		Intrusion:    collectIntrusionPreventionSnapshot(ctx),
	}
}

func collectFailedLoginSnapshot(ctx *Context) failedLoginSnapshot {
	snapshot := failedLoginSnapshot{Activity: newFailedLoginActivity()}
	var journalErr error
	if ctx.Commander.Exists("journalctl") {
		var slices int
		snapshot.Activity, slices, journalErr = collectSSHFailureJournal(ctx)
		if journalErr == nil {
			suffix := ""
			if slices != 1 {
				suffix = "s"
			}
			snapshot.Source = fmt.Sprintf("journalctl filtered SSH units (%d slice%s)", slices, suffix)
		} else {
			// A partial journal window must not be presented as complete evidence.
			snapshot.Activity = newFailedLoginActivity()
		}
	}
	if snapshot.Source == "" {
		for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
			if data, err := ctx.Facts.ReadSmall(path, 100<<20); err == nil {
				snapshot.Activity.add(data)
				snapshot.Source = path
				break
			}
		}
	}
	if snapshot.Source == "" {
		if journalErr != nil {
			snapshot.Err = fmt.Errorf("journalctl SSH units: %w", journalErr)
		} else {
			snapshot.Err = errors.New("no readable SSH authentication log source")
		}
	}
	return snapshot
}

func collectSudoAuditSnapshot(ctx *Context) sudoAuditSnapshot {
	if !ctx.Commander.Exists("journalctl") {
		return sudoAuditSnapshot{}
	}
	return sudoAuditSnapshot{
		Available: true,
		Result:    ctx.Commander.Run(15*time.Second, "journalctl", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat", "_COMM=sudo"),
	}
}

func collectIntrusionPreventionSnapshot(ctx *Context) intrusionPreventionSnapshot {
	return intrusionPreventionSnapshot{
		Fail2ban: collectIntrusionService(ctx, "fail2ban-client", "fail2ban", func() (bool, string, error) {
			result := ctx.Commander.Run(12*time.Second, "fail2ban-client", "status")
			if result.Err != nil || result.Truncated {
				return false, commandError(result), fmt.Errorf("fail2ban-client status: %s", commandError(result))
			}
			protected := regexp.MustCompile(`(?i)jail list:.*\bsshd\b`).MatchString(result.Stdout)
			return protected, truncate(result.Stdout, 600), nil
		}),
		CrowdSec: collectIntrusionService(ctx, "cscli", "crowdsec", func() (bool, string, error) {
			result := ctx.Commander.Run(12*time.Second, "cscli", "bouncers", "list", "-o", "json")
			if result.Err != nil || result.Truncated {
				return false, commandError(result), fmt.Errorf("cscli bouncers list: %s", commandError(result))
			}
			protected := crowdSecHasBouncer(result.Stdout)
			return protected, strconv.FormatBool(protected), nil
		}),
	}
}

func collectIntrusionService(ctx *Context, command, unit string, detail func() (bool, string, error)) intrusionServiceSnapshot {
	snapshot := intrusionServiceSnapshot{Installed: ctx.Commander.Exists(command)}
	if !snapshot.Installed {
		return snapshot
	}
	active := ctx.Commander.Run(8*time.Second, "systemctl", "is-active", unit)
	snapshot.ActiveValue = valueOr(strings.TrimSpace(active.Stdout), "inactive")
	if active.Truncated || (active.Err != nil && active.Code != 3) {
		snapshot.Err = fmt.Errorf("systemctl is-active %s: %s", unit, commandError(active))
		return snapshot
	}
	snapshot.ActiveKnown = true
	snapshot.Active = strings.TrimSpace(active.Stdout) == "active"
	if !snapshot.Active {
		snapshot.ProtectionKnown = true
		return snapshot
	}
	protected, value, err := detail()
	snapshot.Detail = value
	if err != nil {
		snapshot.Err = err
		return snapshot
	}
	snapshot.ProtectionKnown = true
	snapshot.Protected = protected
	return snapshot
}

func evaluateFailedLogins(snapshot failedLoginSnapshot) model.Finding {
	if snapshot.Err != nil {
		source := "journal/auth log"
		if strings.Contains(snapshot.Err.Error(), "journalctl") {
			source = "journalctl SSH units"
		}
		return unknown("AUTH-001", "auth", source, snapshot.Err.Error())
	}
	activity := snapshot.Activity
	f := model.Finding{ID: "AUTH-001", Category: "auth", Status: model.Info, Facts: map[string]string{}}
	f.Facts["failed_password_or_key"] = strconv.Itoa(activity.failedPassword)
	f.Facts["invalid_user_lines"] = strconv.Itoa(activity.invalidUser)
	f.Facts["pam_auth_failure_lines"] = strconv.Itoa(activity.pamFailure)
	f.Facts["max_attempt_lines"] = strconv.Itoa(activity.maxAttempts)
	f.Facts["unique_sources"] = strconv.Itoa(len(activity.ips))
	f.Facts["targeted_users"] = strconv.Itoa(len(activity.users))
	f.Evidence = []model.Evidence{
		{Source: snapshot.Source, Key: "failed_password_or_key", Value: strconv.Itoa(activity.failedPassword)},
		{Source: snapshot.Source, Key: "invalid_user_lines", Value: strconv.Itoa(activity.invalidUser)},
		{Source: snapshot.Source, Key: "pam_auth_failure_lines", Value: strconv.Itoa(activity.pamFailure)},
		{Source: snapshot.Source, Key: "max_attempt_lines", Value: strconv.Itoa(activity.maxAttempts)},
		{Source: snapshot.Source, Key: "unique_sources", Value: strconv.Itoa(len(activity.ips))},
	}
	for _, entry := range topCounts(activity.ips, 10) {
		f.Evidence = append(f.Evidence, model.Evidence{Source: snapshot.Source, Key: "source_count", Value: entry})
	}
	return f
}

func evaluateSudoAudit(snapshot sudoAuditSnapshot) model.Finding {
	if !snapshot.Available {
		return unknown("AUTH-002", "auth", "journalctl", "command not found")
	}
	if snapshot.Result.Err != nil || snapshot.Result.Truncated {
		return unknown("AUTH-002", "auth", "journalctl _COMM=sudo", commandError(snapshot.Result))
	}
	count := len(lines(snapshot.Result.Stdout))
	status := model.Pass
	if count == 0 {
		status = model.Info
	}
	return model.Finding{ID: "AUTH-002", Category: "auth", Status: status,
		Facts:    map[string]string{"sudo_journal_lines": strconv.Itoa(count)},
		Evidence: []model.Evidence{{Source: "journalctl _COMM=sudo", Key: "lines", Value: strconv.Itoa(count)}}}
}

func evaluateIntrusionPrevention(snapshot intrusionPreventionSnapshot) model.Finding {
	f := model.Finding{ID: "AUTH-003", Category: "auth", Status: model.Info, Facts: map[string]string{}}
	f.Facts["fail2ban_installed"] = strconv.FormatBool(snapshot.Fail2ban.Installed)
	f.Facts["crowdsec_installed"] = strconv.FormatBool(snapshot.CrowdSec.Installed)
	if !snapshot.Fail2ban.Installed && !snapshot.CrowdSec.Installed {
		f.NotApplicable = true
		f.Evidence = []model.Evidence{{Source: "command lookup", Value: "neither fail2ban-client nor cscli is installed"}}
		return f
	}
	protected, knownUnprotected := false, false
	var discoveryErr error
	for _, service := range []struct {
		name   string
		status intrusionServiceSnapshot
	}{
		{"fail2ban", snapshot.Fail2ban},
		{"crowdsec", snapshot.CrowdSec},
	} {
		if !service.status.Installed {
			continue
		}
		if service.status.Err != nil {
			discoveryErr = errors.Join(discoveryErr, service.status.Err)
			f.Evidence = append(f.Evidence, model.Evidence{Source: service.name, Key: "unavailable", Value: service.status.Err.Error()})
			continue
		}
		f.Facts[service.name+"_active"] = strconv.FormatBool(service.status.Active)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-active", Key: service.name, Value: service.status.ActiveValue})
		if !service.status.Active {
			knownUnprotected = true
			continue
		}
		if service.name == "fail2ban" {
			f.Facts["fail2ban_sshd_jail"] = strconv.FormatBool(service.status.Protected)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "fail2ban-client status", Value: service.status.Detail})
		} else {
			f.Facts["crowdsec_bouncer_configured"] = strconv.FormatBool(service.status.Protected)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "cscli bouncers list", Key: "configured", Value: service.status.Detail})
		}
		protected = protected || service.status.Protected
		knownUnprotected = knownUnprotected || service.status.ProtectionKnown && !service.status.Protected
	}
	if protected {
		f.Status = model.Pass
	} else if knownUnprotected {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return withIncompleteEvidence(f, "intrusion-prevention discovery", discoveryErr)
}

// updateAuditSnapshot freezes package-manager and service-manager evidence for
// UPD-001 and UPD-002 before either policy is evaluated.
type updateAuditSnapshot struct {
	APTAvailable       bool
	APTUpgrade         CommandResult
	RebootRequired     bool
	DPKGQueryAvailable bool
	UnattendedPackage  CommandResult
	SystemctlAvailable bool
	UpgradeTimer       CommandResult
}

func collectUpdateAuditSnapshot(ctx *Context) updateAuditSnapshot {
	snapshot := updateAuditSnapshot{
		APTAvailable:       ctx.Commander.Exists("apt-get"),
		DPKGQueryAvailable: ctx.Commander.Exists("dpkg-query"),
		SystemctlAvailable: ctx.Commander.Exists("systemctl"),
	}
	if snapshot.APTAvailable {
		snapshot.APTUpgrade = ctx.Commander.Run(45*time.Second, "apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade")
	}
	_, err := ctx.Facts.Stat("/var/run/reboot-required")
	snapshot.RebootRequired = err == nil
	if snapshot.DPKGQueryAvailable {
		snapshot.UnattendedPackage = ctx.Commander.Run(8*time.Second, "dpkg-query", "-W", "-f=${Status}", "unattended-upgrades")
	}
	if snapshot.SystemctlAvailable {
		snapshot.UpgradeTimer = ctx.Commander.Run(8*time.Second, "systemctl", "is-enabled", "apt-daily-upgrade.timer")
	}
	return snapshot
}

func evaluatePendingUpdates(snapshot updateAuditSnapshot) model.Finding {
	if !snapshot.APTAvailable {
		return unknown("UPD-001", "updates", "apt-get", "command not found")
	}
	if snapshot.APTUpgrade.Truncated || snapshot.APTUpgrade.Err != nil {
		return unknown("UPD-001", "updates", "apt-get -s upgrade", commandError(snapshot.APTUpgrade))
	}
	regular, security, phased := 0, 0, 0
	var packages []string
	for _, line := range lines(snapshot.APTUpgrade.Stdout) {
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
	if snapshot.RebootRequired {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "/var/run/reboot-required", Value: "present"})
		if f.Status == model.Pass {
			f.Status, f.Severity = model.Risk, model.Medium
		}
	}
	return f
}

func evaluateUnattended(snapshot updateAuditSnapshot) model.Finding {
	f := model.Finding{ID: "UPD-002", Category: "updates", Status: model.Pass}
	installed, installedKnown := false, false
	var discoveryErr error
	if snapshot.DPKGQueryAvailable {
		if snapshot.UnattendedPackage.Err != nil || snapshot.UnattendedPackage.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("dpkg-query unattended-upgrades: %s", commandError(snapshot.UnattendedPackage)))
		} else {
			installedKnown = true
			installed = strings.Contains(snapshot.UnattendedPackage.Stdout, "install ok installed")
		}
	} else {
		discoveryErr = errors.Join(discoveryErr, errors.New("dpkg-query command not found"))
	}
	timerState, enabled, enabledKnown := "unavailable", false, false
	if snapshot.SystemctlAvailable {
		timerState = strings.TrimSpace(snapshot.UpgradeTimer.Stdout)
		if snapshot.UpgradeTimer.Err != nil || snapshot.UpgradeTimer.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("systemctl is-enabled apt-daily-upgrade.timer: %s", commandError(snapshot.UpgradeTimer)))
		} else {
			enabledKnown = true
			enabled = timerState == "enabled" || timerState == "static"
		}
	} else {
		discoveryErr = errors.Join(discoveryErr, errors.New("systemctl command not found"))
	}
	f.Evidence = []model.Evidence{{Source: "dpkg-query", Key: "unattended-upgrades_installed", Value: strconv.FormatBool(installed)}, {Source: "systemctl is-enabled", Key: "apt-daily-upgrade.timer", Value: timerState}}
	if installedKnown && !installed || enabledKnown && !enabled {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return withIncompleteEvidence(f, "automatic security update discovery", discoveryErr)
}
