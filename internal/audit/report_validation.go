package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
)

var reportReasonCodePattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

// ValidateReport checks the semantic integrity of a completed audit report.
// It complements bundle hashes: a byte-perfect file can still be incomplete
// or internally inconsistent.
func ValidateReport(r model.Report, verifierVersion ...string) []string {
	var failures []string
	if r.SchemaVersion != "1.0" {
		failures = append(failures, fmt.Sprintf("unsupported report schema %q", r.SchemaVersion))
	}
	if r.ToolVersion == "" {
		failures = append(failures, "tool_version is empty")
	}
	if !i18n.Supported(r.Locale) {
		failures = append(failures, fmt.Sprintf("unsupported or empty report locale %q", r.Locale))
	}
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() || r.FinishedAt.Before(r.StartedAt) {
		failures = append(failures, "audit timestamps are missing or out of order")
	}
	if duration, err := time.ParseDuration(r.LogSince); err != nil || duration <= 0 {
		failures = append(failures, fmt.Sprintf("invalid log_since %q", r.LogSince))
	}
	if r.Host.OS != "ubuntu" && r.Host.OS != "debian" {
		failures = append(failures, fmt.Sprintf("unsupported or empty host OS %q", r.Host.OS))
	}
	for _, field := range []struct{ name, value string }{
		{"stable_id", r.Host.StableID}, {"hostname", r.Host.Hostname}, {"os_version", r.Host.OSVersion},
		{"kernel", r.Host.Kernel}, {"architecture", r.Host.Architecture},
	} {
		if strings.TrimSpace(field.value) == "" {
			failures = append(failures, "host "+field.name+" is empty")
		}
	}
	for _, field := range []struct {
		name, value string
		requested   bool
	}{
		{"requested", r.Profile.Requested, true},
		{"detected", r.Profile.Detected, false},
		{"effective", r.Profile.Effective, false},
	} {
		if !validReportProfile(field.value, field.requested) {
			failures = append(failures, fmt.Sprintf("invalid profile %s %q", field.name, field.value))
		}
	}
	seenEndpoints := map[string]bool{}
	for index, endpoint := range r.Endpoints {
		if endpoint.Protocol != "tcp" && endpoint.Protocol != "udp" {
			failures = append(failures, fmt.Sprintf("endpoint %d has invalid protocol %q", index+1, endpoint.Protocol))
		}
		if endpoint.Port < 1 || endpoint.Port > 65535 {
			failures = append(failures, fmt.Sprintf("endpoint %d has invalid port %d", index+1, endpoint.Port))
		}
		if endpoint.Family != "ipv4" && endpoint.Family != "ipv6" {
			failures = append(failures, fmt.Sprintf("endpoint %d has invalid family %q", index+1, endpoint.Family))
		}
		if !containsReportValue(endpoint.Scope, "public", "public-wildcard", "private", "loopback") {
			failures = append(failures, fmt.Sprintf("endpoint %d has invalid scope %q", index+1, endpoint.Scope))
		}
		if endpoint.Role != "" && !containsReportValue(endpoint.Role, "proxy-ingress", "management", "subscription", "control-api", "web", "ssh", "other") {
			failures = append(failures, fmt.Sprintf("endpoint %d has invalid role %q", index+1, endpoint.Role))
		}
		if endpoint.ExpectedExposure != "" && !containsReportValue(endpoint.ExpectedExposure, "public", "restricted", "private", "loopback", "blocked") {
			failures = append(failures, fmt.Sprintf("endpoint %d has invalid expected_exposure %q", index+1, endpoint.ExpectedExposure))
		}
		if len(endpoint.Process) > 256 {
			failures = append(failures, fmt.Sprintf("endpoint %d process evidence is too long", index+1))
		}
		key := fmt.Sprintf("%s/%d/%s/%s", endpoint.Protocol, endpoint.Port, endpoint.Family, endpoint.Scope)
		if seenEndpoints[key] {
			failures = append(failures, fmt.Sprintf("duplicate endpoint %s", key))
		}
		seenEndpoints[key] = true
	}

	expected := make(map[string]bool, len(StableCheckIDs))
	for _, id := range StableCheckIDs {
		expected[id] = true
	}
	seen := map[string]bool{}
	_, _, parsedVersion := semanticVersion(r.ToolVersion)
	requireFullContract := !parsedVersion || versionAtLeast(r.ToolVersion, 0, 12)
	requireReasons := !parsedVersion || versionAtLeast(r.ToolVersion, 0, 13)
	allowFutureIDs := len(verifierVersion) == 1 && versionNewerThan(r.ToolVersion, verifierVersion[0])
	for _, f := range r.Findings {
		if !expected[f.ID] && !(allowFutureIDs && stableCheckIDPattern.MatchString(f.ID)) {
			failures = append(failures, fmt.Sprintf("unexpected check ID %q", f.ID))
		}
		if seen[f.ID] {
			failures = append(failures, fmt.Sprintf("duplicate check ID %q", f.ID))
		}
		seen[f.ID] = true
		switch f.Status {
		case model.Pass, model.Risk, model.Info, model.Unknown:
		default:
			failures = append(failures, fmt.Sprintf("%s has invalid status %q", f.ID, f.Status))
		}
		if f.Status == model.Risk && !validSeverity(f.Severity) {
			failures = append(failures, fmt.Sprintf("%s is RISK without a valid severity", f.ID))
		}
		if f.Status != model.Risk && f.Severity != "" {
			failures = append(failures, fmt.Sprintf("%s has severity %q without RISK status", f.ID, f.Severity))
		}
		if f.Unavailable && f.Status != model.Unknown {
			failures = append(failures, fmt.Sprintf("%s is unavailable without UNKNOWN status", f.ID))
		}
		if f.Unavailable && f.NotApplicable {
			failures = append(failures, fmt.Sprintf("%s is both unavailable and not_applicable", f.ID))
		}
		if f.NotApplicable && f.Status != model.Info {
			failures = append(failures, fmt.Sprintf("%s is not_applicable without INFO status", f.ID))
		}
		if category := reportCategoryForID(f.ID); category != "" {
			if f.Category != category {
				failures = append(failures, fmt.Sprintf("%s has category %q; expected %q", f.ID, f.Category, category))
			}
		} else if f.Category == "" {
			failures = append(failures, fmt.Sprintf("%s has an empty category", f.ID))
		}
		if requireReasons && f.ReasonCode == "" {
			failures = append(failures, fmt.Sprintf("%s is missing reason_code", f.ID))
		}
		if f.ReasonCode != "" {
			prefix := strings.ToLower(strings.ReplaceAll(f.ID, "-", ".")) + "."
			if !reportReasonCodePattern.MatchString(f.ReasonCode) || !strings.HasPrefix(f.ReasonCode, prefix) {
				failures = append(failures, fmt.Sprintf("%s has invalid reason_code %q", f.ID, f.ReasonCode))
			}
		}
	}
	if requireFullContract {
		for _, id := range StableCheckIDs {
			if !seen[id] {
				failures = append(failures, fmt.Sprintf("required check ID %s is missing", id))
			}
		}
	}
	recounted := r
	recounted.Recount()
	if recounted.Summary != r.Summary {
		failures = append(failures, fmt.Sprintf("summary does not match findings: declared=%+v recounted=%+v", r.Summary, recounted.Summary))
	}
	return failures
}

func containsReportValue(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func validSeverity(severity model.Severity) bool {
	return severity == model.Critical || severity == model.High || severity == model.Medium || severity == model.Low
}

func versionAtLeast(version string, wantMajor, wantMinor int) bool {
	major, minor, ok := semanticVersion(version)
	if !ok {
		return false
	}
	return major > wantMajor || major == wantMajor && minor >= wantMinor
}

func semanticVersion(version string) (int, int, bool) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil || major < 0 || minor < 0 {
		return 0, 0, false
	}
	return major, minor, true
}

func versionNewerThan(version, reference string) bool {
	major, minor, ok := semanticVersion(version)
	referenceMajor, referenceMinor, referenceOK := semanticVersion(reference)
	if !ok || !referenceOK {
		return false
	}
	return major > referenceMajor || major == referenceMajor && minor > referenceMinor
}

func reportCategoryForID(id string) string {
	prefix, _, _ := strings.Cut(id, "-")
	switch prefix {
	case "SYS":
		return "system"
	case "ACC":
		return "accounts"
	case "SSH":
		return "ssh"
	case "PRIV":
		return "privileges"
	case "NET":
		return "network"
	case "FW":
		return "firewall"
	case "AUTH":
		return "auth"
	case "UPD":
		return "updates"
	case "PKG":
		return "packages"
	case "PROC":
		return "processes"
	case "DOCKER":
		return "docker"
	case "TLS":
		return "tls"
	case "WORK":
		return "workloads"
	case "FS":
		return "filesystem"
	case "PERSIST":
		return "persistence"
	case "REL":
		return "reliability"
	default:
		return ""
	}
}

func validReportProfile(profile string, requested bool) bool {
	if requested && profile == "auto" {
		return true
	}
	for _, allowed := range []string{"general", "proxy", "web", "docker", "mixed", "custom"} {
		if profile == allowed {
			return true
		}
	}
	return false
}
