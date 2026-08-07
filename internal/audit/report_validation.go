package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/contract"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
)

var reportReasonCodePattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

const (
	maxReportDeploymentComponents = 512
	maxReportDeploymentEndpoints  = 2048
	maxReportDeploymentLinks      = 8192
)

var topologyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$`)

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
	failures = append(failures, validateDeployment(r.Deployment)...)

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
		if !expected[f.ID] && !(allowFutureIDs && contract.ValidCheckID(f.ID)) {
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

func validateDeployment(deployment *model.Deployment) []string {
	if deployment == nil {
		return nil
	}
	var failures []string
	for _, field := range []struct{ name, value string }{
		{"configuration", deployment.Coverage.Configuration},
		{"runtime", deployment.Coverage.Runtime},
		{"firewall", deployment.Coverage.Firewall},
		{"panels", deployment.Coverage.Panels},
		{"reverse_proxy", deployment.Coverage.ReverseProxy},
		{"docker", deployment.Coverage.Docker},
	} {
		if !containsReportValue(field.value, "complete", "partial", "unavailable", "not-applicable") {
			failures = append(failures, fmt.Sprintf("deployment coverage %s has invalid state %q", field.name, field.value))
		}
	}
	tooLarge := false
	for _, count := range []struct {
		name       string
		got, limit int
	}{
		{"components", len(deployment.Components), maxReportDeploymentComponents},
		{"endpoints", len(deployment.Endpoints), maxReportDeploymentEndpoints},
		{"links", len(deployment.Links), maxReportDeploymentLinks},
	} {
		if count.got > count.limit {
			failures = append(failures, fmt.Sprintf("deployment contains %d %s; limit is %d", count.got, count.name, count.limit))
			tooLarge = true
		}
	}
	// Do not walk an attacker-controlled oversized topology after recording its
	// bounded failure. Normal reports remain small enough for full validation.
	if tooLarge {
		return failures
	}

	componentIDs := make(map[string]bool, len(deployment.Components))
	allIDs := make(map[string]bool, len(deployment.Components)+len(deployment.Endpoints))
	for index, component := range deployment.Components {
		label := fmt.Sprintf("deployment component %d", index+1)
		if !validTopologyID(component.ID, "component") {
			failures = append(failures, fmt.Sprintf("%s has invalid ID %q", label, component.ID))
		}
		if allIDs[component.ID] {
			failures = append(failures, fmt.Sprintf("duplicate deployment node ID %q", component.ID))
		}
		allIDs[component.ID], componentIDs[component.ID] = true, true
		if strings.TrimSpace(component.Product) == "" || len(component.Product) > 256 {
			failures = append(failures, fmt.Sprintf("%s has invalid product", label))
		}
		if !validTopologyToken(component.Kind) {
			failures = append(failures, fmt.Sprintf("%s has invalid kind %q", label, component.Kind))
		}
		if !validTopologyConfidence(component.Confidence) {
			failures = append(failures, fmt.Sprintf("%s has invalid confidence %q", label, component.Confidence))
		}
		if len(component.Source) > 1024 || len(component.Deployment) > 256 {
			failures = append(failures, fmt.Sprintf("%s contains oversized text", label))
		}
	}

	for index, endpoint := range deployment.Endpoints {
		label := fmt.Sprintf("deployment endpoint %d", index+1)
		if !validTopologyID(endpoint.ID, "endpoint") {
			failures = append(failures, fmt.Sprintf("%s has invalid ID %q", label, endpoint.ID))
		}
		if allIDs[endpoint.ID] {
			failures = append(failures, fmt.Sprintf("duplicate deployment node ID %q", endpoint.ID))
		}
		allIDs[endpoint.ID] = true
		if endpoint.ComponentID != "" && !componentIDs[endpoint.ComponentID] {
			failures = append(failures, fmt.Sprintf("%s references unknown component %q", label, endpoint.ComponentID))
		}
		if endpoint.Port < 1 || endpoint.Port > 65535 {
			failures = append(failures, fmt.Sprintf("%s has invalid port %d", label, endpoint.Port))
		}
		if !containsReportValue(endpoint.Transport, "tcp", "udp") {
			failures = append(failures, fmt.Sprintf("%s has invalid transport %q", label, endpoint.Transport))
		}
		if !containsReportValue(endpoint.Role,
			"proxy-ingress", "management", "subscription", "control-api", "web", "ssh", "other",
			"reverse-proxy-frontend", "reverse-proxy-backend", "container-publish",
			"unclassified-listener", "unclassified-product-listener") {
			failures = append(failures, fmt.Sprintf("%s has invalid role %q", label, endpoint.Role))
		}
		if !containsReportValue(endpoint.State, "configured", "live") {
			failures = append(failures, fmt.Sprintf("%s has invalid state %q", label, endpoint.State))
		}
		if !validTopologyConfidence(endpoint.Confidence) {
			failures = append(failures, fmt.Sprintf("%s has invalid confidence %q", label, endpoint.Confidence))
		}
		if endpoint.Family != "" && !containsReportValue(endpoint.Family, "ipv4", "ipv6", "any") {
			failures = append(failures, fmt.Sprintf("%s has invalid family %q", label, endpoint.Family))
		}
		if endpoint.Scope != "" && !containsReportValue(endpoint.Scope, "public", "public-wildcard", "private", "loopback", "container", "unknown") {
			failures = append(failures, fmt.Sprintf("%s has invalid scope %q", label, endpoint.Scope))
		}
		if endpoint.TLS != "" && !containsReportValue(endpoint.TLS, "true", "false", "unknown") {
			failures = append(failures, fmt.Sprintf("%s has invalid TLS state %q", label, endpoint.TLS))
		}
		if endpoint.PathPosture != "" && !containsReportValue(endpoint.PathPosture, "root-or-default", "non-default", "unknown") {
			failures = append(failures, fmt.Sprintf("%s has invalid path posture %q", label, endpoint.PathPosture))
		}
		if endpoint.ConnectionCount != nil && *endpoint.ConnectionCount < 0 {
			failures = append(failures, fmt.Sprintf("%s has a negative connection count", label))
		}
		if len(endpoint.Product) > 256 || len(endpoint.Protocol) > 256 || len(endpoint.Address) > 512 ||
			len(endpoint.Process) > 256 || len(endpoint.Security) > 512 || len(endpoint.Firewall) > 512 ||
			len(endpoint.Judgment) > 512 || len(endpoint.Source) > 1024 {
			failures = append(failures, fmt.Sprintf("%s contains oversized text", label))
		}
	}

	seenLinks := make(map[string]bool, len(deployment.Links))
	for index, link := range deployment.Links {
		label := fmt.Sprintf("deployment link %d", index+1)
		if !allIDs[link.From] {
			failures = append(failures, fmt.Sprintf("%s has unknown source %q", label, link.From))
		}
		if !allIDs[link.To] {
			failures = append(failures, fmt.Sprintf("%s has unknown target %q", label, link.To))
		}
		if !containsReportValue(link.Kind, "declares", "owns", "published-as", "proxies-to", "routes-to") {
			failures = append(failures, fmt.Sprintf("%s has invalid kind %q", label, link.Kind))
		}
		key := link.From + "\x00" + link.To + "\x00" + link.Kind
		if seenLinks[key] {
			failures = append(failures, fmt.Sprintf("duplicate deployment link %s -> %s (%s)", link.From, link.To, link.Kind))
		}
		seenLinks[key] = true
	}
	return failures
}

func validTopologyID(id, kind string) bool {
	return len(id) <= 128 && strings.HasPrefix(id, kind+":") && topologyIDPattern.MatchString(id)
}

func validTopologyToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

func validTopologyConfidence(value string) bool {
	return containsReportValue(value, "confirmed", "inferred", "partial", "unknown")
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
	return contract.Category(id)
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
