package app

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestSemanticDiffClassifiesProxyRegressions(t *testing.T) {
	oldReport := model.Report{Findings: []model.Finding{
		{ID: "WORK-002", Status: model.Pass, Facts: map[string]string{"public_unrestricted_management": "0"}},
		{ID: "TLS-001", Status: model.Pass, Facts: map[string]string{"minimum_certificate_days": "80", "renewal_state": "verified-with-reload"}},
	}}
	newReport := model.Report{Findings: []model.Finding{
		{ID: "WORK-002", Status: model.Risk, Facts: map[string]string{"public_unrestricted_management": "1"}},
		{ID: "TLS-001", Status: model.Pass, Facts: map[string]string{"minimum_certificate_days": "12", "renewal_state": "failing"}},
	}}
	changes, covered := semanticDiff(oldReport, newReport)
	if len(changes) < 4 || !covered["WORK-002"] || !covered["TLS-001"] {
		t.Fatalf("unexpected semantic changes: %#v", changes)
	}
	for _, change := range changes {
		if change.Kind != "REGRESSION" {
			t.Fatalf("expected regression, got %#v", change)
		}
	}
}

func TestSemanticDiffReportsReasonChangeWithoutStatusChange(t *testing.T) {
	oldReport := model.Report{Findings: []model.Finding{{ID: "WORK-002", Status: model.Risk, ReasonCode: "work.002.public-default-path-management"}}}
	newReport := model.Report{Findings: []model.Finding{{ID: "WORK-002", Status: model.Risk, ReasonCode: "work.002.public-plaintext-management"}}}
	changes, covered := semanticDiff(oldReport, newReport)
	if len(changes) != 1 || changes[0].Kind != "CHANGE" || !covered["WORK-002"] {
		t.Fatalf("unexpected changes: %#v covered=%#v", changes, covered)
	}
}

func TestSemanticDiffDoesNotCallNewDeepEvidenceARegression(t *testing.T) {
	oldReport := model.Report{Metadata: map[string]string{"audit_depth": "standard"}, Findings: []model.Finding{{ID: "PKG-002", Status: model.Info, NotApplicable: true}}}
	newReport := model.Report{Metadata: map[string]string{"audit_depth": "deep"}, Findings: []model.Finding{{ID: "PKG-002", Status: model.Risk, Severity: model.Medium}}}
	changes, _ := semanticDiff(oldReport, newReport)
	if len(changes) != 2 || changes[0].Kind != "CONTEXT" || changes[1].Kind != "CHANGE" {
		t.Fatalf("unexpected deep comparison: %#v", changes)
	}
}

func TestSemanticDiffClassifiesTypedTopologyExposure(t *testing.T) {
	endpoint := model.ServiceEndpoint{ID: "endpoint:0123456789abcdef", Product: "S-UI", Role: "management", Transport: "tcp", Port: 2095, State: "live", Scope: "loopback", Firewall: "blocked-by-default", Judgment: "internal-panel-endpoint", Confidence: "confirmed"}
	oldReport := model.Report{Deployment: &model.Deployment{Coverage: model.DeploymentCoverage{Configuration: "complete", Runtime: "complete", Firewall: "complete", Panels: "complete", ReverseProxy: "not-applicable", Docker: "not-applicable"}, Endpoints: []model.ServiceEndpoint{endpoint}}}
	endpoint.Scope, endpoint.Firewall, endpoint.Judgment = "public-wildcard", "allow-anywhere", "public-management-exposed"
	newReport := model.Report{Deployment: &model.Deployment{Coverage: oldReport.Deployment.Coverage, Endpoints: []model.ServiceEndpoint{endpoint}}}
	changes, _ := semanticDiff(oldReport, newReport)
	found := false
	for _, change := range changes {
		if change.ID == "TOPOLOGY" && change.Kind == "REGRESSION" {
			found = true
		}
	}
	if !found {
		t.Fatalf("topology exposure regression not reported: %#v", changes)
	}
}

func TestSemanticDiffClassifiesTopologyCoverageLoss(t *testing.T) {
	oldReport := model.Report{Deployment: &model.Deployment{Coverage: model.DeploymentCoverage{Configuration: "complete"}}}
	newReport := model.Report{Deployment: &model.Deployment{Coverage: model.DeploymentCoverage{Configuration: "unavailable"}}}
	changes, _ := semanticDiff(oldReport, newReport)
	if len(changes) != 1 || changes[0].Kind != "REGRESSION" || changes[0].ID != "TOPOLOGY" {
		t.Fatalf("coverage loss=%#v", changes)
	}
}

func TestSemanticDiffMessagesCoverAllLocales(t *testing.T) {
	oldReport := model.Report{
		Metadata: map[string]string{"audit_depth": "standard"}, LogSince: "24h", Profile: model.Profile{Effective: "proxy"},
		Findings: []model.Finding{
			{ID: "ACC-001", NotApplicable: true},
			{ID: "ACC-002", Status: model.Info, ReasonCode: "acc.002.old"},
			{ID: "ACC-003", Status: model.Pass},
			{ID: "WORK-001", Facts: map[string]string{"products": "sing-box"}},
			{ID: "WORK-002", Facts: map[string]string{"public_unrestricted_management": "0", "public_plaintext_management": "0", "public_default_path_management": "0"}},
			{ID: "WORK-012", Facts: map[string]string{"runtime_mismatches": "0", "public_plaintext_subscription_listeners": "0", "disabled_inbounds_still_listening": "0"}},
			{ID: "DOCKER-001", Facts: map[string]string{"isolation_problems": "0"}},
			{ID: "DOCKER-002", Facts: map[string]string{"input_policy_bypass_paths": "0"}},
			{ID: "TLS-001", Facts: map[string]string{"minimum_certificate_days": "90", "renewal_state": "verified-with-reload"}},
			{ID: "SSH-005", Facts: map[string]string{"authorized_keys": "1"}},
		},
	}
	newReport := oldReport
	newReport.Metadata = map[string]string{"audit_depth": "deep"}
	newReport.LogSince, newReport.Profile = "168h", model.Profile{Effective: "mixed"}
	newReport.Findings = []model.Finding{
		{ID: "ACC-001", NotApplicable: false},
		{ID: "ACC-002", Status: model.Info, ReasonCode: "acc.002.new"},
		{ID: "ACC-003", Status: model.Risk},
		{ID: "WORK-001", Facts: map[string]string{"products": "sing-box,xray"}},
		{ID: "WORK-002", Facts: map[string]string{"public_unrestricted_management": "1", "public_plaintext_management": "1", "public_default_path_management": "1"}},
		{ID: "WORK-012", Facts: map[string]string{"runtime_mismatches": "1", "public_plaintext_subscription_listeners": "1", "disabled_inbounds_still_listening": "1"}},
		{ID: "DOCKER-001", Facts: map[string]string{"isolation_problems": "1"}},
		{ID: "DOCKER-002", Facts: map[string]string{"input_policy_bypass_paths": "1"}},
		{ID: "TLS-001", Facts: map[string]string{"minimum_certificate_days": "10", "renewal_state": "failing"}},
		{ID: "SSH-005", Facts: map[string]string{"authorized_keys": "2"}},
	}
	changes, _ := semanticDiff(oldReport, newReport)
	changes = append(changes, topologySemanticDiff(nil, &model.Deployment{})...)
	changes = append(changes, topologySemanticDiff(&model.Deployment{}, nil)...)
	if len(changes) < 15 {
		t.Fatalf("too few semantic change variants exercised: %d", len(changes))
	}
	for _, change := range changes {
		for _, locale := range []string{"zh-CN", "en", "ru-RU", "fa-IR"} {
			if strings.TrimSpace(change.message(locale)) == "" {
				t.Errorf("%s %s has no %s message: %#v", change.Kind, change.ID, locale, change)
			}
		}
	}
}

func TestSemanticDiffReportsRiskSeverityChangesDeterministically(t *testing.T) {
	oldReport := model.Report{ToolVersion: "1.0.0", Findings: []model.Finding{
		{ID: "WORK-002", Status: model.Risk, Severity: model.Medium, ReasonCode: "work.002.public-management"},
		{ID: "SSH-001", Status: model.Pass, ReasonCode: "ssh.001.password-disabled"},
	}}
	newReport := model.Report{ToolVersion: "1.1.0", Findings: []model.Finding{
		{ID: "SSH-001", Status: model.Risk, Severity: model.High, ReasonCode: "ssh.001.password-enabled"},
		{ID: "WORK-002", Status: model.Risk, Severity: model.High, ReasonCode: "work.002.public-management"},
	}}
	first, _ := semanticDiff(oldReport, newReport)
	second, _ := semanticDiff(oldReport, newReport)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("semantic diff order is unstable:\n%#v\n%#v", first, second)
	}
	var sawVersion, sawSeverity bool
	for _, change := range first {
		sawVersion = sawVersion || change.Kind == "CONTEXT" && strings.Contains(change.MessageEN, "tool version")
		sawSeverity = sawSeverity || change.Kind == "REGRESSION" && change.ID == "WORK-002" && strings.Contains(change.MessageEN, "severity")
	}
	if !sawVersion || !sawSeverity {
		t.Fatalf("missing version/severity changes: %#v", first)
	}
}
