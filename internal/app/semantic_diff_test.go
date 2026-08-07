package app

import (
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
