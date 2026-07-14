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

func TestSemanticDiffDoesNotCallNewDeepEvidenceARegression(t *testing.T) {
	oldReport := model.Report{Metadata: map[string]string{"audit_depth": "standard"}, Findings: []model.Finding{{ID: "PKG-002", Status: model.Info, NotApplicable: true}}}
	newReport := model.Report{Metadata: map[string]string{"audit_depth": "deep"}, Findings: []model.Finding{{ID: "PKG-002", Status: model.Risk, Severity: model.Medium}}}
	changes, _ := semanticDiff(oldReport, newReport)
	if len(changes) != 2 || changes[0].Kind != "CONTEXT" || changes[1].Kind != "CHANGE" {
		t.Fatalf("unexpected deep comparison: %#v", changes)
	}
}
