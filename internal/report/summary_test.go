package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestEvidenceFormattingDoesNotRepeatStructuredKey(t *testing.T) {
	for _, test := range []struct {
		evidence model.Evidence
		want     string
	}{
		{model.Evidence{Key: "product", Value: "product=S-UI version=1.5.3"}, "product=S-UI version=1.5.3"},
		{model.Evidence{Key: "pending_total", Value: "0"}, "pending_total=0"},
		{model.Evidence{Value: "present"}, "present"},
	} {
		if got := formattedEvidence(test.evidence); got != test.want {
			t.Fatalf("formatted evidence = %q, want %q", got, test.want)
		}
	}
}

func TestActionVerdictsExplainSubscriptionAndRebootRisks(t *testing.T) {
	subscription := model.Finding{ID: "WORK-012", Status: model.Risk, Evidence: []model.Evidence{{Key: "plaintext_public_subscription", Value: "product=S-UI"}}}
	if got := verdictForFinding(subscription, "en"); !strings.Contains(got, "subscription endpoint") || strings.Contains(got, "do not agree") {
		t.Fatalf("subscription verdict = %q", got)
	}
	reboot := model.Finding{ID: "UPD-001", Status: model.Risk, Facts: map[string]string{"pending_total": "0"}, Evidence: []model.Evidence{{Source: "/var/run/reboot-required", Value: "present"}}}
	if got := verdictForFinding(reboot, "en"); !strings.Contains(got, "reboot is required") {
		t.Fatalf("reboot verdict = %q", got)
	}
	selected := keyEvidence(reboot)
	if len(selected) == 0 || !strings.Contains(selected[0].Source, "reboot-required") {
		t.Fatalf("reboot evidence was not prioritized: %+v", selected)
	}
}

func TestOverallVerdictBreakdownConservesConfirmedFindings(t *testing.T) {
	tests := []struct {
		name         string
		findings     []model.Finding
		confirmed    int
		urgent       int
		availability int
		maintenance  int
		gaps         int
	}{
		{
			name:        "maintenance is not omitted",
			findings:    []model.Finding{{ID: "FW-002", Status: model.Risk, Severity: model.Medium}},
			confirmed:   1,
			maintenance: 1,
		},
		{
			name: "all action bands",
			findings: []model.Finding{
				{ID: "WORK-002", Status: model.Risk, Severity: model.High},
				{ID: "TLS-001", Status: model.Risk, Severity: model.Medium},
				{ID: "FW-002", Status: model.Risk, Severity: model.Medium},
				{ID: "PKG-001", Status: model.Unknown},
			},
			confirmed: 3, urgent: 1, availability: 1, maintenance: 1, gaps: 1,
		},
		{
			name: "multiple maintenance findings",
			findings: []model.Finding{
				{ID: "FW-002", Status: model.Risk, Severity: model.Medium},
				{ID: "UPD-001", Status: model.Risk, Severity: model.Low},
			},
			confirmed: 2, maintenance: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verdict := overallVerdictFor(model.Report{Findings: test.findings}, "en")
			wantHeadline := fmt.Sprintf("%d findings need attention", test.confirmed)
			wantDetail := fmt.Sprintf("Handle now: %d · May affect availability: %d · Maintenance and review: %d · Evidence gaps requiring manual confirmation: %d", test.urgent, test.availability, test.maintenance, test.gaps)
			if verdict.Headline != wantHeadline || verdict.Detail != wantDetail {
				t.Fatalf("verdict=%#v want headline=%q detail=%q", verdict, wantHeadline, wantDetail)
			}
			if test.confirmed != test.urgent+test.availability+test.maintenance {
				t.Fatalf("invalid test fixture: confirmed=%d bands=%d", test.confirmed, test.urgent+test.availability+test.maintenance)
			}
		})
	}
}
