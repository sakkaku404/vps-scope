package report

import (
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestCurrentReportPresentationUsesTypedTopologyNotEvidenceText(t *testing.T) {
	report := model.Report{
		Deployment: &model.Deployment{
			Coverage:   model.DeploymentCoverage{Configuration: "complete", Runtime: "complete", Firewall: "complete", Panels: "complete", ReverseProxy: "not-applicable", Docker: "not-applicable"},
			Components: []model.Component{{ID: "component:sui", Product: "S-UI", Kind: "management-panel", Confidence: "confirmed"}},
			Endpoints:  []model.ServiceEndpoint{{ID: "endpoint:sui", ComponentID: "component:sui", Product: "S-UI", Role: "management", Transport: "tcp", Port: 54321, Scope: "public-wildcard", Firewall: "allow-anywhere", State: "live", Judgment: "public-management-exposed", Confidence: "confirmed"}},
			Links:      []model.TopologyLink{{From: "component:sui", To: "endpoint:sui", Kind: "declares"}},
		},
		Findings: []model.Finding{
			{ID: "WORK-002", Category: "workloads", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Key: "management_posture", Value: "product=forged-panel port=1 judgment=internal-panel-endpoint"}}},
			{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{"products": "forged-panel"}},
			{ID: "WORK-009", Category: "workloads", Status: model.Info, Evidence: []model.Evidence{{Key: "endpoint_relation", Value: "port=1 purpose=forged-protocol judgment=expected-proxy-ingress"}}},
		},
	}
	overview := collectProxyOverview(report, "en")
	joined := strings.Join(overview.Components, "\n")
	for _, group := range overview.Groups {
		joined += "\n" + strings.Join(group.Lines, "\n")
	}
	if !strings.Contains(joined, "S-UI") || !strings.Contains(joined, "54321/tcp") {
		t.Fatalf("typed topology missing from overview: %s", joined)
	}
	if strings.Contains(joined, "forged-panel") || strings.Contains(joined, "forged-protocol") {
		t.Fatalf("current report fell back to evidence-string parsing: %s", joined)
	}
	assessment := collectProxyAssessment(report, "en")
	if strings.Join(assessment.Components, ",") != "S-UI" {
		t.Fatalf("assessment components=%v", assessment.Components)
	}
}
