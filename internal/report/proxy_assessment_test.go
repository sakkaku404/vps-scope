package report

import (
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestProxyAssessmentDoesNotDoubleCountAvailabilityRisks(t *testing.T) {
	r := model.Report{Findings: []model.Finding{
		{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{"products": "3x-ui"}},
		{ID: "PROC-001", Category: "processes", Status: model.Risk, Severity: model.Low},
		{ID: "SYS-002", Category: "system", Status: model.Risk, Severity: model.Low},
		{ID: "AUTH-003", Category: "auth", Status: model.Risk, Severity: model.Medium},
		{ID: "UPD-001", Category: "updates", Status: model.Risk, Severity: model.High},
		{ID: "REL-001", Category: "reliability", Status: model.Unknown, Unavailable: true, Error: "coredump evidence unavailable"},
	}}

	assessment := collectProxyAssessment(r, "en")
	if len(assessment.Lines) != 5 {
		t.Fatalf("lines=%d", len(assessment.Lines))
	}
	availability, baseline := assessment.Lines[3], assessment.Lines[4]
	if !strings.Contains(availability.Message, "1 findings") {
		t.Fatalf("availability=%q", availability.Message)
	}
	if !strings.Contains(baseline.Message, "3 Linux host-baseline risks") {
		t.Fatalf("baseline=%q", baseline.Message)
	}
	if strings.Contains(baseline.Message, "4 ") {
		t.Fatalf("availability risk was counted again in baseline: %q", baseline.Message)
	}
}

func TestProxyRuntimeAssessmentDoesNotPromoteStaticParsingToPass(t *testing.T) {
	config := model.Finding{ID: "WORK-004", Category: "workloads", Status: model.Info, Facts: map[string]string{"native_self_test_mode": "disabled_by_default"}}
	runtime := model.Finding{ID: "WORK-012", Category: "workloads", Status: model.Pass}
	line := proxyRuntimeAssessment(config, true, runtime, true, "en")
	if line.Status != "INFO" {
		t.Fatalf("status=%q", line.Status)
	}
	if !strings.Contains(line.Message, "not executed by default") || !strings.Contains(line.Message, "not marked PASS") {
		t.Fatalf("message=%q", line.Message)
	}
}

func TestProxyRuntimeAssessmentDoesNotPromoteMissingConfigurationToPass(t *testing.T) {
	config := model.Finding{ID: "WORK-004", Category: "workloads", Status: model.Info, NotApplicable: true}
	runtime := model.Finding{ID: "WORK-012", Category: "workloads", Status: model.Pass}
	line := proxyRuntimeAssessment(config, true, runtime, true, "en")
	if line.Status != "INFO" {
		t.Fatalf("status=%q", line.Status)
	}
	if !strings.Contains(line.Message, "No native configuration check was available") {
		t.Fatalf("message=%q", line.Message)
	}
}

func TestCombinedAssessmentPassRequiresEveryApplicableFindingToPass(t *testing.T) {
	tests := []struct {
		name     string
		findings []model.Finding
		want     model.Status
	}{
		{name: "all pass", findings: []model.Finding{{Status: model.Pass}, {Status: model.Pass}}, want: model.Pass},
		{name: "pass and info", findings: []model.Finding{{Status: model.Pass}, {Status: model.Info}}, want: model.Info},
		{name: "unknown dominates info", findings: []model.Finding{{Status: model.Info}, {Status: model.Unknown}}, want: model.Unknown},
		{name: "risk dominates unknown", findings: []model.Finding{{Status: model.Unknown}, {Status: model.Risk, Severity: model.Low}}, want: model.Risk},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, _ := combinedAssessmentFindings(test.findings)
			if got != test.want {
				t.Fatalf("status=%q, want %q", got, test.want)
			}
		})
	}
}
