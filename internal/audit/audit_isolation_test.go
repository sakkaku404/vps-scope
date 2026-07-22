package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestSafeCheckPanicPreservesStableCategoryIDsWithoutLeakingValue(t *testing.T) {
	const secret = "secret-token-from-panic"
	findings := safeCheck(func(*Context) []model.Finding {
		panic(secret)
	}, &Context{}, "ssh")
	assignReasonCodes(findings)

	wantIDs := []string{"SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005"}
	if len(findings) != len(wantIDs) {
		t.Fatalf("findings=%d, want %d: %+v", len(findings), len(wantIDs), findings)
	}
	for i, finding := range findings {
		if finding.ID != wantIDs[i] || finding.Category != "ssh" {
			t.Fatalf("finding[%d]=%s/%s, want %s/ssh", i, finding.ID, finding.Category, wantIDs[i])
		}
		if finding.Status != model.Unknown || !finding.Unavailable {
			t.Fatalf("%s status=%s unavailable=%t", finding.ID, finding.Status, finding.Unavailable)
		}
		if finding.ReasonCode != strings.ToLower(strings.ReplaceAll(finding.ID, "-", "."))+".evidence-unavailable" {
			t.Fatalf("%s reason=%q", finding.ID, finding.ReasonCode)
		}
		if strings.Contains(finding.Error, secret) {
			t.Fatalf("panic value leaked through error: %q", finding.Error)
		}
		for _, evidence := range finding.Evidence {
			if strings.Contains(evidence.Value, secret) {
				t.Fatalf("panic value leaked through evidence: %+v", evidence)
			}
		}
	}
}

func TestRecoveredCategoryStillProducesSemanticallyValidFullReport(t *testing.T) {
	var findings []model.Finding
	for _, category := range CategoryOrder {
		current := category
		fn := func(*Context) []model.Finding {
			if current == "workloads" {
				panic("private configuration value")
			}
			var result []model.Finding
			for _, id := range StableCheckIDs {
				if reportCategoryForID(id) == current {
					result = append(result, model.Finding{ID: id, Category: current, Status: model.Pass})
				}
			}
			return result
		}
		findings = append(findings, safeCheck(fn, &Context{}, category)...)
	}
	assignReasonCodes(findings)
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	r := model.Report{
		SchemaVersion: "1.0", ToolVersion: "1.1.1", Locale: "en",
		StartedAt: now, FinishedAt: now.Add(time.Second), LogSince: (7 * 24 * time.Hour).String(),
		Host:     model.Host{StableID: "fixture", Hostname: "fixture", OS: "debian", OSVersion: "13", Kernel: "fixture", Architecture: "x86_64"},
		Profile:  model.Profile{Requested: "auto", Detected: "proxy", Effective: "proxy"},
		Findings: findings,
	}
	r.Recount()
	if failures := ValidateReport(r, "1.1.1"); len(failures) != 0 {
		t.Fatalf("recovered report is not valid:\n%s", strings.Join(failures, "\n"))
	}
	if got := r.Summary.Unknown; got != 17 {
		t.Fatalf("unknown=%d, want all 17 workload checks unavailable", got)
	}
}
