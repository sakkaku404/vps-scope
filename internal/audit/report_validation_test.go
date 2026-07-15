package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func validContractReport() model.Report {
	r := model.Report{
		SchemaVersion: "1.0", ToolVersion: "0.13.0", Locale: "en",
		StartedAt: time.Unix(1, 0).UTC(), FinishedAt: time.Unix(2, 0).UTC(),
		LogSince: "168h0m0s",
		Host:     model.Host{StableID: "fixture-id", Hostname: "fixture", OS: "debian", OSVersion: "12", Kernel: "fixture-kernel", Architecture: "x86_64"},
		Profile:  model.Profile{Requested: "auto", Detected: "proxy", Effective: "proxy"},
	}
	for _, id := range StableCheckIDs {
		r.Findings = append(r.Findings, model.Finding{ID: id, Category: reportCategoryForID(id), Status: model.Pass, ReasonCode: strings.ToLower(strings.ReplaceAll(id, "-", ".")) + ".verified"})
	}
	r.Recount()
	return r
}

func TestValidateReportAcceptsCompleteContract(t *testing.T) {
	if failures := ValidateReport(validContractReport()); len(failures) != 0 {
		t.Fatalf("failures=%v", failures)
	}
}

func TestValidateReportFindsSemanticCorruption(t *testing.T) {
	r := validContractReport()
	r.Findings[0].ReasonCode = "wrong.reason"
	r.Findings[1].Status = model.Risk
	r.Findings[1].Severity = ""
	r.Locale = ""
	r.Profile.Effective = ""
	r.Findings = append(r.Findings, r.Findings[2])
	r.Summary.Pass = 999
	failures := strings.Join(ValidateReport(r), "\n")
	for _, want := range []string{"invalid reason_code", "without a valid severity", "duplicate check ID", "summary does not match", "report locale", "profile effective"} {
		if !strings.Contains(failures, want) {
			t.Fatalf("missing %q in %s", want, failures)
		}
	}
}

func TestValidateReportKeepsPre013ReasonCodesOptional(t *testing.T) {
	r := validContractReport()
	r.ToolVersion = "0.12.0"
	for i := range r.Findings {
		r.Findings[i].ReasonCode = ""
	}
	if failures := ValidateReport(r); len(failures) != 0 {
		t.Fatalf("failures=%v", failures)
	}
}

func TestValidateReportKeepsPre012PartialContractsReadable(t *testing.T) {
	r := validContractReport()
	r.ToolVersion = "0.7.0"
	r.Findings = r.Findings[:2]
	for i := range r.Findings {
		r.Findings[i].ReasonCode = ""
	}
	r.Recount()
	if failures := ValidateReport(r); len(failures) != 0 {
		t.Fatalf("failures=%v", failures)
	}
}

func TestValidateReportRequiresCurrentDevelopmentContract(t *testing.T) {
	r := validContractReport()
	r.ToolVersion = "dev"
	r.Findings = r.Findings[:len(r.Findings)-1]
	r.Recount()
	failures := strings.Join(ValidateReport(r), "\n")
	if !strings.Contains(failures, "required check ID REL-002 is missing") {
		t.Fatalf("failures=%s", failures)
	}
}

func TestValidateReportAllowsAppendOnlyIDsFromNewerTools(t *testing.T) {
	r := validContractReport()
	r.ToolVersion = "0.15.0"
	r.Findings = append(r.Findings, model.Finding{
		ID: "FUTURE-001", Category: "future", Status: model.Info,
		ReasonCode: "future.001.observed",
	})
	r.Recount()
	if failures := ValidateReport(r, "0.14.0"); len(failures) != 0 {
		t.Fatalf("future append-only report rejected: %v", failures)
	}
	if failures := strings.Join(ValidateReport(r, "0.15.0"), "\n"); !strings.Contains(failures, "unexpected check ID") {
		t.Fatalf("same-version unexpected ID was not rejected: %s", failures)
	}
}

func TestValidateReportFailureOrderIsDeterministic(t *testing.T) {
	r := validContractReport()
	r.Host.StableID = ""
	r.Host.Hostname = ""
	r.Profile.Requested = ""
	want := strings.Join(ValidateReport(r), "\n")
	for i := 0; i < 20; i++ {
		if got := strings.Join(ValidateReport(r), "\n"); got != want {
			t.Fatalf("validation order changed:\nwant=%s\ngot=%s", want, got)
		}
	}
}

func TestSemanticVersionRejectsNegativeComponents(t *testing.T) {
	for _, version := range []string{"-1.0.0", "1.-1.0"} {
		if _, _, ok := semanticVersion(version); ok {
			t.Fatalf("accepted invalid version %q", version)
		}
	}
}
