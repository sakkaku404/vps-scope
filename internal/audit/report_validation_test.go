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

func validDeploymentFixture() *model.Deployment {
	count := 3
	return &model.Deployment{
		Coverage: model.DeploymentCoverage{
			Configuration: "complete", Runtime: "complete", Firewall: "partial",
			Panels: "not-applicable", ReverseProxy: "unavailable", Docker: "not-applicable",
		},
		Components: []model.Component{{
			ID: "component:0000000000000001", Product: "sing-box", Kind: "proxy-core",
			Source: "/etc/sing-box/config.json", Runtime: true, Deployment: "native-or-managed", Confidence: "confirmed",
		}},
		Endpoints: []model.ServiceEndpoint{{
			ID: "endpoint:0000000000000001", ComponentID: "component:0000000000000001",
			Product: "sing-box", Role: "proxy-ingress", Protocol: "vless", Transport: "tcp",
			Port: 443, Address: "0.0.0.0", Family: "ipv4", Scope: "public-wildcard",
			State: "live", Confidence: "confirmed", ConnectionCount: &count,
		}},
		Links: []model.TopologyLink{{From: "component:0000000000000001", To: "endpoint:0000000000000001", Kind: "declares"}},
	}
}

func TestValidateReportAcceptsTypedDeploymentAndLegacyAbsence(t *testing.T) {
	legacy := validContractReport()
	if failures := ValidateReport(legacy); len(failures) != 0 {
		t.Fatalf("legacy report failures=%v", failures)
	}
	current := validContractReport()
	current.Deployment = validDeploymentFixture()
	if failures := ValidateReport(current); len(failures) != 0 {
		t.Fatalf("typed deployment failures=%v", failures)
	}
}

func TestValidateReportRejectsInvalidDeploymentTopology(t *testing.T) {
	tests := []struct {
		name, want string
		mutate     func(*model.Deployment)
	}{
		{"coverage", "coverage runtime has invalid state", func(d *model.Deployment) { d.Coverage.Runtime = "optimistic" }},
		{"component ID", "invalid ID", func(d *model.Deployment) { d.Components[0].ID = "component:\nsecret" }},
		{"duplicate component ID", "duplicate deployment node ID", func(d *model.Deployment) { d.Components = append(d.Components, d.Components[0]) }},
		{"duplicate endpoint ID", "duplicate deployment node ID", func(d *model.Deployment) { d.Endpoints = append(d.Endpoints, d.Endpoints[0]) }},
		{"component reference", "references unknown component", func(d *model.Deployment) { d.Endpoints[0].ComponentID = "component:missing" }},
		{"port", "invalid port", func(d *model.Deployment) { d.Endpoints[0].Port = 0 }},
		{"transport", "invalid transport", func(d *model.Deployment) { d.Endpoints[0].Transport = "icmp" }},
		{"role", "invalid role", func(d *model.Deployment) { d.Endpoints[0].Role = "root-shell" }},
		{"component confidence", "invalid confidence", func(d *model.Deployment) { d.Components[0].Confidence = "certain" }},
		{"endpoint confidence", "invalid confidence", func(d *model.Deployment) { d.Endpoints[0].Confidence = "certain" }},
		{"state", "invalid state", func(d *model.Deployment) { d.Endpoints[0].State = "maybe-live" }},
		{"negative connections", "negative connection count", func(d *model.Deployment) { count := -1; d.Endpoints[0].ConnectionCount = &count }},
		{"dangling link", "unknown source", func(d *model.Deployment) { d.Links[0].From, d.Links[0].To = "component:missing", "endpoint:missing" }},
		{"link kind", "invalid kind", func(d *model.Deployment) { d.Links[0].Kind = "executes" }},
		{"oversized text", "oversized text", func(d *model.Deployment) { d.Endpoints[0].Process = strings.Repeat("x", 257) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validContractReport()
			r.Deployment = validDeploymentFixture()
			test.mutate(r.Deployment)
			failures := strings.Join(ValidateReport(r), "\n")
			if !strings.Contains(failures, test.want) {
				t.Fatalf("missing %q in %s", test.want, failures)
			}
		})
	}
}

func TestValidateReportRejectsOversizedDeploymentCollections(t *testing.T) {
	tests := []struct {
		name, want string
		mutate     func(*model.Deployment)
	}{
		{"components", "513 components", func(d *model.Deployment) { d.Components = make([]model.Component, maxReportDeploymentComponents+1) }},
		{"endpoints", "2049 endpoints", func(d *model.Deployment) { d.Endpoints = make([]model.ServiceEndpoint, maxReportDeploymentEndpoints+1) }},
		{"links", "8193 links", func(d *model.Deployment) { d.Links = make([]model.TopologyLink, maxReportDeploymentLinks+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := validContractReport()
			r.Deployment = validDeploymentFixture()
			test.mutate(r.Deployment)
			if failures := strings.Join(ValidateReport(r), "\n"); !strings.Contains(failures, test.want) {
				t.Fatalf("missing %q in %s", test.want, failures)
			}
		})
	}
}

func TestValidateReportRejectsInvalidStructuredEndpoint(t *testing.T) {
	r := validContractReport()
	r.Endpoints = []model.Endpoint{{Protocol: "tcp", Port: 443, Family: "ipv4", Scope: "public", Role: "ssh", ExpectedExposure: "public"}, {Protocol: "tcp", Port: 443, Family: "ipv4", Scope: "public", Role: "invented", ExpectedExposure: "magic"}}
	failures := strings.Join(ValidateReport(r), "\n")
	for _, want := range []string{"invalid role", "invalid expected_exposure", "duplicate endpoint"} {
		if !strings.Contains(failures, want) {
			t.Fatalf("missing %q in %s", want, failures)
		}
	}
}

func TestValidateReportAcceptsEverySupportedLocale(t *testing.T) {
	for _, locale := range []string{"zh-CN", "en", "ru-RU", "fa-IR"} {
		r := validContractReport()
		r.Locale = locale
		if failures := ValidateReport(r); len(failures) != 0 {
			t.Fatalf("%s: failures=%v", locale, failures)
		}
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
