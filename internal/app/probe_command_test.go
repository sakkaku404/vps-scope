package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestProbePlanRunImportRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	planPath := filepath.Join(dir, "plan.json")
	observationPath := filepath.Join(dir, "observation.json")
	enrichedPath := filepath.Join(dir, "enriched.json")
	report := model.Report{
		SchemaVersion: "1.0", ToolVersion: "dev", Locale: "en", StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(), LogSince: "24h0m0s",
		Host:      model.Host{StableID: "fixture-host", Hostname: "fixture", OS: "debian", OSVersion: "13", Kernel: "fixture", Architecture: "x86_64"},
		Profile:   model.Profile{Requested: "proxy", Detected: "proxy", Effective: "proxy"},
		Findings:  []model.Finding{{ID: "NET-004", Category: "network", Status: model.Info, NotApplicable: true}},
		Endpoints: []model.Endpoint{{Protocol: "tcp", Port: port, Family: "ipv4", Scope: "public-wildcard"}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Run([]string{"probe", "plan", "--target", "127.0.0.1", "--output", planPath, "--management", strconv.Itoa(port) + "/tcp", reportPath}, nil, &output, &output, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"probe", "run", "--output", observationPath, planPath}, nil, &output, &output, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"probe", "import", "--output", enrichedPath, reportPath, observationPath}, nil, &output, &output, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	enriched, err := readReport(enrichedPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(enriched.Findings) != 1 || enriched.Findings[0].Status != model.Risk || enriched.Findings[0].Severity != model.High {
		t.Fatalf("external management observation = %#v", enriched.Findings)
	}
}

func TestProbeUDPIsExplicitlyIndeterminate(t *testing.T) {
	plan := probePlan{SchemaVersion: probeSchemaVersion, ReportStableID: "fixture", Target: "127.0.0.1", CreatedAt: time.Now(), Nonce: "0123456789abcdef", Endpoints: []model.Endpoint{{Protocol: "udp", Port: 443, Family: "ipv4", Scope: "public-wildcard"}}}
	results := runProbePlan(plan, time.Second)
	if len(results) != 1 || results[0].State != "indeterminate" {
		t.Fatalf("UDP result = %#v", results)
	}
}

func TestProbeRejectsMismatchedHost(t *testing.T) {
	observation := probeObservation{SchemaVersion: probeSchemaVersion, PlanSHA256: strings.Repeat("0", 64), ObservedAt: time.Now(), Plan: probePlan{SchemaVersion: probeSchemaVersion, ReportStableID: "other", Target: "127.0.0.1", CreatedAt: time.Now(), Nonce: strings.Repeat("0", 32), Endpoints: []model.Endpoint{{Protocol: "tcp", Port: 22, Family: "ipv4", Scope: "public"}}}, Results: []probeResult{{Protocol: "tcp", Port: 22, Family: "ipv4", State: "reachable"}}}
	report := model.Report{Host: model.Host{StableID: "expected"}}
	if err := validateProbeObservation(observation, report); err == nil {
		t.Fatal("mismatched host observation was accepted")
	}
}

func TestProbeRejectsResultPolicyMutation(t *testing.T) {
	plan := probePlan{SchemaVersion: probeSchemaVersion, ReportStableID: "fixture", Target: "127.0.0.1", CreatedAt: time.Now().UTC(), Nonce: strings.Repeat("0", 32), Endpoints: []model.Endpoint{{Protocol: "tcp", Port: 22, Family: "ipv4", Scope: "public", Role: "ssh", ExpectedExposure: "public"}}}
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	digest := sha256.Sum256(encoded)
	observation := probeObservation{SchemaVersion: probeSchemaVersion, PlanSHA256: hex.EncodeToString(digest[:]), Plan: plan, ObservedAt: time.Now().UTC(), Results: []probeResult{{Protocol: "tcp", Port: 22, Family: "ipv4", Role: "management", ExpectedExposure: "blocked", State: "reachable"}}}
	if err := validateProbeObservation(observation, model.Report{Host: model.Host{StableID: "fixture"}}); err == nil {
		t.Fatal("mutated role and exposure were accepted")
	}
}

func TestProbeSkipsDHCPClientListener(t *testing.T) {
	endpoint := model.Endpoint{Protocol: "udp", Port: 68, Family: "ipv4", Scope: "public", Process: `users:(("dhcpcd",pid=1))`}
	if probeableEndpoint(endpoint) {
		t.Fatal("DHCP client listener was included in an external observation plan")
	}
}

func TestUnclassifiedUDPDoesNotOverrideExplicitTCPMatch(t *testing.T) {
	report := model.Report{Findings: []model.Finding{{ID: "NET-004", Category: "network", Status: model.Info, NotApplicable: true}}}
	observation := probeObservation{ObservedAt: time.Now(), PlanSHA256: "fixture", Results: []probeResult{
		{Protocol: "tcp", Port: 22, Family: "ipv4", Role: "ssh", ExpectedExposure: "public", State: "reachable"},
		{Protocol: "udp", Port: 39082, Family: "ipv4", State: "indeterminate"},
	}}
	applyProbeObservation(&report, observation)
	if report.Findings[0].Status != model.Pass {
		t.Fatalf("status=%s, want PASS", report.Findings[0].Status)
	}
}

func TestExpectedPublicEndpointNotReachableIsRisk(t *testing.T) {
	report := model.Report{Findings: []model.Finding{{ID: "NET-004", Category: "network", Status: model.Info, NotApplicable: true}}}
	observation := probeObservation{ObservedAt: time.Now(), PlanSHA256: "fixture", Results: []probeResult{{Protocol: "tcp", Port: 443, Family: "ipv4", Role: "proxy-ingress", ExpectedExposure: "public", State: "not-reachable", Detail: "timeout"}}}
	applyProbeObservation(&report, observation)
	if report.Findings[0].Status != model.Risk || report.Findings[0].Severity != model.High {
		t.Fatalf("finding=%#v", report.Findings[0])
	}
}

func TestExpectedUDPRemainsUnknown(t *testing.T) {
	report := model.Report{Findings: []model.Finding{{ID: "NET-004", Category: "network", Status: model.Info, NotApplicable: true}}}
	observation := probeObservation{ObservedAt: time.Now(), PlanSHA256: "fixture", Results: []probeResult{{Protocol: "udp", Port: 443, Family: "ipv4", Role: "proxy-ingress", ExpectedExposure: "public", State: "indeterminate"}}}
	applyProbeObservation(&report, observation)
	if report.Findings[0].Status != model.Unknown {
		t.Fatalf("finding=%#v", report.Findings[0])
	}
}

func TestProbeInputValidation(t *testing.T) {
	for _, valid := range []string{"203.0.113.10", "2001:db8::1", "probe.example.test"} {
		if !validProbeTarget(valid) {
			t.Errorf("valid target rejected: %s", valid)
		}
	}
	for _, invalid := range []string{"", "https://example.test", "host:443", "bad host"} {
		if validProbeTarget(invalid) {
			t.Errorf("invalid target accepted: %s", invalid)
		}
	}
	roles, err := parseProbeRoleEndpoints("2095/tcp,443/udp")
	if err != nil || roles["2095/tcp"] != "management" || roles["443/udp"] != "management" {
		t.Fatalf("roles=%#v err=%v", roles, err)
	}
	if _, err := parseProbeRoleEndpoints("70000/tcp"); err == nil {
		t.Fatal("invalid management endpoint accepted")
	}
}

func TestPolicyCommandRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	var output bytes.Buffer
	if err := Run([]string{"policy", "init", path}, nil, &output, &output, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"policy", "validate", path}, nil, &output, &output, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"policy", "init", path}, nil, &output, &output, BuildInfo{Version: "test"}); err == nil {
		t.Fatal("policy init overwrote an existing file")
	}
}
