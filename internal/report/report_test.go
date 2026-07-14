package report

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func sampleReport() model.Report {
	r := model.Report{SchemaVersion: "1.0", ToolVersion: "test", Locale: "zh-CN", StartedAt: time.Unix(100, 0).UTC(), FinishedAt: time.Unix(101, 0).UTC(), LogSince: "168h0m0s", Host: model.Host{Hostname: "sgp", OS: "ubuntu", OSVersion: "24.04", Architecture: "x86_64", IsRoot: true}, Profile: model.Profile{Effective: "mixed", Detected: "mixed"}, Findings: []model.Finding{{ID: "SSH-001", Category: "ssh", Status: model.Pass, Evidence: []model.Evidence{{Source: "sshd -T", Key: "passwordauthentication", Value: "no"}}}, {ID: "FW-001", Category: "firewall", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Source: "ufw", Value: "inactive"}}}, {ID: "TLS-001", Category: "tls", Status: model.Unknown, Unavailable: true, Error: "permission denied"}}}
	r.Recount()
	return r
}

func TestAllRenderers(t *testing.T) {
	r := sampleReport()
	for name, render := range map[string]func(*bytes.Buffer) error{"json": func(b *bytes.Buffer) error { return JSON(b, r) }, "text": func(b *bytes.Buffer) error { return Text(b, r, Options{Locale: "zh-CN", Verbose: true}) }, "markdown": func(b *bytes.Buffer) error { return Markdown(b, r, Options{Locale: "en"}) }, "html": func(b *bytes.Buffer) error { return HTML(b, r, Options{Locale: "en"}) }} {
		var b bytes.Buffer
		if err := render(&b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b.Len() == 0 {
			t.Fatalf("%s produced no output", name)
		}
		if name != "json" && !strings.Contains(b.String(), "SSH") {
			t.Fatalf("%s missing finding", name)
		}
	}
}

func TestBundleVerifyAndDetectTamper(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	manifest, err := Bundle(dir, sampleReport(), Options{Locale: "zh-CN"})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 4 {
		t.Fatalf("files=%d", len(manifest.Files))
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || len(failures) != 0 {
		t.Fatalf("verify err=%v failures=%v", err, failures)
	}
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, failures, err = VerifyBundle(dir)
	if err != nil || len(failures) != 1 {
		t.Fatalf("tamper err=%v failures=%v", err, failures)
	}
}

func TestBundleRefusesExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Bundle(dir, sampleReport(), Options{Locale: "zh-CN"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Bundle(dir, sampleReport(), Options{Locale: "zh-CN"}); err == nil {
		t.Fatal("expected existing bundle directory to be refused")
	}
}

func TestVerifyBundleRejectsTraversalAndDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"schema_version":"1.0","files":[{"name":"../outside","size":0,"sha256":""},{"name":"report.json","size":0,"sha256":""},{"name":"report.json","size":0,"sha256":""}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 3 {
		t.Fatalf("failures=%v, want three invalid/missing entries", failures)
	}
	if !strings.Contains(failures[0], "invalid manifest file name") || !strings.Contains(failures[2], "duplicate") {
		t.Fatalf("unexpected failures: %v", failures)
	}
}

func TestVerifyBundleRejectsOversizedDeclaredFileBeforeReading(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"schema_version":"1.0","files":[{"name":"report.json","size":67108865,"sha256":""}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || len(failures) != 1 || !strings.Contains(failures[0], "safety limit") {
		t.Fatalf("verify err=%v failures=%v", err, failures)
	}
}

func TestHTMLIsSelfContainedAndUsable(t *testing.T) {
	var out bytes.Buffer
	if err := HTML(&out, sampleReport(), Options{Locale: "zh-CN"}); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, required := range []string{`data-filter="RISK"`, `class="search"`, `data-status="UNKNOWN"`, "Action summary", "风险解释", "证据", "报告保存在本地"} {
		if !strings.Contains(html, required) {
			t.Errorf("HTML missing %q", required)
		}
	}
	for _, external := range []string{"https://", "http://", "<link rel=", "<script src="} {
		if strings.Contains(html, external) {
			t.Errorf("HTML unexpectedly depends on external content %q", external)
		}
	}
}

func TestPriorityRiskShowsEvidenceWithoutVerbose(t *testing.T) {
	var out bytes.Buffer
	if err := Text(&out, sampleReport(), Options{Locale: "en", Verbose: false}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "[ufw] inactive") {
		t.Fatalf("priority risk evidence was hidden: %s", out.String())
	}
}

func TestActionSummarySeparatesUrgentAvailabilityAndEvidenceGaps(t *testing.T) {
	r := sampleReport()
	r.Findings = append(r.Findings,
		model.Finding{ID: "SSH-001", Category: "ssh", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Source: "sshd -T", Key: "passwordauthentication", Value: "yes"}}},
		model.Finding{ID: "WORK-009", Category: "workloads", Status: model.Risk, Severity: model.Medium, Evidence: []model.Evidence{{Source: "endpoint graph", Key: "endpoint_relation", Value: "configured-public-ingress-blocked-by-host-firewall"}}},
	)
	r.Recount()
	var out bytes.Buffer
	if err := Text(&out, r, Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, expected := range []string{"Handle now", "Confirmed risk: SSH password authentication is effective.", "May affect availability", "Availability issue: a configured proxy ingress is blocked by the host firewall.", "Evidence gaps requiring manual confirmation"} {
		if !strings.Contains(text, expected) {
			t.Errorf("text missing %q:\n%s", expected, text)
		}
	}
}

func TestMarkdownCompressesLongEvidence(t *testing.T) {
	r := sampleReport()
	r.Findings[1].Evidence = []model.Evidence{{Source: "ufw", Key: "one", Value: "1"}, {Source: "ufw", Key: "two", Value: "2"}, {Source: "ufw", Key: "three", Value: "3"}}
	var out bytes.Buffer
	if err := Markdown(&out, r, Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "<details><summary>All evidence (3)</summary>") {
		t.Fatalf("long evidence was not collapsed:\n%s", out.String())
	}
}

func TestProxyOverviewShowsPanelsAndIngressWithoutVerbose(t *testing.T) {
	r := sampleReport()
	r.Findings = append(r.Findings,
		model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Risk, Severity: model.High, Facts: map[string]string{"products": "S-UI"}, Evidence: []model.Evidence{{Source: "panel discovery", Key: "product", Value: "product=S-UI version=1.5.3 adapter=native"}}},
		model.Finding{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{"products": "S-UI,sing-box"}},
		model.Finding{ID: "WORK-009", Category: "workloads", Status: model.Pass, Evidence: []model.Evidence{{Source: "endpoint graph", Key: "endpoint_relation", Value: "port=443/tcp process=sing-box purpose=sing-box/vless security=reality scope=public-wildcard firewall=allow-anywhere judgment=expected-proxy-ingress"}}},
	)
	r.Recount()
	var out bytes.Buffer
	if err := Text(&out, r, Options{Locale: "zh-CN"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, expected := range []string{"代理工作负载概览", "S-UI 1.5.3 [RISK/HIGH]", "S-UI, sing-box", "443/tcp  sing-box/vless (reality)", "公网通配", "符合入口预期"} {
		if !strings.Contains(text, expected) {
			t.Errorf("text missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "系统修改:") {
		t.Fatalf("removed header line is still present:\n%s", text)
	}
}

func TestProxyOverviewShowsPostureActivityRuntimeAndDeployment(t *testing.T) {
	r := sampleReport()
	r.Findings = append(r.Findings,
		model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Key: "management_posture", Value: "product=S-UI port=2095/tcp scope=public-wildcard firewall=allow-anywhere tls=false path_default=true judgment=public-management-exposed+root-or-default-path+plaintext-panel"}}},
		model.Finding{ID: "WORK-010", Category: "workloads", Status: model.Info, Facts: map[string]string{"suspicious_activity_signals": "3", "panel_login_failure_signals": "2", "web_probe_signals": "1"}},
		model.Finding{ID: "WORK-012", Category: "workloads", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Key: "disabled_inbound_still_listening", Value: "product=S-UI protocol=hysteria2 port=8443/udp process=sing-box scope=public-wildcard"}}},
		model.Finding{ID: "WORK-013", Category: "workloads", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Key: "reverse_proxy_route", Value: "frontend=:::443/tcp proxy=nginx backend=127.0.0.1:2095/tcp judgment=public-reverse-proxy-exposes-s-ui-management"}}},
		model.Finding{ID: "DOCKER-001", Category: "docker", Status: model.Pass, Evidence: []model.Evidence{{Key: "compose_service", Value: "project=proxy service=panel container=panel image=example/panel network_mode=bridge"}}},
	)
	r.Recount()
	var out bytes.Buffer
	if err := Text(&out, r, Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, expected := range []string{"root/default path", "TLS disabled", "Operational and attack log signals", "panel login failures=2", "Disabled in panel but still listening", "Deployment relationships", "Docker Compose", "[INFO]", "[RISK/HIGH]"} {
		if !strings.Contains(text, expected) {
			t.Errorf("text missing %q:\n%s", expected, text)
		}
	}
}
