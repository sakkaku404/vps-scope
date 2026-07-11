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

func TestHTMLIsSelfContainedAndUsable(t *testing.T) {
	var out bytes.Buffer
	if err := HTML(&out, sampleReport(), Options{Locale: "zh-CN"}); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, required := range []string{`data-filter="RISK"`, `class="search"`, `data-status="UNKNOWN"`, "风险解释", "证据", "报告保存在本地"} {
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
