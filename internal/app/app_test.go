package app

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/report"
)

func TestInteractiveProfilePromptUsesConfiguredWriter(t *testing.T) {
	var out bytes.Buffer
	_ = Run(nil, strings.NewReader("1\n1\n1\n"), &out, &out, BuildInfo{Version: "test"})
	if strings.Contains(out.String(), "&{") {
		t.Fatalf("interactive output contains a formatted writer pointer: %q", out.String())
	}
	if !strings.Contains(out.String(), "选择 [1]: ") {
		t.Fatalf("interactive output is missing the profile prompt: %q", out.String())
	}
}

func TestDownloadCommandFromSSHConnection(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 203.0.113.20 2222")
	t.Setenv("USER", "root")
	got := downloadCommand("/root/vps-scope-reports/latest/report.zh-CN.html")
	want := "scp -P 2222 root@203.0.113.20:'/root/vps-scope-reports/latest/report.zh-CN.html' ."
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSavedReportLatestCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	root := t.TempDir()
	t.Setenv("VPS_SCOPE_REPORT_DIR", root)
	r := model.Report{Locale: "zh-CN", StartedAt: time.Date(2026, 7, 11, 6, 19, 30, 0, time.UTC), Host: model.Host{Hostname: "test-vps"}}
	var out bytes.Buffer
	e := environment{out: &out, errOut: &out}
	if err := e.writeReport("bundle", "", r, report.Options{Locale: "zh-CN"}); err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join(root, "test-vps", "20260711T061930.000000000Z")
	latest, err := filepath.EvalSymlinks(filepath.Join(root, "latest"))
	if err != nil {
		t.Fatal(err)
	}
	if latest != wantDir {
		t.Fatalf("latest=%q, want %q", latest, wantDir)
	}
	for _, name := range []string{"report.zh-CN.txt", "report.zh-CN.html", "report.zh-CN.md", "report.json", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(wantDir, name)); err != nil {
			t.Errorf("missing %s: %v", name, err)
		}
	}
	out.Reset()
	if err := e.report([]string{"path"}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != wantDir {
		t.Fatalf("report path output=%q", out.String())
	}
}

func TestParseDurationDays(t *testing.T) {
	got, err := parseDuration("7d")
	if err != nil || got != 7*24*time.Hour {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestChecksBilingual(t *testing.T) {
	for _, lang := range []string{"zh-CN", "en"} {
		var out bytes.Buffer
		if err := Run([]string{"checks", "--lang", lang}, bytes.NewBuffer(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out.Bytes(), []byte("SSH-001")) {
			t.Fatalf("%s output missing SSH-001", lang)
		}
	}
}

func TestParseExpectedPublic(t *testing.T) {
	got, err := parseExpectedPublic("22/tcp, 443/tcp,8443/udp")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"22/tcp", "443/tcp", "8443/udp"} {
		if !got[key] {
			t.Fatalf("missing %s", key)
		}
	}
	if _, err := parseExpectedPublic("tcp/22"); err == nil {
		t.Fatal("invalid format accepted")
	}
}

func TestParseExternalDomains(t *testing.T) {
	got, err := parseExternalDomains("Panel.Example.com, panel.example.com.,api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "panel.example.com" || got[1] != "api.example.com" {
		t.Fatalf("domains=%v", got)
	}
	for _, invalid := range []string{"https://example.com", "bad name.example", "-bad.example"} {
		if _, err := parseExternalDomains(invalid); err == nil {
			t.Fatalf("accepted invalid domain %q", invalid)
		}
	}
}
