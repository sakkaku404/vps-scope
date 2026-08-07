package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/report"
)

type doctorFixtureCommander struct {
	exists  map[string]bool
	trusted map[string]error
}

func TestSubcommandHelpIsSuccessfulAndUsesProvidedWriter(t *testing.T) {
	for _, args := range [][]string{{"audit", "--help"}, {"diff", "--help"}, {"baseline", "--help"}, {"policy", "--help"}, {"probe", "--help"}, {"report", "--help"}, {"verify", "--help"}} {
		var out bytes.Buffer
		if err := Run(args, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(strings.ToLower(out.String()), "usage") {
			t.Fatalf("%v produced no usage text: %q", args, out.String())
		}
	}
}

func TestAuditHelpDocumentsNativeSelfTestOptIn(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"audit", "--help"}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "native-self-test") {
		t.Fatalf("audit help does not document the native self-test opt-in: %q", out.String())
	}
}

func (c doctorFixtureCommander) Run(time.Duration, string, ...string) audit.CommandResult {
	return audit.CommandResult{}
}

func (c doctorFixtureCommander) Exists(name string) bool {
	return c.exists[name]
}

func (c doctorFixtureCommander) TrustedExecutable(name string) (string, error) {
	if err, ok := c.trusted[name]; ok {
		return "", err
	}
	return "/usr/bin/" + name, nil
}

type doctorAvailabilityCommander map[string]bool

func (c doctorAvailabilityCommander) Run(time.Duration, string, ...string) audit.CommandResult {
	return audit.CommandResult{}
}

func (c doctorAvailabilityCommander) Exists(name string) bool {
	return c[name]
}

func TestDoctorCommandStatusMatchesAuditTrustPolicy(t *testing.T) {
	commander := doctorFixtureCommander{
		exists:  map[string]bool{"trusted": true, "untrusted": true},
		trusted: map[string]error{"untrusted": errors.New("writable parent directory")},
	}
	for _, tc := range []struct {
		name string
		want string
	}{
		{name: "trusted", want: "TRUSTED"},
		{name: "untrusted", want: "UNTRUSTED"},
		{name: "missing", want: "MISSING"},
	} {
		if got := doctorCommandStatus(commander, tc.name); got != tc.want {
			t.Errorf("doctorCommandStatus(%q)=%q, want %q", tc.name, got, tc.want)
		}
	}
	if got := doctorCommandStatus(doctorAvailabilityCommander{"legacy": true}, "legacy"); got != "FOUND" {
		t.Fatalf("commander without trust inspection=%q, want FOUND", got)
	}
}

func TestInteractiveProfilePromptUsesConfiguredWriter(t *testing.T) {
	var out bytes.Buffer
	_ = Run(nil, strings.NewReader("1\n1\n1\n"), &out, &out, BuildInfo{Version: "test"})
	if strings.Contains(out.String(), "&{") {
		t.Fatalf("interactive output contains a formatted writer pointer: %q", out.String())
	}
	if !strings.Contains(out.String(), "选择 [1]: ") {
		t.Fatalf("interactive output is missing the profile prompt: %q", out.String())
	}
	for _, language := range []string{"简体中文", "English", "Русский", "فارسی"} {
		if !strings.Contains(out.String(), language) {
			t.Fatalf("interactive output is missing %s: %q", language, out.String())
		}
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

func TestBundleHelpExplainsOneAuditAndFiveFiles(t *testing.T) {
	// The output contract under test is the non-SSH fallback. CI and real-VPS
	// runners may themselves execute over SSH, so seal that ambient input.
	t.Setenv("SSH_CONNECTION", "")
	var out bytes.Buffer
	e := environment{out: &out}
	dir := filepath.Join(string(filepath.Separator), "root", "vps-scope-reports", "latest")
	e.printBundleHelp(dir, "zh-CN", 4)
	text := out.String()
	for _, expected := range []string{
		"本次只执行了 1 次审计",
		"4 种报告格式和 1 份校验清单，共 5 个文件",
		"[1] " + filepath.Join(dir, "report.zh-CN.html"),
		"[5] " + filepath.Join(dir, "manifest.json"),
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("bundle help missing %q:\n%s", expected, text)
		}
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(text, "可点击下面的本地链接") || !strings.Contains(text, "file:///") {
			t.Fatalf("Windows bundle help is missing a local HTML link:\n%s", text)
		}
	} else {
		for _, expected := range []string{"SSH 终端不能直接把它当网页打开", "scp <SSH_HOST>:" + shellQuote(filepath.Join(dir, "report.zh-CN.html")) + " ."} {
			if !strings.Contains(text, expected) {
				t.Errorf("Linux bundle help missing %q:\n%s", expected, text)
			}
		}
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

func TestReportShowRejectsExcessiveLatestDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("VPS_SCOPE_REPORT_DIR", root)
	latest := filepath.Join(root, "latest")
	if err := os.Mkdir(latest, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxLatestReportEntries; i++ {
		if err := os.WriteFile(filepath.Join(latest, "entry-"+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := (environment{out: io.Discard, errOut: io.Discard}).report([]string{"show"})
	if err == nil || !strings.Contains(err.Error(), "entry safety limit") {
		t.Fatalf("error=%v, want directory safety limit", err)
	}
}

func TestReportListRejectsExcessiveHostDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("VPS_SCOPE_REPORT_DIR", root)
	for i := 0; i <= maxReportHostEntries; i++ {
		if err := os.Mkdir(filepath.Join(root, "host-"+strconv.Itoa(i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	err := (environment{out: io.Discard, errOut: io.Discard}).report([]string{"list"})
	if err == nil || !strings.Contains(err.Error(), "entry safety limit") {
		t.Fatalf("error=%v, want directory safety limit", err)
	}
}

func TestParseDurationDays(t *testing.T) {
	got, err := parseDuration("7d")
	if err != nil || got != 7*24*time.Hour {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestAtomicWriteNewPublishesCompleteFileWithoutOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := atomicWriteNew(path, 32, func(w io.Writer) error {
		_, err := io.WriteString(w, "complete")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "complete" {
		t.Fatalf("data=%q err=%v", data, err)
	}
	if err := atomicWriteNew(path, 32, func(w io.Writer) error {
		_, err := io.WriteString(w, "replacement")
		return err
	}); err == nil {
		t.Fatal("existing report was overwritten")
	}
	data, _ = os.ReadFile(path)
	if string(data) != "complete" {
		t.Fatalf("existing report changed: %q", data)
	}
}

func TestAtomicWriteNewRemovesFailedPartialOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	err := atomicWriteNew(path, 32, func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return errors.New("fixture failure")
	})
	if err == nil {
		t.Fatal("expected write failure")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial output survived: %v", statErr)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".vps-scope-output-*"))
	if len(matches) != 0 {
		t.Fatalf("temporary outputs survived: %v", matches)
	}
}

func TestAtomicWriteNewEnforcesOutputLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	err := atomicWriteNew(path, 3, func(w io.Writer) error {
		_, err := io.WriteString(w, "four")
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "output safety limit") {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyAcceptsReportAndCompleteBundle(t *testing.T) {
	r := appContractReport()
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	writeJSONReport(t, reportPath, r)
	for _, input := range []string{reportPath, filepath.Join(dir, "bundle")} {
		if input != reportPath {
			if _, err := report.Bundle(input, r, report.Options{Locale: "en"}); err != nil {
				t.Fatal(err)
			}
		}
		var out bytes.Buffer
		if err := Run([]string{"verify", input}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatalf("input=%s err=%v output=%s", input, err, out.String())
		}
		if !strings.Contains(out.String(), "PASS report structure and semantic contract are valid") {
			t.Fatalf("input=%s output=%s", input, out.String())
		}
	}
}

func TestVerifyRejectsSemanticallyIncompleteReport(t *testing.T) {
	r := appContractReport()
	r.Findings = r.Findings[:len(r.Findings)-1]
	r.Recount()
	path := filepath.Join(t.TempDir(), "report.json")
	writeJSONReport(t, path, r)
	var out bytes.Buffer
	err := Run([]string{"verify", path}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(out.String(), "required check ID REL-002 is missing") {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func TestVerifyKeepsLegacyReportReadable(t *testing.T) {
	var out bytes.Buffer
	err := Run([]string{"verify", filepath.Join("testdata", "golden-report-v1.json")}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
	if err != nil {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func appContractReport() model.Report {
	r := model.Report{
		SchemaVersion: "1.0", ToolVersion: "0.13.0", Locale: "en",
		StartedAt: time.Unix(1, 0).UTC(), FinishedAt: time.Unix(2, 0).UTC(),
		LogSince: "168h0m0s",
		Host:     model.Host{StableID: "fixture-id", Hostname: "fixture", OS: "debian", OSVersion: "12", Kernel: "fixture-kernel", Architecture: "x86_64"},
		Profile:  model.Profile{Requested: "auto", Detected: "proxy", Effective: "proxy"},
	}
	for _, id := range audit.StableCheckIDs {
		prefix, _, _ := strings.Cut(id, "-")
		category := map[string]string{
			"SYS": "system", "ACC": "accounts", "SSH": "ssh", "PRIV": "privileges",
			"NET": "network", "FW": "firewall", "AUTH": "auth", "UPD": "updates",
			"PKG": "packages", "PROC": "processes", "DOCKER": "docker", "TLS": "tls",
			"WORK": "workloads", "FS": "filesystem", "PERSIST": "persistence", "REL": "reliability",
		}[prefix]
		r.Findings = append(r.Findings, model.Finding{
			ID: id, Category: category, Status: model.Pass,
			ReasonCode: strings.ToLower(strings.ReplaceAll(id, "-", ".")) + ".verified",
		})
	}
	r.Recount()
	return r
}

func writeJSONReport(t *testing.T, path string, r model.Report) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.JSON(f, r); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestChecksAllSupportedLanguages(t *testing.T) {
	for _, lang := range []string{"zh-CN", "en", "ru-RU", "fa-IR"} {
		var out bytes.Buffer
		if err := Run([]string{"checks", "--lang", lang}, bytes.NewBuffer(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out.Bytes(), []byte("SSH-001")) {
			t.Fatalf("%s output missing SSH-001", lang)
		}
	}
}

func TestSupportAcceptsOutputFlagBeforeOrAfterReport(t *testing.T) {
	reportPath := filepath.Join("testdata", "golden-report-v1.json")
	for _, after := range []bool{false, true} {
		outDir := filepath.Join(t.TempDir(), "support")
		args := []string{"support", "--output", outDir, reportPath}
		if after {
			args = []string{"support", reportPath, "--output", outDir}
		}
		var out bytes.Buffer
		if err := Run(args, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatalf("after=%t: %v", after, err)
		}
		if _, err := os.Stat(filepath.Join(outDir, "compatibility.json")); err != nil {
			t.Fatalf("after=%t: %v", after, err)
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
	many := make([]string, 17)
	for index := range many {
		many[index] = "host-" + strconv.Itoa(index) + ".example.com"
	}
	if _, err := parseExternalDomains(strings.Join(many, ",")); err == nil {
		t.Fatal("external domain safety limit was not enforced")
	}
}
