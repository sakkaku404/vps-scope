package app

import (
	"bufio"
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
	"unicode/utf8"

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

func TestPublicCommandsRejectInvalidLanguageAndUnexpectedArguments(t *testing.T) {
	tests := [][]string{
		{"audit", "unexpected"},
		{"doctor", "unexpected"},
		{"checks", "unexpected"},
		{"version", "unexpected"},
		{"help", "unexpected"},
		{"checks", "--lang", "not-a-language"},
		{"audit", "--format", "text", "--also-terminal"},
	}
	for _, args := range tests {
		var output bytes.Buffer
		if err := Run(args, bytes.NewReader(nil), &output, &output, BuildInfo{Version: "test"}); err == nil {
			t.Fatalf("%v succeeded", args)
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

func TestExplainAcceptsLanguageBeforeOrAfterCheckID(t *testing.T) {
	for _, args := range [][]string{
		{"explain", "--lang", "ru-RU", "SSH-001"},
		{"explain", "SSH-001", "--lang", "ru-RU"},
	} {
		var out bytes.Buffer
		if err := Run(args, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if !strings.Contains(out.String(), "SSH-001") {
			t.Fatalf("%v did not explain the requested check: %q", args, out.String())
		}
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

func TestInteractiveEOFDoesNotSilentlyChooseDefaults(t *testing.T) {
	var out bytes.Buffer
	err := Run(nil, strings.NewReader(""), &out, &out, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "interactive input is unavailable") {
		t.Fatalf("Run() error=%v, want explicit interactive-input error", err)
	}
	if strings.Contains(out.String(), "[01/16]") {
		t.Fatalf("audit started after interactive EOF: %q", out.String())
	}
}

func TestInteractiveOutputDefaultsToTerminalOnly(t *testing.T) {
	for _, tc := range []struct {
		choice       string
		format       string
		alsoTerminal bool
	}{
		{choice: "", format: "terminal"},
		{choice: "1", format: "terminal"},
		{choice: "2", format: "bundle", alsoTerminal: true},
		{choice: "3", format: "bundle"},
	} {
		format, alsoTerminal := selectInteractiveOutput(tc.choice)
		if format != tc.format || alsoTerminal != tc.alsoTerminal {
			t.Errorf("selectInteractiveOutput(%q)=(%q,%t), want (%q,%t)", tc.choice, format, alsoTerminal, tc.format, tc.alsoTerminal)
		}
	}
}

func TestInteractiveChoiceRejectsInvalidValuesInsteadOfSilentlyDefaulting(t *testing.T) {
	var out bytes.Buffer
	choice, err := readInteractiveChoice(bufio.NewReader(strings.NewReader("9\n2\n")), &out, "Select [1]: ", "1", 1, 4, "en")
	if err != nil {
		t.Fatal(err)
	}
	if choice != "2" {
		t.Fatalf("choice=%q, want 2", choice)
	}
	if !strings.Contains(out.String(), "Enter a number from 1 to 4.") {
		t.Fatalf("invalid choice was not explained: %q", out.String())
	}
}

func TestInteractiveCustomProfileRequiresAValidListener(t *testing.T) {
	var out bytes.Buffer
	err := Run(nil, strings.NewReader("1\n7\n\ninvalid\n22/tcp\n1\n"), &out, &out, BuildInfo{Version: "test"})
	if runtime.GOOS != "linux" && (err == nil || !strings.Contains(err.Error(), "supported only")) {
		t.Fatalf("Run() error=%v, want platform error after completing prompts", err)
	}
	if count := strings.Count(out.String(), "请输入至少一个有效端口"); count != 2 {
		t.Fatalf("invalid custom listeners were not retried twice (count=%d): %q", count, out.String())
	}
}

func TestAuditRejectsInvalidOutputBeforeCollection(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "format", args: []string{"audit", "--format", "unknown"}, want: `unsupported format "unknown"`},
		{name: "empty custom", args: []string{"audit", "--profile", "custom"}, want: "--profile custom requires"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Run(tc.args, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Run(%v) error=%v, want %q", tc.args, err, tc.want)
			}
			if strings.Contains(out.String(), "[01/16]") {
				t.Fatalf("collection started before validation: %q", out.String())
			}
		})
	}
}

func TestAuditRejectsExistingOutputBeforeCollection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Run([]string{"audit", "--format", "json", "--output", path}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("Run() error=%v, want early overwrite refusal", err)
	}
	if strings.Contains(out.String(), "[01/16]") {
		t.Fatalf("collection started before output preflight: %q", out.String())
	}
}

func TestBundleHelpExplainsOneAuditAndFiveFiles(t *testing.T) {
	var out bytes.Buffer
	e := environment{out: &out}
	dir := filepath.Join(string(filepath.Separator), "root", "vps-scope-reports", "host", "timestamp")
	latest := filepath.Join(string(filepath.Separator), "root", "vps-scope-reports", "latest")
	e.printBundleHelp(dir, latest, "zh-CN", 4)
	text := out.String()
	for _, expected := range []string{
		"本次只执行了 1 次审计",
		"4 种报告格式和 1 份校验清单，共 5 个文件",
		"推荐查看:\n  " + filepath.Join(latest, "report.zh-CN.html"),
		"报告历史目录:\n  " + dir,
		"[1] report.zh-CN.html",
		"[5] manifest.json",
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
		for _, expected := range []string{"在 SSH 软件中打开 SFTP", "scp <SSH_HOST>:" + shellQuote(filepath.Join(latest, "report.zh-CN.html")) + " .", "IP、域名或 SSH 别名"} {
			if !strings.Contains(text, expected) {
				t.Errorf("Linux bundle help missing %q:\n%s", expected, text)
			}
		}
	}
}

func TestRemoteDownloadHelpDoesNotGuessClientCredentials(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 203.0.113.20 2222")
	var out bytes.Buffer
	e := environment{out: &out}
	dir := "/root/vps-scope-reports/latest"
	e.printRemoteDownloadHelp(dir, "report.zh-CN.html", "zh-CN")
	text := out.String()
	for _, expected := range []string{
		"在 SSH 软件中打开 SFTP",
		dir,
		"scp <SSH_HOST>:'" + dir + "/report.zh-CN.html' .",
		"IP、域名或 SSH 别名",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("remote download help missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "root@203.0.113.20") {
		t.Fatalf("remote download help guessed unusable client credentials:\n%s", text)
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

func TestParseDurationRejectsOverflowAndExcessiveLookback(t *testing.T) {
	for _, value := range []string{"0s", "367d", "1000000000000000000d", "8784h1s"} {
		if _, err := parseDuration(value); err == nil {
			t.Fatalf("parseDuration(%q) succeeded", value)
		}
	}
	if got, err := parseDuration("366d"); err != nil || got != audit.MaxLogSince {
		t.Fatalf("maximum duration = %v, %v", got, err)
	}
}

func TestDisplayAndReportNamesRemainUnicodeSafe(t *testing.T) {
	if got := truncateDisplay("你好世界", 3); got != "你好…" || !utf8.ValidString(got) {
		t.Fatalf("unicode truncation = %q", got)
	}
	name := safeName("测试主机")
	if name == "" || !strings.HasPrefix(name, "host-") {
		t.Fatalf("safeName = %q", name)
	}
	root := t.TempDir()
	t.Setenv("VPS_SCOPE_REPORT_DIR", root)
	path, err := defaultBundleDir(model.Report{Host: model.Host{Hostname: "测试主机"}, StartedAt: time.Unix(1, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Dir(filepath.Dir(path)); got != root {
		t.Fatalf("latest root would be %q, want %q", got, root)
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

func TestBundleHelpClarifiesInstalledCommandRequirement(t *testing.T) {
	var out bytes.Buffer
	environment{out: &out}.printBundleHelp("/tmp/history", "/tmp/latest", "en", 4)
	if !strings.Contains(out.String(), "require an installed copy of VPS Scope") {
		t.Fatalf("bundle help can mislead temporary-runner users: %q", out.String())
	}
}

func TestAuxiliaryCommandLabelsAreLocalized(t *testing.T) {
	for _, test := range []struct {
		locale, kind, want string
	}{
		{"zh-CN", "REGRESSION", "退化"},
		{"ru-RU", "CHANGED", "ИЗМЕНЕНО"},
		{"fa-IR", "IMPROVEMENT", "بهبود"},
	} {
		if got := diffKindLabel(test.kind, test.locale); got != test.want {
			t.Errorf("diffKindLabel(%q, %q)=%q want %q", test.kind, test.locale, got, test.want)
		}
	}

	r := appContractReport()
	r.Locale = "fa-IR"
	path := filepath.Join(t.TempDir(), "report.json")
	writeJSONReport(t, path, r)
	var out bytes.Buffer
	if err := Run([]string{"verify", path}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ساختار گزارش") {
		t.Fatalf("Persian verify output was not localized: %q", out.String())
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
		SchemaVersion: "1.0", ToolVersion: "1.0.0", Locale: "en",
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
