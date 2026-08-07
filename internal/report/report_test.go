package report

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

func TestBundleRejectsUnsafeLocale(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Bundle(dir, sampleReport(), Options{Locale: "../escape"}); err == nil {
		t.Fatal("unsafe bundle locale was accepted")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle directory was created: %v", err)
	}
}

func TestVerifyBundleRejectsUndeclaredFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Bundle(dir, sampleReport(), Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unexpected.txt"), []byte("not covered by manifest"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || !strings.Contains(strings.Join(failures, "\n"), "file is not declared in manifest") {
		t.Fatalf("verify err=%v failures=%v", err, failures)
	}
}

func TestVerifyBundleBoundsDirectoryEnumeration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Bundle(dir, sampleReport(), Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	// A normal bundle has five directory entries. Thirteen undeclared files
	// cross the protocol-wide maximum without requiring a huge test fixture.
	for i := 0; i < 13; i++ {
		name := filepath.Join(dir, fmt.Sprintf("unexpected-%02d", i))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || !strings.Contains(strings.Join(failures, "\n"), "entry safety limit") {
		t.Fatalf("verify err=%v failures=%v", err, failures)
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
	joined := strings.Join(failures, "\n")
	if !strings.Contains(joined, "invalid manifest file name") || !strings.Contains(joined, "duplicate") || !strings.Contains(joined, "localized report set is incomplete") {
		t.Fatalf("unexpected failures: %v", failures)
	}
}

func TestVerifyBundleRejectsUnknownManifestFieldsAndTrailingJSON(t *testing.T) {
	for name, manifest := range map[string]string{
		"unknown":  `{"schema_version":"1.0","unexpected":true,"files":[]}`,
		"trailing": `{"schema_version":"1.0","files":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyBundle(dir); err == nil {
				t.Fatal("malformed manifest was accepted")
			}
		})
	}
}

func TestVerifyBundleRejectsOversizedDeclaredFileBeforeReading(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"schema_version":"1.0","files":[{"name":"report.json","size":67108865,"sha256":""}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || !strings.Contains(strings.Join(failures, "\n"), "safety limit") {
		t.Fatalf("verify err=%v failures=%v", err, failures)
	}
}

func TestVerifyBundleRejectsIncompleteManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"schema_version":"1.0","files":[]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(failures, "\n")
	for _, want := range []string{"report.json", "localized report set is incomplete", "requires exactly 4"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("failures missing %q: %v", want, failures)
		}
	}
}

func TestVerifyBundleRejectsSymlinkedPayload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional Windows privileges")
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if _, err := Bundle(dir, sampleReport(), Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "report.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "report.json")); err != nil {
		t.Fatal(err)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || !strings.Contains(strings.Join(failures, "\n"), "not a regular file") {
		t.Fatalf("verify err=%v failures=%v", err, failures)
	}
}

func TestBundleCreationFailureRemovesPartialDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "partial")
	_, err := writeBundleFiles(dir, "1.0", map[string]func(io.Writer) error{
		"report.json": func(io.Writer) error { return errors.New("fixture failure") },
	})
	if err == nil {
		t.Fatal("expected creation failure")
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial directory survived: %v", statErr)
	}
}

func TestHTMLIsSelfContainedAndUsable(t *testing.T) {
	var out bytes.Buffer
	if err := HTML(&out, sampleReport(), Options{Locale: "zh-CN"}); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, required := range []string{`data-filter="RISK"`, `class="search"`, `data-status="UNKNOWN"`, "处理摘要", "风险解释", "证据", "报告保存在本地"} {
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

func TestActionLinksResolveToExactlyOneFinding(t *testing.T) {
	r := sampleReport()
	r.Findings = append(r.Findings,
		model.Finding{ID: "WORK-009", Category: "workloads", Status: model.Risk, Severity: model.Medium, Evidence: []model.Evidence{{Source: "endpoint graph", Key: "endpoint_relation", Value: "configured-public-ingress-blocked-by-host-firewall"}}},
		model.Finding{ID: "FW-002", Category: "firewall", Status: model.Risk, Severity: model.Medium},
	)
	r.Recount()

	var htmlOut bytes.Buffer
	if err := HTML(&htmlOut, r, Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	html := htmlOut.String()
	htmlLinks := regexp.MustCompile(`<a class="action-link" href="#([^"]+)">`).FindAllStringSubmatch(html, -1)
	if got, want := len(htmlLinks), 4; got != want {
		t.Fatalf("HTML action links=%d, want %d\n%s", got, want, html)
	}
	for _, match := range htmlLinks {
		anchor := match[1]
		if got := strings.Count(html, `id="`+anchor+`"`); got != 1 {
			t.Errorf("HTML action target %q appears %d times, want exactly once", anchor, got)
		}
	}
	for _, id := range []string{"SSH-001", "FW-001", "FW-002", "TLS-001", "WORK-009"} {
		if got := strings.Count(html, `id="finding-`+id+`"`); got != 1 {
			t.Errorf("HTML finding %s has %d stable IDs, want exactly one", id, got)
		}
	}
	if !strings.Contains(html, `.action-link:focus-visible`) || !strings.Contains(html, `scroll-margin-top:6.5rem`) {
		t.Error("HTML is missing keyboard-focus or anchored-scroll styling")
	}

	var markdownOut bytes.Buffer
	if err := Markdown(&markdownOut, r, Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	markdown := markdownOut.String()
	markdownLinks := regexp.MustCompile(`\]\(#(finding-[^)]+)\)`).FindAllStringSubmatch(markdown, -1)
	if got, want := len(markdownLinks), 4; got != want {
		t.Fatalf("Markdown action links=%d, want %d\n%s", got, want, markdown)
	}
	for _, match := range markdownLinks {
		anchor := match[1]
		if got := strings.Count(markdown, `<a id="`+anchor+`"></a>`); got != 1 {
			t.Errorf("Markdown action target %q appears %d times, want exactly once", anchor, got)
		}
	}
	linkedVerdict := regexp.MustCompile("(?m)^- \\[\\*\\*.+\\*\\* \\(`FW-001`\\)\\]\\(#finding-FW-001\\) \\(`RISK/HIGH`\\): .+$")
	if !linkedVerdict.MatchString(markdown) {
		t.Fatalf("Markdown action summary did not preserve title, ID, and verdict:\n%s", markdown)
	}
}

func TestFindingAnchorEncodesSpecialCharacters(t *testing.T) {
	const id = `BAD id/#?&"<`
	const want = "finding-BAD_20id_2f_23_3f_26_22_3c"
	if got := findingAnchor(id); got != want {
		t.Fatalf("findingAnchor(%q)=%q, want %q", id, got, want)
	}

	r := sampleReport()
	r.Findings = []model.Finding{{ID: id, Category: "ssh", Status: model.Risk, Severity: model.High}}
	r.Recount()
	var out bytes.Buffer
	if err := HTML(&out, r, Options{Locale: "en"}); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	if strings.Count(html, `href="#`+want+`"`) != 1 || strings.Count(html, `id="`+want+`"`) != 1 {
		t.Fatalf("encoded action link and target do not match exactly once:\n%s", html)
	}
	if strings.Contains(html, `id="finding-BAD id`) || strings.Contains(html, `href="#finding-BAD id`) {
		t.Fatal("raw special characters reached an anchor attribute")
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
	if !strings.Contains(out.String(), "`ufw`: one=1") {
		t.Fatalf("evidence key and value are not separated:\n%s", out.String())
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
	for _, expected := range []string{"代理 VPS 结论", "节点入口", "管理面", "代理部署明细", "S-UI 1.5.3 [RISK/HIGH]", "S-UI, sing-box", "443/tcp  sing-box/vless (reality)", "公网通配", "符合入口预期", "检查结果索引", "完整证据请打开"} {
		if !strings.Contains(text, expected) {
			t.Errorf("text missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "系统修改:") {
		t.Fatalf("removed header line is still present:\n%s", text)
	}
}

func TestProxyOverviewIsPresentInMarkdownAndHTML(t *testing.T) {
	r := sampleReport()
	r.Findings = append(r.Findings,
		model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Key: "management_posture", Value: "product=S-UI port=2095/tcp scope=public-wildcard firewall=allow-anywhere tls=true path_default=false judgment=public-management-exposed"}}},
		model.Finding{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{"products": "S-UI,sing-box"}},
		model.Finding{ID: "WORK-009", Category: "workloads", Status: model.Pass, Evidence: []model.Evidence{{Key: "endpoint_relation", Value: "port=443/tcp process=sing-box purpose=sing-box/vless security=reality scope=public-wildcard firewall=allow-anywhere judgment=expected-proxy-ingress"}}},
	)
	r.Recount()
	for _, render := range []struct {
		name string
		fn   func(io.Writer, model.Report, Options) error
	}{
		{"markdown", Markdown},
		{"html", HTML},
	} {
		t.Run(render.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := render.fn(&out, r, Options{Locale: "en"}); err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{"Proxy VPS assessment", "Proxy deployment details", "S-UI, sing-box", "Management panels", "443/tcp  sing-box/vless (reality)"} {
				if !strings.Contains(out.String(), expected) {
					t.Errorf("output missing %q:\n%s", expected, out.String())
				}
			}
		})
	}
}

func TestRussianAndPersianReportsAreLocalized(t *testing.T) {
	r := sampleReport()
	r.Findings = append(r.Findings,
		model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Risk, Severity: model.High, Evidence: []model.Evidence{{Key: "management_posture", Value: "product=S-UI port=2095/tcp scope=public-wildcard firewall=allow-anywhere tls=true path_default=false judgment=public-management-exposed"}}},
		model.Finding{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{"products": "S-UI,sing-box"}},
		model.Finding{ID: "WORK-009", Category: "workloads", Status: model.Pass, Evidence: []model.Evidence{{Key: "endpoint_relation", Value: "port=443/tcp process=sing-box purpose=sing-box/vless security=reality scope=public-wildcard firewall=allow-anywhere judgment=expected-proxy-ingress"}}},
	)
	r.Recount()
	for _, test := range []struct {
		locale        string
		assessment    string
		category      string
		htmlDirection string
	}{
		{"ru-RU", "Оценка прокси VPS", "SSH", `dir="ltr"`},
		{"fa-IR", "ارزیابی VPS پروکسی", "SSH", `dir="rtl"`},
	} {
		t.Run(test.locale, func(t *testing.T) {
			var text bytes.Buffer
			if err := Text(&text, r, Options{Locale: test.locale}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text.String(), test.assessment) || !strings.Contains(text.String(), test.category) {
				t.Fatalf("localized text is incomplete:\n%s", text.String())
			}
			var html bytes.Buffer
			if err := HTML(&html, r, Options{Locale: test.locale}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(html.String(), test.htmlDirection) {
				t.Fatalf("%s HTML direction is wrong", test.locale)
			}
			if test.locale == "fa-IR" && !strings.Contains(html.String(), "direction:ltr;text-align:left") {
				t.Fatal("Persian technical evidence does not retain LTR direction")
			}
		})
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

func TestTypedProxyOverviewKeepsGenericHostListenersOutOfRuntimeMismatches(t *testing.T) {
	r := sampleReport()
	r.Deployment = &model.Deployment{
		Coverage: model.DeploymentCoverage{Configuration: "complete", Runtime: "complete", Firewall: "complete", Panels: "complete", ReverseProxy: "not-applicable", Docker: "not-applicable"},
		Endpoints: []model.ServiceEndpoint{
			{ID: "endpoint-ssh", Role: "unclassified-listener", Product: "unknown-proxy", Port: 22, Transport: "tcp", Scope: "public-wildcard", Judgment: "listener-purpose-not-classified"},
			{ID: "endpoint-core", Role: "unclassified-product-listener", Product: "xray", Port: 443, Transport: "tcp", Scope: "public-wildcard", Judgment: "listener-purpose-not-classified"},
		},
	}
	overview := collectTopologyOverview(r, "en")
	joined := fmt.Sprintf("%+v", overview)
	if strings.Contains(joined, "22/tcp") {
		t.Fatalf("generic host listener leaked into proxy runtime mismatches: %s", joined)
	}
	if !strings.Contains(joined, "443/tcp") || !strings.Contains(joined, "xray") {
		t.Fatalf("recognized proxy listener missing from runtime mismatches: %s", joined)
	}
}
