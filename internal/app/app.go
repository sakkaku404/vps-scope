package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/redact"
	"github.com/sakkaku404/vps-scope/internal/report"
)

type BuildInfo struct{ Version, Commit, Date string }

type environment struct {
	in          io.Reader
	out, errOut io.Writer
	build       BuildInfo
}

const (
	maxLatestReportEntries = 32
	maxReportHostEntries   = 1024
	maxReportListEntries   = 16 << 10
)

func Run(args []string, in io.Reader, out, errOut io.Writer, build BuildInfo) error {
	e := environment{in: in, out: out, errOut: errOut, build: build}
	if len(args) == 0 {
		return e.interactive()
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		switch args[0] {
		case "baseline":
			fmt.Fprintln(out, "Usage: vps-scope baseline create REPORT.json BASELINE.json | vps-scope baseline check BASELINE.json REPORT.json")
			return nil
		case "report":
			fmt.Fprintln(out, "Usage: vps-scope report list|show|path")
			return nil
		case "verify":
			fmt.Fprintln(out, "Usage: vps-scope verify REPORT.json|BUNDLE_DIR")
			return nil
		case "policy":
			fmt.Fprintln(out, "Usage: vps-scope policy init FILE.json | vps-scope policy validate FILE.json")
			return nil
		case "probe":
			fmt.Fprintln(out, "Usage: vps-scope probe plan|run|import")
			return nil
		}
	}
	var err error
	switch args[0] {
	case "audit":
		err = e.audit(args[1:])
	case "doctor":
		err = e.doctor(args[1:])
	case "checks":
		err = e.checks(args[1:])
	case "explain":
		err = e.explain(args[1:])
	case "diff":
		err = e.diff(args[1:])
	case "baseline":
		err = e.baseline(args[1:])
	case "policy":
		err = e.policy(args[1:])
	case "probe":
		err = e.probe(args[1:])
	case "fleet":
		err = e.fleet(args[1:])
	case "render":
		err = e.render(args[1:])
	case "redact":
		err = e.redact(args[1:])
	case "support":
		err = e.support(args[1:])
	case "report":
		err = e.report(args[1:])
	case "verify":
		err = e.verify(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(out, "vps-scope %s commit=%s built=%s go=%s\n", build.Version, build.Commit, build.Date, runtime.Version())
		return nil
	case "help", "--help", "-h":
		e.usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q; run vps-scope help", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func (e environment) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.errOut)
	return fs
}

func (e environment) usage() {
	fmt.Fprintln(e.out, `VPS Scope — evidence-driven, read-only VPS security audit

Usage:
  vps-scope                         interactive mode
  vps-scope audit [flags]           run all 16 audit categories
  vps-scope doctor [flags]          inspect audit capabilities
  vps-scope checks [flags]          list checks
  vps-scope explain CHECK-ID        explain a check
  vps-scope diff OLD.json NEW.json  compare one host over time
  vps-scope baseline create|check   record and check expected host state
  vps-scope policy init|validate    create or validate audit intent
  vps-scope probe plan|run|import   observe listeners from a second host
  vps-scope fleet REPORTS...        compare multiple hosts
  vps-scope render REPORT.json      render another language or format
  vps-scope redact REPORT.json      create a shareable redacted report
  vps-scope support REPORT.json     create a privacy-safe compatibility bundle
  vps-scope report list|show|path   manage saved local reports
  vps-scope verify REPORT_OR_BUNDLE verify hashes and report semantics
  vps-scope version                 show build information

Audit never changes system configuration, services, accounts, firewall, or packages.`)
}

func (e environment) interactive() error {
	reader := bufio.NewReader(e.in)
	fmt.Fprintln(e.out, "VPS Scope — Proxy VPS security and runtime audit")
	fmt.Fprintln(e.out, "\n请选择语言 / Choose language:\n  1. 简体中文\n  2. English\n  3. Русский\n  4. فارسی")
	fmt.Fprint(e.out, "选择 / Select [1]: ")
	choice, _ := reader.ReadString('\n')
	locale := map[string]string{"1": "zh-CN", "2": "en", "3": "ru-RU", "4": "fa-IR"}[strings.TrimSpace(choice)]
	if locale == "" {
		locale = "zh-CN"
	}
	fmt.Fprintln(e.out)
	fmt.Fprintln(e.out, choose(locale, "本工具永不修改系统配置。它只读取证据，并在你明确选择的位置写入报告。", "This tool never changes system configuration. It reads evidence and writes only to a report path you choose."))
	fmt.Fprintln(e.out)
	fmt.Fprintln(e.out, strings.TrimPrefix(choose(locale,
		"\n服务器用途（不确定就选 1）:\n  1. 自动识别（推荐）\n  2. 通用 VPS\n  3. 代理服务器\n  4. Web 服务器\n  5. Docker 主机\n  6. 混合用途\n  7. 自定义公网端口",
		"\nServer role (choose 1 if unsure):\n  1. auto detect (recommended)\n  2. general VPS\n  3. proxy server\n  4. web server\n  5. Docker host\n  6. mixed workloads\n  7. custom public listeners"), "\n"))
	fmt.Fprint(e.out, choose(locale, "选择 [1]: ", "Select [1]: "))
	profileChoice, _ := reader.ReadString('\n')
	profiles := map[string]string{"1": "auto", "2": "general", "3": "proxy", "4": "web", "5": "docker", "6": "mixed"}
	profiles["7"] = "custom"
	profile := profiles[strings.TrimSpace(profileChoice)]
	if profile == "" {
		profile = "auto"
	}
	expected := ""
	if profile == "custom" {
		fmt.Fprint(e.out, choose(locale, "预期公网端口（如 22/tcp,443/tcp）: ", "Expected public listeners (for example 22/tcp,443/tcp): "))
		expected, _ = reader.ReadString('\n')
		expected = strings.TrimSpace(expected)
	}
	fmt.Fprintln(e.out)
	fmt.Fprintln(e.out, strings.TrimPrefix(choose(locale, "\n输出方式:\n  1. 只在终端查看\n  2. 在终端查看，并保存完整报告（推荐）\n  3. 只保存完整报告", "\nOutput:\n  1. terminal only\n  2. terminal and full report bundle (recommended)\n  3. full report bundle only"), "\n"))
	fmt.Fprint(e.out, choose(locale, "选择 [2]: ", "Select [2]: "))
	outputChoice, _ := reader.ReadString('\n')
	format, alsoTerminal := "bundle", true
	switch strings.TrimSpace(outputChoice) {
	case "1":
		format, alsoTerminal = "terminal", false
	case "3":
		alsoTerminal = false
	}
	auditArgs := []string{"--lang", locale, "--profile", profile, "--format", format}
	if alsoTerminal {
		auditArgs = append(auditArgs, "--also-terminal")
	}
	if expected != "" {
		auditArgs = append(auditArgs, "--expect-public", expected)
	}
	return e.audit(auditArgs)
}

func (e environment) audit(args []string) error {
	fs := e.newFlagSet("audit")
	fs.SetOutput(e.errOut)
	lang := fs.String("lang", "auto", "zh-CN, en, ru-RU, fa-IR, or auto")
	profile := fs.String("profile", "auto", "auto, general, proxy, web, docker, mixed")
	format := fs.String("format", "terminal", "terminal, text, json, markdown, html, or bundle")
	output := fs.String("output", "", "output file or bundle directory")
	since := fs.String("log-since", "7d", "journal lookback, e.g. 24h or 7d")
	verbose := fs.Bool("verbose", false, "show evidence in terminal output")
	quiet := fs.Bool("quiet", false, "suppress progress")
	noColor := fs.Bool("no-color", false, "disable color output")
	redacted := fs.Bool("redact", false, "redact public IPs, domains, and host identifiers")
	deep := fs.Bool("deep", false, "run slower filesystem and package-integrity checks")
	alsoTerminal := fs.Bool("also-terminal", false, "print terminal report before saving a bundle")
	expectPublic := fs.String("expect-public", "", "expected public listeners, e.g. 22/tcp,443/tcp")
	externalDomains := fs.String("external-domain", "", "comma-separated domains for opt-in DNS and TLS observation")
	expectCDN := fs.Bool("expect-cdn", false, "treat a domain resolving directly to this VPS as a risk; requires --external-domain")
	policyPath := fs.String("policy", "", "versioned JSON policy describing endpoint and egress intent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateProfile(*profile); err != nil {
		return err
	}
	duration, err := parseDuration(*since)
	if err != nil {
		return fmt.Errorf("invalid --log-since: %w", err)
	}
	locale := i18n.Locale(*lang)
	progress := audit.ProgressFunc(nil)
	if !*quiet && (*format == "terminal" || *format == "text" || *format == "bundle") {
		progress = func(index, total int, category string) {
			fmt.Fprintf(e.out, "[%02d/%02d] %s\n", index, total, i18n.Category(category, locale))
		}
	}
	expected, err := parseExpectedPublic(*expectPublic)
	if err != nil {
		return err
	}
	domains, err := parseExternalDomains(*externalDomains)
	if err != nil {
		return err
	}
	if *expectCDN && len(domains) == 0 {
		return fmt.Errorf("--expect-cdn requires --external-domain")
	}
	var policy *audit.Policy
	if *policyPath != "" {
		policy, err = audit.LoadPolicy(*policyPath)
		if err != nil {
			return err
		}
	}
	r, err := audit.Run(audit.Options{Locale: locale, Profile: *profile, ExpectedPublic: expected, LogSince: duration, Deep: *deep, ExternalDomains: domains, ExpectCDN: *expectCDN, Policy: policy, Build: audit.Build{Version: e.build.Version, Commit: e.build.Commit}, Progress: progress})
	if err != nil {
		return err
	}
	if *redacted {
		r = redact.New().Report(r)
	}
	opts := report.Options{Locale: locale, Color: !*noColor && os.Getenv("NO_COLOR") == "", Verbose: *verbose}
	return e.writeReport(*format, *output, r, opts, *alsoTerminal)
}

func (e environment) doctor(args []string) error {
	fs := e.newFlagSet("doctor")
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	locale := i18n.Locale(*lang)
	fmt.Fprintf(e.out, "VPS Scope doctor\nOS=%s ARCH=%s GO=%s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Fprintf(e.out, "%s=%t\n", choose(locale, "支持完整审计", "full_audit_supported"), runtime.GOOS == "linux")
	if runtime.GOOS == "linux" {
		fmt.Fprintln(e.out, choose(locale, "命令状态: TRUSTED=可安全执行  UNTRUSTED=存在但权限链不可信  MISSING=未找到", "command status: TRUSTED=safe to execute  UNTRUSTED=unsafe ownership or writable path  MISSING=not found"))
	}
	commander := audit.OSCommander{}
	for _, name := range []string{"sshd", "ss", "journalctl", "ufw", "firewall-cmd", "nft", "iptables", "fail2ban-client", "cscli", "apt-get", "dpkg", "systemctl", "docker", "coredumpctl", "getcap"} {
		status := "MISSING"
		if runtime.GOOS == "linux" {
			status = doctorCommandStatus(commander, name)
		} else if _, err := findCommand(name); err == nil {
			status = "FOUND"
		}
		fmt.Fprintf(e.out, "%-18s %s\n", name, status)
	}
	return nil
}

type trustedExecutableInspector interface {
	TrustedExecutable(string) (string, error)
}

func doctorCommandStatus(cmd audit.Commander, name string) string {
	if !cmd.Exists(name) {
		return "MISSING"
	}
	trusted, ok := cmd.(trustedExecutableInspector)
	if !ok {
		return "FOUND"
	}
	if _, err := trusted.TrustedExecutable(name); err != nil {
		return "UNTRUSTED"
	}
	return "TRUSTED"
}

func (e environment) checks(args []string) error {
	fs := e.newFlagSet("checks")
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	locale := i18n.Locale(*lang)
	for index, category := range audit.CategoryOrder {
		fmt.Fprintf(e.out, "%02d. %s\n", index+1, i18n.Category(category, locale))
		var ids []string
		for id := range i18n.Rules {
			if categoryForID(id) == category {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(e.out, "    %-12s %s\n", id, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		}
	}
	return nil
}

func (e environment) explain(args []string) error {
	fs := e.newFlagSet("explain")
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vps-scope explain CHECK-ID")
	}
	id := strings.ToUpper(fs.Arg(0))
	if _, ok := i18n.Rules[id]; !ok {
		return fmt.Errorf("unknown check ID %q", id)
	}
	locale := i18n.Locale(*lang)
	rule := i18n.RuleForLocale(id, locale)
	fmt.Fprintf(e.out, "%s — %s\n\n%s: %s\n\n%s: %s\n", id, i18n.Pick(rule.Title, locale), choose(locale, "风险解释", "Why it matters"), i18n.Pick(rule.Why, locale), choose(locale, "建议", "Suggestion"), i18n.Pick(rule.Recommendation, locale))
	return nil
}

func (e environment) render(args []string) error {
	fs := e.newFlagSet("render")
	lang := fs.String("lang", "auto", "language")
	format := fs.String("format", "markdown", "text, markdown, html, json, bundle")
	output := fs.String("output", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vps-scope render REPORT.json")
	}
	r, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	locale := i18n.Locale(*lang)
	r.Locale = locale
	return e.writeReport(*format, *output, r, report.Options{Locale: locale})
}

func (e environment) redact(args []string) error {
	fs := e.newFlagSet("redact")
	lang := fs.String("lang", "auto", "language")
	format := fs.String("format", "json", "output format")
	output := fs.String("output", "", "output path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vps-scope redact REPORT.json")
	}
	r, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	r = redact.New().Report(r)
	locale := i18n.Locale(*lang)
	r.Locale = locale
	return e.writeReport(*format, *output, r, report.Options{Locale: locale})
}

func (e environment) support(args []string) error {
	fs := e.newFlagSet("support")
	output := fs.String("output", "", "new output directory")
	input := ""
	// Accept both common CLI styles: `support report.json --output dir`
	// and the Go flag package's native `support --output dir report.json`.
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		input, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if input == "" && fs.NArg() == 1 {
		input = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return errors.New("usage: vps-scope support REPORT.json [--output DIR]")
	}
	if input == "" {
		return errors.New("usage: vps-scope support REPORT.json [--output DIR]")
	}
	r, err := readReport(input)
	if err != nil {
		return err
	}
	if *output == "" {
		*output = "vps-scope-support-" + time.Now().UTC().Format("20060102T150405Z")
	}
	manifest, err := report.SupportBundle(*output, r)
	if err != nil {
		return fmt.Errorf("create support bundle: %w", err)
	}
	fmt.Fprintf(e.out, "support bundle: %s (%d files)\n", *output, len(manifest.Files))
	fmt.Fprintln(e.out, "Review every file before sharing. Raw configuration, databases, credentials, keys, UUIDs and host addresses are not included.")
	return nil
}

func (e environment) verify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: vps-scope verify REPORT.json|BUNDLE_DIR")
	}
	info, err := os.Stat(args[0])
	if err != nil {
		return err
	}
	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("verify input is not a regular report file or bundle directory")
		}
		return e.verifyReport(args[0])
	}
	manifest, failures, err := report.VerifyBundle(args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "manifest schema=%s files=%d\n", manifest.SchemaVersion, len(manifest.Files))
	if len(failures) > 0 {
		for _, failure := range failures {
			fmt.Fprintln(e.out, "FAIL", failure)
		}
		return fmt.Errorf("bundle verification failed for %d file(s)", len(failures))
	}
	fmt.Fprintln(e.out, "PASS all report files match the complete manifest")
	reportName := "report.json"
	if manifest.SchemaVersion == report.SupportSchema {
		reportName = "report.redacted.json"
	}
	return e.verifyReport(filepath.Join(args[0], reportName))
}

func (e environment) verifyReport(path string) error {
	r, err := readReport(path)
	if err != nil {
		return err
	}
	failures := audit.ValidateReport(r, e.build.Version)
	fmt.Fprintf(e.out, "report schema=%s tool=%s findings=%d\n", r.SchemaVersion, r.ToolVersion, len(r.Findings))
	if len(failures) > 0 {
		for _, failure := range failures {
			fmt.Fprintln(e.out, "FAIL", failure)
		}
		return fmt.Errorf("report semantic verification failed for %d condition(s)", len(failures))
	}
	fmt.Fprintln(e.out, "PASS report structure and semantic contract are valid")
	return nil
}

func categoryForID(id string) string {
	prefix, _, _ := strings.Cut(id, "-")
	return map[string]string{"SYS": "system", "ACC": "accounts", "SSH": "ssh", "PRIV": "privileges", "NET": "network", "FW": "firewall", "AUTH": "auth", "UPD": "updates", "PKG": "packages", "PROC": "processes", "DOCKER": "docker", "TLS": "tls", "WORK": "workloads", "FS": "filesystem", "PERSIST": "persistence", "REL": "reliability"}[prefix]
}
func validateProfile(value string) error {
	for _, allowed := range []string{"auto", "general", "proxy", "web", "docker", "mixed", "custom"} {
		if value == allowed {
			return nil
		}
	}
	return fmt.Errorf("unsupported profile %q", value)
}
func parseDuration(value string) (time.Duration, error) {
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}
func parseExternalDomains(value string) ([]string, error) {
	seen := map[string]bool{}
	var domains []string
	for _, item := range strings.Split(value, ",") {
		domain := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(item, ".")))
		if domain == "" {
			continue
		}
		if len(domain) > 253 || strings.ContainsAny(domain, "/:@[] \\") {
			return nil, fmt.Errorf("invalid --external-domain value %q", item)
		}
		for _, label := range strings.Split(domain, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, fmt.Errorf("invalid --external-domain value %q", item)
			}
			for _, character := range label {
				if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
					return nil, fmt.Errorf("invalid --external-domain value %q", item)
				}
			}
		}
		if !seen[domain] {
			seen[domain] = true
			domains = append(domains, domain)
		}
	}
	return domains, nil
}
func parseExpectedPublic(value string) (map[string]bool, error) {
	out := map[string]bool{}
	if strings.TrimSpace(value) == "" {
		return out, nil
	}
	for _, item := range strings.Split(value, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		parts := strings.Split(item, "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid --expect-public item %q; use PORT/tcp or PORT/udp", item)
		}
		port, err := strconv.Atoi(parts[0])
		if err != nil || port < 1 || port > 65535 || (parts[1] != "tcp" && parts[1] != "udp") {
			return nil, fmt.Errorf("invalid --expect-public item %q", item)
		}
		out[fmt.Sprintf("%d/%s", port, parts[1])] = true
	}
	return out, nil
}
func safeName(value string) string {
	value = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)
	return strings.Trim(value, "-")
}
func choose(locale, chinese, english string) string {
	return i18n.UI(locale, chinese, english)
}
func truncateDisplay(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n-1] + "…"
}
func findCommand(name string) (string, error) { return findExecutable(name) }
