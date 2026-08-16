package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
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
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Fprintf(out, "vps-scope %s commit=%s built=%s go=%s\n", build.Version, build.Commit, build.Date, runtime.Version())
		return nil
	case "help", "--help", "-h":
		if len(args) != 1 {
			return errors.New("help does not accept arguments; use COMMAND --help")
		}
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
	choice, err := readInteractiveChoice(reader, e.out, "选择 / Select [1]: ", "1", 1, 4, "zh-CN")
	if err != nil {
		return err
	}
	locale := map[string]string{"1": "zh-CN", "2": "en", "3": "ru-RU", "4": "fa-IR"}[strings.TrimSpace(choice)]
	if locale == "" {
		locale = "zh-CN"
	}
	fmt.Fprintln(e.out)
	fmt.Fprintln(e.out, strings.TrimPrefix(choose(locale,
		"\n服务器用途（不确定就选 1）:\n  1. 自动识别（推荐）\n  2. 通用 VPS\n  3. 代理服务器\n  4. Web 服务器\n  5. Docker 主机\n  6. 混合用途\n  7. 自定义公网端口",
		"\nServer role (choose 1 if unsure):\n  1. auto detect (recommended)\n  2. general VPS\n  3. proxy server\n  4. web server\n  5. Docker host\n  6. mixed workloads\n  7. custom public listeners"), "\n"))
	profileChoice, err := readInteractiveChoice(reader, e.out, choose(locale, "选择 [1]: ", "Select [1]: "), "1", 1, 7, locale)
	if err != nil {
		return err
	}
	profiles := map[string]string{"1": "auto", "2": "general", "3": "proxy", "4": "web", "5": "docker", "6": "mixed"}
	profiles["7"] = "custom"
	profile := profiles[strings.TrimSpace(profileChoice)]
	if profile == "" {
		profile = "auto"
	}
	expected := ""
	if profile == "custom" {
		for {
			fmt.Fprint(e.out, choose(locale, "预期公网端口（如 22/tcp,443/tcp）: ", "Expected public listeners (for example 22/tcp,443/tcp): "))
			expected, err = readInteractiveLine(reader)
			if err != nil {
				return err
			}
			expected = strings.TrimSpace(expected)
			parsed, parseErr := parseExpectedPublic(expected)
			if parseErr == nil && len(parsed) > 0 {
				break
			}
			fmt.Fprintln(e.out, choose(locale, "请输入至少一个有效端口，例如 22/tcp,443/tcp。", "Enter at least one valid listener, for example 22/tcp,443/tcp."))
		}
	}
	fmt.Fprintln(e.out)
	fmt.Fprintln(e.out, strings.TrimPrefix(choose(locale, "\n输出方式:\n  1. 只在终端查看（推荐）\n  2. 在终端查看，并保存完整报告\n  3. 只保存完整报告", "\nOutput:\n  1. terminal only (recommended)\n  2. terminal and full report bundle\n  3. full report bundle only"), "\n"))
	outputChoice, err := readInteractiveChoice(reader, e.out, choose(locale, "选择 [1]: ", "Select [1]: "), "1", 1, 3, locale)
	if err != nil {
		return err
	}
	format, alsoTerminal := selectInteractiveOutput(outputChoice)
	auditArgs := []string{"--lang", locale, "--profile", profile, "--format", format}
	if alsoTerminal {
		auditArgs = append(auditArgs, "--also-terminal")
	}
	if expected != "" {
		auditArgs = append(auditArgs, "--expect-public", expected)
	}
	return e.audit(auditArgs)
}

func readInteractiveChoice(reader *bufio.Reader, out io.Writer, prompt, defaultChoice string, minimum, maximum int, locale string) (string, error) {
	for {
		fmt.Fprint(out, prompt)
		value, err := readInteractiveLine(reader)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return defaultChoice, nil
		}
		choice, parseErr := strconv.Atoi(value)
		if parseErr == nil && choice >= minimum && choice <= maximum {
			return value, nil
		}
		fmt.Fprintf(out, choose(locale, "请输入 %d 到 %d。\n", "Enter a number from %d to %d.\n"), minimum, maximum)
	}
}

func selectInteractiveOutput(choice string) (format string, alsoTerminal bool) {
	switch strings.TrimSpace(choice) {
	case "2":
		return "bundle", true
	case "3":
		return "bundle", false
	default:
		return "terminal", false
	}
}

func readInteractiveLine(reader *bufio.Reader) (string, error) {
	value, err := reader.ReadString('\n')
	if err == nil || (errors.Is(err, io.EOF) && value != "") {
		return value, nil
	}
	if errors.Is(err, io.EOF) {
		return "", errors.New("无法读取交互输入 / interactive input is unavailable; run VPS Scope in a terminal or pass explicit audit flags")
	}
	return "", fmt.Errorf("read interactive input: %w", err)
}

func (e environment) audit(args []string) error {
	fs := e.newFlagSet("audit")
	fs.SetOutput(e.errOut)
	lang := fs.String("lang", "auto", "zh-CN, en, ru-RU, fa-IR, or auto")
	profile := fs.String("profile", "auto", "auto, general, proxy, web, docker, mixed, custom")
	format := fs.String("format", "terminal", "terminal, text, json, markdown, html, or bundle")
	output := fs.String("output", "", "output file or bundle directory")
	since := fs.String("log-since", "7d", "journal lookback, e.g. 24h or 7d")
	verbose := fs.Bool("verbose", false, "show evidence in terminal output")
	quiet := fs.Bool("quiet", false, "suppress progress")
	noColor := fs.Bool("no-color", false, "disable color output")
	redacted := fs.Bool("redact", false, "redact public IPs, domains, and host identifiers")
	deep := fs.Bool("deep", false, "run slower filesystem and package-integrity checks")
	nativeSelfTest := fs.Bool("native-self-test", false, "execute trusted local workload binaries with the audit process privileges")
	auditTimeout := fs.Duration("audit-timeout", 5*time.Minute, "overall audit deadline for commands and collectors (30s to 30m)")
	alsoTerminal := fs.Bool("also-terminal", false, "print terminal report before saving a bundle")
	expectPublic := fs.String("expect-public", "", "expected public listeners, e.g. 22/tcp,443/tcp")
	externalDomains := fs.String("external-domain", "", "comma-separated domains for opt-in DNS and TLS observation")
	expectCDN := fs.Bool("expect-cdn", false, "treat a domain resolving directly to this VPS as a risk; requires --external-domain")
	policyPath := fs.String("policy", "", "versioned JSON policy describing endpoint and egress intent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("audit does not accept positional arguments: %q", fs.Args())
	}
	if err := validateProfile(*profile); err != nil {
		return err
	}
	if err := validateReportDestination(*format, *output); err != nil {
		return err
	}
	duration, err := parseDuration(*since)
	if err != nil {
		return fmt.Errorf("invalid --log-since: %w", err)
	}
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
	if *alsoTerminal && *format != "bundle" {
		return errors.New("--also-terminal is only valid with --format bundle")
	}
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
	if *profile == "custom" && len(expected) == 0 {
		return errors.New("--profile custom requires at least one --expect-public PORT/tcp or PORT/udp value")
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
	auditContext, stopAudit := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopAudit()
	r, err := audit.Run(audit.Options{Context: auditContext, Locale: locale, Profile: *profile, ExpectedPublic: expected, LogSince: duration, Deep: *deep, NativeSelfTest: *nativeSelfTest, AuditTimeout: *auditTimeout, ExternalDomains: domains, ExpectCDN: *expectCDN, Policy: policy, Build: audit.Build{Version: e.build.Version, Commit: e.build.Commit}, Progress: progress})
	if err != nil {
		return err
	}
	if *redacted {
		r = redact.New().Report(r)
	}
	opts := report.Options{Locale: locale, Color: !*noColor && os.Getenv("NO_COLOR") == "", Verbose: *verbose}
	return e.writeReport(*format, *output, r, opts, *alsoTerminal)
}

func validateReportDestination(format, output string) error {
	switch format {
	case "terminal", "text", "json", "markdown", "md", "html", "bundle":
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if output == "" {
		return nil
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("refusing to overwrite existing output %q", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output %q: %w", output, err)
	}
	parent := filepath.Dir(output)
	info, err := os.Stat(parent)
	if err != nil {
		if format == "bundle" && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("output parent directory %q is unavailable: %w", parent, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output parent %q is not a directory", parent)
	}
	return nil
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
		days, err := strconv.ParseInt(strings.TrimSuffix(value, "d"), 10, 64)
		maxDays := int64(audit.MaxLogSince / (24 * time.Hour))
		if err != nil || days <= 0 || days > maxDays {
			return 0, fmt.Errorf("invalid day duration")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > audit.MaxLogSince {
		return 0, fmt.Errorf("duration must be greater than zero and no longer than %s", audit.MaxLogSince)
	}
	return duration, nil
}
func parseExternalDomains(value string) ([]string, error) {
	const maxExternalDomains = 16
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
			if len(domains) > maxExternalDomains {
				return nil, fmt.Errorf("--external-domain accepts at most %d unique domains", maxExternalDomains)
			}
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

func parseLocaleFlag(value string) (string, error) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "_", "-")
	switch normalized {
	case "", "auto", "zh", "zh-cn", "cn", "en", "en-us", "en-gb", "ru", "ru-ru", "fa", "fa-ir", "persian", "farsi":
		return i18n.Locale(value), nil
	default:
		return "", fmt.Errorf("unsupported language %q; use auto, zh-CN, en, ru-RU, or fa-IR", value)
	}
}
func safeName(value string) string {
	original := value
	value = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, value)
	value = strings.Trim(value, "-")
	if value != "" {
		return value
	}
	// Linux hostnames are normally ASCII, but offline rendering accepts reports
	// from other producers. Never let an all-non-ASCII name collapse the host
	// directory and move the `latest` link one level above the report root.
	sum := sha256.Sum256([]byte(original))
	return fmt.Sprintf("host-%x", sum[:6])
}
func choose(locale, chinese, english string) string {
	return i18n.UI(locale, chinese, english)
}
func truncateDisplay(value string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= n {
		return value
	}
	if n == 1 {
		return "…"
	}
	return string(runes[:n-1]) + "…"
}
func findCommand(name string) (string, error) { return findExecutable(name) }
