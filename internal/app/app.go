package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/redact"
	"github.com/sakkaku404/vps-scope/internal/report"
)

type BuildInfo struct{ Version, Commit, Date string }

type environment struct {
	in          io.Reader
	out, errOut io.Writer
	build       BuildInfo
}

func Run(args []string, in io.Reader, out, errOut io.Writer, build BuildInfo) error {
	e := environment{in: in, out: out, errOut: errOut, build: build}
	if len(args) == 0 {
		return e.interactive()
	}
	switch args[0] {
	case "audit":
		return e.audit(args[1:])
	case "doctor":
		return e.doctor(args[1:])
	case "checks":
		return e.checks(args[1:])
	case "explain":
		return e.explain(args[1:])
	case "diff":
		return e.diff(args[1:])
	case "fleet":
		return e.fleet(args[1:])
	case "render":
		return e.render(args[1:])
	case "redact":
		return e.redact(args[1:])
	case "verify":
		return e.verify(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(out, "vps-scope %s commit=%s built=%s go=%s\n", build.Version, build.Commit, build.Date, runtime.Version())
		return nil
	case "help", "--help", "-h":
		e.usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q; run vps-scope help", args[0])
	}
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
  vps-scope fleet REPORTS...        compare multiple hosts
  vps-scope render REPORT.json      render another language or format
  vps-scope redact REPORT.json      create a shareable redacted report
  vps-scope verify BUNDLE_DIR       verify report SHA-256 values
  vps-scope version                 show build information

Audit never changes system configuration, services, accounts, firewall, or packages.`)
}

func (e environment) interactive() error {
	reader := bufio.NewReader(e.in)
	fmt.Fprintln(e.out, "VPS Scope — Evidence-driven server security audit")
	fmt.Fprintln(e.out, "\n请选择语言 / Choose language:\n  1. 简体中文\n  2. English")
	fmt.Fprint(e.out, "选择 / Select [1]: ")
	choice, _ := reader.ReadString('\n')
	locale := "zh-CN"
	if strings.TrimSpace(choice) == "2" {
		locale = "en"
	}
	zh := locale == "zh-CN"
	fmt.Fprintln(e.out)
	if zh {
		fmt.Fprintln(e.out, "本工具永不修改系统配置。它只读取证据，并在你明确选择的位置写入报告。")
	} else {
		fmt.Fprintln(e.out, "This tool never changes system configuration. It reads evidence and writes only to a report path you choose.")
	}
	fmt.Fprintln(e.out, "\nProfile: 1. auto  2. general  3. proxy  4. web  5. docker  6. mixed  7. custom")
	fmt.Fprint(e.out, choose(zh, "选择 [1]: ", "Select [1]: "))
	profileChoice, _ := reader.ReadString('\n')
	profiles := map[string]string{"1": "auto", "2": "general", "3": "proxy", "4": "web", "5": "docker", "6": "mixed"}
	profiles["7"] = "custom"
	profile := profiles[strings.TrimSpace(profileChoice)]
	if profile == "" {
		profile = "auto"
	}
	expected := ""
	if profile == "custom" {
		fmt.Fprint(e.out, choose(zh, "预期公网端口（如 22/tcp,443/tcp）: ", "Expected public listeners (for example 22/tcp,443/tcp): "))
		expected, _ = reader.ReadString('\n')
		expected = strings.TrimSpace(expected)
	}
	fmt.Fprintln(e.out, choose(zh, "\n输出: 1. 仅终端  2. 完整报告包", "\nOutput: 1. terminal only  2. full report bundle"))
	fmt.Fprint(e.out, choose(zh, "选择 [1]: ", "Select [1]: "))
	outputChoice, _ := reader.ReadString('\n')
	format := "terminal"
	if strings.TrimSpace(outputChoice) == "2" {
		format = "bundle"
	}
	auditArgs := []string{"--lang", locale, "--profile", profile, "--format", format}
	if expected != "" {
		auditArgs = append(auditArgs, "--expect-public", expected)
	}
	return e.audit(auditArgs)
}

func (e environment) audit(args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(e.errOut)
	lang := fs.String("lang", "auto", "zh-CN, en, or auto")
	profile := fs.String("profile", "auto", "auto, general, proxy, web, docker, mixed")
	format := fs.String("format", "terminal", "terminal, text, json, markdown, html, or bundle")
	output := fs.String("output", "", "output file or bundle directory")
	since := fs.String("log-since", "7d", "journal lookback, e.g. 24h or 7d")
	verbose := fs.Bool("verbose", false, "show evidence in terminal output")
	quiet := fs.Bool("quiet", false, "suppress progress")
	noColor := fs.Bool("no-color", false, "disable color output")
	redacted := fs.Bool("redact", false, "redact public IPs, domains, and host identifiers")
	expectPublic := fs.String("expect-public", "", "expected public listeners, e.g. 22/tcp,443/tcp")
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
			fmt.Fprintf(e.out, "[%02d/%02d] %s\n", index, total, i18n.Pick(i18n.Categories[category], locale))
		}
	}
	expected, err := parseExpectedPublic(*expectPublic)
	if err != nil {
		return err
	}
	r, err := audit.Run(audit.Options{Locale: locale, Profile: *profile, ExpectedPublic: expected, LogSince: duration, Build: audit.Build{Version: e.build.Version, Commit: e.build.Commit}, Progress: progress})
	if err != nil {
		return err
	}
	if *redacted {
		r = redact.New().Report(r)
	}
	opts := report.Options{Locale: locale, Color: !*noColor && os.Getenv("NO_COLOR") == "", Verbose: *verbose}
	return e.writeReport(*format, *output, r, opts)
}

func (e environment) writeReport(format, output string, r model.Report, opts report.Options) error {
	if format == "bundle" {
		if output == "" {
			output = fmt.Sprintf("vps-scope-%s-%s", safeName(r.Host.Hostname), r.StartedAt.Format("20060102T150405Z"))
		}
		manifest, err := report.Bundle(output, r, opts)
		if err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s: %s (%d files)\n", choose(opts.Locale == "zh-CN", "报告包", "Report bundle"), output, len(manifest.Files))
		for _, file := range manifest.Files {
			if file.Name == "report.json" {
				fmt.Fprintf(e.out, "report.json SHA-256: %s\n", file.SHA256)
			}
		}
		return nil
	}
	var write func(io.Writer) error
	switch format {
	case "terminal", "text":
		write = func(w io.Writer) error { return report.Text(w, r, opts) }
	case "json":
		write = func(w io.Writer) error { return report.JSON(w, r) }
	case "markdown", "md":
		write = func(w io.Writer) error { return report.Markdown(w, r, opts) }
	case "html":
		write = func(w io.Writer) error { return report.HTML(w, r, opts) }
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if output == "" {
		return write(e.out)
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := write(file); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "%s: %s\n", choose(opts.Locale == "zh-CN", "报告", "Report"), output)
	return nil
}

func (e environment) doctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	locale := i18n.Locale(*lang)
	zh := locale == "zh-CN"
	fmt.Fprintf(e.out, "VPS Scope doctor\nOS=%s ARCH=%s GO=%s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Fprintf(e.out, "%s=%t\n", choose(zh, "支持完整审计", "full_audit_supported"), runtime.GOOS == "linux")
	for _, name := range []string{"sshd", "ss", "journalctl", "ufw", "nft", "iptables", "fail2ban-client", "apt-get", "dpkg", "systemctl", "docker", "coredumpctl", "getcap"} {
		_, err := findCommand(name)
		fmt.Fprintf(e.out, "%-18s %s\n", name, map[bool]string{true: "FOUND", false: "MISSING"}[err == nil])
	}
	return nil
}

func (e environment) checks(args []string) error {
	fs := flag.NewFlagSet("checks", flag.ContinueOnError)
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	locale := i18n.Locale(*lang)
	for index, category := range audit.CategoryOrder {
		fmt.Fprintf(e.out, "%02d. %s\n", index+1, i18n.Pick(i18n.Categories[category], locale))
		var ids []string
		for id := range i18n.Rules {
			if categoryForID(id) == category {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(e.out, "    %-12s %s\n", id, i18n.Pick(i18n.RuleFor(id).Title, locale))
		}
	}
	return nil
}

func (e environment) explain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vps-scope explain CHECK-ID")
	}
	id := strings.ToUpper(fs.Arg(0))
	rule, ok := i18n.Rules[id]
	if !ok {
		return fmt.Errorf("unknown check ID %q", id)
	}
	locale := i18n.Locale(*lang)
	zh := locale == "zh-CN"
	fmt.Fprintf(e.out, "%s — %s\n\n%s: %s\n\n%s: %s\n", id, i18n.Pick(rule.Title, locale), choose(zh, "风险解释", "Why it matters"), i18n.Pick(rule.Why, locale), choose(zh, "建议", "Suggestion"), i18n.Pick(rule.Recommendation, locale))
	return nil
}

func (e environment) render(args []string) error {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
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
	fs := flag.NewFlagSet("redact", flag.ContinueOnError)
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

func (e environment) verify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: vps-scope verify BUNDLE_DIR")
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
	fmt.Fprintln(e.out, "PASS all report files match manifest SHA-256 values")
	return nil
}

func (e environment) diff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: vps-scope diff OLD.json NEW.json")
	}
	oldReport, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	newReport, err := readReport(fs.Arg(1))
	if err != nil {
		return err
	}
	locale := i18n.Locale(*lang)
	oldMap, newMap := findingMap(oldReport), findingMap(newReport)
	var ids []string
	seen := map[string]bool{}
	for id := range oldMap {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range newMap {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		o, okOld := oldMap[id]
		n, okNew := newMap[id]
		switch {
		case !okOld:
			fmt.Fprintf(e.out, "NEW      %-12s %-8s %s\n", id, n.Status, i18n.Pick(i18n.RuleFor(id).Title, locale))
		case !okNew:
			fmt.Fprintf(e.out, "REMOVED  %-12s %-8s %s\n", id, o.Status, i18n.Pick(i18n.RuleFor(id).Title, locale))
		case o.Status != n.Status || evidenceFingerprint(o) != evidenceFingerprint(n):
			fmt.Fprintf(e.out, "CHANGED  %-12s %s -> %s  %s\n", id, o.Status, n.Status, i18n.Pick(i18n.RuleFor(id).Title, locale))
		}
	}
	return nil
}

func (e environment) fleet(args []string) error {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = lang
	if fs.NArg() < 1 {
		return errors.New("usage: vps-scope fleet REPORT.json...")
	}
	fmt.Fprintf(e.out, "%-24s %5s %5s %5s %8s %10s\n", "HOST", "RISK", "PASS", "INFO", "UNKNOWN", "PROFILE")
	for _, path := range fs.Args() {
		r, err := readReport(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Fprintf(e.out, "%-24s %5d %5d %5d %8d %10s\n", truncateDisplay(r.Host.Hostname, 24), r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown, r.Profile.Effective)
	}
	return nil
}

func readReport(path string) (model.Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.Report{}, err
	}
	defer file.Close()
	var r model.Report
	err = json.NewDecoder(file).Decode(&r)
	return r, err
}
func findingMap(r model.Report) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range r.Findings {
		out[f.ID] = f
	}
	return out
}
func evidenceFingerprint(f model.Finding) string {
	data, _ := json.Marshal(struct {
		Evidence []model.Evidence
		Facts    map[string]string
	}{f.Evidence, f.Facts})
	return string(data)
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
func choose(zh bool, chinese, english string) string {
	if zh {
		return chinese
	}
	return english
}
func truncateDisplay(value string, n int) string {
	if len(value) <= n {
		return value
	}
	return value[:n-1] + "…"
}
func findCommand(name string) (string, error) { return findExecutable(name) }
