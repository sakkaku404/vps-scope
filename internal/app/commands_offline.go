package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/redact"
	"github.com/sakkaku404/vps-scope/internal/report"
)

func (e environment) doctor(args []string) error {
	fs := e.newFlagSet("doctor")
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("doctor does not accept positional arguments")
	}
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "VPS Scope doctor\nOS=%s ARCH=%s GO=%s\n", runtime.GOOS, runtime.GOARCH, runtime.Version())
	fmt.Fprintf(e.out, "%s=%t\n", choose(locale, "支持完整审计", "full_audit_supported"), runtime.GOOS == "linux")
	if runtime.GOOS == "linux" {
		fmt.Fprintln(e.out, choose(locale, "命令状态: TRUSTED=可安全执行  UNTRUSTED=存在但权限链不可信  MISSING=未找到", "command status: TRUSTED=safe to execute  UNTRUSTED=unsafe ownership or writable path  MISSING=not found"))
	}
	fmt.Fprintln(e.out, choose(locale, "原生工作负载自检: 默认关闭；audit --native-self-test 会在信任检查后以审计进程权限执行本地工作负载代码", "native workload self-test: disabled by default; audit --native-self-test executes local workload code with audit-process privileges after trust checks"))
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
	if fs.NArg() != 0 {
		return errors.New("checks does not accept positional arguments")
	}
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
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
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
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
	load := e.readReport
	if *format == "json" || *format == "bundle" {
		load = e.readReportForRewrite
	}
	r, err := load(fs.Arg(0))
	if err != nil {
		return err
	}
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
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
	r, err := e.readReportForRewrite(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := validateComparableHostIdentity(r); err != nil {
		return err
	}
	r = redact.New().Report(r)
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
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
	r, err := e.readReportForRewrite(input)
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
	// Verification deliberately loads semantic damage so it can enumerate the
	// complete failure set. Every other offline command uses strict readReport.
	r, err := readReportWithOptions(path, reportReadOptions{allowSemanticFailures: true, verifierVersion: e.build.Version})
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
