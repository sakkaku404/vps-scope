package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
)

type Options struct {
	Locale  string
	Color   bool
	Verbose bool
}

type localizedFinding struct {
	model.Finding
	Title          string
	Why            string
	Recommendation string
}

func localize(f model.Finding, locale string) localizedFinding {
	rule := i18n.RuleFor(f.ID)
	return localizedFinding{Finding: f, Title: i18n.Pick(rule.Title, locale), Why: i18n.Pick(rule.Why, locale), Recommendation: i18n.Pick(rule.Recommendation, locale)}
}

func JSON(w io.Writer, report model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}

func Text(w io.Writer, r model.Report, opts Options) error {
	zh := opts.Locale == "zh-CN"
	line := strings.Repeat("─", 68)
	if zh {
		fmt.Fprintf(w, "VPS Scope %s — 证据驱动的服务器安全审计\n%s\n", r.ToolVersion, line)
		fmt.Fprintf(w, "主机: %s  系统: %s %s  架构: %s\n", r.Host.Hostname, r.Host.OS, r.Host.OSVersion, r.Host.Architecture)
		fmt.Fprintf(w, "Profile: %s (检测: %s)  Root: %t  日志范围: %s\n", r.Profile.Effective, r.Profile.Detected, r.Host.IsRoot, r.LogSince)
	} else {
		fmt.Fprintf(w, "VPS Scope %s — Evidence-driven server security audit\n%s\n", r.ToolVersion, line)
		fmt.Fprintf(w, "Host: %s  OS: %s %s  Arch: %s\n", r.Host.Hostname, r.Host.OS, r.Host.OSVersion, r.Host.Architecture)
		fmt.Fprintf(w, "Profile: %s (detected: %s)  Root: %t  Log window: %s\n", r.Profile.Effective, r.Profile.Detected, r.Host.IsRoot, r.LogSince)
	}
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "RISK %d   PASS %d   INFO %d   UNKNOWN %d\n", r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown)
	if zh {
		fmt.Fprintf(w, "已执行 %d   不可用 %d   不适用 %d\n\n", r.Summary.Completed, r.Summary.Unavailable, r.Summary.NotApplicable)
	} else {
		fmt.Fprintf(w, "Completed %d   Unavailable %d   Not applicable %d\n\n", r.Summary.Completed, r.Summary.Unavailable, r.Summary.NotApplicable)
	}
	verdict := overallVerdictFor(r, opts.Locale)
	fmt.Fprintf(w, "%s\n  %s\n\n", verdict.Headline, verdict.Detail)
	writeExposureText(w, r, zh, line)
	writeResourceText(w, r, zh, line)
	writeProxyOverviewText(w, r, zh, line)
	writeActionSummaryText(w, summarizeActions(r, opts.Locale), zh, line)

	if r.Summary.Risk > 0 && opts.Verbose {
		if zh {
			fmt.Fprintln(w, "需要优先关注")
		} else {
			fmt.Fprintln(w, "Priority risks")
		}
		fmt.Fprintln(w, line)
		for _, f := range sortedFindings(r.Findings, model.Risk) {
			lf := localize(f, opts.Locale)
			label := string(f.Status) + "/" + strings.ToUpper(string(f.Severity))
			fmt.Fprintf(w, "[%s] %s  (%s)\n", colorStatus(label, f.Status, opts.Color), lf.Title, f.ID)
			if f.ReasonCode != "" {
				fmt.Fprintf(w, "  Reason: %s\n", f.ReasonCode)
			}
			writeEvidence(w, f, "  ", true, 8)
			if zh {
				fmt.Fprintf(w, "  风险: %s\n  建议: %s\n\n", lf.Why, lf.Recommendation)
			} else {
				fmt.Fprintf(w, "  Why: %s\n  Suggestion: %s\n\n", lf.Why, lf.Recommendation)
			}
		}
	}

	if r.Summary.Unknown > 0 && opts.Verbose {
		if zh {
			fmt.Fprintln(w, "证据不足或未完成")
		} else {
			fmt.Fprintln(w, "Evidence gaps and incomplete checks")
		}
		fmt.Fprintln(w, line)
		for _, f := range sortedFindings(r.Findings, model.Unknown) {
			lf := localize(f, opts.Locale)
			fmt.Fprintf(w, "[%s] %s (%s)\n", colorStatus("UNKNOWN", model.Unknown, opts.Color), lf.Title, f.ID)
			if f.ReasonCode != "" {
				fmt.Fprintf(w, "  Reason: %s\n", f.ReasonCode)
			}
			if f.Error != "" {
				fmt.Fprintf(w, "  %s\n", f.Error)
			}
			writeEvidence(w, f, "  ", true, 5)
		}
		fmt.Fprintln(w)
	}

	if zh {
		fmt.Fprintln(w, "全部检查结果")
	} else {
		fmt.Fprintln(w, "All findings")
	}
	for _, category := range audit.CategoryOrder {
		categoryFindings := filterCategory(r.Findings, category)
		if len(categoryFindings) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n[%s]\n", i18n.Pick(i18n.Categories[category], opts.Locale))
		for _, f := range categoryFindings {
			lf := localize(f, opts.Locale)
			severity := ""
			if f.Severity != "" {
				severity = "/" + strings.ToUpper(string(f.Severity))
			}
			rawStatus := fmt.Sprintf("%-13s", string(f.Status)+severity)
			fmt.Fprintf(w, "  %s %s (%s)\n", colorStatus(rawStatus, f.Status, opts.Color), lf.Title, f.ID)
			if opts.Verbose {
				writeEvidence(w, f, "    ", true, 20)
			}
		}
	}
	fmt.Fprintln(w)
	if zh {
		fmt.Fprintf(w, "开始: %s\n结束: %s\n", r.StartedAt.Format(time.RFC3339), r.FinishedAt.Format(time.RFC3339))
	} else {
		fmt.Fprintf(w, "Started: %s\nFinished: %s\n", r.StartedAt.Format(time.RFC3339), r.FinishedAt.Format(time.RFC3339))
	}
	return nil
}

func writeActionSummaryText(w io.Writer, summary actionSummary, zh bool, line string) {
	sections := []struct {
		title string
		items []actionItem
	}{
		{choose(zh, "现在优先处理", "Handle now"), summary.Urgent},
		{choose(zh, "可能影响可用性", "May affect availability"), summary.Availability},
		{choose(zh, "例行维护与复核", "Maintenance and review"), summary.Maintenance},
		{choose(zh, "证据不足，需要人工确认", "Evidence gaps requiring manual confirmation"), summary.EvidenceGaps},
	}
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		fmt.Fprintln(w, section.title)
		fmt.Fprintln(w, line)
		for _, item := range section.items {
			f := item.Localized.Finding
			fmt.Fprintf(w, "[%s/%s] %s  (%s)\n", f.Status, strings.ToUpper(string(f.Severity)), item.Localized.Title, f.ID)
			fmt.Fprintf(w, "  %s\n", item.Verdict)
			for _, evidence := range keyEvidence(f) {
				key := evidence.Key
				if key != "" {
					key += "="
				}
				fmt.Fprintf(w, "  - [%s] %s%s\n", evidence.Source, key, evidence.Value)
			}
			fmt.Fprintf(w, "  %s: %s\n\n", choose(zh, "建议", "Suggestion"), item.Localized.Recommendation)
		}
	}
}

func writeEvidence(w io.Writer, f model.Finding, indent string, include bool, limit int) {
	if !include {
		return
	}
	for i, e := range f.Evidence {
		if i >= limit {
			fmt.Fprintf(w, "%s... %d more evidence items\n", indent, len(f.Evidence)-limit)
			break
		}
		key := e.Key
		if key != "" {
			key += "="
		}
		fmt.Fprintf(w, "%s- [%s] %s%s\n", indent, e.Source, key, e.Value)
	}
}

func Markdown(w io.Writer, r model.Report, opts Options) error {
	zh := opts.Locale == "zh-CN"
	title := "VPS Scope Security Audit"
	if zh {
		title = "VPS Scope 安全审计报告"
	}
	fmt.Fprintf(w, "# %s\n\n", title)
	fmt.Fprintf(w, "| %s | %s |\n|---|---|\n", choose(zh, "字段", "Field"), choose(zh, "值", "Value"))
	rows := [][2]string{{choose(zh, "主机", "Host"), r.Host.Hostname}, {choose(zh, "系统", "OS"), r.Host.OS + " " + r.Host.OSVersion}, {"Profile", r.Profile.Effective}, {choose(zh, "权限", "Privilege"), fmt.Sprintf("root=%t", r.Host.IsRoot)}, {choose(zh, "开始", "Started"), r.StartedAt.Format(time.RFC3339)}}
	for _, row := range rows {
		fmt.Fprintf(w, "| %s | %s |\n", escapeMD(row[0]), escapeMD(row[1]))
	}
	fmt.Fprintf(w, "\n> %s\n\n", choose(zh, "本工具永不修改系统配置；只在明确指定位置写入报告。", "This tool never modifies system configuration; it writes only to an explicitly selected report path."))
	fmt.Fprintf(w, "## %s\n\n", choose(zh, "摘要", "Summary"))
	fmt.Fprintf(w, "| RISK | PASS | INFO | UNKNOWN |\n|---:|---:|---:|---:|\n| %d | %d | %d | %d |\n\n", r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown)
	verdict := overallVerdictFor(r, opts.Locale)
	fmt.Fprintf(w, "**%s**  \n%s\n\n", escapeMD(verdict.Headline), escapeMD(verdict.Detail))
	writeActionSummaryMarkdown(w, summarizeActions(r, opts.Locale), zh)
	writeExposureMarkdown(w, r, zh)
	for _, category := range audit.CategoryOrder {
		items := filterCategory(r.Findings, category)
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", i18n.Pick(i18n.Categories[category], opts.Locale))
		for _, f := range items {
			lf := localize(f, opts.Locale)
			fmt.Fprintf(w, "### `%s` %s — %s\n\n", f.Status, escapeMD(lf.Title), f.ID)
			if f.Severity != "" {
				fmt.Fprintf(w, "**%s:** `%s`\n\n", choose(zh, "优先级", "Severity"), f.Severity)
			}
			if f.ReasonCode != "" {
				fmt.Fprintf(w, "**Reason code:** `%s`\n\n", f.ReasonCode)
			}
			if len(f.Evidence) > 0 {
				fmt.Fprintf(w, "**%s**\n\n", choose(zh, "关键证据", "Key evidence"))
				for _, e := range keyEvidence(f) {
					fmt.Fprintf(w, "- `%s`: %s%s\n", escapeMD(e.Source), escapeMD(e.Key), escapeMD(e.Value))
				}
				fmt.Fprintln(w)
				if len(f.Evidence) > len(keyEvidence(f)) {
					fmt.Fprintf(w, "<details><summary>%s (%d)</summary>\n\n", choose(zh, "全部证据", "All evidence"), len(f.Evidence))
					for _, e := range f.Evidence {
						fmt.Fprintf(w, "- `%s`: %s%s\n", escapeMD(e.Source), escapeMD(e.Key), escapeMD(e.Value))
					}
					fmt.Fprint(w, "\n</details>\n\n")
				}
			}
			if f.Status == model.Risk || f.Status == model.Unknown {
				fmt.Fprintf(w, "**%s:** %s\n\n", choose(zh, "风险解释", "Why it matters"), escapeMD(lf.Why))
				fmt.Fprintf(w, "**%s:** %s\n\n", choose(zh, "建议", "Suggestion"), escapeMD(lf.Recommendation))
			}
		}
	}
	return nil
}

func writeActionSummaryMarkdown(w io.Writer, summary actionSummary, zh bool) {
	sections := []struct {
		title string
		items []actionItem
	}{
		{choose(zh, "现在优先处理", "Handle now"), summary.Urgent},
		{choose(zh, "可能影响可用性", "May affect availability"), summary.Availability},
		{choose(zh, "例行维护与复核", "Maintenance and review"), summary.Maintenance},
		{choose(zh, "证据不足，需要人工确认", "Evidence gaps requiring manual confirmation"), summary.EvidenceGaps},
	}
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", section.title)
		for _, item := range section.items {
			f := item.Localized.Finding
			fmt.Fprintf(w, "- **%s** (`%s`, %s): %s\n", escapeMD(item.Localized.Title), f.ID, strings.ToUpper(string(f.Severity)), escapeMD(item.Verdict))
		}
		fmt.Fprintln(w)
	}
}

func networkInventory(r model.Report) (model.Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == "NET-001" {
			return f, true
		}
	}
	return model.Finding{}, false
}

func findingByID(r model.Report, id string) (model.Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

func writeResourceText(w io.Writer, r model.Report, zh bool, line string) {
	resource, ok := findingByID(r, "SYS-003")
	if !ok {
		return
	}
	fmt.Fprintln(w, choose(zh, "系统资源概览", "System resource overview"))
	fmt.Fprintln(w, line)
	labelsZH := map[string]string{"logical_cpu_cores": "CPU 核心", "model": "CPU 型号", "cpu_used_sample": "CPU 即时占用", "memory": "内存", "swap": "交换分区", "uptime": "运行时间", "load_1m_5m_15m": "负载 1/5/15m", "root_disk": "根分区"}
	labelsEN := map[string]string{"logical_cpu_cores": "CPU cores", "model": "CPU model", "cpu_used_sample": "CPU sample", "memory": "Memory", "swap": "Swap", "uptime": "Uptime", "load_1m_5m_15m": "Load 1/5/15m", "root_disk": "Root disk"}
	for _, key := range []string{"logical_cpu_cores", "model", "cpu_used_sample", "memory", "swap", "uptime", "load_1m_5m_15m", "root_disk"} {
		for _, evidence := range resource.Evidence {
			if evidence.Key == key {
				label := labelsEN[key]
				if zh {
					label = labelsZH[key]
				}
				fmt.Fprintf(w, "  %s: %s\n", label, evidence.Value)
			}
		}
	}
	if connections, ok := findingByID(r, "NET-003"); ok {
		fmt.Fprintf(w, "  %s %s", choose(zh, "活动连接:", "Active connections:"), strconvOrZero(connections.Facts["total"]))
		for _, scope := range []string{"public", "private", "loopback", "unknown"} {
			if count := connections.Facts["peer_"+scope]; count != "" {
				fmt.Fprintf(w, "  %s=%s", scope, count)
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
}

func writeExposureText(w io.Writer, r model.Report, zh bool, line string) {
	f, ok := networkInventory(r)
	if !ok {
		return
	}
	if zh {
		fmt.Fprintln(w, "公网绑定摘要")
	} else {
		fmt.Fprintln(w, "Public binding summary")
	}
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "%s: %s  %s: %s  %s: %s  %s: %s\n",
		choose(zh, "公网/通配", "public/wildcard"), strconvOrZero(f.Facts["public"])+"/"+strconvOrZero(f.Facts["public-wildcard"]),
		choose(zh, "私网", "private"), strconvOrZero(f.Facts["private"]), choose(zh, "回环", "loopback"), strconvOrZero(f.Facts["loopback"]),
		choose(zh, "总计", "total"), strconvOrZero(f.Facts["total"]))
	for _, e := range f.Evidence {
		if strings.Contains(e.Value, "scope=public") {
			fmt.Fprintf(w, "  %s\n", e.Value)
		}
	}
	fmt.Fprintln(w)
}

func writeExposureMarkdown(w io.Writer, r model.Report, zh bool) {
	f, ok := networkInventory(r)
	if !ok {
		return
	}
	fmt.Fprintf(w, "## %s\n\n", choose(zh, "公网绑定摘要", "Public binding summary"))
	fmt.Fprintf(w, "- %s: `%s/%s`\n- %s: `%s`\n- %s: `%s`\n\n", choose(zh, "公网/通配", "Public/wildcard"), strconvOrZero(f.Facts["public"]), strconvOrZero(f.Facts["public-wildcard"]), choose(zh, "私网", "Private"), strconvOrZero(f.Facts["private"]), choose(zh, "回环", "Loopback"), strconvOrZero(f.Facts["loopback"]))
	for _, e := range f.Evidence {
		if strings.Contains(e.Value, "scope=public") {
			fmt.Fprintf(w, "- `%s`\n", escapeMD(e.Value))
		}
	}
	fmt.Fprintln(w)
}

func strconvOrZero(value string) string {
	if value == "" {
		return "0"
	}
	return value
}

func HTML(w io.Writer, r model.Report, opts Options) error {
	type page struct {
		Report   model.Report
		Findings []localizedFinding
		Actions  actionSummary
		Verdict  overallVerdict
		Locale   string
		ZH       bool
	}
	items := make([]localizedFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		items = append(items, localize(f, opts.Locale))
	}
	t := template.Must(template.New("report").Funcs(template.FuncMap{
		"cat": func(category string) string { return i18n.Pick(i18n.Categories[category], opts.Locale) },
		"t":   func(zh, en string) string { return choose(opts.Locale == "zh-CN", zh, en) },
	}).Parse(htmlTemplate))
	return t.Execute(w, page{Report: r, Findings: items, Actions: summarizeActions(r, opts.Locale), Verdict: overallVerdictFor(r, opts.Locale), Locale: opts.Locale, ZH: opts.Locale == "zh-CN"})
}

func filterCategory(findings []model.Finding, category string) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.Category == category {
			out = append(out, f)
		}
	}
	return out
}

func sortedFindings(findings []model.Finding, status model.Status) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if f.Status == status {
			out = append(out, f)
		}
	}
	rank := map[model.Severity]int{model.Critical: 0, model.High: 1, model.Medium: 2, model.Low: 3}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := rank[out[i].Severity], rank[out[j].Severity]
		if ri == rj {
			return out[i].ID < out[j].ID
		}
		return ri < rj
	})
	return out
}

func choose(zh bool, chinese, english string) string {
	if zh {
		return chinese
	}
	return english
}

func colorStatus(text string, status model.Status, enabled bool) string {
	if !enabled {
		return text
	}
	code := map[model.Status]string{model.Pass: "\x1b[32m", model.Risk: "\x1b[31m", model.Info: "\x1b[34m", model.Unknown: "\x1b[33m"}[status]
	if code == "" {
		return text
	}
	return code + text + "\x1b[0m"
}
func escapeMD(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	CreatedAt     time.Time      `json:"created_at"`
	Files         []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

const maxManifestBytes = 1 << 20
const maxBundleFileBytes = 64 << 20

var bundleFileNameRE = regexp.MustCompile(`^report\.[A-Za-z0-9-]+\.(txt|md|html)$`)

func Bundle(dir string, r model.Report, opts Options) (Manifest, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return Manifest{}, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	locale := opts.Locale
	files := map[string]func(io.Writer) error{
		"report.json": func(w io.Writer) error { return JSON(w, r) },
		"report." + locale + ".txt": func(w io.Writer) error {
			local := opts
			local.Verbose = true
			local.Color = false
			return Text(w, r, local)
		},
		"report." + locale + ".md":   func(w io.Writer) error { return Markdown(w, r, opts) },
		"report." + locale + ".html": func(w io.Writer) error { return HTML(w, r, opts) },
	}
	manifest := Manifest{SchemaVersion: "1.0", CreatedAt: time.Now().UTC()}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := atomicWriteLimited(path, maxBundleFileBytes, files[name]); err != nil {
			return Manifest{}, err
		}
		size, digest, err := fileDigest(path, maxBundleFileBytes)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Files = append(manifest.Files, ManifestFile{Name: name, Size: int(size), SHA256: digest})
	}
	if err := atomicWriteLimited(filepath.Join(dir, "manifest.json"), maxManifestBytes, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func VerifyBundle(dir string) (Manifest, []string, error) {
	data, err := readFileLimited(filepath.Join(dir, "manifest.json"), maxManifestBytes)
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, nil, err
	}
	if len(manifest.Files) > 16 {
		return Manifest{}, nil, fmt.Errorf("manifest declares too many files")
	}
	if manifest.SchemaVersion != "1.0" && manifest.SchemaVersion != SupportSchema {
		return Manifest{}, nil, fmt.Errorf("unsupported manifest schema %q", manifest.SchemaVersion)
	}
	var failures []string
	seen := map[string]bool{}
	for _, item := range manifest.Files {
		if !safeBundleFileName(manifest.SchemaVersion, item.Name) {
			failures = append(failures, item.Name+": invalid manifest file name")
			continue
		}
		if seen[item.Name] {
			failures = append(failures, item.Name+": duplicate manifest file name")
			continue
		}
		seen[item.Name] = true
		if item.Size < 0 || item.Size > maxBundleFileBytes {
			failures = append(failures, item.Name+": declared size exceeds safety limit")
			continue
		}
		size, digest, err := fileDigest(filepath.Join(dir, item.Name), int64(item.Size))
		if err != nil {
			failures = append(failures, item.Name+": "+err.Error())
			continue
		}
		if size != int64(item.Size) || digest != item.SHA256 {
			failures = append(failures, item.Name+": size or SHA-256 mismatch")
		}
	}
	return manifest, failures, nil
}

func safeBundleFileName(schema, name string) bool {
	if schema == SupportSchema {
		return name == "report.redacted.json" || name == "compatibility.json" || name == "README.txt"
	}
	if name == "report.json" {
		return true
	}
	return filepath.Base(name) == name && bundleFileNameRE.MatchString(name)
}

func atomicWriteLimited(path string, maxBytes int64, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vps-scope-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := write(&limitedWriter{Writer: tmp, remaining: maxBytes}); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type limitedWriter struct {
	io.Writer
	remaining int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("report exceeds %d byte bundle safety limit", w.remaining+int64(len(p)))
	}
	n, err := w.Writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func fileDigest(path string, maxBytes int64) (int64, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", fmt.Errorf("not a regular file")
	}
	if info.Size() < 0 || info.Size() > maxBytes {
		return 0, "", fmt.Errorf("file exceeds %d byte safety limit", maxBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return 0, "", err
	}
	if n > maxBytes {
		return 0, "", fmt.Errorf("file exceeds %d byte safety limit", maxBytes)
	}
	return n, hex.EncodeToString(hash.Sum(nil)), nil
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxBytes)
	}
	return data, nil
}

const htmlTemplate = `<!doctype html>
<html lang="{{.Locale}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPS Scope · {{.Report.Host.Hostname}}</title><style>
:root{color-scheme:dark;--bg:#090d18;--panel:#111827;--panel2:#0c1322;--line:#263249;--text:#eef2f8;--muted:#9aa7bb;--risk:#ff6675;--pass:#45d483;--info:#63a9ff;--unknown:#f2ba57;--shadow:0 16px 40px rgba(0,0,0,.22);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#16213a 0,transparent 34rem),var(--bg);color:var(--text)}main{max-width:1160px;margin:auto;padding:38px 28px 72px}.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:28px}.eyebrow{color:var(--info);font-size:.76rem;font-weight:800;letter-spacing:.16em;text-transform:uppercase}h1{font-size:clamp(2rem,5vw,3.3rem);line-height:1.05;margin:.35rem 0 .6rem;letter-spacing:-.045em}.subtitle,.muted{color:var(--muted)}.readonly{border:1px solid #365072;background:#111d31;color:#b9d8ff;border-radius:999px;padding:7px 12px;font-size:.8rem;white-space:nowrap}.host-grid,.summary{display:grid;gap:12px}.host-grid{grid-template-columns:repeat(4,1fr);margin:26px 0}.host-item,.card,.finding,.toolbar{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);box-shadow:var(--shadow)}.host-item{border-radius:12px;padding:12px 14px}.host-item span{display:block;color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}.host-item strong{display:block;margin-top:3px;overflow-wrap:anywhere}.summary{grid-template-columns:repeat(4,1fr);margin:14px 0 20px}.card{border-radius:15px;padding:17px 18px;border-top:3px solid var(--accent)}.card .label{font-size:.78rem;font-weight:800;letter-spacing:.12em;color:var(--accent)}.number{font-size:2.25rem;line-height:1.15;font-weight:760;margin-top:4px}.risk{--accent:var(--risk)}.pass{--accent:var(--pass)}.info{--accent:var(--info)}.unknown{--accent:var(--unknown)}
.toolbar{position:sticky;top:10px;z-index:3;display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-radius:14px;padding:10px;margin:22px 0;background:rgba(12,19,34,.9);backdrop-filter:blur(14px)}.filters{display:flex;gap:6px;flex-wrap:wrap}.filter{appearance:none;border:1px solid var(--line);background:#172036;color:var(--muted);border-radius:9px;padding:7px 10px;cursor:pointer;font:inherit;font-size:.82rem}.filter:hover,.filter[aria-pressed="true"]{color:var(--text);border-color:#526582;background:#22304a}.search{min-width:220px;flex:1;border:1px solid var(--line);background:#080d18;color:var(--text);border-radius:9px;padding:8px 11px;font:inherit}.search::placeholder{color:#71809a}
.findings{display:grid;gap:13px}.finding{--accent:var(--info);border-radius:14px;padding:0;border-left:4px solid var(--accent);overflow:hidden}.finding[data-status="RISK"]{--accent:var(--risk)}.finding[data-status="PASS"]{--accent:var(--pass)}.finding[data-status="UNKNOWN"]{--accent:var(--unknown)}.finding[data-na="true"]{opacity:.68}.finding-head{display:grid;grid-template-columns:auto 1fr auto;gap:13px;align-items:start;padding:16px 18px}.pill{color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);border-radius:8px;padding:4px 7px;font-size:.7rem;font-weight:850;letter-spacing:.06em}.finding h2{font-size:1.08rem;line-height:1.35;margin:0}.finding-meta{color:var(--muted);font-size:.78rem;margin-top:4px}.severity{color:var(--risk);font-size:.76rem;font-weight:800;text-transform:uppercase}.finding-body{padding:0 18px 17px 18px}.explain{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:13px}.explain p{margin:0;background:var(--panel2);border-radius:9px;padding:11px 12px}.explain b{display:block;color:var(--muted);font-size:.73rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}details{border-top:1px solid var(--line);margin-top:13px;padding-top:10px}summary{cursor:pointer;color:var(--muted);font-size:.82rem}.evidence-list{display:grid;gap:7px;margin-top:9px}.evidence{font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;background:#080d18;border:1px solid #1e2a3d;padding:9px 10px;border-radius:8px;overflow-wrap:anywhere}.source{color:#85b9ff}.error{color:var(--unknown);background:#2a2112;border-radius:8px;padding:10px 12px}.empty{display:none;text-align:center;color:var(--muted);padding:50px 10px}.footer{color:var(--muted);font-size:.8rem;margin-top:30px;text-align:center}
@media(prefers-color-scheme:light){:root{color-scheme:light;--bg:#f4f7fb;--panel:#fff;--panel2:#f5f7fb;--line:#d8e0eb;--text:#172033;--muted:#617087;--shadow:0 12px 32px rgba(44,62,86,.09)}body{background:radial-gradient(circle at 15% 0,#e4edff 0,transparent 34rem),var(--bg)}.toolbar{background:rgba(255,255,255,.9)}.filter{background:#f5f7fb}.filter:hover,.filter[aria-pressed="true"]{background:#e9eff8}.search,.evidence{background:#f7f9fc}.readonly{background:#eaf2ff;color:#285585}}
@media(max-width:760px){main{padding:24px 14px 50px}.hero{display:block}.readonly{display:inline-block;margin-top:12px}.host-grid,.summary{grid-template-columns:repeat(2,1fr)}.finding-head{grid-template-columns:auto 1fr}.severity{grid-column:2}.explain{grid-template-columns:1fr}.toolbar{top:5px}.search{width:100%;min-width:0}}
@media print{body{background:#fff}.toolbar{display:none}main{max-width:none;padding:0}.finding,.card,.host-item{box-shadow:none;break-inside:avoid}details:not([open])>*:not(summary){display:block}.footer{margin-top:15px}}
</style></head><body><main>
<header class="hero"><div><div class="eyebrow">Evidence-first VPS audit</div><h1>VPS Scope</h1><div class="subtitle">{{t "代理服务器与通用 VPS 安全审计" "Security audit for proxy and general-purpose VPS hosts"}}</div></div><div class="readonly">{{t "只读 · 永不自动修复" "Read-only · never remediates"}}</div></header>
<section class="host-grid" aria-label="host context"><div class="host-item"><span>{{t "主机" "Host"}}</span><strong>{{.Report.Host.Hostname}}</strong></div><div class="host-item"><span>{{t "系统" "System"}}</span><strong>{{.Report.Host.OS}} {{.Report.Host.OSVersion}}</strong></div><div class="host-item"><span>Profile</span><strong>{{.Report.Profile.Effective}}</strong></div><div class="host-item"><span>{{t "完成时间" "Finished"}}</span><strong>{{.Report.FinishedAt.Format "2006-01-02 15:04 UTC"}}</strong></div></section>
<section class="summary" aria-label="summary"><div class="card risk"><div class="label">RISK</div><div class="number">{{.Report.Summary.Risk}}</div></div><div class="card pass"><div class="label">PASS</div><div class="number">{{.Report.Summary.Pass}}</div></div><div class="card info"><div class="label">INFO</div><div class="number">{{.Report.Summary.Info}}</div></div><div class="card unknown"><div class="label">UNKNOWN</div><div class="number">{{.Report.Summary.Unknown}}</div></div></section>
<section class="card"><h2>{{.Verdict.Headline}}</h2><p>{{.Verdict.Detail}}</p><p class="muted">PASS = {{t "证据支持当前判断" "evidence supports the current judgment"}} · INFO = {{t "事实与上下文" "facts and context"}} · UNKNOWN = {{t "证据不足，不代表安全" "insufficient evidence, not safe by default"}}</p></section>
{{if or .Actions.Urgent .Actions.Availability .Actions.Maintenance .Actions.EvidenceGaps}}<section class="card"><h2>Action summary / 处理摘要</h2>{{if .Actions.Urgent}}<h3>Handle now / 优先处理</h3><ul>{{range .Actions.Urgent}}<li>{{.Localized.Title}} ({{.Localized.ID}}) — {{.Verdict}}</li>{{end}}</ul>{{end}}{{if .Actions.Availability}}<h3>May affect availability / 可用性</h3><ul>{{range .Actions.Availability}}<li>{{.Localized.Title}} ({{.Localized.ID}}) — {{.Verdict}}</li>{{end}}</ul>{{end}}{{if .Actions.Maintenance}}<h3>Maintenance and review / 维护复核</h3><ul>{{range .Actions.Maintenance}}<li>{{.Localized.Title}} ({{.Localized.ID}}) — {{.Verdict}}</li>{{end}}</ul>{{end}}{{if .Actions.EvidenceGaps}}<h3>Evidence gaps / 证据不足</h3><ul>{{range .Actions.EvidenceGaps}}<li>{{.Localized.Title}} ({{.Localized.ID}}) — {{.Verdict}}</li>{{end}}</ul>{{end}}</section>{{end}}
<div class="toolbar"><div class="filters" role="group" aria-label="status filters"><button class="filter" data-filter="ALL" aria-pressed="true">{{t "全部" "All"}}</button><button class="filter" data-filter="RISK" aria-pressed="false">RISK</button><button class="filter" data-filter="UNKNOWN" aria-pressed="false">UNKNOWN</button><button class="filter" data-filter="PASS" aria-pressed="false">PASS</button><button class="filter" data-filter="INFO" aria-pressed="false">INFO</button></div><input class="search" type="search" placeholder="{{t "搜索检查、证据或 ID" "Search checks, evidence, or IDs"}}" aria-label="{{t "搜索报告" "Search report"}}"></div>
<section class="findings" aria-label="findings">{{range .Findings}}<article class="finding" data-status="{{.Status}}" data-na="{{.NotApplicable}}"><header class="finding-head"><div class="pill">{{.Status}}</div><div><h2>{{.Title}}</h2><div class="finding-meta">{{.ID}} · {{cat .Category}}{{if .ReasonCode}} · {{.ReasonCode}}{{end}}{{if .NotApplicable}} · {{t "不适用" "Not applicable"}}{{end}}</div></div>{{if .Severity}}<div class="severity">{{.Severity}}</div>{{end}}</header><div class="finding-body">{{if .Error}}<p class="error">{{.Error}}</p>{{end}}{{if or (eq .Status "RISK") (eq .Status "UNKNOWN")}}<div class="explain"><p><b>{{t "风险解释" "Why it matters"}}</b>{{.Why}}</p><p><b>{{t "建议" "Suggestion"}}</b>{{.Recommendation}}</p></div>{{end}}{{if .Evidence}}<details {{if or (eq .Status "RISK") (eq .Status "UNKNOWN")}}open{{end}}><summary>{{t "证据" "Evidence"}} · {{len .Evidence}}</summary><div class="evidence-list">{{range .Evidence}}<div class="evidence"><span class="source">[{{.Source}}]</span> {{if .Key}}{{.Key}}={{end}}{{.Value}}</div>{{end}}</div></details>{{end}}</div></article>{{end}}</section>
<div class="empty">{{t "没有符合当前筛选条件的结果。" "No findings match the current filters."}}</div><footer class="footer">VPS Scope {{.Report.ToolVersion}} · schema {{.Report.SchemaVersion}} · {{t "报告保存在本地" "Report remains local"}}</footer>
</main><script>
(()=>{const buttons=[...document.querySelectorAll('[data-filter]')],items=[...document.querySelectorAll('.finding')],input=document.querySelector('.search'),empty=document.querySelector('.empty');let filter='ALL';const apply=()=>{const q=input.value.trim().toLowerCase();let shown=0;for(const item of items){const visible=(filter==='ALL'||item.dataset.status===filter)&&(!q||item.textContent.toLowerCase().includes(q));item.hidden=!visible;if(visible)shown++}empty.style.display=shown?'none':'block'};for(const button of buttons)button.addEventListener('click',()=>{filter=button.dataset.filter;for(const other of buttons)other.setAttribute('aria-pressed',String(other===button));apply()});input.addEventListener('input',apply)})();
</script></body></html>`
