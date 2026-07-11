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
		fmt.Fprintln(w, "系统修改: 永不执行；仅在明确指定位置写入报告。")
	} else {
		fmt.Fprintf(w, "VPS Scope %s — Evidence-driven server security audit\n%s\n", r.ToolVersion, line)
		fmt.Fprintf(w, "Host: %s  OS: %s %s  Arch: %s\n", r.Host.Hostname, r.Host.OS, r.Host.OSVersion, r.Host.Architecture)
		fmt.Fprintf(w, "Profile: %s (detected: %s)  Root: %t  Log window: %s\n", r.Profile.Effective, r.Profile.Detected, r.Host.IsRoot, r.LogSince)
		fmt.Fprintln(w, "System mutation: never; files are written only to an explicitly selected report path.")
	}
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "RISK %d   PASS %d   INFO %d   UNKNOWN %d\n", r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown)
	if zh {
		fmt.Fprintf(w, "已执行 %d   不可用 %d   不适用 %d\n\n", r.Summary.Completed, r.Summary.Unavailable, r.Summary.NotApplicable)
	} else {
		fmt.Fprintf(w, "Completed %d   Unavailable %d   Not applicable %d\n\n", r.Summary.Completed, r.Summary.Unavailable, r.Summary.NotApplicable)
	}
	writeExposureText(w, r, zh, line)

	if r.Summary.Risk > 0 {
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
			writeEvidence(w, f, "  ", opts.Verbose, 8)
			if zh {
				fmt.Fprintf(w, "  风险: %s\n  建议: %s\n\n", lf.Why, lf.Recommendation)
			} else {
				fmt.Fprintf(w, "  Why: %s\n  Suggestion: %s\n\n", lf.Why, lf.Recommendation)
			}
		}
	}

	if r.Summary.Unknown > 0 {
		if zh {
			fmt.Fprintln(w, "证据不足或未完成")
		} else {
			fmt.Fprintln(w, "Evidence gaps and incomplete checks")
		}
		fmt.Fprintln(w, line)
		for _, f := range sortedFindings(r.Findings, model.Unknown) {
			lf := localize(f, opts.Locale)
			fmt.Fprintf(w, "[%s] %s (%s)\n", colorStatus("UNKNOWN", model.Unknown, opts.Color), lf.Title, f.ID)
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
			if len(f.Evidence) > 0 {
				fmt.Fprintf(w, "**%s**\n\n", choose(zh, "证据", "Evidence"))
				for _, e := range f.Evidence {
					fmt.Fprintf(w, "- `%s`: %s%s\n", escapeMD(e.Source), escapeMD(e.Key), escapeMD(e.Value))
				}
				fmt.Fprintln(w)
			}
			if f.Status == model.Risk || f.Status == model.Unknown {
				fmt.Fprintf(w, "**%s:** %s\n\n", choose(zh, "风险解释", "Why it matters"), escapeMD(lf.Why))
				fmt.Fprintf(w, "**%s:** %s\n\n", choose(zh, "建议", "Suggestion"), escapeMD(lf.Recommendation))
			}
		}
	}
	return nil
}

func networkInventory(r model.Report) (model.Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == "NET-001" {
			return f, true
		}
	}
	return model.Finding{}, false
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
		Locale   string
		ZH       bool
	}
	items := make([]localizedFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		items = append(items, localize(f, opts.Locale))
	}
	t := template.Must(template.New("report").Funcs(template.FuncMap{"cat": func(category string) string { return i18n.Pick(i18n.Categories[category], opts.Locale) }}).Parse(htmlTemplate))
	return t.Execute(w, page{Report: r, Findings: items, Locale: opts.Locale, ZH: opts.Locale == "zh-CN"})
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

func Bundle(dir string, r model.Report, opts Options) (Manifest, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
		if err := atomicWrite(path, files[name]); err != nil {
			return Manifest{}, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return Manifest{}, err
		}
		hash := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, ManifestFile{Name: name, Size: len(data), SHA256: hex.EncodeToString(hash[:])})
	}
	if err := atomicWrite(filepath.Join(dir, "manifest.json"), func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func VerifyBundle(dir string) (Manifest, []string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, nil, err
	}
	var failures []string
	for _, item := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(dir, item.Name))
		if err != nil {
			failures = append(failures, item.Name+": "+err.Error())
			continue
		}
		hash := sha256.Sum256(data)
		if len(data) != item.Size || hex.EncodeToString(hash[:]) != item.SHA256 {
			failures = append(failures, item.Name+": size or SHA-256 mismatch")
		}
	}
	return manifest, failures, nil
}

func atomicWrite(path string, write func(io.Writer) error) error {
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
	if err := write(tmp); err != nil {
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

const htmlTemplate = `<!doctype html><html lang="{{.Locale}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VPS Scope</title><style>
:root{color-scheme:dark;background:#0b1020;color:#e7eaf0;font:15px/1.55 system-ui,sans-serif}body{max-width:1100px;margin:auto;padding:32px}h1{margin-bottom:4px}.meta{color:#9ca7bd}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.card,.finding{background:#131a2c;border:1px solid #27304a;border-radius:12px;padding:16px}.number{font-size:28px;font-weight:700}.RISK{border-left:5px solid #ff5c6c}.PASS{border-left:5px solid #43d17a}.INFO{border-left:5px solid #55a7ff}.UNKNOWN{border-left:5px solid #f0b84b}.sev{color:#ff9ba5}.evidence{font-family:ui-monospace,monospace;background:#0a0f1c;padding:10px;border-radius:8px;overflow-wrap:anywhere}section{margin-top:34px}@media(max-width:700px){.grid{grid-template-columns:repeat(2,1fr)}body{padding:16px}}</style></head><body>
<h1>VPS Scope</h1><div class="meta">{{.Report.Host.Hostname}} · {{.Report.Host.OS}} {{.Report.Host.OSVersion}} · {{.Report.Profile.Effective}} · {{.Report.StartedAt}}</div>
<div class="grid"><div class="card RISK"><div>RISK</div><div class="number">{{.Report.Summary.Risk}}</div></div><div class="card PASS"><div>PASS</div><div class="number">{{.Report.Summary.Pass}}</div></div><div class="card INFO"><div>INFO</div><div class="number">{{.Report.Summary.Info}}</div></div><div class="card UNKNOWN"><div>UNKNOWN</div><div class="number">{{.Report.Summary.Unknown}}</div></div></div>
{{range .Findings}}<section class="finding {{.Status}}"><h2>{{.Status}} · {{.Title}} <small>{{.ID}}</small></h2>{{if .Severity}}<div class="sev">{{.Severity}}</div>{{end}}{{range .Evidence}}<div class="evidence">[{{.Source}}] {{.Key}} {{.Value}}</div>{{end}}{{if eq .Status "RISK"}}<p>{{.Why}}</p><p>{{.Recommendation}}</p>{{end}}{{if .Error}}<p>{{.Error}}</p>{{end}}</section>{{end}}
</body></html>`
