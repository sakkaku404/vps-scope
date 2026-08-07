package report

import (
	"bytes"
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

	"github.com/sakkaku404/vps-scope/internal/contract"
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
	rule := i18n.RuleForLocale(f.ID, locale)
	return localizedFinding{Finding: f, Title: i18n.Pick(rule.Title, locale), Why: i18n.Pick(rule.Why, locale), Recommendation: i18n.Pick(rule.Recommendation, locale)}
}

func JSON(w io.Writer, report model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}

func Text(w io.Writer, r model.Report, opts Options) error {
	locale := opts.Locale
	line := strings.Repeat("─", 68)
	fmt.Fprintf(w, "VPS Scope %s — %s\n%s\n", r.ToolVersion, choose(locale, "代理 VPS 安全与运行状态审计", "Proxy VPS security and runtime audit"), line)
	fmt.Fprintf(w, "%s: %s  %s: %s %s  %s: %s\n", choose(locale, "主机", "Host"), r.Host.Hostname, choose(locale, "系统", "OS"), r.Host.OS, r.Host.OSVersion, choose(locale, "架构", "Arch"), r.Host.Architecture)
	fmt.Fprintf(w, "Profile: %s (%s: %s)  Root: %t  %s: %s\n", r.Profile.Effective, choose(locale, "检测", "detected"), r.Profile.Detected, r.Host.IsRoot, choose(locale, "日志范围", "Log window"), r.LogSince)
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "RISK %d   PASS %d   INFO %d   UNKNOWN %d\n", r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown)
	fmt.Fprintf(w, "%s %d   %s %d   %s %d\n\n", choose(locale, "已执行", "Completed"), r.Summary.Completed, choose(locale, "不可用", "Unavailable"), r.Summary.Unavailable, choose(locale, "不适用", "Not applicable"), r.Summary.NotApplicable)
	assessment := collectProxyAssessment(r, locale)
	writeProxyAssessmentText(w, assessment, locale, line)
	verdict := overallVerdictFor(r, opts.Locale)
	fmt.Fprintf(w, "%s\n  %s\n\n", verdict.Headline, verdict.Detail)
	writeActionSummaryText(w, summarizeActions(r, opts.Locale), locale, line)
	writeProxyOverviewText(w, r, locale, line)

	if opts.Verbose {
		fmt.Fprintln(w, choose(locale, "全部技术检查与证据", "All technical checks and evidence"))
		fmt.Fprintln(w, choose(locale, "  以下是审计底稿；普通使用者通常只需阅读上面的结论和处理摘要。", "  This is the audit record; most users only need the assessment and action summary above."))
	} else {
		fmt.Fprintln(w, choose(locale, "检查结果索引", "Finding index"))
		fmt.Fprintln(w, choose(locale, "  以下仅列出每项状态；完整证据请打开报告包中的 HTML、Markdown 或 JSON。", "  Status index only; open the HTML, Markdown, or JSON report for complete evidence."))
	}
	for _, category := range contract.Categories() {
		categoryFindings := filterCategory(r.Findings, category)
		if len(categoryFindings) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n[%s]\n", i18n.Category(category, opts.Locale))
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
	fmt.Fprintf(w, "%s: %s\n%s: %s\n", choose(locale, "开始", "Started"), r.StartedAt.Format(time.RFC3339), choose(locale, "结束", "Finished"), r.FinishedAt.Format(time.RFC3339))
	return nil
}

func writeActionSummaryText(w io.Writer, summary actionSummary, locale string, line string) {
	sections := []struct {
		title string
		items []actionItem
	}{
		{choose(locale, "现在优先处理", "Handle now"), summary.Urgent},
		{choose(locale, "可能影响可用性", "May affect availability"), summary.Availability},
		{choose(locale, "例行维护与复核", "Maintenance and review"), summary.Maintenance},
		{choose(locale, "证据不足，需要人工确认", "Evidence gaps requiring manual confirmation"), summary.EvidenceGaps},
	}
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		fmt.Fprintln(w, section.title)
		fmt.Fprintln(w, line)
		for _, item := range section.items {
			f := item.Localized.Finding
			fmt.Fprintf(w, "[%s] %s  (%s)\n", assessmentFindingLabel(f), item.Localized.Title, f.ID)
			fmt.Fprintf(w, "  %s\n", item.Verdict)
			for _, evidence := range keyEvidence(f) {
				fmt.Fprintf(w, "  - [%s] %s\n", evidence.Source, formattedEvidence(evidence))
			}
			fmt.Fprintf(w, "  %s: %s\n\n", choose(locale, "建议", "Suggestion"), item.Localized.Recommendation)
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
		fmt.Fprintf(w, "%s- [%s] %s\n", indent, e.Source, formattedEvidence(e))
	}
}

func Markdown(w io.Writer, r model.Report, opts Options) error {
	locale := opts.Locale
	title := "VPS Scope " + choose(locale, "代理 VPS 安全与运行状态报告", "Proxy VPS Security and Runtime Report")
	fmt.Fprintf(w, "# %s\n\n", title)
	fmt.Fprintf(w, "| %s | %s |\n|---|---|\n", choose(locale, "字段", "Field"), choose(locale, "值", "Value"))
	rows := [][2]string{{choose(locale, "主机", "Host"), r.Host.Hostname}, {choose(locale, "系统", "OS"), r.Host.OS + " " + r.Host.OSVersion}, {"Profile", r.Profile.Effective}, {choose(locale, "权限", "Privilege"), fmt.Sprintf("root=%t", r.Host.IsRoot)}, {choose(locale, "开始", "Started"), r.StartedAt.Format(time.RFC3339)}}
	for _, row := range rows {
		fmt.Fprintf(w, "| %s | %s |\n", escapeMD(row[0]), escapeMD(row[1]))
	}
	fmt.Fprintf(w, "## %s\n\n", choose(locale, "摘要", "Summary"))
	fmt.Fprintf(w, "| RISK | PASS | INFO | UNKNOWN |\n|---:|---:|---:|---:|\n| %d | %d | %d | %d |\n\n", r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown)
	assessment := collectProxyAssessment(r, locale)
	writeProxyAssessmentMarkdown(w, assessment, locale)
	verdict := overallVerdictFor(r, opts.Locale)
	fmt.Fprintf(w, "**%s**  \n%s\n\n", escapeMD(verdict.Headline), escapeMD(verdict.Detail))
	writeActionSummaryMarkdown(w, summarizeActions(r, opts.Locale), locale)
	writeProxyOverviewMarkdown(w, r, locale)
	fmt.Fprintf(w, "## %s\n\n%s\n\n", choose(locale, "全部技术检查与证据", "All technical checks and evidence"), choose(locale, "以下是审计底稿；普通使用者通常只需阅读上面的结论和处理摘要。", "This is the audit record; most users only need the assessment and action summary above."))
	for _, category := range contract.Categories() {
		items := filterCategory(r.Findings, category)
		if len(items) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", i18n.Category(category, opts.Locale))
		for _, f := range items {
			lf := localize(f, opts.Locale)
			fmt.Fprintf(w, "<a id=\"%s\"></a>\n\n", findingAnchor(f.ID))
			fmt.Fprintf(w, "### `%s` %s — %s\n\n", f.Status, escapeMD(lf.Title), f.ID)
			if f.Severity != "" {
				fmt.Fprintf(w, "**%s:** `%s`\n\n", choose(locale, "优先级", "Severity"), f.Severity)
			}
			if f.ReasonCode != "" {
				fmt.Fprintf(w, "**Reason code:** `%s`\n\n", f.ReasonCode)
			}
			if len(f.Evidence) > 0 {
				fmt.Fprintf(w, "**%s**\n\n", choose(locale, "关键证据", "Key evidence"))
				for _, e := range keyEvidence(f) {
					fmt.Fprintf(w, "- `%s`: %s\n", escapeMD(e.Source), escapeMD(markdownEvidence(e)))
				}
				fmt.Fprintln(w)
				if len(f.Evidence) > len(keyEvidence(f)) {
					fmt.Fprintf(w, "<details><summary>%s (%d)</summary>\n\n", choose(locale, "全部证据", "All evidence"), len(f.Evidence))
					for _, e := range f.Evidence {
						fmt.Fprintf(w, "- `%s`: %s\n", escapeMD(e.Source), escapeMD(markdownEvidence(e)))
					}
					fmt.Fprint(w, "\n</details>\n\n")
				}
			}
			if f.Status == model.Risk || f.Status == model.Unknown {
				fmt.Fprintf(w, "**%s:** %s\n\n", choose(locale, "风险解释", "Why it matters"), escapeMD(lf.Why))
				fmt.Fprintf(w, "**%s:** %s\n\n", choose(locale, "建议", "Suggestion"), escapeMD(lf.Recommendation))
			}
		}
	}
	return nil
}

func writeActionSummaryMarkdown(w io.Writer, summary actionSummary, locale string) {
	sections := []struct {
		title string
		items []actionItem
	}{
		{choose(locale, "现在优先处理", "Handle now"), summary.Urgent},
		{choose(locale, "可能影响可用性", "May affect availability"), summary.Availability},
		{choose(locale, "例行维护与复核", "Maintenance and review"), summary.Maintenance},
		{choose(locale, "证据不足，需要人工确认", "Evidence gaps requiring manual confirmation"), summary.EvidenceGaps},
	}
	for _, section := range sections {
		if len(section.items) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", section.title)
		for _, item := range section.items {
			f := item.Localized.Finding
			fmt.Fprintf(w, "- [**%s** (`%s`)](#%s) (`%s`): %s\n", escapeMDLinkText(item.Localized.Title), escapeMDCode(f.ID), findingAnchor(f.ID), assessmentFindingLabel(f), escapeMD(item.Verdict))
		}
		fmt.Fprintln(w)
	}
}

func findingByID(r model.Report, id string) (model.Finding, bool) {
	for _, f := range r.Findings {
		if f.ID == id {
			return f, true
		}
	}
	return model.Finding{}, false
}

func HTML(w io.Writer, r model.Report, opts Options) error {
	type page struct {
		Report        model.Report
		Findings      []localizedFinding
		Actions       actionSummary
		Verdict       overallVerdict
		Assessment    proxyAssessment
		ProxyOverview proxyOverview
		Locale        string
		RTL           bool
	}
	items := make([]localizedFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		items = append(items, localize(f, opts.Locale))
	}
	t := template.Must(template.New("report").Funcs(template.FuncMap{
		"anchor":   findingAnchor,
		"cat":      func(category string) string { return i18n.Category(category, opts.Locale) },
		"evidence": formattedEvidence,
		"t":        func(zh, en string) string { return choose(opts.Locale, zh, en) },
	}).Parse(htmlTemplate))
	return t.Execute(w, page{Report: r, Findings: items, Actions: summarizeActions(r, opts.Locale), Verdict: overallVerdictFor(r, opts.Locale), Assessment: collectProxyAssessment(r, opts.Locale), ProxyOverview: collectProxyOverview(r, opts.Locale), Locale: opts.Locale, RTL: i18n.RTL(opts.Locale)})
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

func choose(locale, chinese, english string) string {
	return i18n.UI(locale, chinese, english)
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

func escapeMDLinkText(s string) string {
	s = strings.NewReplacer("\\", "\\\\", "[", "\\[", "]", "\\]").Replace(s)
	return escapeMD(s)
}

func escapeMDCode(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "`", "\\`"), "\n", " ")
}

// findingAnchor keeps contract IDs readable (for example, finding-FW-001)
// while encoding every other byte so untrusted input cannot break an HTML
// attribute or a Markdown fragment link. The encoding is deterministic, and
// '_' is encoded too so encoded and literal input cannot collide.
func findingAnchor(id string) string {
	const hexDigits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(len("finding-") + len(id))
	b.WriteString("finding-")
	for i := 0; i < len(id); i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('_')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&0x0f])
	}
	return b.String()
}

func markdownEvidence(e model.Evidence) string {
	return formattedEvidence(e)
}

func formattedEvidence(e model.Evidence) string {
	if e.Key == "" {
		return e.Value
	}
	prefix := e.Key + "="
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(e.Value)), strings.ToLower(prefix)) {
		return e.Value
	}
	return prefix + e.Value
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
const maxBundleDirectoryEntries = 17 // manifest plus the maximum 16 declared files

var bundleFileNameRE = regexp.MustCompile(`^report\.([A-Za-z0-9-]+)\.(txt|md|html)$`)

func Bundle(dir string, r model.Report, opts Options) (Manifest, error) {
	locale := opts.Locale
	if !i18n.Supported(locale) {
		return Manifest{}, fmt.Errorf("unsupported report bundle locale %q", locale)
	}
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
	return writeBundleFiles(dir, "1.0", files)
}

func writeBundleFiles(dir, schema string, files map[string]func(io.Writer) error) (manifest Manifest, err error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return Manifest{}, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()
	manifest = Manifest{SchemaVersion: schema, CreatedAt: time.Now().UTC()}
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
	complete = true
	return manifest, nil
}

func VerifyBundle(dir string) (Manifest, []string, error) {
	data, err := readFileLimited(filepath.Join(dir, "manifest.json"), maxManifestBytes)
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, nil, fmt.Errorf("manifest contains more than one JSON value")
		}
		return Manifest{}, nil, fmt.Errorf("manifest trailing data: %w", err)
	}
	if len(manifest.Files) > 16 {
		return Manifest{}, nil, fmt.Errorf("manifest declares too many files")
	}
	if manifest.SchemaVersion != "1.0" && manifest.SchemaVersion != SupportSchema {
		return Manifest{}, nil, fmt.Errorf("unsupported manifest schema %q", manifest.SchemaVersion)
	}
	failures := manifestCompletenessFailures(manifest)
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
	entries, tooManyEntries, err := readDirectoryEntriesLimited(dir, maxBundleDirectoryEntries)
	if err != nil {
		return Manifest{}, nil, err
	}
	if tooManyEntries {
		failures = append(failures, fmt.Sprintf("bundle directory exceeds the %d entry safety limit", maxBundleDirectoryEntries))
		return manifest, failures, nil
	}
	declared := map[string]bool{"manifest.json": true}
	for _, item := range manifest.Files {
		declared[item.Name] = true
	}
	for _, entry := range entries {
		if !declared[entry.Name()] {
			failures = append(failures, entry.Name()+": file is not declared in manifest")
		}
	}
	return manifest, failures, nil
}

func readDirectoryEntriesLimited(dir string, maxEntries int) ([]os.DirEntry, bool, error) {
	if maxEntries < 0 {
		return nil, false, fmt.Errorf("invalid directory entry limit")
	}
	// #nosec G304 -- dir is the explicitly requested bundle directory; only a
	// bounded directory listing is performed.
	f, err := os.Open(dir)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("bundle path is not a directory")
	}
	entries, err := f.ReadDir(maxEntries + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	return entries, len(entries) > maxEntries, nil
}

func manifestCompletenessFailures(manifest Manifest) []string {
	if manifest.SchemaVersion == SupportSchema {
		required := map[string]bool{"report.redacted.json": false, "compatibility.json": false, "README.txt": false}
		for _, item := range manifest.Files {
			if _, ok := required[item.Name]; ok {
				required[item.Name] = true
			}
		}
		var failures []string
		for _, name := range []string{"README.txt", "compatibility.json", "report.redacted.json"} {
			if !required[name] {
				failures = append(failures, name+": required support-bundle file is missing from manifest")
			}
		}
		if len(manifest.Files) != 3 {
			failures = append(failures, fmt.Sprintf("manifest declares %d files; a support bundle requires exactly 3", len(manifest.Files)))
		}
		return failures
	}

	var failures []string
	hasJSON := false
	locales := map[string]map[string]bool{}
	for _, item := range manifest.Files {
		if item.Name == "report.json" {
			hasJSON = true
			continue
		}
		match := bundleFileNameRE.FindStringSubmatch(item.Name)
		if len(match) != 3 {
			continue
		}
		if locales[match[1]] == nil {
			locales[match[1]] = map[string]bool{}
		}
		locales[match[1]][match[2]] = true
	}
	if !hasJSON {
		failures = append(failures, "report.json: required report file is missing from manifest")
	}
	completeLocales := 0
	for _, extensions := range locales {
		if extensions["txt"] && extensions["md"] && extensions["html"] {
			completeLocales++
		}
	}
	if completeLocales == 0 {
		failures = append(failures, "localized report set is incomplete; expected matching txt, md, and html files")
	} else if completeLocales > 1 {
		failures = append(failures, "manifest contains more than one complete report locale")
	}
	if len(manifest.Files) != 4 {
		failures = append(failures, fmt.Sprintf("manifest declares %d files; a report bundle requires exactly 4", len(manifest.Files)))
	}
	return failures
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
		_ = tmp.Close()
		return err
	}
	if err := write(&limitedWriter{Writer: tmp, limit: maxBytes, remaining: maxBytes}); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type limitedWriter struct {
	io.Writer
	limit     int64
	remaining int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("report exceeds %d byte bundle safety limit", w.limit)
	}
	n, err := w.Writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func fileDigest(path string, maxBytes int64) (int64, string, error) {
	f, size, err := openRegularLimited(path, maxBytes)
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
	if n != size {
		return 0, "", fmt.Errorf("file size changed during verification")
	}
	return n, hex.EncodeToString(hash.Sum(nil)), nil
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	f, size, err := openRegularLimited(path, maxBytes)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxBytes)
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("manifest size changed during verification")
	}
	return data, nil
}

// openRegularLimited verifies the path both before and after opening it. The
// SameFile check prevents a symlink or inode swap between Lstat and Open from
// turning bundle verification into an unintended file reader.
func openRegularLimited(path string, maxBytes int64) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file")
	}
	if before.Size() < 0 || before.Size() > maxBytes {
		return nil, 0, fmt.Errorf("file exceeds %d byte safety limit", maxBytes)
	}
	// #nosec G304 -- manifest-controlled names are allowlisted before this
	// call; Lstat, size, regular-file and SameFile checks prevent path swaps.
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		_ = f.Close()
		return nil, 0, fmt.Errorf("file changed during verification")
	}
	return f, after.Size(), nil
}

const htmlTemplate = `<!doctype html>
<html lang="{{.Locale}}" dir="{{if .RTL}}rtl{{else}}ltr{{end}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPS Scope · {{.Report.Host.Hostname}}</title><style>
:root{color-scheme:dark;--bg:#090d18;--panel:#111827;--panel2:#0c1322;--line:#263249;--text:#eef2f8;--muted:#9aa7bb;--risk:#ff6675;--pass:#45d483;--info:#63a9ff;--unknown:#f2ba57;--shadow:0 16px 40px rgba(0,0,0,.22);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#16213a 0,transparent 34rem),var(--bg);color:var(--text)}main{max-width:1160px;margin:auto;padding:38px 28px 72px}.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:28px}.eyebrow{color:var(--info);font-size:.76rem;font-weight:800;letter-spacing:.16em;text-transform:uppercase}h1{font-size:clamp(2rem,5vw,3.3rem);line-height:1.05;margin:.35rem 0 .6rem;letter-spacing:-.045em}.subtitle,.muted{color:var(--muted)}.readonly{border:1px solid #365072;background:#111d31;color:#b9d8ff;border-radius:999px;padding:7px 12px;font-size:.8rem;white-space:nowrap}.host-grid,.summary{display:grid;gap:12px}.host-grid{grid-template-columns:repeat(4,1fr);margin:26px 0}.host-item,.card,.finding,.toolbar{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);box-shadow:var(--shadow)}.host-item{border-radius:12px;padding:12px 14px}.host-item span{display:block;color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.06em}.host-item strong{display:block;margin-top:3px;overflow-wrap:anywhere}.summary{grid-template-columns:repeat(4,1fr);margin:14px 0 20px}.card{border-radius:15px;padding:17px 18px;border-top:3px solid var(--accent)}.card .label{font-size:.78rem;font-weight:800;letter-spacing:.12em;color:var(--accent)}.number{font-size:2.25rem;line-height:1.15;font-weight:760;margin-top:4px}.risk{--accent:var(--risk)}.pass{--accent:var(--pass)}.info{--accent:var(--info)}.unknown{--accent:var(--unknown)}
.assessment{display:grid;gap:9px}.assessment-line{display:grid;grid-template-columns:9rem 7rem 1fr;gap:12px;align-items:start;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:11px 12px}.assessment-status{font-size:.76rem;font-weight:850;letter-spacing:.04em}.assessment-line[data-status^="RISK"] .assessment-status{color:var(--risk)}.assessment-line[data-status^="PASS"] .assessment-status{color:var(--pass)}.assessment-line[data-status^="UNKNOWN"] .assessment-status{color:var(--unknown)}.assessment-line[data-status^="INFO"] .assessment-status{color:var(--info)}
.toolbar{position:sticky;top:10px;z-index:3;display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-radius:14px;padding:10px;margin:22px 0;background:rgba(12,19,34,.9);backdrop-filter:blur(14px)}.filters{display:flex;gap:6px;flex-wrap:wrap}.filter{appearance:none;border:1px solid var(--line);background:#172036;color:var(--muted);border-radius:9px;padding:7px 10px;cursor:pointer;font:inherit;font-size:.82rem}.filter:hover,.filter[aria-pressed="true"]{color:var(--text);border-color:#526582;background:#22304a}.search{min-width:220px;flex:1;border:1px solid var(--line);background:#080d18;color:var(--text);border-radius:9px;padding:8px 11px;font:inherit}.search::placeholder{color:#71809a}
.action-link{color:inherit;text-decoration-color:color-mix(in srgb,var(--info) 62%,transparent);text-decoration-thickness:.09em;text-underline-offset:.16em}.action-link:hover,.action-link:focus-visible{color:var(--info);text-decoration-color:currentColor}.action-link:focus-visible{outline:2px solid var(--info);outline-offset:3px;border-radius:3px}.action-id{direction:ltr;unicode-bidi:embed;white-space:nowrap}.findings{display:grid;gap:13px}.finding{--accent:var(--info);border-radius:14px;padding:0;border-inline-start:4px solid var(--accent);overflow:hidden;scroll-margin-top:6.5rem}.finding[data-status="RISK"]{--accent:var(--risk)}.finding[data-status="PASS"]{--accent:var(--pass)}.finding[data-status="UNKNOWN"]{--accent:var(--unknown)}.finding[data-na="true"]{opacity:.68}.finding-head{display:grid;grid-template-columns:auto 1fr auto;gap:13px;align-items:start;padding:16px 18px}.pill{color:var(--accent);background:color-mix(in srgb,var(--accent) 12%,transparent);border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);border-radius:8px;padding:4px 7px;font-size:.7rem;font-weight:850;letter-spacing:.06em}.finding h2{font-size:1.08rem;line-height:1.35;margin:0}.finding-meta{color:var(--muted);font-size:.78rem;margin-top:4px;direction:ltr;unicode-bidi:embed}.severity{color:var(--risk);font-size:.76rem;font-weight:800;text-transform:uppercase}.finding-body{padding:0 18px 17px 18px}.explain{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:13px}.explain p{margin:0;background:var(--panel2);border-radius:9px;padding:11px 12px}.explain b{display:block;color:var(--muted);font-size:.73rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px}details{border-top:1px solid var(--line);margin-top:13px;padding-top:10px}summary{cursor:pointer;color:var(--muted);font-size:.82rem}.evidence-list{display:grid;gap:7px;margin-top:9px}.evidence{direction:ltr;text-align:left;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;background:#080d18;border:1px solid #1e2a3d;padding:9px 10px;border-radius:8px;overflow-wrap:anywhere}.source{color:#85b9ff}.error{color:var(--unknown);background:#2a2112;border-radius:8px;padding:10px 12px}.empty{display:none;text-align:center;color:var(--muted);padding:50px 10px}.footer{color:var(--muted);font-size:.8rem;margin-top:30px;text-align:center}
@media(prefers-color-scheme:light){:root{color-scheme:light;--bg:#f4f7fb;--panel:#fff;--panel2:#f5f7fb;--line:#d8e0eb;--text:#172033;--muted:#617087;--shadow:0 12px 32px rgba(44,62,86,.09)}body{background:radial-gradient(circle at 15% 0,#e4edff 0,transparent 34rem),var(--bg)}.toolbar{background:rgba(255,255,255,.9)}.filter{background:#f5f7fb}.filter:hover,.filter[aria-pressed="true"]{background:#e9eff8}.search,.evidence{background:#f7f9fc}.readonly{background:#eaf2ff;color:#285585}}
@media(max-width:760px){main{padding:24px 14px 50px}.hero{display:block}.readonly{display:inline-block;margin-top:12px}.host-grid,.summary{grid-template-columns:repeat(2,1fr)}.assessment-line{grid-template-columns:1fr auto}.assessment-line span:last-child{grid-column:1/-1}.finding-head{grid-template-columns:auto 1fr}.severity{grid-column:2}.explain{grid-template-columns:1fr}.toolbar{top:5px}.search{width:100%;min-width:0}}
@media print{body{background:#fff}.toolbar{display:none}main{max-width:none;padding:0}.action-link{color:inherit;text-decoration:none}.finding{scroll-margin-top:0}.finding,.card,.host-item{box-shadow:none;break-inside:avoid}details:not([open])>*:not(summary){display:block}.footer{margin-top:15px}}
</style></head><body><main>
<header class="hero"><div><div class="eyebrow">Proxy VPS security audit</div><h1>VPS Scope</h1><div class="subtitle">{{t "自建代理、隧道和隐私网络 VPS 的安全与运行状态报告" "Security and runtime report for self-hosted proxy, tunnel, and privacy-network VPS hosts"}}</div></div></header>
<section class="host-grid" aria-label="host context"><div class="host-item"><span>{{t "主机" "Host"}}</span><strong>{{.Report.Host.Hostname}}</strong></div><div class="host-item"><span>{{t "系统" "System"}}</span><strong>{{.Report.Host.OS}} {{.Report.Host.OSVersion}}</strong></div><div class="host-item"><span>Profile</span><strong>{{.Report.Profile.Effective}}</strong></div><div class="host-item"><span>{{t "完成时间" "Finished"}}</span><strong>{{.Report.FinishedAt.Format "2006-01-02 15:04 UTC"}}</strong></div></section>
<section class="summary" aria-label="summary"><div class="card risk"><div class="label">RISK</div><div class="number">{{.Report.Summary.Risk}}</div></div><div class="card pass"><div class="label">PASS</div><div class="number">{{.Report.Summary.Pass}}</div></div><div class="card info"><div class="label">INFO</div><div class="number">{{.Report.Summary.Info}}</div></div><div class="card unknown"><div class="label">UNKNOWN</div><div class="number">{{.Report.Summary.Unknown}}</div></div></section>
{{if .Assessment.HasContent}}<section class="card"><h2>{{t "代理 VPS 结论" "Proxy VPS assessment"}}</h2>{{if .Assessment.Components}}<p><b>{{t "识别到" "Detected"}}:</b> {{range $index, $component := .Assessment.Components}}{{if $index}}, {{end}}{{$component}}{{end}}</p>{{end}}<div class="assessment">{{range .Assessment.Lines}}<div class="assessment-line" data-status="{{.Status}}"><strong>{{.Label}}</strong><span class="assessment-status">{{.Status}}</span><span>{{.Message}}</span></div>{{end}}</div></section>{{end}}
<section class="card"><h2>{{.Verdict.Headline}}</h2><p>{{.Verdict.Detail}}</p><p class="muted">PASS = {{t "证据支持当前判断" "evidence supports the current judgment"}} · INFO = {{t "事实与上下文" "facts and context"}} · UNKNOWN = {{t "证据不足，不代表安全" "insufficient evidence, not safe by default"}}</p></section>
{{if or .Actions.Urgent .Actions.Availability .Actions.Maintenance .Actions.EvidenceGaps}}<section class="card"><h2>{{t "处理摘要" "Action summary"}}</h2>{{if .Actions.Urgent}}<h3>{{t "现在优先处理" "Handle now"}}</h3><ul>{{range .Actions.Urgent}}<li><a class="action-link" href="#{{anchor .Localized.ID}}"><strong>{{.Localized.Title}}</strong> <span class="action-id">({{.Localized.ID}})</span></a> — {{.Verdict}}</li>{{end}}</ul>{{end}}{{if .Actions.Availability}}<h3>{{t "可能影响可用性" "May affect availability"}}</h3><ul>{{range .Actions.Availability}}<li><a class="action-link" href="#{{anchor .Localized.ID}}"><strong>{{.Localized.Title}}</strong> <span class="action-id">({{.Localized.ID}})</span></a> — {{.Verdict}}</li>{{end}}</ul>{{end}}{{if .Actions.Maintenance}}<h3>{{t "例行维护与复核" "Maintenance and review"}}</h3><ul>{{range .Actions.Maintenance}}<li><a class="action-link" href="#{{anchor .Localized.ID}}"><strong>{{.Localized.Title}}</strong> <span class="action-id">({{.Localized.ID}})</span></a> — {{.Verdict}}</li>{{end}}</ul>{{end}}{{if .Actions.EvidenceGaps}}<h3>{{t "证据不足，需要人工确认" "Evidence gaps requiring confirmation"}}</h3><ul>{{range .Actions.EvidenceGaps}}<li><a class="action-link" href="#{{anchor .Localized.ID}}"><strong>{{.Localized.Title}}</strong> <span class="action-id">({{.Localized.ID}})</span></a> — {{.Verdict}}</li>{{end}}</ul>{{end}}</section>{{end}}
{{if .ProxyOverview.HasContent}}<section class="card"><h2>{{t "代理部署明细" "Proxy deployment details"}}</h2>{{if .ProxyOverview.Components}}<p><b>{{t "已识别组件" "Detected components"}}:</b> {{range $index, $component := .ProxyOverview.Components}}{{if $index}}, {{end}}{{$component}}{{end}}</p>{{end}}{{range .ProxyOverview.Groups}}<h3>{{.Title}}</h3><ul>{{range .Lines}}<li>{{.}}</li>{{end}}</ul>{{end}}</section>{{end}}
<section><h2>{{t "全部技术检查与证据" "All technical checks and evidence"}}</h2><p class="muted">{{t "以下是审计底稿；普通使用者通常只需阅读上面的结论和处理摘要。" "This is the audit record; most users only need the assessment and action summary above."}}</p></section>
<div class="toolbar"><div class="filters" role="group" aria-label="status filters"><button class="filter" data-filter="ALL" aria-pressed="true">{{t "全部" "All"}}</button><button class="filter" data-filter="RISK" aria-pressed="false">RISK</button><button class="filter" data-filter="UNKNOWN" aria-pressed="false">UNKNOWN</button><button class="filter" data-filter="PASS" aria-pressed="false">PASS</button><button class="filter" data-filter="INFO" aria-pressed="false">INFO</button></div><input class="search" type="search" placeholder="{{t "搜索检查、证据或 ID" "Search checks, evidence, or IDs"}}" aria-label="{{t "搜索报告" "Search report"}}"></div>
<section class="findings" aria-label="findings">{{range .Findings}}<article class="finding" id="{{anchor .ID}}" data-status="{{.Status}}" data-na="{{.NotApplicable}}"><header class="finding-head"><div class="pill">{{.Status}}</div><div><h2>{{.Title}}</h2><div class="finding-meta">{{.ID}} · {{cat .Category}}{{if .ReasonCode}} · {{.ReasonCode}}{{end}}{{if .NotApplicable}} · {{t "不适用" "Not applicable"}}{{end}}</div></div>{{if .Severity}}<div class="severity">{{.Severity}}</div>{{end}}</header><div class="finding-body">{{if .Error}}<p class="error">{{.Error}}</p>{{end}}{{if or (eq .Status "RISK") (eq .Status "UNKNOWN")}}<div class="explain"><p><b>{{t "风险解释" "Why it matters"}}</b>{{.Why}}</p><p><b>{{t "建议" "Suggestion"}}</b>{{.Recommendation}}</p></div>{{end}}{{if .Evidence}}<details {{if or (eq .Status "RISK") (eq .Status "UNKNOWN")}}open{{end}}><summary>{{t "证据" "Evidence"}} · {{len .Evidence}}</summary><div class="evidence-list">{{range .Evidence}}<div class="evidence"><span class="source">[{{.Source}}]</span> {{evidence .}}</div>{{end}}</div></details>{{end}}</div></article>{{end}}</section>
<div class="empty">{{t "没有符合当前筛选条件的结果。" "No findings match the current filters."}}</div><footer class="footer">VPS Scope {{.Report.ToolVersion}} · schema {{.Report.SchemaVersion}} · {{t "报告保存在本地" "Report remains local"}}</footer>
</main><script>
(()=>{const buttons=[...document.querySelectorAll('[data-filter]')],items=[...document.querySelectorAll('.finding')],input=document.querySelector('.search'),empty=document.querySelector('.empty');let filter='ALL';const apply=()=>{const q=input.value.trim().toLowerCase();let shown=0;for(const item of items){const visible=(filter==='ALL'||item.dataset.status===filter)&&(!q||item.textContent.toLowerCase().includes(q));item.hidden=!visible;if(visible)shown++}empty.style.display=shown?'none':'block'};for(const button of buttons)button.addEventListener('click',()=>{filter=button.dataset.filter;for(const other of buttons)other.setAttribute('aria-pressed',String(other===button));apply()});input.addEventListener('input',apply)})();
</script></body></html>`
