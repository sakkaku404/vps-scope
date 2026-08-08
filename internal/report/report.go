package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
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
	fmt.Fprintf(w, "VPS Scope %s — %s\n%s\n", r.ToolVersion, i18n.Message(locale, i18n.MessageAuditTitle), line)
	fmt.Fprintf(w, "%s: %s  %s: %s %s  %s: %s\n", i18n.Message(locale, i18n.MessageHost), r.Host.Hostname, i18n.Message(locale, i18n.MessageOS), r.Host.OS, r.Host.OSVersion, i18n.Message(locale, i18n.MessageArchitecture), r.Host.Architecture)
	fmt.Fprintf(w, "Profile: %s (%s: %s)  Root: %t  %s: %s\n", r.Profile.Effective, i18n.Message(locale, i18n.MessageDetected), r.Profile.Detected, r.Host.IsRoot, i18n.Message(locale, i18n.MessageLogWindow), r.LogSince)
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "RISK %d   PASS %d   INFO %d   UNKNOWN %d\n", r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown)
	fmt.Fprintf(w, "%s %d   %s %d   %s %d\n\n", i18n.Message(locale, i18n.MessageCompleted), r.Summary.Completed, i18n.Message(locale, i18n.MessageUnavailable), r.Summary.Unavailable, i18n.Message(locale, i18n.MessageNotApplicable), r.Summary.NotApplicable)
	if auditTimedOut(r) {
		fmt.Fprintf(w, "[UNKNOWN] %s\n\n", choose(locale, "审计已达到截止时间。本报告保留了已完成的证据；未运行的检查标记为 UNKNOWN。", "Audit deadline reached. This report preserves completed evidence; checks that did not run are UNKNOWN."))
	}
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
				writeEvidence(w, f, "    ", true, 20, locale)
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

func writeEvidence(w io.Writer, f model.Finding, indent string, include bool, limit int, locale string) {
	if !include {
		return
	}
	for i, e := range f.Evidence {
		if i >= limit {
			fmt.Fprintf(w, "%s%s\n", indent, fmt.Sprintf(choose(locale, "……另有 %d 条证据未显示", "%d more evidence items"), len(f.Evidence)-limit))
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
	if auditTimedOut(r) {
		fmt.Fprintf(w, "> **UNKNOWN:** %s\n\n", escapeMD(choose(locale, "审计已达到截止时间。本报告保留了已完成的证据；未运行的检查标记为 UNKNOWN。", "Audit deadline reached. This report preserves completed evidence; checks that did not run are UNKNOWN.")))
	}
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
				fmt.Fprintf(w, "**%s:** `%s`\n\n", choose(locale, "原因代码", "Reason code"), f.ReasonCode)
			}
			if len(f.Evidence) > 0 {
				fmt.Fprintf(w, "**%s**\n\n", choose(locale, "关键证据", "Key evidence"))
				for _, e := range keyEvidence(f) {
					fmt.Fprintf(w, "- **%s:** %s\n", escapeMD(e.Source), escapeMD(markdownEvidence(e)))
				}
				fmt.Fprintln(w)
				if len(f.Evidence) > len(keyEvidence(f)) {
					fmt.Fprintf(w, "<details><summary>%s (%d)</summary>\n\n", choose(locale, "全部证据", "All evidence"), len(f.Evidence))
					for _, e := range f.Evidence {
						fmt.Fprintf(w, "- **%s:** %s\n", escapeMD(e.Source), escapeMD(markdownEvidence(e)))
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
		TimedOut      bool
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
	return t.Execute(w, page{Report: r, Findings: items, Actions: summarizeActions(r, opts.Locale), Verdict: overallVerdictFor(r, opts.Locale), Assessment: collectProxyAssessment(r, opts.Locale), ProxyOverview: collectProxyOverview(r, opts.Locale), Locale: opts.Locale, RTL: i18n.RTL(opts.Locale), TimedOut: auditTimedOut(r)})
}

func auditTimedOut(r model.Report) bool { return r.Metadata["collection_timed_out"] == "true" }

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
	return strings.NewReplacer(
		"\\", "\\\\",
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"`", "\\`",
		"*", "\\*",
		"_", "\\_",
		"[", "\\[",
		"]", "\\]",
		"|", "\\|",
		"\r", " ",
		"\n", " ",
	).Replace(s)
}

func escapeMDLinkText(s string) string {
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
