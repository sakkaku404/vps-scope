package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// proxyAssessment is a presentation-only answer to the questions a proxy VPS
// owner usually asks first. The stable findings and JSON evidence remain the
// source of truth.
type proxyAssessment struct {
	Components []string
	Lines      []proxyAssessmentLine
}

type proxyAssessmentLine struct {
	Label   string
	Status  string
	Message string
}

func (a proxyAssessment) HasContent() bool {
	return len(a.Components) > 0 || len(a.Lines) > 0
}

func writeProxyAssessmentText(w io.Writer, assessment proxyAssessment, locale string, line string) {
	if !assessment.HasContent() {
		return
	}
	fmt.Fprintln(w, choose(locale, "代理 VPS 结论", "Proxy VPS assessment"))
	fmt.Fprintln(w, line)
	if len(assessment.Components) > 0 {
		fmt.Fprintf(w, "%s: %s\n", choose(locale, "识别到", "Detected"), strings.Join(assessment.Components, ", "))
	}
	for _, item := range assessment.Lines {
		fmt.Fprintf(w, "[%s] %s\n  %s\n", item.Status, item.Label, item.Message)
	}
	fmt.Fprintln(w)
}

func writeProxyAssessmentMarkdown(w io.Writer, assessment proxyAssessment, locale string) {
	if !assessment.HasContent() {
		return
	}
	fmt.Fprintf(w, "## %s\n\n", choose(locale, "代理 VPS 结论", "Proxy VPS assessment"))
	if len(assessment.Components) > 0 {
		fmt.Fprintf(w, "**%s%s** %s\n\n", choose(locale, "识别到", "Detected"), choose(locale, "：", ":"), escapeMD(strings.Join(assessment.Components, ", ")))
	}
	fmt.Fprintf(w, "| %s | %s | %s |\n|---|---|---|\n", choose(locale, "你需要知道的事", "Question"), choose(locale, "结论", "Result"), choose(locale, "说明", "Explanation"))
	for _, item := range assessment.Lines {
		fmt.Fprintf(w, "| %s | `%s` | %s |\n", escapeMD(item.Label), item.Status, escapeMD(item.Message))
	}
	fmt.Fprintln(w)
}

func collectProxyAssessment(r model.Report, locale string) proxyAssessment {
	inventory, inventoryOK := findingByID(r, "WORK-003")
	panel, panelOK := findingByID(r, "WORK-002")
	ingress, ingressOK := findingByID(r, "WORK-009")
	config, configOK := findingByID(r, "WORK-004")
	runtime, runtimeOK := findingByID(r, "WORK-012")

	components := setFromCSV(inventory.Facts["products"])
	hasProxyContext := len(components) > 0 ||
		panelOK && !panel.NotApplicable ||
		ingressOK && !ingress.NotApplicable ||
		inventoryOK && !inventory.NotApplicable
	if !hasProxyContext {
		return proxyAssessment{}
	}

	return proxyAssessment{
		Components: components,
		Lines: []proxyAssessmentLine{
			proxyIngressAssessment(ingress, ingressOK, locale),
			proxyPanelAssessment(panel, panelOK, locale),
			proxyRuntimeAssessment(config, configOK, runtime, runtimeOK, locale),
			proxyAvailabilityAssessment(r, locale),
			hostBaselineAssessment(r, locale),
		},
	}
}

func proxyIngressAssessment(f model.Finding, ok bool, locale string) proxyAssessmentLine {
	line := proxyAssessmentLine{Label: choose(locale, "节点入口", "Proxy ingress"), Status: "INFO"}
	if !ok || f.NotApplicable {
		line.Message = choose(locale, "未发现当前适配器能够确认的代理入口。", "No proxy ingress was confirmed by the active adapters.")
		return line
	}
	line.Status = assessmentFindingLabel(f)
	total, expected, problems := 0, 0, 0
	var firstProblem string
	for _, evidence := range f.Evidence {
		if evidence.Key != "endpoint_relation" {
			continue
		}
		total++
		judgment := relationValue(evidence.Value, "judgment")
		if judgment == "expected-proxy-ingress" {
			expected++
			continue
		}
		problems++
		if firstProblem == "" {
			firstProblem = compactEndpointRelation(evidence.Value, locale)
		}
	}
	switch f.Status {
	case model.Pass:
		line.Message = fmt.Sprintf(choose(locale, "已确认 %d 个代理入口；配置、实际监听和主机防火墙关系一致。", "%d proxy ingress endpoints were confirmed; configuration, live listeners, and host-firewall state agree."), expected)
	case model.Risk:
		line.Message = fmt.Sprintf(choose(locale, "%d 个入口中有 %d 个关系异常。", "%d ingress endpoints include %d relationship problems."), total, problems)
		if firstProblem != "" {
			line.Message += " " + firstProblem
		}
	case model.Unknown:
		line.Message = choose(locale, "入口配置、实际监听或防火墙证据不完整，不能确认节点入口是否按预期工作。", "Configuration, live-listener, or firewall evidence is incomplete; ingress operation cannot be confirmed.")
	default:
		line.Message = fmt.Sprintf(choose(locale, "记录了 %d 个代理入口；本项只提供运行上下文。", "%d proxy ingress endpoints were recorded as runtime context."), total)
	}
	return line
}

func proxyPanelAssessment(f model.Finding, ok bool, locale string) proxyAssessmentLine {
	line := proxyAssessmentLine{Label: choose(locale, "管理面", "Management plane"), Status: "INFO"}
	if !ok || f.NotApplicable {
		line.Message = choose(locale, "未检测到当前适配器支持的代理面板。", "No supported proxy panel was detected.")
		return line
	}
	line.Status = assessmentFindingLabel(f)
	posture := firstPanelPostureLine(f, locale)
	switch f.Status {
	case model.Risk:
		line.Message = choose(locale, "发现需要立即复核的管理面暴露。", "A management-plane exposure needs immediate review.")
	case model.Pass:
		line.Message = choose(locale, "未发现管理面直接向整个公网开放。", "No management plane was found directly open to the whole public internet.")
	case model.Unknown:
		line.Message = choose(locale, "面板结构、监听或防火墙证据不足，不能确认管理面是否安全。", "Panel schema, listener, or firewall evidence is incomplete; management exposure cannot be confirmed.")
	default:
		line.Message = choose(locale, "面板状态仅作为部署上下文记录。", "Panel state is recorded as deployment context only.")
	}
	if posture != "" {
		line.Message += " " + posture
	}
	return line
}

func proxyRuntimeAssessment(config model.Finding, configOK bool, runtime model.Finding, runtimeOK bool, locale string) proxyAssessmentLine {
	status, severity := combinedAssessmentStatus(config, configOK, runtime, runtimeOK)
	line := proxyAssessmentLine{Label: choose(locale, "配置与运行", "Configuration and runtime"), Status: assessmentLabel(status, severity)}
	switch {
	case status == model.Risk && configOK && config.Status == model.Risk:
		line.Message = choose(locale, "代理核心原生配置校验失败；服务可能无法在重启后恢复。", "A native proxy-core configuration check failed; the service may not recover after restart.")
	case status == model.Risk:
		line.Message = choose(locale, "面板数据库、生成配置和实际监听之间存在无法解释的差异。", "The panel database, generated configuration, and live listeners contain an unexplained mismatch.")
	case status == model.Unknown:
		line.Message = choose(locale, "配置校验或面板运行态证据不完整，不能确认重启后的可恢复性。", "Configuration validation or panel runtime evidence is incomplete; restart recovery cannot be confirmed.")
	case status == model.Pass:
		line.Message = choose(locale, "配置自检和面板运行态关系未发现异常。", "Configuration validation and panel runtime relationships show no problem.")
	default:
		line.Message = choose(locale, "没有可执行的原生配置自检；运行信息仅作上下文。", "No native configuration check was available; runtime information is context only.")
	}
	return line
}

func proxyAvailabilityAssessment(r model.Report, locale string) proxyAssessmentLine {
	ids := []string{"PROC-001", "TLS-001", "REL-001", "WORK-010"}
	findings := make([]model.Finding, 0, len(ids))
	for _, id := range ids {
		if finding, ok := findingByID(r, id); ok && !finding.NotApplicable {
			findings = append(findings, finding)
		}
	}
	status, severity := combinedAssessmentFindings(findings)
	line := proxyAssessmentLine{Label: choose(locale, "服务可用性", "Service availability"), Status: assessmentLabel(status, severity)}
	riskCount, unknownCount := countStatus(findings, model.Risk), countStatus(findings, model.Unknown)
	switch {
	case riskCount > 0:
		line.Message = fmt.Sprintf(choose(locale, "发现 %d 项可能影响服务持续运行的问题；优先查看失败服务、证书、OOM 或日志证据。", "%d findings may affect continued service operation; review failed services, certificates, OOM, or log evidence first."), riskCount)
	case unknownCount > 0:
		line.Message = fmt.Sprintf(choose(locale, "%d 项可用性证据不足，不能确认服务长期运行状态。", "%d availability checks lack enough evidence to confirm long-running service health."), unknownCount)
	default:
		line.Message = choose(locale, "未发现失败或反复重启服务、证书到期、OOM 或 core dump 风险。", "No failed/restarting service, certificate-expiry, OOM, or core-dump risk was found.")
	}
	return line
}

func hostBaselineAssessment(r model.Report, locale string) proxyAssessmentLine {
	var findings []model.Finding
	for _, finding := range r.Findings {
		if finding.Category == "workloads" || finding.Category == "docker" || finding.NotApplicable || finding.Status == model.Info {
			continue
		}
		findings = append(findings, finding)
	}
	status, severity := combinedAssessmentFindings(findings)
	line := proxyAssessmentLine{Label: choose(locale, "Linux 安全底座", "Linux security baseline"), Status: assessmentLabel(status, severity)}
	riskCount, unknownCount := countStatus(findings, model.Risk), countStatus(findings, model.Unknown)
	switch {
	case riskCount > 0:
		line.Message = fmt.Sprintf(choose(locale, "另有 %d 项 SSH、账户、防火墙、更新或持久化风险；它们不是节点协议问题，但仍需要处理。", "%d SSH, account, firewall, update, or persistence risks remain; they are not proxy-protocol problems but still need attention."), riskCount)
	case unknownCount > 0:
		line.Message = fmt.Sprintf(choose(locale, "通用 Linux 基线没有明确风险，但有 %d 项证据不足。", "The Linux baseline has no confirmed risk, but %d checks lack evidence."), unknownCount)
	default:
		line.Message = choose(locale, "SSH、账户、防火墙、更新和持久化基线未触发风险；INFO 项只是状态清单。", "SSH, account, firewall, update, and persistence checks triggered no risk; INFO items are inventory only.")
	}
	return line
}

func compactEndpointRelation(value string, locale string) string {
	port := relationValue(value, "port", "process", "purpose", "security", "scope", "firewall", "judgment")
	purpose := relationValue(value, "purpose", "security", "scope", "firewall", "judgment")
	scope := relationValue(value, "scope", "firewall", "judgment")
	firewall := relationValue(value, "firewall", "judgment")
	judgment := relationValue(value, "judgment")
	return fmt.Sprintf("%s %s · %s · %s · %s", port, purpose, scopeLabel(scope, locale), firewallLabel(firewall, locale), judgmentLabel(judgment, locale))
}

func firstPanelPostureLine(f model.Finding, locale string) string {
	for _, line := range panelOverviewLines(f, locale) {
		if strings.Contains(line, " · ") {
			return line
		}
	}
	return ""
}

func combinedAssessmentStatus(first model.Finding, firstOK bool, second model.Finding, secondOK bool) (model.Status, model.Severity) {
	var findings []model.Finding
	if firstOK && !first.NotApplicable {
		findings = append(findings, first)
	}
	if secondOK && !second.NotApplicable {
		findings = append(findings, second)
	}
	return combinedAssessmentFindings(findings)
}

func combinedAssessmentFindings(findings []model.Finding) (model.Status, model.Severity) {
	status := model.Info
	severity := model.Severity("")
	for _, finding := range findings {
		if finding.Status == model.Risk {
			if status != model.Risk || severityRank(finding.Severity) < severityRank(severity) {
				status, severity = model.Risk, finding.Severity
			}
			continue
		}
		if status != model.Risk && finding.Status == model.Unknown {
			status = model.Unknown
			severity = ""
			continue
		}
		if status == model.Info && finding.Status == model.Pass {
			status = model.Pass
		}
	}
	return status, severity
}

func severityRank(severity model.Severity) int {
	switch severity {
	case model.Critical:
		return 0
	case model.High:
		return 1
	case model.Medium:
		return 2
	case model.Low:
		return 3
	default:
		return 4
	}
}

func assessmentFindingLabel(f model.Finding) string {
	return assessmentLabel(f.Status, f.Severity)
}

func assessmentLabel(status model.Status, severity model.Severity) string {
	if status == "" {
		status = model.Info
	}
	if severity == "" {
		return string(status)
	}
	return string(status) + "/" + strings.ToUpper(string(severity))
}

func countStatus(findings []model.Finding, status model.Status) int {
	count := 0
	for _, finding := range findings {
		if finding.Status == status {
			count++
		}
	}
	return count
}
