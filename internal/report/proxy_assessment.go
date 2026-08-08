package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/i18n"
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
	fmt.Fprintln(w, i18n.Message(locale, i18n.MessageProxyAssessment))
	fmt.Fprintln(w, line)
	if len(assessment.Components) > 0 {
		fmt.Fprintf(w, "%s: %s\n", i18n.Message(locale, i18n.MessageDetectedComponents), strings.Join(assessment.Components, ", "))
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
	fmt.Fprintf(w, "## %s\n\n", i18n.Message(locale, i18n.MessageProxyAssessment))
	if len(assessment.Components) > 0 {
		fmt.Fprintf(w, "**%s%s** %s\n\n", i18n.Message(locale, i18n.MessageDetectedComponents), choose(locale, "：", ":"), escapeMD(strings.Join(assessment.Components, ", ")))
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
	if r.Deployment != nil {
		components = topologyComponentProducts(r.Deployment.Components)
	}
	hasProxyContext := len(components) > 0 ||
		panelOK && !panel.NotApplicable ||
		ingressOK && !ingress.NotApplicable ||
		inventoryOK && !inventory.NotApplicable
	if !hasProxyContext {
		return proxyAssessment{}
	}

	ingressLine := proxyIngressAssessment(ingress, ingressOK, locale)
	panelLine := proxyPanelAssessment(panel, panelOK, locale)
	if r.Deployment != nil {
		ingressLine = topologyIngressAssessment(*r.Deployment, ingress, ingressOK, locale)
		panelLine = topologyPanelAssessment(*r.Deployment, panel, panelOK, locale)
	}
	return proxyAssessment{
		Components: components,
		Lines: []proxyAssessmentLine{
			ingressLine,
			panelLine,
			proxyRuntimeAssessment(config, configOK, runtime, runtimeOK, locale),
			proxyAvailabilityAssessment(r, locale),
			hostBaselineAssessment(r, locale),
		},
	}
}

func topologyComponentProducts(components []model.Component) []string {
	seen := map[string]bool{}
	for _, component := range components {
		if component.Product != "" && component.Product != "unknown" {
			seen[component.Product] = true
		}
	}
	if seen["3x-ui"] || seen["x-ui"] {
		delete(seen, "x-ui/3x-ui")
	}
	out := make([]string, 0, len(seen))
	for product := range seen {
		out = append(out, product)
	}
	sort.Strings(out)
	return out
}

func topologyIngressAssessment(deployment model.Deployment, finding model.Finding, ok bool, locale string) proxyAssessmentLine {
	line := proxyAssessmentLine{Label: choose(locale, "节点入口", "Proxy ingress"), Status: "INFO"}
	var endpoints []model.ServiceEndpoint
	for _, endpoint := range deployment.Endpoints {
		if endpoint.Role == "proxy-ingress" {
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) == 0 {
		line.Message = choose(locale, "未发现当前适配器能够确认的代理入口。", "No proxy ingress was confirmed by the active adapters.")
		return line
	}
	if ok {
		line.Status = assessmentFindingLabel(finding)
	}
	problems, unknown := 0, 0
	for _, endpoint := range endpoints {
		if endpoint.Confidence == "unknown" || strings.Contains(endpoint.Judgment, "unknown") {
			unknown++
		} else if endpoint.Judgment != "expected-proxy-ingress" {
			problems++
		}
	}
	switch {
	case finding.Status == model.Risk || problems > 0:
		line.Message = fmt.Sprintf(choose(locale, "已识别 %d 个代理入口，其中 %d 个配置、监听或防火墙关系异常。", "%d proxy ingress endpoints were identified; %d have a configuration, listener, or firewall mismatch."), len(endpoints), problems)
	case finding.Status == model.Unknown || unknown > 0:
		line.Message = fmt.Sprintf(choose(locale, "已识别 %d 个代理入口，但 %d 个关系证据不足，不能确认是否按预期工作。", "%d proxy ingress endpoints were identified, but %d relationships lack enough evidence to confirm expected operation."), len(endpoints), unknown)
	default:
		line.Message = fmt.Sprintf(choose(locale, "已确认 %d 个代理入口；配置、实际监听和主机防火墙关系一致。", "%d proxy ingress endpoints were confirmed; configuration, live listeners, and host-firewall state agree."), len(endpoints))
	}
	return line
}

func topologyPanelAssessment(deployment model.Deployment, finding model.Finding, ok bool, locale string) proxyAssessmentLine {
	line := proxyAssessmentLine{Label: choose(locale, "管理面", "Management plane"), Status: "INFO"}
	var management []model.ServiceEndpoint
	for _, endpoint := range deployment.Endpoints {
		if endpoint.Role == "management" {
			management = append(management, endpoint)
		}
	}
	if len(management) == 0 {
		line.Message = choose(locale, "未检测到当前适配器支持的代理面板。", "No supported proxy panel was detected.")
		return line
	}
	if ok {
		line.Status = assessmentFindingLabel(finding)
	}
	switch finding.Status {
	case model.Risk:
		line.Message = choose(locale, "发现需要立即复核的管理面暴露。", "A management-plane exposure needs immediate review.")
	case model.Pass:
		line.Message = choose(locale, "未发现管理面直接向整个公网开放。", "No management plane was found directly open to the whole public internet.")
	case model.Unknown:
		line.Message = choose(locale, "面板结构、监听或防火墙证据不足，不能确认管理面是否安全。", "Panel schema, listener, or firewall evidence is incomplete; management exposure cannot be confirmed.")
	default:
		line.Message = choose(locale, "面板状态仅作为部署上下文记录。", "Panel state is recorded as deployment context only.")
	}
	first := management[0]
	line.Message += fmt.Sprintf(" %s %d/%s · %s · %s · TLS=%s · %s.", first.Product, first.Port, first.Transport, scopeLabel(first.Scope, locale), firewallLabel(first.Firewall, locale), valueOrReport(first.TLS, "unknown"), topologyPathLabel(valueOrReport(first.PathPosture, "unknown"), locale))
	return line
}

func valueOrReport(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
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
	case status == model.Risk && runtimeOK && strings.HasSuffix(runtime.ReasonCode, "public-plaintext-subscription"):
		line.Message = choose(locale, "面板角色与实际监听一致，但订阅端点从公网明文开放，订阅链接中的访问凭据可能泄露。", "Panel roles match the live listeners, but a subscription endpoint is publicly reachable over plaintext and may expose credentials carried in subscription links.")
	case status == model.Risk:
		line.Message = choose(locale, "面板数据库、生成配置和实际监听之间存在无法解释的差异。", "The panel database, generated configuration, and live listeners contain an unexplained mismatch.")
	case status == model.Unknown:
		line.Message = choose(locale, "配置校验或面板运行态证据不完整，不能确认重启后的可恢复性。", "Configuration validation or panel runtime evidence is incomplete; restart recovery cannot be confirmed.")
	case status == model.Pass && configOK && config.NotApplicable:
		// A panel-runtime PASS cannot prove a configuration that was not found
		// or parsed. Keep the combined user-facing claim contextual.
		line.Status = "INFO"
		line.Message = choose(locale, "没有可执行的原生配置自检；运行信息仅作上下文。", "No native configuration check was available; runtime information is context only.")
	case status == model.Pass:
		line.Message = choose(locale, "配置自检和面板运行态关系未发现异常。", "Configuration validation and panel runtime relationships show no problem.")
	case status == model.Info && configOK && config.Facts["native_self_test_mode"] == "disabled_by_default":
		line.Message = choose(locale, "已记录静态配置解析和面板运行态；默认未执行第三方工作负载的原生自检，因此不标记为 PASS。", "Static configuration parsing and panel runtime were recorded; native self-tests for third-party workloads were not executed by default, so this is not marked PASS.")
	default:
		line.Message = choose(locale, "没有可执行的原生配置自检；运行信息仅作上下文。", "No native configuration check was available; runtime information is context only.")
	}
	return line
}

func proxyAvailabilityAssessment(r model.Report, locale string) proxyAssessmentLine {
	findings := make([]model.Finding, 0, len(availabilityAssessmentIDs))
	for _, id := range availabilityAssessmentIDs {
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
		if finding.Category == "workloads" || finding.Category == "docker" || finding.NotApplicable || finding.Status == model.Info || isAvailabilityAssessmentFinding(finding.ID) {
			continue
		}
		findings = append(findings, finding)
	}
	status, severity := combinedAssessmentFindings(findings)
	line := proxyAssessmentLine{Label: choose(locale, "Linux 安全底座", "Linux security baseline"), Status: assessmentLabel(status, severity)}
	riskCount, unknownCount := countStatus(findings, model.Risk), countStatus(findings, model.Unknown)
	switch {
	case riskCount > 0:
		line.Message = fmt.Sprintf(choose(locale, "另有 %d 项 Linux 主机基线风险；它们不是节点协议问题，但仍需要处理。", "%d Linux host-baseline risks remain; they are not proxy-protocol problems but still need attention."), riskCount)
	case unknownCount > 0:
		line.Message = fmt.Sprintf(choose(locale, "通用 Linux 基线没有明确风险，但有 %d 项证据不足。", "The Linux baseline has no confirmed risk, but %d checks lack evidence."), unknownCount)
	default:
		line.Message = choose(locale, "SSH、账户、防火墙、更新和持久化基线未触发风险；INFO 项只是状态清单。", "SSH, account, firewall, update, and persistence checks triggered no risk; INFO items are inventory only.")
	}
	return line
}

var availabilityAssessmentIDs = []string{"PROC-001", "TLS-001", "REL-001", "WORK-010"}

func isAvailabilityAssessmentFinding(id string) bool {
	for _, candidate := range availabilityAssessmentIDs {
		if id == candidate {
			return true
		}
	}
	return false
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
	severity := model.Severity("")
	hasRisk, hasUnknown, hasInfo, hasPass := false, false, false, false
	for _, finding := range findings {
		switch finding.Status {
		case model.Risk:
			if !hasRisk || severityRank(finding.Severity) < severityRank(severity) {
				severity = finding.Severity
			}
			hasRisk = true
		case model.Unknown:
			hasUnknown = true
		case model.Info:
			hasInfo = true
		case model.Pass:
			hasPass = true
		}
	}
	if hasRisk {
		return model.Risk, severity
	}
	if hasUnknown {
		return model.Unknown, ""
	}
	// A combined PASS promises that every applicable sub-conclusion passed.
	// INFO is intentionally sticky: one contextual or deliberately unexecuted
	// check must not borrow a PASS badge from a different check.
	if hasInfo {
		return model.Info, ""
	}
	if hasPass {
		return model.Pass, ""
	}
	return model.Info, ""
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
