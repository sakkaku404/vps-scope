package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type proxyOverview struct {
	Components []string
	Groups     []proxyOverviewGroup
}

type proxyOverviewGroup struct {
	Title string
	Lines []string
}

func (o proxyOverview) HasContent() bool {
	return len(o.Components) > 0 || len(o.Groups) > 0
}

// collectProxyOverview promotes non-secret relationship evidence already
// collected by the proxy checks. It is intentionally an inventory: findings
// remain the source of truth for status and severity in every renderer.
func collectProxyOverview(r model.Report, locale string) proxyOverview {
	if r.Deployment != nil {
		return collectTopologyOverview(r, locale)
	}
	panels, panelOK := findingByID(r, "WORK-002")
	inventory, inventoryOK := findingByID(r, "WORK-003")
	relations, relationsOK := findingByID(r, "WORK-009")
	controls, controlsOK := findingByID(r, "WORK-005")
	runtime, runtimeOK := findingByID(r, "WORK-012")
	activity, activityOK := findingByID(r, "WORK-010")
	reverseProxy, reverseProxyOK := findingByID(r, "WORK-013")
	docker, dockerOK := findingByID(r, "DOCKER-001")
	if !panelOK && !inventoryOK && !relationsOK && !controlsOK && !runtimeOK && !activityOK && !reverseProxyOK && !dockerOK {
		return proxyOverview{}
	}

	components := setFromCSV(inventory.Facts["products"])
	panelLines := panelOverviewLines(panels, locale)
	endpointLines := endpointOverviewLines(relations, locale)
	controlLines := controlOverviewLines(controls, locale)
	runtimeLines := runtimeOverviewLines(runtime, locale)
	activityLines := activityOverviewLines(activity, locale)
	deploymentLines := deploymentOverviewLines(reverseProxy, docker, locale)
	if len(components) == 0 && len(panelLines) == 0 && len(endpointLines) == 0 && len(controlLines) == 0 && len(runtimeLines) == 0 && len(activityLines) == 0 && len(deploymentLines) == 0 {
		return proxyOverview{}
	}
	groups := []proxyOverviewGroup{
		{Title: choose(locale, "管理面板", "Management panels"), Lines: panelLines},
		{Title: choose(locale, "代理入口", "Proxy ingress"), Lines: endpointLines},
		{Title: choose(locale, "控制接口", "Control APIs"), Lines: controlLines},
		{Title: choose(locale, "运行态异常", "Runtime mismatches"), Lines: runtimeLines},
		{Title: choose(locale, "运行与攻击日志信号", "Operational and attack log signals"), Lines: activityLines},
		{Title: choose(locale, "部署关系", "Deployment relationships"), Lines: deploymentLines},
	}
	filtered := make([]proxyOverviewGroup, 0, len(groups))
	for _, group := range groups {
		if len(group.Lines) > 0 {
			filtered = append(filtered, group)
		}
	}
	return proxyOverview{Components: components, Groups: filtered}
}

// writeProxyOverviewText renders the relationship inventory before the full
// check list, so a terminal user can understand the proxy layout at a glance.
func writeProxyOverviewText(w io.Writer, r model.Report, locale string, line string) {
	overview := collectProxyOverview(r, locale)
	if !overview.HasContent() {
		return
	}

	fmt.Fprintln(w, choose(locale, "代理部署明细", "Proxy deployment details"))
	fmt.Fprintln(w, line)
	if len(overview.Components) > 0 {
		fmt.Fprintf(w, "%s: %s\n", choose(locale, "已识别组件", "Detected components"), strings.Join(overview.Components, ", "))
	}
	for _, group := range overview.Groups {
		writeOverviewGroup(w, group.Title, group.Lines)
	}
	fmt.Fprintln(w)
}

func writeProxyOverviewMarkdown(w io.Writer, r model.Report, locale string) {
	overview := collectProxyOverview(r, locale)
	if !overview.HasContent() {
		return
	}
	fmt.Fprintf(w, "## %s\n\n", choose(locale, "代理部署明细", "Proxy deployment details"))
	if len(overview.Components) > 0 {
		fmt.Fprintf(w, "- **%s:** %s\n", choose(locale, "已识别组件", "Detected components"), escapeMD(strings.Join(overview.Components, ", ")))
	}
	for _, group := range overview.Groups {
		fmt.Fprintf(w, "\n### %s\n\n", escapeMD(group.Title))
		for _, line := range group.Lines {
			fmt.Fprintf(w, "- %s\n", escapeMD(line))
		}
	}
	fmt.Fprintln(w)
}

func runtimeOverviewLines(f model.Finding, locale string) []string {
	if f.ID == "" || f.NotApplicable {
		return nil
	}
	var out []string
	for _, item := range f.Evidence {
		switch item.Key {
		case "disabled_inbound_still_listening":
			out = append(out, choose(locale, "面板已禁用但仍在监听：", "Disabled in panel but still listening: ")+item.Value+" "+findingLabel(f))
		case "unclassified_panel_listener":
			if strings.Contains(item.Value, "scope=public") {
				out = append(out, choose(locale, "无法解释的面板/核心公网监听：", "Unexplained public panel/core listener: ")+item.Value+" "+findingLabel(f))
			}
		}
	}
	return limitOverviewLines(out, 6, locale)
}

func activityOverviewLines(f model.Finding, locale string) []string {
	if f.ID == "" || f.NotApplicable {
		return nil
	}
	labels := []struct{ key, zh, en string }{
		{"authentication_signals", "认证错误", "authentication errors"},
		{"handshake_signals", "握手错误", "handshake errors"},
		{"dns_signals", "DNS 错误", "DNS errors"},
		{"tls_signals", "TLS/证书错误", "TLS/certificate errors"},
		{"routing_signals", "路由/出站错误", "routing/outbound errors"},
		{"fatal_signals", "致命错误", "fatal errors"},
		{"panel_login_failure_signals", "面板登录失败", "panel login failures"},
		{"api_unauthorized_signals", "API 未授权访问", "unauthorized API access"},
		{"subscription_abuse_signals", "订阅异常访问", "subscription abuse"},
		{"rate_limit_signals", "限速/429", "rate limiting/429"},
		{"web_probe_signals", "Web 扫描探测", "web probes"},
	}
	var parts []string
	for _, label := range labels {
		if value := f.Facts[label.key]; value != "" && value != "0" {
			parts = append(parts, fmt.Sprintf("%s=%s", choose(locale, label.zh, label.en), value))
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return []string{strings.Join(parts, choose(locale, "；", "; ")) + choose(locale, "（分类可能重叠；不导出原始日志）", " (categories may overlap; raw logs are not exported)")}
}

func deploymentOverviewLines(reverseProxy, docker model.Finding, locale string) []string {
	var out []string
	for _, item := range reverseProxy.Evidence {
		if item.Key == "reverse_proxy_route" {
			judgment := relationValue(item.Value, "judgment")
			label := "[INFO]"
			switch {
			case strings.Contains(judgment, "public-") && strings.Contains(judgment, "management"):
				label = "[RISK/HIGH]"
			case strings.Contains(judgment, "not-listening"), strings.Contains(judgment, "more-broadly"):
				label = "[RISK/MEDIUM]"
			case judgment == "reverse-proxy-chain-consistent":
				label = "[PASS]"
			}
			frontend := relationValue(item.Value, "frontend", "process", "scope", "firewall", "proxy", "access", "backend", "judgment")
			frontend = prettyEndpoint(frontend)
			frontScope := relationValue(item.Value, "scope", "firewall", "proxy", "access", "backend", "judgment")
			firewall := relationValue(item.Value, "firewall", "proxy", "access", "backend", "judgment")
			proxy := relationValue(item.Value, "proxy", "access", "backend", "judgment")
			access := relationValue(item.Value, "access", "backend", "judgment")
			backend := relationValue(item.Value, "backend", "process", "scope", "judgment")
			backendScope := "unknown"
			if index := strings.Index(item.Value, " backend="); index >= 0 {
				backendScope = relationValue(item.Value[index+1:], "scope", "judgment")
			}
			line := fmt.Sprintf("%s %s → %s · %s · %s · %s · %s · %s %s", frontend, proxy, backend, scopeLabel(frontScope, locale), firewallLabel(firewall, locale), scopeLabel(backendScope, locale), reverseProxyAccessLabel(access, locale), reverseProxyJudgmentLabel(judgment, locale), label)
			out = append(out, line)
		}
	}
	for _, item := range docker.Evidence {
		if item.Key == "compose_service" {
			out = append(out, "Docker Compose: "+item.Value+" [INFO]")
		}
	}
	if problems := docker.Facts["isolation_problems"]; problems != "" && problems != "0" {
		out = append(out, fmt.Sprintf(choose(locale, "Docker 隔离异常=%s；详见 DOCKER-001 ", "Docker isolation problems=%s; see DOCKER-001 "), problems)+findingLabel(docker))
	}
	return limitOverviewLines(out, 8, locale)
}

func prettyEndpoint(value string) string {
	if strings.HasPrefix(value, ":::") {
		return "*:" + strings.TrimPrefix(value, ":::")
	}
	return value
}

func reverseProxyAccessLabel(value string, locale string) string {
	labels := map[string][2]string{
		"unconditional": {"无条件路由", "unconditional route"},
		"conditional":   {"条件路由", "conditional route"},
		"path-gated":    {"路径路由", "path route"},
		"unknown":       {"路由条件未知", "route condition unknown"},
	}
	if label, ok := labels[value]; ok {
		return choose(locale, label[0], label[1])
	}
	return value
}

func reverseProxyJudgmentLabel(value string, locale string) string {
	labels := map[string][2]string{
		"reverse-proxy-chain-consistent":                             {"链路一致", "chain consistent"},
		"configured-frontend-not-listening":                          {"前端未监听", "frontend not listening"},
		"configured-backend-not-listening":                           {"后端未监听", "backend not listening"},
		"backend-listens-more-broadly-than-configured":               {"后端监听范围过宽", "backend listens too broadly"},
		"external-upstream-not-verified-from-local-listeners":        {"外部上游，仅作上下文", "external upstream; context only"},
		"public-path-gated-reverse-proxy-reaches-hiddify-management": {"公网路径可到达 Hiddify 管理面", "public path reaches Hiddify management"},
		"public-path-gated-reverse-proxy-reaches-s-ui-management":    {"公网路径可到达 S-UI 管理面", "public path reaches S-UI management"},
		"public-path-gated-reverse-proxy-reaches-3x-ui-management":   {"公网路径可到达 3x-ui 管理面", "public path reaches 3x-ui management"},
		"public-path-gated-reverse-proxy-reaches-x-ui-management":    {"公网路径可到达 x-ui 管理面", "public path reaches x-ui management"},
		"public-reverse-proxy-exposes-hiddify-management":            {"公网反代暴露 Hiddify 管理面", "public reverse proxy exposes Hiddify management"},
		"public-reverse-proxy-exposes-s-ui-management":               {"公网反代暴露 S-UI 管理面", "public reverse proxy exposes S-UI management"},
		"public-reverse-proxy-exposes-3x-ui-management":              {"公网反代暴露 3x-ui 管理面", "public reverse proxy exposes 3x-ui management"},
		"public-reverse-proxy-exposes-x-ui-management":               {"公网反代暴露 x-ui 管理面", "public reverse proxy exposes x-ui management"},
	}
	if label, ok := labels[value]; ok {
		return choose(locale, label[0], label[1])
	}
	return value
}

func writeOverviewGroup(w io.Writer, title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(w, "%s:\n", title)
	for _, line := range lines {
		fmt.Fprintf(w, "  %s\n", line)
	}
}

func panelOverviewLines(f model.Finding, locale string) []string {
	if f.ID == "" || f.NotApplicable {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, evidence := range f.Evidence {
		if evidence.Key != "product" {
			continue
		}
		product := relationValue(evidence.Value, "product", "version", "adapter", "schema", "binary")
		if product == "" {
			continue
		}
		version := relationValue(evidence.Value, "version", "adapter", "schema", "binary")
		line := product
		if version != "" && version != "unknown" {
			line += " " + version
		}
		line += " " + findingLabel(f)
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	for _, evidence := range f.Evidence {
		if evidence.Key != "management_posture" {
			continue
		}
		product := relationValue(evidence.Value, "product", "port", "scope", "firewall", "tls", "path_default", "judgment")
		port := relationValue(evidence.Value, "port", "scope", "firewall", "tls", "path_default", "judgment")
		scope := relationValue(evidence.Value, "scope", "firewall", "tls", "path_default", "judgment")
		firewall := relationValue(evidence.Value, "firewall", "tls", "path_default", "judgment")
		tls := relationValue(evidence.Value, "tls", "path_default", "judgment")
		pathDefault := relationValue(evidence.Value, "path_default", "judgment")
		judgment := relationValue(evidence.Value, "judgment")
		if product == "" || port == "" {
			continue
		}
		line := fmt.Sprintf("%s %s · %s · %s · %s · %s · %s", product, port, scopeLabel(scope, locale), firewallLabel(firewall, locale), booleanPostureLabel("tls", tls, locale), booleanPostureLabel("path", pathDefault, locale), judgmentLabel(judgment, locale))
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	if len(out) == 0 && f.Facts["products"] != "" {
		for _, product := range setFromCSV(f.Facts["products"]) {
			out = append(out, product+" "+findingLabel(f))
		}
	}
	sort.Strings(out)
	return out
}

func endpointOverviewLines(f model.Finding, locale string) []string {
	if f.ID == "" || f.NotApplicable {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	var connectionLines []string
	for _, evidence := range f.Evidence {
		if evidence.Key != "endpoint_relation" {
			continue
		}
		port := relationValue(evidence.Value, "port", "process", "purpose", "security", "scope", "firewall", "judgment")
		purpose := relationValue(evidence.Value, "purpose", "security", "scope", "firewall", "judgment")
		security := relationValue(evidence.Value, "security", "scope", "firewall", "judgment")
		scope := relationValue(evidence.Value, "scope", "firewall", "judgment")
		firewall := relationValue(evidence.Value, "firewall", "judgment")
		judgment := relationValue(evidence.Value, "judgment")
		if port == "" || purpose == "" {
			continue
		}
		line := fmt.Sprintf("%s  %s", port, purpose)
		if security != "" && security != "none-or-protocol-native" {
			line += " (" + security + ")"
		}
		line += fmt.Sprintf(" · %s · %s · %s", scopeLabel(scope, locale), firewallLabel(firewall, locale), judgmentLabel(judgment, locale))
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	for _, evidence := range f.Evidence {
		if evidence.Key != "connection_snapshot" {
			continue
		}
		port := relationValue(evidence.Value, "port", "established")
		count := relationValue(evidence.Value, "established")
		if semicolon := strings.Index(count, ";"); semicolon >= 0 {
			count = strings.TrimSpace(count[:semicolon])
		}
		if port != "" && count != "" {
			line := fmt.Sprintf(choose(locale, "%s 当前已建立 TCP 连接=%s（仅快照，不按数量武断判风险）", "%s current established TCP connections=%s (snapshot only; no arbitrary risk threshold)"), port, count)
			connectionLines = append(connectionLines, line)
		}
	}
	sort.Strings(out)
	sort.Strings(connectionLines)
	out = limitOverviewLines(out, 10, locale)
	return append(out, limitOverviewLines(connectionLines, 6, locale)...)
}

func controlOverviewLines(f model.Finding, locale string) []string {
	if f.ID == "" || f.NotApplicable {
		return nil
	}
	var out []string
	for _, evidence := range f.Evidence {
		if evidence.Key != "control_endpoint" {
			continue
		}
		product := relationValue(evidence.Value, "product", "kind", "listen", "port", "scope", "live")
		kind := relationValue(evidence.Value, "kind", "listen", "port", "scope", "live")
		port := relationValue(evidence.Value, "port", "scope", "live")
		scope := relationValue(evidence.Value, "scope", "live")
		if product != "" && kind != "" && port != "" {
			out = append(out, fmt.Sprintf("%s %s %s/tcp · %s · %s", product, kind, port, scopeLabel(scope, locale), findingLabel(f)))
		}
	}
	sort.Strings(out)
	return limitOverviewLines(out, 6, locale)
}

func relationValue(value, key string, following ...string) string {
	needle := key + "="
	start := strings.Index(value, needle)
	if start < 0 {
		return ""
	}
	part := value[start+len(needle):]
	end := len(part)
	for _, next := range following {
		if index := strings.Index(part, " "+next+"="); index >= 0 && index < end {
			end = index
		}
	}
	return strings.TrimSpace(part[:end])
}

func setFromCSV(value string) []string {
	seen := map[string]bool{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			seen[part] = true
		}
	}
	out := make([]string, 0, len(seen))
	for part := range seen {
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

func limitOverviewLines(lines []string, limit int, locale string) []string {
	if len(lines) <= limit {
		return lines
	}
	return append(lines[:limit], fmt.Sprintf(choose(locale, "… 另有 %d 项，详见 WORK 证据", "… %d more; see WORK evidence"), len(lines)-limit))
}

func findingLabel(f model.Finding) string {
	if f.Severity == "" {
		return "[" + string(f.Status) + "]"
	}
	return "[" + string(f.Status) + "/" + strings.ToUpper(string(f.Severity)) + "]"
}

func scopeLabel(value string, locale string) string {
	labels := map[string][2]string{
		"public":          {"公网", "public"},
		"public-wildcard": {"公网通配", "public wildcard"},
		"loopback":        {"回环", "loopback"},
		"private":         {"私网", "private"},
		"none":            {"未监听", "not listening"},
		"not-live":        {"未监听", "not listening"},
	}
	if label, ok := labels[value]; ok {
		return choose(locale, label[0], label[1])
	}
	return value
}

func firewallLabel(value string, locale string) string {
	labels := map[string][2]string{
		"allow-anywhere":          {"防火墙允许", "firewall allows"},
		"blocked-by-default":      {"防火墙默认阻断", "firewall default-blocked"},
		"configured-but-not-live": {"未运行", "not live"},
		"not-live":                {"未运行", "not live"},
		"inactive":                {"防火墙未启用", "firewall inactive"},
		"restricted":              {"防火墙受限允许", "firewall restricted"},
	}
	if label, ok := labels[value]; ok {
		return choose(locale, label[0], label[1])
	}
	return value
}

func judgmentLabel(value string, locale string) string {
	labels := map[string][2]string{
		"expected-proxy-ingress":                                             {"符合入口预期", "expected proxy ingress"},
		"configured-public-ingress-blocked-by-host-firewall":                 {"被主机防火墙阻断", "blocked by host firewall"},
		"configured-but-not-listening":                                       {"未找到实际监听", "not listening"},
		"listener-owned-by-different-product":                                {"监听进程不匹配", "listener owned by another product"},
		"public-management-exposed":                                          {"管理面公网暴露", "public management exposure"},
		"public-management-exposed+root-or-default-path":                     {"管理面公网暴露且使用根/默认路径", "public management exposure with root/default path"},
		"public-management-exposed+plaintext-panel":                          {"管理面公网明文暴露", "public plaintext management exposure"},
		"public-management-exposed+root-or-default-path+plaintext-panel":     {"管理面公网明文暴露且使用根/默认路径", "public plaintext management exposure with root/default path"},
		"public-management-restricted-by-host-firewall":                      {"管理面受主机防火墙限制", "management restricted by host firewall"},
		"public-management-restricted-by-host-firewall+root-or-default-path": {"管理面受限，但使用根/默认路径", "restricted management with root/default path"},
		"public-reverse-proxy-management-exposed":                            {"管理面经公网反向代理暴露", "management exposed through a public reverse proxy"},
		"public-path-gated-reverse-proxy-management-exposed":                 {"管理面经公网路径路由暴露；路径不是访问控制", "management exposed through a public path route; a path is not access control"},
	}
	if label, ok := labels[value]; ok {
		return choose(locale, label[0], label[1])
	}
	return value
}

func booleanPostureLabel(kind, value string, locale string) string {
	if value == "unknown" || value == "" {
		return choose(locale, map[string]string{"tls": "TLS未知", "path": "路径未知"}[kind], map[string]string{"tls": "TLS unknown", "path": "path unknown"}[kind])
	}
	if kind == "tls" {
		if value == "true" {
			return choose(locale, "TLS启用", "TLS enabled")
		}
		return choose(locale, "TLS未启用", "TLS disabled")
	}
	if value == "true" {
		return choose(locale, "根/默认路径", "root/default path")
	}
	return choose(locale, "非默认路径", "non-default path")
}
