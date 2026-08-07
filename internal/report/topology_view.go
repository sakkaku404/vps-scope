package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
)

// collectTopologyOverview is the normal path for current reports. The legacy
// evidence-string parser remains only so previously saved schema-1.0 reports
// can still be rendered.
func collectTopologyOverview(r model.Report, locale string) proxyOverview {
	if r.Deployment == nil {
		return proxyOverview{}
	}
	components := topologyComponentNames(r.Deployment.Components)
	groups := []proxyOverviewGroup{
		{Title: choose(locale, "管理面板", "Management panels")},
		{Title: choose(locale, "代理入口", "Proxy ingress")},
		{Title: choose(locale, "控制接口", "Control APIs")},
		{Title: choose(locale, "需要关注的暴露与运行问题", "Exposure and runtime issues")},
		{Title: choose(locale, "部署关系", "Deployment relationships")},
		{Title: choose(locale, "证据覆盖", "Evidence coverage")},
	}
	for _, endpoint := range r.Deployment.Endpoints {
		line := topologyEndpointLine(endpoint, locale) + " " + topologyFindingLabel(r, endpoint.Role)
		switch endpoint.Role {
		case "management", "subscription":
			groups[0].Lines = append(groups[0].Lines, line)
		case "proxy-ingress":
			groups[1].Lines = append(groups[1].Lines, line)
		case "control-api":
			groups[2].Lines = append(groups[2].Lines, line)
		case "unclassified-product-listener":
			groups[3].Lines = append(groups[3].Lines, line)
		case "container-publish":
			groups[4].Lines = append(groups[4].Lines, line)
		}
		if topologyJudgmentNeedsReview(endpoint.Judgment) && endpoint.Role != "unclassified-listener" && endpoint.Role != "unclassified-product-listener" {
			groups[3].Lines = append(groups[3].Lines, line)
		}
	}
	groups[4].Lines = append(groups[4].Lines, topologyLinkLines(*r.Deployment, locale)...)
	groups[5].Lines = topologyCoverageLines(r.Deployment.Coverage, locale)
	filtered := make([]proxyOverviewGroup, 0, len(groups))
	for _, group := range groups {
		group.Lines = uniqueSortedLimited(group.Lines, 12, locale)
		if len(group.Lines) > 0 {
			filtered = append(filtered, group)
		}
	}
	return proxyOverview{Components: components, Groups: filtered}
}

func topologyComponentNames(components []model.Component) []string {
	seen := map[string]bool{}
	for _, component := range components {
		name := component.Product
		if component.Kind != "" {
			name += " (" + component.Kind + ")"
		}
		seen[name] = true
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func topologyEndpointLine(endpoint model.ServiceEndpoint, locale string) string {
	product := endpoint.Product
	if product == "" || product == "unknown-proxy" {
		product = choose(locale, "未识别进程", "unclassified process")
	}
	purpose := product
	if endpoint.Protocol != "" {
		purpose += "/" + endpoint.Protocol
	}
	line := fmt.Sprintf("%d/%s  %s · %s · %s", endpoint.Port, endpoint.Transport, purpose, topologyRoleLabel(endpoint.Role, locale), scopeLabel(endpoint.Scope, locale))
	if endpoint.Firewall != "" {
		line += " · " + firewallLabel(endpoint.Firewall, locale)
	}
	if endpoint.Security != "" && endpoint.Security != "none-or-protocol-native" {
		line += " · " + endpoint.Security
	}
	if endpoint.TLS != "" && endpoint.TLS != "unknown" {
		line += " · TLS=" + endpoint.TLS
	}
	if endpoint.PathPosture != "" && endpoint.PathPosture != "unknown" {
		line += " · " + topologyPathLabel(endpoint.PathPosture, locale)
	}
	if endpoint.Judgment != "" {
		line += " · " + topologyJudgmentLabel(endpoint.Judgment, locale)
	}
	if endpoint.ConnectionCount != nil {
		line += fmt.Sprintf(choose(locale, " · 当前 TCP 连接=%d", " · current TCP connections=%d"), *endpoint.ConnectionCount)
	}
	return line
}

func topologyLinkLines(deployment model.Deployment, locale string) []string {
	endpoints := make(map[string]model.ServiceEndpoint, len(deployment.Endpoints))
	for _, endpoint := range deployment.Endpoints {
		endpoints[endpoint.ID] = endpoint
	}
	var out []string
	for _, link := range deployment.Links {
		if link.Kind != "proxies-to" && link.Kind != "routes-to" {
			continue
		}
		from, fromOK := endpoints[link.From]
		to, toOK := endpoints[link.To]
		if !fromOK || !toOK {
			continue
		}
		out = append(out, fmt.Sprintf("%d/%s %s %s %d/%s · %s", from.Port, from.Transport, choose(locale, "转发到", "proxies to"), topologyRoleLabel(to.Role, locale), to.Port, to.Transport, topologyJudgmentLabel(to.Judgment, locale)))
	}
	return out
}

func topologyCoverageLines(coverage model.DeploymentCoverage, locale string) []string {
	items := []struct{ name, value string }{
		{choose(locale, "代理配置", "proxy configuration"), coverage.Configuration},
		{choose(locale, "实际监听", "live listeners"), coverage.Runtime},
		{choose(locale, "主机防火墙", "host firewall"), coverage.Firewall},
		{choose(locale, "面板", "panels"), coverage.Panels},
		{choose(locale, "反向代理", "reverse proxy"), coverage.ReverseProxy},
		{"Docker", coverage.Docker},
	}
	var out []string
	for _, item := range items {
		if item.value == "partial" || item.value == "unavailable" {
			out = append(out, item.name+"="+topologyCoverageLabel(item.value, locale))
		}
	}
	return out
}

func topologyFindingLabel(r model.Report, role string) string {
	id := map[string]string{
		"management": "WORK-002", "subscription": "WORK-012", "proxy-ingress": "WORK-009",
		"control-api": "WORK-005", "container-publish": "DOCKER-002",
		"unclassified-listener": "NET-002", "unclassified-product-listener": "WORK-012",
	}[role]
	if finding, ok := findingByID(r, id); ok {
		return findingLabel(finding)
	}
	return "[INFO]"
}

func topologyJudgmentNeedsReview(judgment string) bool {
	return containsAnyText(judgment, "not-listening", "unknown", "exposed", "does-not-match", "not-classified", "blocked", "mismatch")
}

func containsAnyText(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func uniqueSortedLimited(lines []string, limit int, locale string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if line != "" && !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return limitOverviewLines(out, limit, locale)
}

func topologyRoleLabel(value, locale string) string {
	labels := map[string][2]string{
		"proxy-ingress":                 {"代理入口", "proxy ingress"},
		"management":                    {"管理面", "management"},
		"subscription":                  {"订阅端点", "subscription"},
		"control-api":                   {"控制 API", "control API"},
		"reverse-proxy-frontend":        {"反向代理前端", "reverse-proxy frontend"},
		"reverse-proxy-backend":         {"反向代理后端", "reverse-proxy backend"},
		"container-publish":             {"容器发布端口", "container publish"},
		"unclassified-listener":         {"用途未识别监听", "unclassified listener"},
		"unclassified-product-listener": {"代理进程未归类监听", "unclassified proxy listener"},
	}
	if label, ok := labels[value]; ok {
		return i18n.UI(locale, label[0], label[1])
	}
	return value
}

func topologyPathLabel(value, locale string) string {
	if value == "root-or-default" {
		return choose(locale, "根/默认路径", "root/default path")
	}
	if value == "non-default" {
		return choose(locale, "非默认路径", "non-default path")
	}
	return value
}

func topologyCoverageLabel(value, locale string) string {
	labels := map[string][2]string{
		"complete": {"完整", "complete"}, "partial": {"部分完成", "partial"},
		"unavailable": {"不可用", "unavailable"}, "not-applicable": {"不适用", "not applicable"},
	}
	if label, ok := labels[value]; ok {
		return i18n.UI(locale, label[0], label[1])
	}
	return value
}

func topologyJudgmentLabel(value, locale string) string {
	labels := map[string][2]string{
		"expected-proxy-ingress":                             {"符合入口预期", "expected proxy ingress"},
		"active_product_but_not_listening":                   {"运行中的核心没有对应监听", "active core has no matching listener"},
		"configured_not_listening":                           {"已配置但未监听", "configured but not listening"},
		"listener-owner-does-not-match-configured-product":   {"监听进程与配置产品不匹配", "listener process does not match configured product"},
		"configured-public-ingress-blocked-by-host-firewall": {"被主机防火墙阻断", "blocked by host firewall"},
		"configured-public-ingress-firewall-unknown":         {"防火墙关系未知", "firewall relationship unknown"},
		"internal-control-endpoint":                          {"仅内部访问", "internal only"},
		"public-control-exposed":                             {"控制 API 公网暴露", "public control API exposure"},
		"public-control-restricted":                          {"控制 API 受防火墙限制", "control API restricted by firewall"},
		"configured-control-not-listening":                   {"控制 API 未监听", "control API not listening"},
		"internal-panel-endpoint":                            {"面板仅内部访问", "panel endpoint is internal"},
		"public-management-exposed":                          {"管理面公网暴露", "public management exposure"},
		"public-management-restricted":                       {"管理面受防火墙限制", "management restricted by firewall"},
		"public-subscription-exposed":                        {"订阅端点公网开放", "public subscription endpoint"},
		"public-subscription-restricted":                     {"订阅端点受防火墙限制", "subscription restricted by firewall"},
		"configured-panel-endpoint-not-listening":            {"面板端点未监听", "panel endpoint not listening"},
		"reverse-proxy-frontend-live":                        {"反向代理前端正在监听", "reverse-proxy frontend is live"},
		"reverse-proxy-backend-live":                         {"反向代理后端正在监听", "reverse-proxy backend is live"},
		"configured-frontend-not-listening":                  {"反向代理前端未监听", "reverse-proxy frontend not listening"},
		"configured-backend-not-listening":                   {"反向代理后端未监听", "reverse-proxy backend not listening"},
		"external-upstream-not-verified":                     {"外部上游未在本机验证", "external upstream not verified locally"},
		"docker-published-port":                              {"Docker 发布端口", "Docker-published port"},
		"listener-purpose-not-classified":                    {"用途未能归类", "listener purpose not classified"},
	}
	if label, ok := labels[value]; ok {
		return i18n.UI(locale, label[0], label[1])
	}
	return strings.ReplaceAll(value, "-", " ")
}
