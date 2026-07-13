package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// writeProxyOverviewText promotes the non-secret relationship evidence already
// collected by the proxy checks. It is intentionally an inventory: the check
// findings remain the source of truth for their status and severity.
func writeProxyOverviewText(w io.Writer, r model.Report, zh bool, line string) {
	panels, panelOK := findingByID(r, "WORK-002")
	inventory, inventoryOK := findingByID(r, "WORK-003")
	relations, relationsOK := findingByID(r, "WORK-009")
	controls, controlsOK := findingByID(r, "WORK-005")
	if !panelOK && !inventoryOK && !relationsOK && !controlsOK {
		return
	}

	components := setFromCSV(inventory.Facts["products"])
	panelLines := panelOverviewLines(panels, zh)
	endpointLines := endpointOverviewLines(relations, zh)
	controlLines := controlOverviewLines(controls, zh)
	if len(components) == 0 && len(panelLines) == 0 && len(endpointLines) == 0 && len(controlLines) == 0 {
		return
	}

	fmt.Fprintln(w, choose(zh, "代理工作负载概览", "Proxy workload overview"))
	fmt.Fprintln(w, line)
	if len(components) > 0 {
		fmt.Fprintf(w, "%s: %s\n", choose(zh, "已识别组件", "Detected components"), strings.Join(components, ", "))
	}
	writeOverviewGroup(w, choose(zh, "管理面板", "Management panels"), panelLines)
	writeOverviewGroup(w, choose(zh, "代理入口", "Proxy ingress"), endpointLines)
	writeOverviewGroup(w, choose(zh, "控制接口", "Control APIs"), controlLines)
	fmt.Fprintln(w)
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

func panelOverviewLines(f model.Finding, zh bool) []string {
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
	if len(out) == 0 && f.Facts["products"] != "" {
		for _, product := range setFromCSV(f.Facts["products"]) {
			out = append(out, product+" "+findingLabel(f))
		}
	}
	sort.Strings(out)
	return out
}

func endpointOverviewLines(f model.Finding, zh bool) []string {
	if f.ID == "" || f.NotApplicable {
		return nil
	}
	seen := map[string]bool{}
	var out []string
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
		line += fmt.Sprintf(" · %s · %s · %s", scopeLabel(scope, zh), firewallLabel(firewall, zh), judgmentLabel(judgment, zh))
		if !seen[line] {
			seen[line] = true
			out = append(out, line)
		}
	}
	sort.Strings(out)
	return limitOverviewLines(out, 10, zh)
}

func controlOverviewLines(f model.Finding, zh bool) []string {
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
			out = append(out, fmt.Sprintf("%s %s %s/tcp · %s · %s", product, kind, port, scopeLabel(scope, zh), findingLabel(f)))
		}
	}
	sort.Strings(out)
	return limitOverviewLines(out, 6, zh)
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

func limitOverviewLines(lines []string, limit int, zh bool) []string {
	if len(lines) <= limit {
		return lines
	}
	return append(lines[:limit], fmt.Sprintf(choose(zh, "… 另有 %d 项，详见 WORK 证据", "… %d more; see WORK evidence"), len(lines)-limit))
}

func findingLabel(f model.Finding) string {
	if f.Severity == "" {
		return "[" + string(f.Status) + "]"
	}
	return "[" + string(f.Status) + "/" + strings.ToUpper(string(f.Severity)) + "]"
}

func scopeLabel(value string, zh bool) string {
	labels := map[string][2]string{
		"public":          {"公网", "public"},
		"public-wildcard": {"公网通配", "public wildcard"},
		"loopback":        {"回环", "loopback"},
		"private":         {"私网", "private"},
		"none":            {"未监听", "not listening"},
	}
	if label, ok := labels[value]; ok {
		return choose(zh, label[0], label[1])
	}
	return value
}

func firewallLabel(value string, zh bool) string {
	labels := map[string][2]string{
		"allow-anywhere":          {"防火墙允许", "firewall allows"},
		"blocked-by-default":      {"防火墙默认阻断", "firewall default-blocked"},
		"configured-but-not-live": {"未运行", "not live"},
		"not-live":                {"未运行", "not live"},
		"inactive":                {"防火墙未启用", "firewall inactive"},
		"restricted":              {"防火墙受限允许", "firewall restricted"},
	}
	if label, ok := labels[value]; ok {
		return choose(zh, label[0], label[1])
	}
	return value
}

func judgmentLabel(value string, zh bool) string {
	labels := map[string][2]string{
		"expected-proxy-ingress":                             {"符合入口预期", "expected proxy ingress"},
		"configured-public-ingress-blocked-by-host-firewall": {"被主机防火墙阻断", "blocked by host firewall"},
		"configured-but-not-listening":                       {"未找到实际监听", "not listening"},
		"listener-owned-by-different-product":                {"监听进程不匹配", "listener owned by another product"},
	}
	if label, ok := labels[value]; ok {
		return choose(zh, label[0], label[1])
	}
	return value
}
