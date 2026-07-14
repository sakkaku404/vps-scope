package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// actionSummary is a presentation-only reading aid. It deliberately does not
// alter findings, severity, or raw evidence in JSON reports.
type actionSummary struct {
	Urgent       []actionItem
	Availability []actionItem
	Maintenance  []actionItem
	EvidenceGaps []actionItem
}

type actionItem struct {
	Localized localizedFinding
	Verdict   string
}

type overallVerdict struct {
	Headline string
	Detail   string
}

func overallVerdictFor(r model.Report, locale string) overallVerdict {
	actions := summarizeActions(r, locale)
	zh := locale == "zh-CN"
	confirmed := len(actions.Urgent) + len(actions.Availability) + len(actions.Maintenance)
	gaps := len(actions.EvidenceGaps)
	if confirmed == 0 && gaps == 0 {
		return overallVerdict{choose(zh, "本次未发现明确风险", "No confirmed risks in this run"), choose(zh, "这不等于服务器绝对安全；它表示本次可读取证据未触发风险判断。", "This is not proof of an uncompromised host; available evidence did not trigger a risk finding.")}
	}
	if confirmed == 0 {
		return overallVerdict{choose(zh, "没有明确风险，但存在证据缺口", "No confirmed risks, with evidence gaps"), fmt.Sprintf(choose(zh, "%d 项检查无法形成可靠结论，应先查看 UNKNOWN。", "%d checks could not reach a reliable conclusion; review UNKNOWN first."), gaps)}
	}
	return overallVerdict{fmt.Sprintf(choose(zh, "发现 %d 项需要处理的问题", "%d findings need attention"), confirmed), fmt.Sprintf(choose(zh, "其中 %d 项优先处理，%d 项可能影响可用性，另有 %d 项证据不足。", "%d urgent, %d availability-related, and %d evidence gaps."), len(actions.Urgent), len(actions.Availability), gaps)}
}

func summarizeActions(r model.Report, locale string) actionSummary {
	zh := locale == "zh-CN"
	var summary actionSummary
	for _, finding := range r.Findings {
		if finding.NotApplicable {
			continue
		}
		item := actionItem{Localized: localize(finding, locale), Verdict: verdictForFinding(finding, zh)}
		switch actionBandForFinding(finding) {
		case "urgent":
			summary.Urgent = append(summary.Urgent, item)
		case "availability":
			summary.Availability = append(summary.Availability, item)
		case "maintenance":
			summary.Maintenance = append(summary.Maintenance, item)
		case "evidence-gap":
			summary.EvidenceGaps = append(summary.EvidenceGaps, item)
		}
	}
	for _, items := range [][]actionItem{summary.Urgent, summary.Availability, summary.Maintenance, summary.EvidenceGaps} {
		sort.SliceStable(items, func(i, j int) bool {
			return actionRank(items[i].Localized.Finding) < actionRank(items[j].Localized.Finding)
		})
	}
	return summary
}

func actionBandForFinding(f model.Finding) string {
	if f.Status == model.Unknown {
		return "evidence-gap"
	}
	if f.Status != model.Risk {
		return ""
	}
	if f.ID == "WORK-009" || f.ID == "TLS-001" {
		return "availability"
	}
	if f.Severity == model.Critical || f.Severity == model.High {
		return "urgent"
	}
	return "maintenance"
}

func actionRank(f model.Finding) int {
	ranks := map[model.Severity]int{model.Critical: 0, model.High: 1, model.Medium: 2, model.Low: 3}
	return ranks[f.Severity]*10000 + int(f.ID[0])
}

func verdictForFinding(f model.Finding, zh bool) string {
	blocked := evidenceContains(f, "blocked-by-host-firewall") || evidenceContains(f, "blocked by host firewall")
	switch f.ID {
	case "SSH-001":
		return choose(zh, "明确风险：SSH 密码认证已经生效。", "Confirmed risk: SSH password authentication is effective.")
	case "SSH-002":
		return choose(zh, "明确风险：root 可以直接通过 SSH 登录。", "Confirmed risk: root can log in directly through SSH.")
	case "WORK-002":
		defaultPath := evidenceContains(f, "root-or-default-path")
		plaintext := evidenceContains(f, "plaintext-panel")
		switch {
		case defaultPath && plaintext:
			return choose(zh, "明确风险：管理面从公网明文开放，并使用根或默认路径；路径隐藏不能替代访问控制。", "Confirmed risk: the management panel is publicly reachable over plaintext at a root/default path; path obscurity is not access control.")
		case defaultPath:
			return choose(zh, "明确风险：管理面可从公网访问，并使用根或默认路径；应限制访问来源。", "Confirmed risk: the management panel is publicly reachable at a root/default path; restrict its sources.")
		case plaintext:
			return choose(zh, "明确风险：管理面从公网明文开放；应启用 TLS 并限制访问来源。", "Confirmed risk: the management panel is publicly reachable over plaintext; enable TLS and restrict its sources.")
		default:
			return choose(zh, "明确风险：管理面可从公网访问，应限制访问来源。", "Confirmed risk: a management panel is reachable from the public internet; restrict its sources.")
		}
	case "WORK-005":
		return choose(zh, "明确风险：代理控制 API 可从公网访问，应改为回环监听或限制访问来源。", "Confirmed risk: a proxy control API is publicly reachable; bind it to loopback or restrict its sources.")
	case "WORK-012":
		if evidenceContains(f, "disabled_inbound_still_listening") {
			return choose(zh, "明确风险：面板中已禁用的代理入口仍在监听，旧入口可能继续被使用。", "Confirmed risk: an ingress disabled in the panel is still listening, so stale access may remain usable.")
		}
		return choose(zh, "需要核对：面板数据库、生成配置和实际监听之间存在无法解释的差异。", "Review needed: the panel database, generated configuration, and live listeners do not agree.")
	case "WORK-009":
		if blocked {
			return choose(zh, "可用性问题：已配置的代理入口被主机防火墙阻断。", "Availability issue: a configured proxy ingress is blocked by the host firewall.")
		}
		return choose(zh, "需要核对：配置、运行监听或防火墙证据不一致。", "Review needed: configuration, live listener, or firewall evidence does not agree.")
	case "TLS-001":
		return choose(zh, "可用性问题：证书已过期、即将过期或续期证据不足。", "Availability issue: the certificate is expired, near expiry, or renewal evidence is missing.")
	case "FW-002":
		return choose(zh, "维护问题：防火墙允许范围需要与当前服务重新核对。", "Maintenance issue: firewall allowances should be reconciled with current services.")
	case "UPD-001":
		return choose(zh, "维护问题：待安装更新需要按安全更新和普通更新分别处理。", "Maintenance issue: pending updates need separate security and routine-update handling.")
	}
	if f.Status == model.Unknown {
		return choose(zh, "证据不足：本次审计不能确认这一项安全。", "Evidence gap: this audit cannot confirm that this item is safe.")
	}
	return choose(zh, "需要处理：请结合下面的证据和建议确认。", "Action needed: confirm using the evidence and suggestion below.")
}

func evidenceContains(f model.Finding, phrase string) bool {
	phrase = strings.ToLower(phrase)
	for _, item := range f.Evidence {
		if strings.Contains(strings.ToLower(item.Key+"="+item.Value), phrase) {
			return true
		}
	}
	return false
}

func keyEvidence(f model.Finding) []model.Evidence {
	if len(f.Evidence) <= 2 {
		return f.Evidence
	}
	priority := []string{"management", "panel", "endpoint_relation", "passwordauthentication", "permitrootlogin", "stale", "blocked", "privileged", "host_network", "reboot", "deleted", "sensitive"}
	out := make([]model.Evidence, 0, 2)
	for _, word := range priority {
		for _, item := range f.Evidence {
			if len(out) == 2 {
				return out
			}
			if strings.Contains(strings.ToLower(item.Key+"="+item.Value), word) && !containsEvidence(out, item) {
				out = append(out, item)
			}
		}
	}
	for _, item := range f.Evidence {
		if len(out) == 2 {
			break
		}
		if !containsEvidence(out, item) {
			out = append(out, item)
		}
	}
	return out
}

func containsEvidence(items []model.Evidence, candidate model.Evidence) bool {
	for _, item := range items {
		if item == candidate {
			return true
		}
	}
	return false
}
