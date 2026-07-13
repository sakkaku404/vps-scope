package report

import (
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
	case "WORK-002", "WORK-005":
		return choose(zh, "明确风险：管理面可从公网访问，应限制访问来源。", "Confirmed risk: a management plane is reachable from the public internet; restrict its access.")
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
