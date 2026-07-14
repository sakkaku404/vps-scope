package app

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type semanticChange struct {
	Kind, ID, MessageZH, MessageEN string
}

type numericSemantic struct {
	ID, Key, ZH, EN string
	HigherIsBetter  bool
}

var numericSemantics = []numericSemantic{
	{"WORK-002", "public_unrestricted_management", "公网无限制管理面", "public unrestricted management endpoints", false},
	{"WORK-002", "public_plaintext_management", "公网明文管理面", "public plaintext management endpoints", false},
	{"WORK-002", "public_default_path_management", "公网默认路径管理面", "public default-path management endpoints", false},
	{"WORK-012", "runtime_mismatches", "面板与运行态不一致", "panel/runtime mismatches", false},
	{"WORK-012", "public_plaintext_subscription_listeners", "公网明文订阅入口", "public plaintext subscription listeners", false},
	{"WORK-012", "disabled_inbounds_still_listening", "已禁用但仍监听的入口", "disabled inbounds still listening", false},
	{"DOCKER-001", "isolation_problems", "Docker 隔离问题", "Docker isolation problems", false},
	{"DOCKER-002", "input_policy_bypass_paths", "绕过主机 INPUT 策略的 Docker 路径", "Docker paths bypassing host INPUT policy", false},
	{"TLS-001", "minimum_certificate_days", "最短证书剩余天数", "minimum certificate days remaining", true},
	{"SSH-005", "authorized_keys", "授权 SSH 密钥数量", "authorized SSH key count", false},
}

func semanticDiff(oldReport, newReport model.Report) ([]semanticChange, map[string]bool) {
	oldMap, newMap := findingMap(oldReport), findingMap(newReport)
	covered := map[string]bool{}
	var out []semanticChange
	if oldReport.Metadata["audit_depth"] != newReport.Metadata["audit_depth"] {
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "审计深度不同：" + displayEmpty(oldReport.Metadata["audit_depth"]) + " → " + displayEmpty(newReport.Metadata["audit_depth"]), MessageEN: "audit depth differs: " + displayEmpty(oldReport.Metadata["audit_depth"]) + " -> " + displayEmpty(newReport.Metadata["audit_depth"])})
	}
	if oldReport.Profile.Effective != newReport.Profile.Effective {
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "Profile 不同：" + displayEmpty(oldReport.Profile.Effective) + " → " + displayEmpty(newReport.Profile.Effective), MessageEN: "profile differs: " + displayEmpty(oldReport.Profile.Effective) + " -> " + displayEmpty(newReport.Profile.Effective)})
	}
	if oldReport.LogSince != newReport.LogSince {
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "日志观察窗口不同：" + displayEmpty(oldReport.LogSince) + " → " + displayEmpty(newReport.LogSince), MessageEN: "log observation window differs: " + displayEmpty(oldReport.LogSince) + " -> " + displayEmpty(newReport.LogSince)})
	}
	for id, oldFinding := range oldMap {
		newFinding, ok := newMap[id]
		if !ok {
			continue
		}
		if oldFinding.NotApplicable != newFinding.NotApplicable {
			covered[id] = true
			messageZH, messageEN := "本次开始评估该检查", "check is evaluated in the new run"
			if newFinding.NotApplicable {
				messageZH, messageEN = "本次不再评估该检查", "check is not evaluated in the new run"
			}
			out = append(out, semanticChange{Kind: "CHANGE", ID: id, MessageZH: messageZH, MessageEN: messageEN})
			continue
		}
		if oldFinding.Status == newFinding.Status {
			continue
		}
		kind := statusChangeKind(oldFinding.Status, newFinding.Status)
		if kind == "CHANGE" {
			continue
		}
		covered[id] = true
		out = append(out, semanticChange{Kind: kind, ID: id,
			MessageZH: fmt.Sprintf("状态从 %s 变为 %s", oldFinding.Status, newFinding.Status),
			MessageEN: fmt.Sprintf("status changed from %s to %s", oldFinding.Status, newFinding.Status)})
	}
	for _, spec := range numericSemantics {
		o, okOld := numericFact(oldMap[spec.ID], spec.Key)
		n, okNew := numericFact(newMap[spec.ID], spec.Key)
		if !okOld || !okNew || o == n {
			continue
		}
		regression := n > o
		if spec.HigherIsBetter {
			regression = n < o
		}
		kind := "IMPROVEMENT"
		if regression {
			kind = "REGRESSION"
		}
		covered[spec.ID] = true
		out = append(out, semanticChange{Kind: kind, ID: spec.ID,
			MessageZH: fmt.Sprintf("%s：%d → %d", spec.ZH, o, n),
			MessageEN: fmt.Sprintf("%s: %d -> %d", spec.EN, o, n)})
	}
	if o, n := oldMap["TLS-001"].Facts["renewal_state"], newMap["TLS-001"].Facts["renewal_state"]; o != "" && n != "" && o != n {
		kind := "CHANGE"
		if renewalStateRank(n) > renewalStateRank(o) {
			kind = "IMPROVEMENT"
		} else if renewalStateRank(n) < renewalStateRank(o) {
			kind = "REGRESSION"
		}
		covered["TLS-001"] = true
		out = append(out, semanticChange{Kind: kind, ID: "TLS-001", MessageZH: "证书续期闭环：" + o + " → " + n, MessageEN: "certificate renewal state: " + o + " -> " + n})
	}
	if o, n := oldMap["WORK-001"].Facts["products"], newMap["WORK-001"].Facts["products"]; o != n {
		covered["WORK-001"] = true
		out = append(out, semanticChange{Kind: "CHANGE", ID: "WORK-001", MessageZH: "识别到的工作负载：" + displayEmpty(o) + " → " + displayEmpty(n), MessageEN: "detected workloads: " + displayEmpty(o) + " -> " + displayEmpty(n)})
	}
	return out, covered
}

func numericFact(f model.Finding, key string) (int, bool) {
	value, ok := f.Facts[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	return n, err == nil
}

func statusChangeKind(oldStatus, newStatus model.Status) string {
	if newStatus == model.Risk && oldStatus != model.Risk || newStatus == model.Unknown && oldStatus == model.Pass {
		return "REGRESSION"
	}
	if oldStatus == model.Risk && newStatus != model.Risk || oldStatus == model.Unknown && newStatus == model.Pass {
		return "IMPROVEMENT"
	}
	return "CHANGE"
}

func renewalStateRank(value string) int {
	return map[string]int{"failing": 0, "not-established": 1, "scheduled-unverified": 2, "verified": 3, "verified-with-reload": 4}[value]
}

func displayEmpty(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(none)"
	}
	return value
}
