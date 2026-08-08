package app

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type semanticChange struct {
	Kind, ID, MessageZH, MessageEN, MessageRU, MessageFA string
}

func (change semanticChange) message(locale string) string {
	switch locale {
	case "zh-CN":
		return change.MessageZH
	case "ru-RU":
		return change.MessageRU
	case "fa-IR":
		return change.MessageFA
	default:
		return change.MessageEN
	}
}

type numericSemantic struct {
	ID, Key, ZH, EN, RU, FA string
	HigherIsBetter          bool
}

var numericSemantics = []numericSemantic{
	{"WORK-002", "public_unrestricted_management", "公网无限制管理面", "public unrestricted management endpoints", "публичные панели управления без ограничений", "نقاط مدیریت عمومی بدون محدودیت", false},
	{"WORK-002", "public_plaintext_management", "公网明文管理面", "public plaintext management endpoints", "публичные панели управления без TLS", "نقاط مدیریت عمومی بدون TLS", false},
	{"WORK-002", "public_default_path_management", "公网默认路径管理面", "public default-path management endpoints", "публичные панели управления с путём по умолчанию", "نقاط مدیریت عمومی با مسیر پیش\u200cفرض", false},
	{"WORK-012", "runtime_mismatches", "面板与运行态不一致", "panel/runtime mismatches", "расхождения панели и фактического состояния", "ناسازگاری پنل و وضعیت اجرا", false},
	{"WORK-012", "public_plaintext_subscription_listeners", "公网明文订阅入口", "public plaintext subscription listeners", "публичные точки подписки без TLS", "نقاط اشتراک عمومی بدون TLS", false},
	{"WORK-012", "disabled_inbounds_still_listening", "已禁用但仍监听的入口", "disabled inbounds still listening", "отключённые входы, которые всё ещё слушают", "ورودی\u200cهای غیرفعال که هنوز در حال گوش\u200cدادن هستند", false},
	{"DOCKER-001", "isolation_problems", "Docker 隔离问题", "Docker isolation problems", "проблемы изоляции Docker", "مشکلات جداسازی Docker", false},
	{"DOCKER-002", "input_policy_bypass_paths", "绕过主机 INPUT 策略的 Docker 路径", "Docker paths bypassing host INPUT policy", "пути Docker в обход политики INPUT хоста", "مسیرهای Docker که سیاست INPUT میزبان را دور می\u200cزنند", false},
	{"TLS-001", "minimum_certificate_days", "最短证书剩余天数", "minimum certificate days remaining", "минимальный остаток срока сертификата в днях", "کمترین روز باقی\u200cمانده اعتبار گواهی", true},
	{"SSH-005", "authorized_keys", "授权 SSH 密钥数量", "authorized SSH key count", "число авторизованных ключей SSH", "تعداد کلیدهای SSH مجاز", false},
}

func semanticDiff(oldReport, newReport model.Report) ([]semanticChange, map[string]bool) {
	oldMap, newMap := findingMap(oldReport), findingMap(newReport)
	covered := map[string]bool{}
	var out []semanticChange
	if oldReport.ToolVersion != newReport.ToolVersion {
		o, n := displayEmpty(oldReport.ToolVersion), displayEmpty(newReport.ToolVersion)
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "工具版本不同：" + o + " -> " + n, MessageEN: "tool version differs: " + o + " -> " + n, MessageRU: "версия инструмента отличается: " + o + " -> " + n, MessageFA: "نسخه ابزار متفاوت است: " + o + " -> " + n})
	}
	if oldReport.Metadata["audit_depth"] != newReport.Metadata["audit_depth"] {
		o, n := displayEmpty(oldReport.Metadata["audit_depth"]), displayEmpty(newReport.Metadata["audit_depth"])
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "审计深度不同：" + o + " → " + n, MessageEN: "audit depth differs: " + o + " -> " + n, MessageRU: "глубина аудита отличается: " + o + " -> " + n, MessageFA: "عمق ممیزی متفاوت است: " + o + " -> " + n})
	}
	if oldReport.Profile.Effective != newReport.Profile.Effective {
		o, n := displayEmpty(oldReport.Profile.Effective), displayEmpty(newReport.Profile.Effective)
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "Profile 不同：" + o + " → " + n, MessageEN: "profile differs: " + o + " -> " + n, MessageRU: "профиль отличается: " + o + " -> " + n, MessageFA: "نمایه متفاوت است: " + o + " -> " + n})
	}
	if oldReport.LogSince != newReport.LogSince {
		o, n := displayEmpty(oldReport.LogSince), displayEmpty(newReport.LogSince)
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: "日志观察窗口不同：" + o + " → " + n, MessageEN: "log observation window differs: " + o + " -> " + n, MessageRU: "окно анализа журналов отличается: " + o + " -> " + n, MessageFA: "بازه بررسی گزارش\u200cها متفاوت است: " + o + " -> " + n})
	}
	for _, key := range []struct{ metadata, zh, en, ru, fa string }{
		{"native_self_test_mode", "原生自检模式", "native self-test mode", "режим встроенной самопроверки", "حالت خودآزمایی بومی"},
		{"collection_timed_out", "采集超时状态", "collection timeout state", "состояние тайм-аута сбора", "وضعیت پایان مهلت گردآوری"},
	} {
		if oldReport.Metadata[key.metadata] == newReport.Metadata[key.metadata] {
			continue
		}
		o, n := displayEmpty(oldReport.Metadata[key.metadata]), displayEmpty(newReport.Metadata[key.metadata])
		out = append(out, semanticChange{Kind: "CONTEXT", ID: "RUN", MessageZH: key.zh + "不同：" + o + " -> " + n, MessageEN: key.en + " differs: " + o + " -> " + n, MessageRU: key.ru + ": " + o + " -> " + n, MessageFA: key.fa + ": " + o + " -> " + n})
	}
	commonIDs := make([]string, 0, len(oldMap))
	for id := range oldMap {
		if _, ok := newMap[id]; ok {
			commonIDs = append(commonIDs, id)
		}
	}
	sort.Strings(commonIDs)
	for _, id := range commonIDs {
		oldFinding := oldMap[id]
		newFinding, ok := newMap[id]
		if !ok {
			continue
		}
		if oldFinding.NotApplicable != newFinding.NotApplicable {
			covered[id] = true
			messageZH, messageEN, messageRU, messageFA := "本次开始评估该检查", "check is evaluated in the new run", "в новом запуске эта проверка выполняется", "این بررسی در اجرای جدید ارزیابی می\u200cشود"
			if newFinding.NotApplicable {
				messageZH, messageEN, messageRU, messageFA = "本次不再评估该检查", "check is not evaluated in the new run", "в новом запуске эта проверка не выполняется", "این بررسی در اجرای جدید ارزیابی نمی\u200cشود"
			}
			out = append(out, semanticChange{Kind: "CHANGE", ID: id, MessageZH: messageZH, MessageEN: messageEN, MessageRU: messageRU, MessageFA: messageFA})
			continue
		}
		if oldFinding.Status == newFinding.Status && oldFinding.ReasonCode != "" && newFinding.ReasonCode != "" && oldFinding.ReasonCode != newFinding.ReasonCode {
			covered[id] = true
			out = append(out, semanticChange{Kind: "CHANGE", ID: id,
				MessageZH: "主要原因变化：" + oldFinding.ReasonCode + " → " + newFinding.ReasonCode,
				MessageEN: "primary reason changed: " + oldFinding.ReasonCode + " -> " + newFinding.ReasonCode,
				MessageRU: "основная причина изменилась: " + oldFinding.ReasonCode + " -> " + newFinding.ReasonCode,
				MessageFA: "دلیل اصلی تغییر کرد: " + oldFinding.ReasonCode + " -> " + newFinding.ReasonCode})
			continue
		}
		if oldFinding.Status == model.Risk && newFinding.Status == model.Risk && oldFinding.Severity != newFinding.Severity {
			kind := "IMPROVEMENT"
			if semanticSeverityRank(newFinding.Severity) < semanticSeverityRank(oldFinding.Severity) {
				kind = "REGRESSION"
			}
			covered[id] = true
			out = append(out, semanticChange{Kind: kind, ID: id,
				MessageZH: fmt.Sprintf("风险严重度从 %s 变为 %s", oldFinding.Severity, newFinding.Severity),
				MessageEN: fmt.Sprintf("risk severity changed from %s to %s", oldFinding.Severity, newFinding.Severity),
				MessageRU: fmt.Sprintf("серьёзность риска изменилась с %s на %s", oldFinding.Severity, newFinding.Severity),
				MessageFA: fmt.Sprintf("شدت خطر از %s به %s تغییر کرد", oldFinding.Severity, newFinding.Severity)})
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
			MessageEN: fmt.Sprintf("status changed from %s to %s", oldFinding.Status, newFinding.Status),
			MessageRU: fmt.Sprintf("статус изменился с %s на %s", oldFinding.Status, newFinding.Status),
			MessageFA: fmt.Sprintf("وضعیت از %s به %s تغییر کرد", oldFinding.Status, newFinding.Status)})
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
			MessageEN: fmt.Sprintf("%s: %d -> %d", spec.EN, o, n),
			MessageRU: fmt.Sprintf("%s: %d -> %d", spec.RU, o, n),
			MessageFA: fmt.Sprintf("%s: %d -> %d", spec.FA, o, n)})
	}
	if o, n := oldMap["TLS-001"].Facts["renewal_state"], newMap["TLS-001"].Facts["renewal_state"]; o != "" && n != "" && o != n {
		kind := "CHANGE"
		if renewalStateRank(n) > renewalStateRank(o) {
			kind = "IMPROVEMENT"
		} else if renewalStateRank(n) < renewalStateRank(o) {
			kind = "REGRESSION"
		}
		covered["TLS-001"] = true
		out = append(out, semanticChange{Kind: kind, ID: "TLS-001", MessageZH: "证书续期闭环：" + o + " → " + n, MessageEN: "certificate renewal state: " + o + " -> " + n, MessageRU: "состояние продления сертификата: " + o + " -> " + n, MessageFA: "وضعیت تمدید گواهی: " + o + " -> " + n})
	}
	if o, n := oldMap["WORK-001"].Facts["products"], newMap["WORK-001"].Facts["products"]; o != n {
		covered["WORK-001"] = true
		o, n = displayEmpty(o), displayEmpty(n)
		out = append(out, semanticChange{Kind: "CHANGE", ID: "WORK-001", MessageZH: "识别到的工作负载：" + o + " → " + n, MessageEN: "detected workloads: " + o + " -> " + n, MessageRU: "обнаруженные нагрузки: " + o + " -> " + n, MessageFA: "بارهای کاری شناسایی\u200cشده: " + o + " -> " + n})
	}
	out = append(out, topologySemanticDiff(oldReport.Deployment, newReport.Deployment)...)
	return out, covered
}

func semanticSeverityRank(value model.Severity) int {
	return map[model.Severity]int{model.Critical: 0, model.High: 1, model.Medium: 2, model.Low: 3}[value]
}

func topologySemanticDiff(oldDeployment, newDeployment *model.Deployment) []semanticChange {
	if oldDeployment == nil && newDeployment == nil {
		return nil
	}
	if oldDeployment == nil || newDeployment == nil {
		messageZH, messageEN, messageRU, messageFA := "新报告开始提供结构化部署拓扑", "structured deployment topology is available in the new report", "в новом отчёте доступна структурированная топология развёртывания", "توپولوژی ساختاریافته استقرار در گزارش جدید موجود است"
		if newDeployment == nil {
			messageZH, messageEN, messageRU, messageFA = "新报告缺少结构化部署拓扑", "structured deployment topology is missing from the new report", "в новом отчёте отсутствует структурированная топология развёртывания", "توپولوژی ساختاریافته استقرار در گزارش جدید وجود ندارد"
		}
		return []semanticChange{{Kind: "CONTEXT", ID: "TOPOLOGY", MessageZH: messageZH, MessageEN: messageEN, MessageRU: messageRU, MessageFA: messageFA}}
	}
	oldEndpoints, newEndpoints := endpointTopologyMap(oldDeployment.Endpoints), endpointTopologyMap(newDeployment.Endpoints)
	ids := make([]string, 0, len(oldEndpoints)+len(newEndpoints))
	seen := map[string]bool{}
	for id := range oldEndpoints {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range newEndpoints {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []semanticChange
	for _, id := range ids {
		oldEndpoint, oldOK := oldEndpoints[id]
		newEndpoint, newOK := newEndpoints[id]
		switch {
		case !oldOK:
			kind := "CHANGE"
			if topologyEndpointRisky(newEndpoint) {
				kind = "REGRESSION"
			}
			identity := topologyEndpointIdentity(newEndpoint)
			out = append(out, semanticChange{Kind: kind, ID: "TOPOLOGY", MessageZH: "新增端点：" + identity, MessageEN: "endpoint added: " + identity, MessageRU: "добавлена конечная точка: " + identity, MessageFA: "نقطه پایانی اضافه شد: " + identity})
		case !newOK:
			kind := "CHANGE"
			if topologyEndpointRisky(oldEndpoint) {
				kind = "IMPROVEMENT"
			}
			identity := topologyEndpointIdentity(oldEndpoint)
			out = append(out, semanticChange{Kind: kind, ID: "TOPOLOGY", MessageZH: "端点消失：" + identity, MessageEN: "endpoint removed: " + identity, MessageRU: "конечная точка удалена: " + identity, MessageFA: "نقطه پایانی حذف شد: " + identity})
		default:
			oldPosture, newPosture := topologyEndpointPosture(oldEndpoint), topologyEndpointPosture(newEndpoint)
			if oldPosture == newPosture {
				continue
			}
			kind := "CHANGE"
			if topologyEndpointRisky(newEndpoint) && !topologyEndpointRisky(oldEndpoint) {
				kind = "REGRESSION"
			} else if topologyEndpointRisky(oldEndpoint) && !topologyEndpointRisky(newEndpoint) {
				kind = "IMPROVEMENT"
			}
			identity := topologyEndpointIdentity(newEndpoint)
			out = append(out, semanticChange{Kind: kind, ID: "TOPOLOGY", MessageZH: identity + "：" + oldPosture + " → " + newPosture, MessageEN: identity + ": " + oldPosture + " -> " + newPosture, MessageRU: identity + ": " + oldPosture + " -> " + newPosture, MessageFA: identity + ": " + oldPosture + " -> " + newPosture})
		}
	}
	coverageNames := []struct {
		nameZH, nameEN, nameRU, nameFA, oldValue, newValue string
	}{
		{"配置证据", "configuration evidence", "данные конфигурации", "شواهد پیکربندی", oldDeployment.Coverage.Configuration, newDeployment.Coverage.Configuration},
		{"监听证据", "runtime evidence", "данные фактического состояния", "شواهد وضعیت اجرا", oldDeployment.Coverage.Runtime, newDeployment.Coverage.Runtime},
		{"防火墙证据", "firewall evidence", "данные межсетевого экрана", "شواهد دیواره آتش", oldDeployment.Coverage.Firewall, newDeployment.Coverage.Firewall},
		{"面板证据", "panel evidence", "данные панели", "شواهد پنل", oldDeployment.Coverage.Panels, newDeployment.Coverage.Panels},
		{"反向代理证据", "reverse-proxy evidence", "данные обратного прокси", "شواهد پراکسی معکوس", oldDeployment.Coverage.ReverseProxy, newDeployment.Coverage.ReverseProxy},
		{"Docker 证据", "Docker evidence", "данные Docker", "شواهد Docker", oldDeployment.Coverage.Docker, newDeployment.Coverage.Docker},
	}
	for _, coverage := range coverageNames {
		if coverage.oldValue == coverage.newValue {
			continue
		}
		kind := "CHANGE"
		if coverageRank(coverage.newValue) < coverageRank(coverage.oldValue) {
			kind = "REGRESSION"
		} else if coverageRank(coverage.newValue) > coverageRank(coverage.oldValue) {
			kind = "IMPROVEMENT"
		}
		out = append(out, semanticChange{Kind: kind, ID: "TOPOLOGY", MessageZH: coverage.nameZH + "：" + coverage.oldValue + " → " + coverage.newValue, MessageEN: coverage.nameEN + ": " + coverage.oldValue + " -> " + coverage.newValue, MessageRU: coverage.nameRU + ": " + coverage.oldValue + " -> " + coverage.newValue, MessageFA: coverage.nameFA + ": " + coverage.oldValue + " -> " + coverage.newValue})
	}
	return out
}

func endpointTopologyMap(endpoints []model.ServiceEndpoint) map[string]model.ServiceEndpoint {
	out := make(map[string]model.ServiceEndpoint, len(endpoints))
	for _, endpoint := range endpoints {
		out[endpoint.ID] = endpoint
	}
	return out
}

func topologyEndpointIdentity(endpoint model.ServiceEndpoint) string {
	product := endpoint.Product
	if product == "" {
		product = "unknown"
	}
	return fmt.Sprintf("%s %s %d/%s", product, endpoint.Role, endpoint.Port, endpoint.Transport)
}

func topologyEndpointPosture(endpoint model.ServiceEndpoint) string {
	return strings.Join([]string{displayEmpty(endpoint.State), displayEmpty(endpoint.Scope), displayEmpty(endpoint.Firewall), displayEmpty(endpoint.Judgment)}, "/")
}

func topologyEndpointRisky(endpoint model.ServiceEndpoint) bool {
	if endpoint.Confidence == "unknown" || strings.Contains(endpoint.Judgment, "unknown") {
		return true
	}
	if strings.Contains(endpoint.Judgment, "blocked") || strings.Contains(endpoint.Judgment, "not-listening") || strings.Contains(endpoint.Judgment, "does-not-match") || strings.Contains(endpoint.Judgment, "not-classified") {
		return true
	}
	return (endpoint.Role == "management" || endpoint.Role == "control-api") && (endpoint.Scope == "public" || endpoint.Scope == "public-wildcard") && (endpoint.Firewall == "allow-anywhere" || endpoint.Firewall == "inactive")
}

func coverageRank(value string) int {
	return map[string]int{"unavailable": 0, "partial": 1, "not-applicable": 2, "complete": 3}[value]
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
