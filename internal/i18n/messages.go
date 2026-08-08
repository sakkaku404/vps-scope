package i18n

import "fmt"

// MessageID is a stable UI contract. Call sites refer to semantic identifiers
// instead of using the English sentence itself as a translation key. The
// legacy ExtraUI catalog remains the storage format for v1 translations while
// messages are migrated incrementally.
type MessageID string

const (
	MessageAuditTitle               MessageID = "report.audit_title"
	MessageHost                     MessageID = "report.host"
	MessageOS                       MessageID = "report.os"
	MessageArchitecture             MessageID = "report.architecture"
	MessageDetected                 MessageID = "report.detected"
	MessageLogWindow                MessageID = "report.log_window"
	MessageCompleted                MessageID = "report.completed"
	MessageUnavailable              MessageID = "report.unavailable"
	MessageNotApplicable            MessageID = "report.not_applicable"
	MessageProxyAssessment          MessageID = "report.proxy_assessment"
	MessageDetectedComponents       MessageID = "report.detected_components"
	MessageManagementPanels         MessageID = "topology.management_panels"
	MessageProxyIngress             MessageID = "topology.proxy_ingress"
	MessageControlAPIs              MessageID = "topology.control_apis"
	MessageExposureAndRuntimeIssues MessageID = "topology.exposure_runtime_issues"
	MessageDeploymentRelationships  MessageID = "topology.deployment_relationships"
	MessageEvidenceCoverage         MessageID = "topology.evidence_coverage"
	MessageUnclassifiedProcess      MessageID = "topology.unclassified_process"
)

var Messages = map[MessageID]Text{
	MessageAuditTitle:               {ZH: "代理 VPS 安全与运行状态审计", EN: "Proxy VPS security and runtime audit"},
	MessageHost:                     {ZH: "主机", EN: "Host"},
	MessageOS:                       {ZH: "系统", EN: "OS"},
	MessageArchitecture:             {ZH: "架构", EN: "Arch"},
	MessageDetected:                 {ZH: "检测", EN: "detected"},
	MessageLogWindow:                {ZH: "日志范围", EN: "Log window"},
	MessageCompleted:                {ZH: "已执行", EN: "Completed"},
	MessageUnavailable:              {ZH: "不可用", EN: "Unavailable"},
	MessageNotApplicable:            {ZH: "不适用", EN: "Not applicable"},
	MessageProxyAssessment:          {ZH: "代理 VPS 结论", EN: "Proxy VPS assessment"},
	MessageDetectedComponents:       {ZH: "识别到", EN: "Detected"},
	MessageManagementPanels:         {ZH: "管理面板", EN: "Management panels"},
	MessageProxyIngress:             {ZH: "代理入口", EN: "Proxy ingress"},
	MessageControlAPIs:              {ZH: "控制接口", EN: "Control APIs"},
	MessageExposureAndRuntimeIssues: {ZH: "需要关注的暴露与运行问题", EN: "Exposure and runtime issues"},
	MessageDeploymentRelationships:  {ZH: "部署关系", EN: "Deployment relationships"},
	MessageEvidenceCoverage:         {ZH: "证据覆盖", EN: "Evidence coverage"},
	MessageUnclassifiedProcess:      {ZH: "未识别进程", EN: "unclassified process"},
}

func Message(locale string, id MessageID) string {
	text, ok := Messages[id]
	if !ok {
		return string(id)
	}
	return UI(locale, text.ZH, text.EN)
}

func FormatMessage(locale string, id MessageID, args ...any) string {
	return fmt.Sprintf(Message(locale, id), args...)
}
