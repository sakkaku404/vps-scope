package audit

import (
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// ReasonCode is a language-neutral, stable explanation of the primary state
// represented by a finding. Check IDs describe what was evaluated; reason
// codes describe why the current result has that status.
func assignReasonCodes(findings []model.Finding) {
	for i := range findings {
		findings[i].ReasonCode = reasonCode(findings[i])
	}
}

func reasonCode(f model.Finding) string {
	prefix := strings.ToLower(strings.ReplaceAll(f.ID, "-", "."))
	if f.NotApplicable {
		return prefix + ".not-applicable"
	}
	if f.Status == model.Unknown {
		switch {
		case positiveFact(f, "unsupported_panel_schemas"):
			return prefix + ".unsupported-panel-schema"
		case f.Unavailable:
			return prefix + ".evidence-unavailable"
		default:
			return prefix + ".inconclusive"
		}
	}
	if f.Status == model.Risk {
		suffix := riskReasonSuffix(f)
		if suffix == "" {
			suffix = "risk-detected"
		}
		return prefix + "." + suffix
	}
	if f.Status == model.Pass {
		return prefix + ".verified"
	}
	return prefix + ".observed"
}

func riskReasonSuffix(f model.Finding) string {
	switch f.ID {
	case "SSH-001":
		return "password-authentication-enabled"
	case "SSH-002":
		return "root-login-enabled"
	case "WORK-002":
		switch {
		case positiveFact(f, "public_plaintext_management"):
			return "public-plaintext-management"
		case positiveFact(f, "public_default_path_management"):
			return "public-default-path-management"
		case positiveFact(f, "public_reverse_proxy_management"):
			return "public-reverse-proxy-management"
		default:
			return "public-unrestricted-management"
		}
	case "WORK-005":
		return "public-control-api"
	case "WORK-009":
		return "configured-runtime-firewall-mismatch"
	case "WORK-012":
		switch {
		case positiveFact(f, "disabled_inbounds_still_listening"):
			return "disabled-inbound-still-listening"
		case positiveFact(f, "role_collisions"):
			return "endpoint-role-collision"
		case positiveFact(f, "public_plaintext_subscription_listeners"):
			return "public-plaintext-subscription"
		default:
			return "panel-runtime-mismatch"
		}
	case "DOCKER-001":
		return "unsafe-container-isolation"
	case "DOCKER-002":
		return "input-policy-bypass-path"
	case "TLS-001":
		days, ok := intFact(f, "minimum_certificate_days")
		switch {
		case ok && days < 0:
			return "certificate-expired"
		case ok && days <= 30:
			return "certificate-expiring"
		case f.Facts["renewal_state"] == "failing":
			return "renewal-failing"
		default:
			return "certificate-or-renewal-risk"
		}
	case "FW-001":
		return "firewall-policy-ineffective"
	case "FW-002":
		return "firewall-exposure-mismatch"
	case "UPD-001":
		return "pending-security-or-reboot"
	case "PROC-001":
		return "failed-or-restarting-service"
	case "PROC-002":
		return "deleted-executable-running"
	case "PERSIST-001", "PERSIST-002":
		return "suspicious-persistence-indicator"
	case "REL-001":
		return "reliability-event-detected"
	case "REL-002":
		return "storage-pressure"
	}
	return ""
}

func positiveFact(f model.Finding, key string) bool {
	value, ok := intFact(f, key)
	return ok && value > 0
}

func intFact(f model.Finding, key string) (int, bool) {
	value, ok := f.Facts[key]
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	return n, err == nil
}
