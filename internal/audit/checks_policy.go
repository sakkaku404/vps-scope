package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func checkDeploymentPolicy(ctx *Context) model.Finding {
	if ctx.Policy == nil || len(ctx.Policy.Endpoints) == 0 {
		return notApplicable("WORK-015", "workloads", "audit policy", "no endpoint policy was supplied")
	}
	listeners, listenerErr := ctx.Facts.Listeners()
	if listenerErr != nil {
		return unknown("WORK-015", "workloads", "audit policy + ss", listenerErr.Error())
	}
	firewall := ctx.Facts.HostFirewall()
	panels, panelErr := ctx.Facts.Panels()
	f := model.Finding{ID: "WORK-015", Category: "workloads", Status: model.Pass, Facts: map[string]string{"declared_endpoints": strconv.Itoa(len(ctx.Policy.Endpoints))}}
	mismatches, unknowns := 0, 0
	for _, expected := range ctx.Policy.Endpoints {
		port := strconv.Itoa(expected.Port)
		matched := matchingPolicyListeners(listeners, expected)
		judgment := "matches-policy"
		if len(matched) == 0 {
			if expected.Exposure == "blocked" {
				judgment = "not-listening-as-declared"
			} else {
				mismatches++
				judgment = "declared-endpoint-not-listening"
			}
		} else {
			if expected.Exposure == "blocked" {
				mismatches++
				judgment = "listener-present-but-policy-requires-blocked"
			}
			for _, listener := range matched {
				disposition := firewallDispositionFamily(firewall, port, expected.Protocol, listenerAddressFamily(listener.Address))
				if expected.Exposure != "blocked" && !policyExposureMatches(expected.Exposure, listener.Scope, disposition) {
					mismatches++
					judgment = "listener-or-firewall-does-not-match-declared-exposure"
				}
				if expected.Exposure == "restricted" && len(expected.AllowedSources) > 0 && disposition == "allow-restricted" && !policySourcesObserved(firewall, expected, listener) {
					unknowns++
					judgment = "restricted-but-declared-source-ranges-not-confirmed"
				}
			}
		}
		if expected.RequireTLS != nil || expected.RequireNonDefaultPath != nil {
			endpoint, ok := policyPanelEndpoint(panels, expected)
			if !ok {
				unknowns++
				judgment = "panel-tls-or-path-evidence-unavailable"
			} else {
				if expected.RequireTLS != nil {
					if !endpoint.TLSKnown {
						unknowns++
						judgment = "panel-tls-evidence-unavailable"
					} else if endpoint.TLS != *expected.RequireTLS {
						mismatches++
						judgment = "panel-tls-does-not-match-policy"
					}
				}
				if expected.RequireNonDefaultPath != nil && *expected.RequireNonDefaultPath {
					if !endpoint.PathKnown {
						unknowns++
						judgment = "panel-path-evidence-unavailable"
					} else if endpoint.PathIsDefault {
						mismatches++
						judgment = "panel-root-or-default-path-violates-policy"
					}
				}
			}
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "audit policy + runtime evidence", Key: "endpoint", Value: fmt.Sprintf("port=%d/%s role=%s exposure=%s workload=%s transport=%s listeners=%d judgment=%s", expected.Port, expected.Protocol, expected.Role, expected.Exposure, valueOr(expected.Workload, "unspecified"), valueOr(expected.Transport, "unspecified"), len(matched), judgment)})
	}
	f.Facts["policy_mismatches"] = strconv.Itoa(mismatches)
	f.Facts["policy_unknowns"] = strconv.Itoa(unknowns)
	if mismatches > 0 {
		f.Status, f.Severity = model.Risk, model.High
	} else if unknowns > 0 {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "one or more policy expectations could not be verified from available evidence"
	}
	if firewall.collectionErr != nil && mismatches == 0 {
		f = withIncompleteEvidence(f, "host firewall discovery", firewall.collectionErr)
	}
	return withIncompleteEvidence(f, "panel discovery", panelErr)
}

func matchingPolicyListeners(listeners []Listener, expected EndpointPolicy) []Listener {
	port := strconv.Itoa(expected.Port)
	var out []Listener
	for _, listener := range listeners {
		protocol := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(listener.Protocol), "4"), "6")
		if listener.Port != port || protocol != expected.Protocol {
			continue
		}
		if len(expected.Families) > 0 {
			family := listenerAddressFamily(listener.Address)
			if !containsString(expected.Families, family) {
				continue
			}
		}
		out = append(out, listener)
	}
	return out
}

func policyExposureMatches(expected, scope, disposition string) bool {
	switch expected {
	case "public":
		return (scope == "public" || scope == "public-wildcard") && (disposition == "allow-anywhere" || disposition == "inactive")
	case "restricted":
		return (scope == "public" || scope == "public-wildcard") && disposition == "allow-restricted"
	case "private":
		return scope == "private"
	case "loopback":
		return scope == "loopback"
	case "blocked":
		return disposition == "blocked-by-default" || disposition == "blocked-by-explicit-rule"
	default:
		return false
	}
}

func policySourcesObserved(firewall hostFirewallSnapshot, expected EndpointPolicy, listener Listener) bool {
	wanted := append([]string(nil), expected.AllowedSources...)
	sort.Strings(wanted)
	seen := map[string]bool{}
	for _, rule := range firewall.rules {
		if rule.Action != "allow" || !firewallRuleMatches(rule, strconv.Itoa(expected.Port), expected.Protocol, listenerAddressFamily(listener.Address)) {
			continue
		}
		seen[rule.Source] = true
	}
	for _, source := range wanted {
		if !seen[source] {
			return false
		}
	}
	return true
}

func firewallRuleMatches(rule firewallRule, port, protocol, family string) bool {
	return (rule.Port == port || rule.Port == "any") && (rule.Protocol == protocol || rule.Protocol == "any") && (rule.Family == family || rule.Family == "any")
}

func policyPanelEndpoint(panels []panelSnapshot, expected EndpointPolicy) (panelEndpoint, bool) {
	for _, panel := range panels {
		if expected.Workload != "" && !strings.EqualFold(panel.Product, expected.Workload) {
			continue
		}
		for _, endpoint := range panel.Endpoints {
			if endpoint.Port == strconv.Itoa(expected.Port) && endpoint.Role == expected.Role {
				return endpoint, true
			}
		}
	}
	return panelEndpoint{}, false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
