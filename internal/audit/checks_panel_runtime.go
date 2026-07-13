package audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func checkPanelRuntimeConsistency(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	panels := ctx.Facts.Panels()
	if len(panels) == 0 {
		return notApplicable("WORK-012", "workloads", "panel facts", "no supported native panel found")
	}
	listeners, listenerErr := ctx.Facts.Listeners()
	if listenerErr != nil {
		return unknown("WORK-012", "workloads", "panel database + ss + proxy config", listenerErr.Error())
	}
	f := model.Finding{ID: "WORK-012", Category: "workloads", Status: model.Pass, Facts: map[string]string{"panels": strconv.Itoa(len(panels))}}
	ufw := readPanelUFW(ctx)
	databaseUnavailable, mismatches, roleCollisions, unclassified, inferredControls := 0, 0, 0, 0, 0
	expired, exhausted := 0, 0
	for _, panel := range panels {
		knownPorts := map[string]bool{}
		for _, endpoint := range panel.Endpoints {
			knownPorts[endpoint.Port] = true
			live, scope, process := listenerForPort(listeners, endpoint.Port, "tcp")
			firewall := endpointFirewallDisposition(ufw, endpoint.Port, "tcp")
			f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source + " + ss + ufw", Key: "panel_role", Value: fmt.Sprintf("product=%s role=%s listen=%s port=%s/tcp live=%t process=%s scope=%s firewall=%s tls=%s path_default=%s", panel.Product, endpoint.Role, endpoint.Listen, endpoint.Port, live, truncate(process, 100), scope, firewall, knownBool(endpoint.TLS, endpoint.TLSKnown), knownBool(endpoint.PathIsDefault, endpoint.PathKnown))})
			if endpoint.Role == "subscription" && !live {
				mismatches++
				f.Status, f.Severity = model.Risk, model.Medium
			}
		}
		for i := range panel.Endpoints {
			for j := i + 1; j < len(panel.Endpoints); j++ {
				if panel.Endpoints[i].Port != "" && panel.Endpoints[i].Port == panel.Endpoints[j].Port {
					roleCollisions++
					f.Status, f.Severity = model.Risk, model.High
					f.Evidence = append(f.Evidence, model.Evidence{Source: "panel settings", Key: "role_collision", Value: fmt.Sprintf("product=%s roles=%s,%s port=%s", panel.Product, panel.Endpoints[i].Role, panel.Endpoints[j].Role, panel.Endpoints[i].Port)})
				}
			}
		}
		if !panel.DatabaseAvailable {
			databaseUnavailable++
			f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database, Key: "database_metadata", Value: panel.DatabaseError})
		}
		enabledPorts := map[string]bool{}
		for _, inbound := range panel.Inbounds {
			if !validPort(inbound.Port) {
				continue
			}
			knownPorts[inbound.Port] = true
			if inbound.Enabled {
				enabledPorts[inbound.Port] = true
			}
		}
		for _, inbound := range panel.Inbounds {
			if !validPort(inbound.Port) {
				continue
			}
			if inbound.Expired {
				expired++
			}
			if inbound.QuotaExhausted {
				exhausted++
			}
			transports := proxyTransports(inbound.Protocol, inbound.Network)
			if inbound.Enabled && !summaryHasInbound(summaries, inbound.Port, inbound.Protocol) {
				mismatches++
				f.Status, f.Severity = model.Risk, model.Medium
				f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database, Key: "enabled_db_inbound_missing_from_runtime_config", Value: fmt.Sprintf("product=%s protocol=%s port=%s transports=%s", panel.Product, inbound.Protocol, inbound.Port, strings.Join(transports, ","))})
			}
			for _, transport := range transports {
				live, scope, process := listenerForPort(listeners, inbound.Port, transport)
				if inbound.Enabled && !live {
					mismatches++
					f.Status, f.Severity = model.Risk, model.Medium
				}
				if !inbound.Enabled && live && !enabledPorts[inbound.Port] {
					mismatches++
					f.Status, f.Severity = model.Risk, model.High
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database + " + ss", Key: "panel_inbound_runtime", Value: fmt.Sprintf("product=%s enabled=%t protocol=%s security=%s port=%s/%s clients=%d live=%t process=%s scope=%s expired=%t quota_exhausted=%t", panel.Product, inbound.Enabled, inbound.Protocol, inbound.Security, inbound.Port, transport, inbound.ClientCount, live, truncate(process, 100), scope, inbound.Expired, inbound.QuotaExhausted)})
			}
		}
		for _, listener := range listeners {
			process := strings.ToLower(listener.Process)
			owned := panelOwnsProcess(panel.Product, process)
			if owned && !knownPorts[listener.Port] {
				if listener.Scope == "loopback" && strings.Contains(process, "xray") && (panel.Product == "Hiddify" || panel.Product == "Marzban") {
					inferredControls++
					f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "inferred_control_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=loopback process=%s role=internal-xray-control", panel.Product, listener.Port, listener.Protocol, truncate(listener.Process, 100))})
					continue
				}
				unclassified++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "unclassified_panel_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=%s process=%s role=unknown", panel.Product, listener.Port, listener.Protocol, listener.Scope, truncate(listener.Process, 100))})
			}
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database, Key: "panel_client_summary", Value: fmt.Sprintf("product=%s enabled_clients=%d disabled_clients=%d", panel.Product, panel.EnabledClients, panel.DisabledClients)})
	}
	f.Facts["database_unavailable"] = strconv.Itoa(databaseUnavailable)
	f.Facts["runtime_mismatches"] = strconv.Itoa(mismatches)
	f.Facts["role_collisions"] = strconv.Itoa(roleCollisions)
	f.Facts["unclassified_panel_listeners"] = strconv.Itoa(unclassified)
	f.Facts["inferred_control_listeners"] = strconv.Itoa(inferredControls)
	f.Facts["expired_inbounds"] = strconv.Itoa(expired)
	f.Facts["quota_exhausted_inbounds"] = strconv.Itoa(exhausted)
	if f.Status != model.Risk && (databaseUnavailable > 0 || unclassified > 0) {
		f.Status = model.Info
	}
	return f
}

func panelOwnsProcess(product, process string) bool {
	product, process = strings.ToLower(product), strings.ToLower(process)
	switch product {
	case "s-ui":
		return strings.Contains(process, "sui") || strings.Contains(process, "sing-box")
	case "x-ui", "3x-ui":
		return strings.Contains(process, "x-ui") || strings.Contains(process, "xray")
	case "hiddify":
		return strings.Contains(process, "hiddify-core") || strings.Contains(process, "xray")
	case "marzban":
		return strings.Contains(process, "marzban") || strings.Contains(process, "xray")
	default:
		return false
	}
}

func listenerForPort(listeners []Listener, port, transport string) (bool, string, string) {
	for _, listener := range listeners {
		if listener.Port == port && strings.HasPrefix(listener.Protocol, transport) {
			return true, listener.Scope, listener.Process
		}
	}
	return false, "none", "none"
}

func summaryHasInbound(summaries []proxyConfigSummary, port, protocol string) bool {
	for _, summary := range summaries {
		for _, inbound := range summary.Inbounds {
			if inbound.Port == port && strings.EqualFold(inbound.Protocol, protocol) {
				return true
			}
		}
	}
	return false
}
