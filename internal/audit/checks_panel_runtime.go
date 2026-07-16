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
	databaseUnavailable, unsupportedSchemas, mismatches, roleCollisions, unclassified, publicUnclassified, inferredControls := 0, 0, 0, 0, 0, 0, 0
	publicSubscriptions, publicPlaintextSubscriptions := 0, 0
	disabledStillListening := 0
	expired, exhausted := 0, 0
	for _, panel := range panels {
		if panel.Database != "" && !panel.SchemaSupported && panel.SchemaFingerprint != "" {
			unsupportedSchemas++
		}
		knownPorts := map[string]bool{}
		for _, endpoint := range panel.Endpoints {
			knownPorts[endpoint.Port] = true
			live, scope, process := listenerForPort(listeners, endpoint.Port, "tcp")
			firewall := endpointFirewallDisposition(ufw, endpoint.Port, "tcp")
			f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source + " + ss + ufw", Key: "panel_role", Value: fmt.Sprintf("product=%s role=%s listen=%s port=%s/tcp live=%t process=%s scope=%s firewall=%s tls=%s path_default=%s", panel.Product, endpoint.Role, endpoint.Listen, endpoint.Port, live, truncate(process, 100), scope, firewall, knownBool(endpoint.TLS, endpoint.TLSKnown), knownBool(endpoint.PathIsDefault, endpoint.PathKnown))})
			if endpoint.Role == "subscription" && !live {
				mismatches++
				raiseRisk(&f, model.Medium)
			} else if endpoint.Role == "subscription" && live && (scope == "public" || scope == "public-wildcard") {
				publicSubscriptions++
				if endpoint.TLSKnown && !endpoint.TLS && (firewall == "allow-anywhere" || firewall == "inactive") {
					publicPlaintextSubscriptions++
					raiseRisk(&f, model.High)
					f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source + " + ss + ufw", Key: "plaintext_public_subscription", Value: fmt.Sprintf("product=%s port=%s/tcp scope=%s firewall=%s; bearer-like subscription URLs may be exposed in transit", panel.Product, endpoint.Port, scope, firewall)})
				}
			}
		}
		for i := range panel.Endpoints {
			for j := i + 1; j < len(panel.Endpoints); j++ {
				if panel.Endpoints[i].Port != "" && panel.Endpoints[i].Port == panel.Endpoints[j].Port {
					roleCollisions++
					raiseRisk(&f, model.High)
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
			for _, endpoint := range panel.Endpoints {
				if endpoint.Port != "" && endpoint.Port == inbound.Port {
					roleCollisions++
					raiseRisk(&f, model.High)
					f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database + " + panel settings", Key: "role_collision", Value: fmt.Sprintf("product=%s roles=%s,proxy-ingress protocol=%s port=%s", panel.Product, endpoint.Role, inbound.Protocol, inbound.Port)})
				}
			}
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
				raiseRisk(&f, model.Medium)
				f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database, Key: "enabled_db_inbound_missing_from_runtime_config", Value: fmt.Sprintf("product=%s protocol=%s port=%s transports=%s", panel.Product, inbound.Protocol, inbound.Port, strings.Join(transports, ","))})
			}
			for _, transport := range transports {
				live, scope, process := listenerForPort(listeners, inbound.Port, transport)
				if inbound.Enabled && !live {
					mismatches++
					raiseRisk(&f, model.Medium)
				}
				if !inbound.Enabled && live && !enabledPorts[inbound.Port] {
					mismatches++
					disabledStillListening++
					raiseRisk(&f, model.High)
					f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database + " + ss", Key: "disabled_inbound_still_listening", Value: fmt.Sprintf("product=%s protocol=%s port=%s/%s process=%s scope=%s", panel.Product, inbound.Protocol, inbound.Port, transport, truncate(process, 100), scope)})
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database + " + ss", Key: "panel_inbound_runtime", Value: fmt.Sprintf("product=%s enabled=%t protocol=%s security=%s port=%s/%s clients=%d live=%t process=%s scope=%s expired=%t quota_exhausted=%t", panel.Product, inbound.Enabled, inbound.Protocol, inbound.Security, inbound.Port, transport, inbound.ClientCount, live, truncate(process, 100), scope, inbound.Expired, inbound.QuotaExhausted)})
			}
		}
		for _, listener := range listeners {
			process := strings.ToLower(listener.Process)
			owned := panelOwnsProcess(panel.Product, process)
			if owned && !knownPorts[listener.Port] {
				if panel.Product == "Outline" && listener.Scope == "loopback" {
					inferredControls++
					f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "inferred_control_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=loopback process=%s role=internal-metrics-or-control", panel.Product, listener.Port, listener.Protocol, truncate(listener.Process, 100))})
					continue
				}
				if listener.Scope == "loopback" && strings.Contains(process, "xray") && (panel.Product == "Hiddify" || panel.Product == "Marzban" || panel.Product == "x-ui" || panel.Product == "3x-ui") {
					inferredControls++
					f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "inferred_control_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=loopback process=%s role=internal-xray-control", panel.Product, listener.Port, listener.Protocol, truncate(listener.Process, 100))})
					continue
				}
				unclassified++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "unclassified_panel_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=%s process=%s role=unknown", panel.Product, listener.Port, listener.Protocol, listener.Scope, truncate(listener.Process, 100))})
				if listener.Scope == "public" || listener.Scope == "public-wildcard" {
					publicUnclassified++
					raiseRisk(&f, model.Medium)
				}
			}
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Database, Key: "panel_client_summary", Value: fmt.Sprintf("product=%s enabled_clients=%d disabled_clients=%d", panel.Product, panel.EnabledClients, panel.DisabledClients)})
	}
	f.Facts["database_unavailable"] = strconv.Itoa(databaseUnavailable)
	f.Facts["unsupported_panel_schemas"] = strconv.Itoa(unsupportedSchemas)
	f.Facts["runtime_mismatches"] = strconv.Itoa(mismatches)
	f.Facts["role_collisions"] = strconv.Itoa(roleCollisions)
	f.Facts["unclassified_panel_listeners"] = strconv.Itoa(unclassified)
	f.Facts["public_unclassified_panel_listeners"] = strconv.Itoa(publicUnclassified)
	f.Facts["inferred_control_listeners"] = strconv.Itoa(inferredControls)
	f.Facts["public_subscription_listeners"] = strconv.Itoa(publicSubscriptions)
	f.Facts["public_plaintext_subscription_listeners"] = strconv.Itoa(publicPlaintextSubscriptions)
	f.Facts["disabled_inbounds_still_listening"] = strconv.Itoa(disabledStillListening)
	f.Facts["expired_inbounds"] = strconv.Itoa(expired)
	f.Facts["quota_exhausted_inbounds"] = strconv.Itoa(exhausted)
	if unsupportedSchemas > 0 {
		f.Error = "one or more panel database schemas are not supported; runtime conclusions are incomplete"
		if f.Status != model.Risk {
			f.Status, f.Unavailable = model.Unknown, true
		}
	} else if f.Status != model.Risk && (databaseUnavailable > 0 || unclassified > 0) {
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
	case "outline":
		return strings.Contains(process, "outline-ss-serv") || strings.Contains(process, "node")
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
