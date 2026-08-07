package audit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

const maxPanelRuntimeEvidence = 80

func checkPanelRuntimeConsistency(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	panels, panelDiscoveryErr := ctx.Facts.Panels()
	if len(panels) == 0 {
		return withIncompleteEvidence(notApplicable("WORK-012", "workloads", "panel facts", "no supported panel found"), "panel and container discovery", panelDiscoveryErr)
	}
	listeners, listenerErr := ctx.Facts.Listeners()
	if listenerErr != nil {
		return unknown("WORK-012", "workloads", "panel database + ss + proxy config", listenerErr.Error())
	}
	f := model.Finding{ID: "WORK-012", Category: "workloads", Status: model.Pass, Facts: map[string]string{"panels": strconv.Itoa(len(panels))}}
	evidence := panelRuntimeEvidenceSet{}
	ufw := readPanelUFW(ctx)
	databaseUnavailable, unsupportedSchemas, mismatches, roleCollisions, unclassified, publicUnclassified, inferredControls := 0, 0, 0, 0, 0, 0, 0
	publicSubscriptions, publicPlaintextSubscriptions := 0, 0
	disabledStillListening := 0
	expired, exhausted := 0, 0
	clientInventoryUnavailable := 0
	var metadataErr error
	for _, panel := range panels {
		if panel.RuntimeCommandError != "" {
			metadataErr = errors.Join(metadataErr, fmt.Errorf("%s runtime metadata: %s", panel.Product, panel.RuntimeCommandError))
		}
		if panel.ManagementMetadataError != "" {
			metadataErr = errors.Join(metadataErr, fmt.Errorf("%s management metadata: %s", panel.Product, panel.ManagementMetadataError))
		}
		if panel.DatabaseError != "" {
			metadataErr = errors.Join(metadataErr, fmt.Errorf("%s configuration metadata: %s", panel.Product, panel.DatabaseError))
		}
		if panel.Database != "" && !panel.SchemaSupported && panel.SchemaFingerprint != "" {
			unsupportedSchemas++
		}
		knownListeners := map[int]bool{}
		enabledListeners := map[int]bool{}
		for _, inbound := range panel.Inbounds {
			if !inbound.Enabled || !validPort(inbound.Port) {
				continue
			}
			for _, transport := range proxyTransports(inbound.Protocol, inbound.Network) {
				for _, index := range panelRuntimeListenerIndexes(listeners, inbound.Listen, inbound.Port, transport) {
					enabledListeners[index] = true
				}
			}
		}
		for _, endpoint := range panel.Endpoints {
			matches := panelRuntimeListenerIndexes(listeners, endpoint.Listen, endpoint.Port, "tcp")
			markPanelRuntimeListeners(knownListeners, matches)
			live, scope, process := panelRuntimeListenerObservation(listeners, matches)
			firewall := endpointFirewallDisposition(ufw, endpoint.Port, "tcp")
			evidence.add(model.Evidence{Source: endpoint.Source + " + ss + ufw", Key: "panel_role", Value: fmt.Sprintf("product=%s role=%s listen=%s port=%s/tcp live=%t process=%s scope=%s firewall=%s tls=%s path_default=%s", panel.Product, endpoint.Role, endpoint.Listen, endpoint.Port, live, truncate(process, 100), scope, firewall, knownBool(endpoint.TLS, endpoint.TLSKnown), knownBool(endpoint.PathIsDefault, endpoint.PathKnown))})
			if endpoint.Role == "subscription" && !live {
				mismatches++
				raiseRisk(&f, model.Medium)
			} else if endpoint.Role == "subscription" && live && (scope == "public" || scope == "public-wildcard") {
				publicSubscriptions++
				if endpoint.TLSKnown && !endpoint.TLS && (firewall == "allow-anywhere" || firewall == "inactive") {
					publicPlaintextSubscriptions++
					raiseRisk(&f, model.High)
					evidence.add(model.Evidence{Source: endpoint.Source + " + ss + ufw", Key: "plaintext_public_subscription", Value: fmt.Sprintf("product=%s port=%s/tcp scope=%s firewall=%s; bearer-like subscription URLs may be exposed in transit", panel.Product, endpoint.Port, scope, firewall)})
				}
			}
		}
		for i := range panel.Endpoints {
			for j := i + 1; j < len(panel.Endpoints); j++ {
				if panel.Endpoints[i].Port != "" && panel.Endpoints[i].Port == panel.Endpoints[j].Port && panelConfiguredAddressesOverlap(panel.Endpoints[i].Listen, panel.Endpoints[j].Listen) {
					roleCollisions++
					raiseRisk(&f, model.High)
					evidence.add(model.Evidence{Source: "panel settings", Key: "role_collision", Value: fmt.Sprintf("product=%s roles=%s,%s port=%s/tcp", panel.Product, panel.Endpoints[i].Role, panel.Endpoints[j].Role, panel.Endpoints[i].Port)})
				}
			}
		}
		if !panel.DatabaseAvailable {
			databaseUnavailable++
			evidence.add(model.Evidence{Source: panel.Database, Key: "database_metadata", Value: panel.DatabaseError})
		}
		for _, inbound := range panel.Inbounds {
			if !validPort(inbound.Port) {
				continue
			}
			for _, endpoint := range panel.Endpoints {
				if panelEndpointOverlapsInbound(endpoint, inbound) {
					roleCollisions++
					raiseRisk(&f, model.High)
					evidence.add(model.Evidence{Source: panel.Database + " + panel settings", Key: "role_collision", Value: fmt.Sprintf("product=%s roles=%s,proxy-ingress protocol=%s port=%s/tcp", panel.Product, endpoint.Role, inbound.Protocol, inbound.Port)})
				}
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
			if inbound.Enabled && !summaryHasPanelInbound(summaries, inbound) {
				mismatches++
				raiseRisk(&f, model.Medium)
				evidence.add(model.Evidence{Source: panel.Database, Key: "enabled_db_inbound_missing_from_runtime_config", Value: fmt.Sprintf("product=%s protocol=%s listen=%s port=%s transports=%s", panel.Product, inbound.Protocol, normalizeListen(inbound.Listen), inbound.Port, strings.Join(transports, ","))})
			}
			for _, transport := range transports {
				matches := panelRuntimeListenerIndexes(listeners, inbound.Listen, inbound.Port, transport)
				markPanelRuntimeListeners(knownListeners, matches)
				live, scope, process := panelRuntimeListenerObservation(listeners, matches)
				if inbound.Enabled && !live {
					mismatches++
					raiseRisk(&f, model.Medium)
				}
				unclaimed := unclaimedPanelRuntimeListeners(matches, enabledListeners)
				disabledLive, disabledScope, disabledProcess := panelRuntimeListenerObservation(listeners, unclaimed)
				if !inbound.Enabled && disabledLive {
					mismatches++
					disabledStillListening++
					raiseRisk(&f, model.High)
					evidence.add(model.Evidence{Source: panel.Database + " + ss", Key: "disabled_inbound_still_listening", Value: fmt.Sprintf("product=%s protocol=%s listen=%s port=%s/%s process=%s scope=%s", panel.Product, inbound.Protocol, normalizeListen(inbound.Listen), inbound.Port, transport, truncate(disabledProcess, 100), disabledScope)})
				}
				evidence.add(model.Evidence{Source: panel.Database + " + ss", Key: "panel_inbound_runtime", Value: fmt.Sprintf("product=%s enabled=%t protocol=%s security=%s listen=%s port=%s/%s clients=%d live=%t process=%s scope=%s expired=%t quota_exhausted=%t", panel.Product, inbound.Enabled, inbound.Protocol, inbound.Security, normalizeListen(inbound.Listen), inbound.Port, transport, inbound.ClientCount, live, truncate(process, 100), scope, inbound.Expired, inbound.QuotaExhausted)})
			}
		}
		for index, listener := range listeners {
			process := strings.ToLower(listener.Process)
			owned := panelOwnsProcess(panel.Product, process)
			if owned && !knownListeners[index] {
				if panel.Product == "Outline" && listener.Scope == "loopback" {
					inferredControls++
					evidence.add(model.Evidence{Source: "ss", Key: "inferred_control_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=loopback process=%s role=internal-metrics-or-control", panel.Product, listener.Port, listener.Protocol, truncate(listener.Process, 100))})
					continue
				}
				if listener.Scope == "loopback" && strings.Contains(process, "xray") && (panel.Product == "Hiddify" || panel.Product == "Marzban" || panel.Product == "x-ui" || panel.Product == "3x-ui") {
					inferredControls++
					evidence.add(model.Evidence{Source: "ss", Key: "inferred_control_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=loopback process=%s role=internal-xray-control", panel.Product, listener.Port, listener.Protocol, truncate(listener.Process, 100))})
					continue
				}
				unclassified++
				evidence.add(model.Evidence{Source: "ss", Key: "unclassified_panel_listener", Value: fmt.Sprintf("product=%s port=%s/%s scope=%s process=%s role=unknown", panel.Product, listener.Port, listener.Protocol, listener.Scope, truncate(listener.Process, 100))})
				if listener.Scope == "public" || listener.Scope == "public-wildcard" {
					publicUnclassified++
					raiseRisk(&f, model.Medium)
				}
			}
		}
		if panelHasCapability(panel, "client-state") && panel.ClientInventoryKnown {
			evidence.add(model.Evidence{Source: panel.Database, Key: "panel_client_summary", Value: fmt.Sprintf("product=%s enabled_clients=%d disabled_clients=%d", panel.Product, panel.EnabledClients, panel.DisabledClients)})
		} else if panelHasCapability(panel, "client-state") {
			clientInventoryUnavailable++
			value := "client inventory unavailable"
			if panel.ClientInventoryError != "" {
				value += ": " + truncate(panel.ClientInventoryError, 180)
			}
			evidence.add(model.Evidence{Source: panel.Database, Key: "panel_client_summary", Value: "product=" + panel.Product + " " + value})
			metadataErr = errors.Join(metadataErr, fmt.Errorf("%s client inventory: %s", panel.Product, value))
		}
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
	f.Facts["client_inventories_unavailable"] = strconv.Itoa(clientInventoryUnavailable)
	if unsupportedSchemas > 0 {
		f.Error = "one or more panel database schemas are not supported; runtime conclusions are incomplete"
		if f.Status != model.Risk {
			f.Status, f.Unavailable = model.Unknown, true
		}
	} else if f.Status != model.Risk && (databaseUnavailable > 0 || unclassified > 0) {
		f.Status = model.Info
	}
	f = withIncompleteEvidence(f, "host firewall discovery", ufw.collectionErr)
	f = withIncompleteEvidence(f, "panel management metadata", metadataErr)
	f = withIncompleteEvidence(f, "panel and container discovery", panelDiscoveryErr)
	for _, item := range f.Evidence {
		evidence.add(item)
	}
	f.Evidence = evidence.entries()
	return f
}

func panelHasCapability(panel panelSnapshot, capability string) bool {
	for _, available := range panel.SchemaCapabilities {
		if available == capability {
			return true
		}
	}
	return false
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

func panelRuntimeListenerIndexes(listeners []Listener, configuredAddress, port, transport string) []int {
	transport = strings.ToLower(strings.TrimSpace(transport))
	var matches []int
	for index, listener := range listeners {
		if listener.Port != port || panelRuntimeTransport(listener.Protocol) != transport {
			continue
		}
		if !configuredAddressMatchesListener(configuredAddress, listener.Address) {
			continue
		}
		matches = append(matches, index)
	}
	return matches
}

func panelRuntimeTransport(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if strings.HasSuffix(protocol, "4") || strings.HasSuffix(protocol, "6") {
		protocol = protocol[:len(protocol)-1]
	}
	if protocol == "tcp" || protocol == "udp" {
		return protocol
	}
	return ""
}

func panelRuntimeListenerObservation(listeners []Listener, indexes []int) (bool, string, string) {
	if len(indexes) == 0 {
		return false, "none", "none"
	}
	rank := map[string]int{"loopback": 1, "private": 2, "container": 2, "public": 3, "public-wildcard": 4}
	selected := listeners[indexes[0]]
	for _, index := range indexes[1:] {
		candidate := listeners[index]
		if rank[candidate.Scope] > rank[selected.Scope] {
			selected = candidate
		}
	}
	return true, selected.Scope, selected.Process
}

func markPanelRuntimeListeners(known map[int]bool, indexes []int) {
	for _, index := range indexes {
		known[index] = true
	}
}

func unclaimedPanelRuntimeListeners(indexes []int, enabled map[int]bool) []int {
	unclaimed := make([]int, 0, len(indexes))
	for _, index := range indexes {
		if !enabled[index] {
			unclaimed = append(unclaimed, index)
		}
	}
	return unclaimed
}

func panelConfiguredAddressesOverlap(left, right string) bool {
	return configuredAddressMatchesListener(left, right) || configuredAddressMatchesListener(right, left)
}

func panelConfiguredAddressesEquivalent(left, right string) bool {
	left, right = canonicalIngressListen(left), canonicalIngressListen(right)
	if left == "wildcard" || right == "wildcard" {
		return left == right
	}
	if strings.EqualFold(left, right) {
		return true
	}
	if strings.EqualFold(left, "localhost") {
		return classifyAddress(right) == "loopback"
	}
	if strings.EqualFold(right, "localhost") {
		return classifyAddress(left) == "loopback"
	}
	return configuredAddressMatchesListener(left, right) && configuredAddressMatchesListener(right, left)
}

func panelEndpointOverlapsInbound(endpoint panelEndpoint, inbound panelInboundFact) bool {
	if endpoint.Port == "" || endpoint.Port != inbound.Port || !panelConfiguredAddressesOverlap(endpoint.Listen, inbound.Listen) {
		return false
	}
	for _, transport := range proxyTransports(inbound.Protocol, inbound.Network) {
		if transport == "tcp" {
			return true
		}
	}
	return false
}

func summaryHasPanelInbound(summaries []proxyConfigSummary, inbound panelInboundFact) bool {
	wanted := map[string]bool{}
	for _, transport := range proxyTransports(inbound.Protocol, inbound.Network) {
		wanted[transport] = true
	}
	for _, summary := range summaries {
		for _, candidate := range summary.Inbounds {
			if candidate.Port != inbound.Port || !strings.EqualFold(candidate.Protocol, inbound.Protocol) || !panelConfiguredAddressesEquivalent(candidate.Listen, inbound.Listen) {
				continue
			}
			transports := candidate.Transports
			if len(transports) == 0 {
				transports = proxyTransports(candidate.Protocol, "")
			}
			for _, transport := range transports {
				delete(wanted, strings.ToLower(transport))
			}
		}
	}
	return len(wanted) == 0
}

type panelRuntimeEvidenceSet struct {
	priority []model.Evidence
	context  []model.Evidence
	total    int
}

func (s *panelRuntimeEvidenceSet) add(item model.Evidence) {
	s.total++
	target := &s.priority
	if panelRuntimeContextEvidence(item) {
		target = &s.context
	}
	// Keep each class bounded independently so late actionable evidence can
	// displace routine rows without allowing a large panel database to grow the
	// report in memory before the final evidence budget is applied.
	if len(*target) < maxPanelRuntimeEvidence {
		*target = append(*target, item)
	}
}

func (s panelRuntimeEvidenceSet) entries() []model.Evidence {
	if s.total == 0 {
		return nil
	}
	budget := maxPanelRuntimeEvidence
	truncated := s.total > maxPanelRuntimeEvidence
	if truncated {
		budget--
	}
	out := make([]model.Evidence, 0, maxPanelRuntimeEvidence)
	for _, items := range [][]model.Evidence{s.priority, s.context} {
		remaining := budget - len(out)
		if remaining <= 0 {
			break
		}
		out = append(out, items[:min(len(items), remaining)]...)
	}
	if truncated {
		out = append(out, model.Evidence{
			Source: "WORK-012 evidence budget", Key: "evidence_truncated",
			Value: fmt.Sprintf("omitted=%d limit=%d; aggregate counters remain available in facts", s.total-len(out), maxPanelRuntimeEvidence),
		})
	}
	return out
}

func panelRuntimeContextEvidence(item model.Evidence) bool {
	switch item.Key {
	case "panel_role", "panel_inbound_runtime", "inferred_control_listener":
		return true
	case "panel_client_summary":
		return !strings.Contains(strings.ToLower(item.Value), "unavailable")
	default:
		return false
	}
}
