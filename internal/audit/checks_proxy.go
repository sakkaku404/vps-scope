package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func proxyChecks(ctx *Context) []model.Finding {
	summaries, discoveryErr := discoverProxyConfigs(ctx)
	panels, panelDiscoveryErr := ctx.Facts.Panels()
	discoveryErr = errors.Join(discoveryErr, panelDiscoveryErr)
	var panelConfigErr error
	for _, panel := range panels {
		if panel.DiscoveryError != "" {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %s", panel.Product, panel.DiscoveryError))
		}
		if panel.DatabaseError != "" {
			panelConfigErr = errors.Join(panelConfigErr, fmt.Errorf("%s configuration metadata: %s", panel.Product, panel.DatabaseError))
		}
	}
	findings := []model.Finding{
		checkProxyInventory(ctx, summaries),
		checkProxyConfiguration(ctx, summaries),
		checkProxyControlEndpoints(ctx, summaries),
		checkProxySensitivePermissions(summaries),
		checkProxyServiceIsolation(ctx),
		checkProxyTransportContext(ctx, summaries),
		checkProxyEndpointRelations(ctx, summaries),
		checkProxyLogSignals(ctx),
		checkWireGuardRuntime(ctx),
		checkPanelRuntimeConsistency(ctx, summaries),
		checkReverseProxyRelations(ctx),
		checkExternalExposure(ctx),
		checkDeploymentPolicy(ctx),
		checkProxyEgress(ctx),
		checkProxyAdvisories(ctx),
	}
	if discoveryErr != nil {
		dependsOnConfigDiscovery := map[string]bool{
			"WORK-003": true, "WORK-004": true, "WORK-005": true, "WORK-006": true,
			"WORK-008": true, "WORK-009": true, "WORK-012": true,
		}
		for i := range findings {
			if dependsOnConfigDiscovery[findings[i].ID] {
				findings[i] = withIncompleteEvidence(findings[i], "proxy configuration discovery", discoveryErr)
			}
		}
	}
	if panelConfigErr != nil {
		dependsOnPanelConfiguration := map[string]bool{
			"WORK-003": true, "WORK-004": true, "WORK-005": true,
			"WORK-008": true, "WORK-009": true, "WORK-012": true,
		}
		for i := range findings {
			if dependsOnPanelConfiguration[findings[i].ID] {
				findings[i] = withIncompleteEvidence(findings[i], "panel configuration metadata", panelConfigErr)
			}
		}
	}
	return findings
}
func checkProxyInventory(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	f := model.Finding{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{}}
	products := map[string]bool{}
	var inventoryErr error
	if ctx.Facts != nil {
		processes, err := ctx.Facts.Processes()
		if err != nil {
			inventoryErr = errors.Join(inventoryErr, fmt.Errorf("ps process inventory: %w", err))
		}
		for _, process := range processes {
			line := processLine(process)
			product, ok := proxyProcessLine(line)
			if !ok {
				continue
			}
			products[product] = true
			if len(f.Evidence) < 30 {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ps", Key: "proxy_process", Value: sanitizeProcessEvidence(line)})
			}
		}
	}
	for _, summary := range summaries {
		products[summary.Product] = true
	}
	for _, inbound := range uniqueProxyInbounds(summaries) {
		if len(f.Evidence) < 80 {
			f.Evidence = append(f.Evidence, model.Evidence{Source: inbound.Path, Key: "proxy_ingress", Value: fmt.Sprintf("product=%s protocol=%s listen=%s port=%s", inbound.Product, inbound.Protocol, inbound.Listen, inbound.Port)})
		}
	}
	if ctx.Facts != nil && ctx.Commander.Exists("docker") {
		containers, err := ctx.Facts.DockerContainers()
		if err != nil {
			inventoryErr = errors.Join(inventoryErr, fmt.Errorf("docker container inventory: %w", err))
		}
		for _, container := range containers {
			line := strings.TrimPrefix(container.Name, "/") + " " + container.Config.Image
			if proxyProcessPattern.MatchString(line) || containsAny(strings.ToLower(line), "marzban", "hiddify", "outline") {
				product := proxyProductFromText(line)
				products[product] = true
				if len(f.Evidence) < 80 {
					f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "proxy_container", Value: truncate(line, 240)})
				}
			}
		}
	}
	if len(products) == 0 {
		return withIncompleteEvidence(notApplicable("WORK-003", "workloads", "process, config, and container discovery", "no supported proxy workload detected"), "proxy workload inventory", inventoryErr)
	}
	names := make([]string, 0, len(products))
	for product := range products {
		names = append(names, product)
	}
	sort.Strings(names)
	f.Facts["products"] = strings.Join(names, ",")
	f.Facts["product_count"] = strconv.Itoa(len(names))
	f.Facts["configured_inbounds"] = strconv.Itoa(len(uniqueProxyInbounds(summaries)))
	return withIncompleteEvidence(f, "proxy workload inventory", inventoryErr)
}

func checkProxyConfiguration(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	if len(summaries) == 0 {
		return notApplicable("WORK-004", "workloads", "configuration discovery", "no supported proxy configuration file found")
	}
	f := model.Finding{ID: "WORK-004", Category: "workloads", Status: model.Pass, Facts: map[string]string{}}
	active := activeProxyProducts(ctx)
	errorsFound, selfTests := 0, 0
	testedCommands := map[string]bool{}
	for _, summary := range summaries {
		if summary.Err != nil {
			errorsFound++
			f.Evidence = append(f.Evidence, model.Evidence{Source: summary.Path, Key: "parse_error", Value: truncate(summary.Err.Error(), 300)})
			if active[strings.ToLower(summary.Product)] {
				f.Status, f.Severity = model.Risk, model.Medium
			} else if f.Status != model.Risk {
				f.Status = model.Info
			}
			continue
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: summary.Path, Key: "parsed", Value: fmt.Sprintf("product=%s inbounds=%d controls=%d", summary.Product, len(summary.Inbounds), len(summary.Controls))})
		// Managed-panel summaries may represent an entire generated config tree
		// or a database-derived runtime model. Passing such a directory to a
		// single-file native self-test produces a false failure.
		if strings.HasSuffix(summary.Path, ".db") || !regularFile(summary.Path) {
			continue
		}
		binary, args := proxySelfTest(summary.Product, summary.Path)
		if binary == "" || !ctx.Commander.Exists(binary) {
			continue
		}
		trustedBinary, err := trustedExecutable(ctx.Commander, binary)
		if err != nil {
			errorsFound++
			f.Status, f.Unavailable = model.Unknown, true
			f.Evidence = append(f.Evidence, model.Evidence{Source: binary, Key: "self_test_skipped", Value: "binary trust check failed: " + truncate(err.Error(), 240)})
			continue
		}
		if summary.Product == "sing-box" && !strings.Contains(summary.Path, "/usr/local/s-ui/") {
			args = []string{"check", "-C", filepath.Dir(summary.Path)}
		}
		command := strings.Join(append([]string{trustedBinary}, args...), " ")
		if testedCommands[command] {
			continue
		}
		testedCommands[command] = true
		selfTests++
		r := ctx.Commander.Run(15*time.Second, trustedBinary, args...)
		if r.Err != nil {
			errorsFound++
			f.Evidence = append(f.Evidence, model.Evidence{Source: command, Key: "self_test_failed", Value: nativeCommandError(r)})
			if active[strings.ToLower(summary.Product)] {
				f.Status, f.Severity = model.Risk, model.Medium
			} else if f.Status != model.Risk {
				f.Status = model.Info
			}
		} else {
			f.Evidence = append(f.Evidence, model.Evidence{Source: command, Key: "self_test", Value: "passed"})
		}
	}
	f.Facts["configs"] = strconv.Itoa(len(summaries))
	f.Facts["parse_or_self_test_errors"] = strconv.Itoa(errorsFound)
	f.Facts["native_self_tests"] = strconv.Itoa(selfTests)
	return f
}

func checkProxyControlEndpoints(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	var endpoints []controlEndpoint
	for _, summary := range summaries {
		endpoints = append(endpoints, summary.Controls...)
	}
	if len(endpoints) == 0 {
		return notApplicable("WORK-005", "workloads", "supported proxy configuration", "no supported control API endpoint configured")
	}
	f := model.Finding{ID: "WORK-005", Category: "workloads", Status: model.Pass, Facts: map[string]string{"configured_endpoints": strconv.Itoa(len(endpoints))}}
	listeners, listenerOK := currentListeners(ctx)
	ufw := readPanelUFW(ctx)
	publicLive, unknown := 0, 0
	for _, endpoint := range endpoints {
		scope := classifyAddress(endpoint.Listen)
		live := false
		family := "any"
		for _, listener := range listeners {
			if listener.Port == endpoint.Port && strings.HasPrefix(listener.Protocol, "tcp") {
				live = true
				if listener.Scope == "public" || listener.Scope == "public-wildcard" {
					scope = listener.Scope
					family = listenerAddressFamily(listener.Address)
				}
			}
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "proxy configuration + ss", Key: "control_endpoint", Value: fmt.Sprintf("product=%s kind=%s listen=%s port=%s scope=%s live=%t", endpoint.Product, endpoint.Kind, endpoint.Listen, endpoint.Port, scope, live)})
		if !listenerOK {
			unknown++
			continue
		}
		if !live || (scope != "public" && scope != "public-wildcard") {
			continue
		}
		publicLive++
		switch panelFirewallDispositionFamily(ufw, endpoint.Port, family, &f) {
		case "allow-anywhere", "inactive":
			f.Status, f.Severity = model.Risk, model.High
		case "restricted", "blocked-by-default", "blocked-by-explicit-rule":
		default:
			unknown++
		}
	}
	f.Facts["live_public_endpoints"] = strconv.Itoa(publicLive)
	if f.Status != model.Risk && unknown > 0 {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "control API exposure could not be fully determined from listener and host-firewall evidence"
	}
	return withIncompleteEvidence(f, "host firewall discovery", ufw.collectionErr)
}

var defaultProxySensitivePaths = []string{
	"/usr/local/s-ui/db/s-ui.db", "/etc/s-ui/s-ui.db", "/etc/x-ui/x-ui.db", "/etc/wireguard/wg0.conf",
	"/etc/hysteria/config.yaml", "/etc/hysteria/config.yml", "/etc/tuic/config.json", "/etc/trojan/config.json",
}

func checkProxySensitivePermissions(summaries []proxyConfigSummary) model.Finding {
	return checkProxySensitivePermissionsWithDefaults(summaries, defaultProxySensitivePaths)
}

func checkProxySensitivePermissionsWithDefaults(summaries []proxyConfigSummary, defaultPaths []string) model.Finding {
	type candidate struct {
		forbidden fs.FileMode
		required  bool
	}
	candidates := map[string]candidate{}
	for _, summary := range summaries {
		if summary.Path != "" {
			candidates[summary.Path] = candidate{forbidden: 0o027, required: true}
		}
		for _, path := range summary.SensitiveFiles {
			if path != "" {
				candidates[path] = candidate{forbidden: 0o027, required: true}
			}
		}
	}
	for _, path := range defaultPaths {
		if path != "" {
			if _, exists := candidates[path]; !exists {
				candidates[path] = candidate{forbidden: 0o027}
			}
		}
	}
	if len(candidates) == 0 {
		return notApplicable("WORK-006", "workloads", "filesystem discovery", "no supported proxy secret-bearing file found")
	}
	f := model.Finding{ID: "WORK-006", Category: "workloads", Status: model.Pass, Facts: map[string]string{}}
	problems, checked := 0, 0
	var discoveryErr error
	var checkedEvidence, problemEvidence []model.Evidence
	ordered := make([]string, 0, len(candidates))
	for path := range candidates {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		info, err := os.Stat(path)
		if err != nil {
			if candidates[path].required || !errors.Is(err, fs.ErrNotExist) {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, err))
			}
			continue
		}
		if !info.Mode().IsRegular() {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s is not a regular file", path))
			continue
		}
		checked++
		checkedEvidence = append(checkedEvidence, model.Evidence{Source: "stat", Key: "proxy_sensitive_file", Value: fmt.Sprintf("%s mode=%s", path, modeString(info))})
		if tooOpen(info, candidates[path].forbidden) {
			problems++
			problemEvidence = append(problemEvidence, model.Evidence{Source: "stat", Key: "insecure_mode", Value: fmt.Sprintf("%s mode=%s", path, modeString(info))})
		}
	}
	f.Facts["files_checked"] = strconv.Itoa(checked)
	f.Facts["permission_problems"] = strconv.Itoa(problems)
	if problems > 0 {
		f.Status, f.Severity = model.Risk, model.High
		f.Evidence = append(f.Evidence, problemEvidence[:min(len(problemEvidence), 20)]...)
		if len(problemEvidence) > 20 {
			f.Facts["evidence_omitted"] = strconv.Itoa(len(problemEvidence) - 20)
		}
	} else {
		f.Evidence = append(f.Evidence, checkedEvidence[:min(len(checkedEvidence), 20)]...)
		if len(checkedEvidence) > 20 {
			f.Facts["evidence_omitted"] = strconv.Itoa(len(checkedEvidence) - 20)
		}
	}
	if checked == 0 && discoveryErr == nil {
		return notApplicable("WORK-006", "workloads", "filesystem discovery", "no supported proxy secret-bearing file found")
	}
	return withIncompleteEvidence(f, "proxy sensitive-file metadata", discoveryErr)
}

func checkProxyServiceIsolation(ctx *Context) model.Finding {
	units, unitErr := proxyServiceUnits(ctx)
	if unitErr != nil {
		return unknown("WORK-007", "workloads", "systemd service discovery", unitErr.Error())
	}
	if len(units) == 0 {
		return notApplicable("WORK-007", "workloads", "systemd", "no supported proxy systemd service found")
	}
	f := model.Finding{ID: "WORK-007", Category: "workloads", Status: model.Info, Facts: map[string]string{"services": strconv.Itoa(len(units))}}
	rootServices, dangerousCapabilities := 0, 0
	var discoveryErr error
	for _, unit := range units {
		r := ctx.Commander.Run(10*time.Second, "systemctl", "show", unit,
			"--property=ActiveState,SubState,User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CapabilityBoundingSet,AmbientCapabilities,LimitNOFILE,NRestarts,FragmentPath")
		if r.Err != nil || r.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("systemctl show %s: %s", unit, commandError(r)))
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl show " + unit, Key: "unavailable", Value: commandError(r)})
			continue
		}
		values := parseKeyValues(r.Stdout)
		if values["User"] == "" || values["User"] == "root" {
			rootServices++
		}
		// CapabilityBoundingSet is only an upper bound and often defaults to a
		// broad set; it does not grant those capabilities. AmbientCapabilities,
		// on the other hand, is an explicit grant inherited by the service.
		ambientCapabilities := strings.ToUpper(values["AmbientCapabilities"])
		if containsAny(ambientCapabilities, "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH") {
			dangerousCapabilities++
			raiseRisk(&f, model.High)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl show", Key: "dangerous_proxy_service_ambient_capability", Value: unit + " explicitly receives a high-impact ambient capability; complete capability list withheld from summary"})
		}
		keys := []string{"ActiveState", "SubState", "User", "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "CapabilityBoundingSet", "AmbientCapabilities", "LimitNOFILE", "NRestarts"}
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			if value, ok := values[key]; ok {
				if key == "CapabilityBoundingSet" || key == "AmbientCapabilities" {
					value = truncate(value, 100)
				}
				parts = append(parts, strings.ToLower(key)+"="+value)
			}
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl show", Key: unit, Value: strings.Join(parts, " ")})
		if path := values["FragmentPath"]; path != "" {
			if info, err := os.Stat(path); err == nil && tooOpen(info, 0o022) {
				f.Status, f.Severity = model.Risk, model.High
				f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "writable_proxy_unit", Value: path + " mode=" + modeString(info)})
			}
		}
	}
	f.Facts["root_services"] = strconv.Itoa(rootServices)
	f.Facts["dangerous_capability_services"] = strconv.Itoa(dangerousCapabilities)
	return withIncompleteEvidence(f, "proxy systemd service properties", discoveryErr)
}

func checkProxyTransportContext(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	usesUDP := false
	for _, summary := range summaries {
		usesUDP = usesUDP || summary.UsesUDP
	}
	active := activeProxyProducts(ctx)
	usesUDP = usesUDP || active["hysteria2"] || active["tuic"] || active["shadowsocks"]
	if !usesUDP {
		return notApplicable("WORK-008", "workloads", "proxy configuration and process inventory", "no supported UDP-heavy proxy transport detected")
	}
	f := model.Finding{ID: "WORK-008", Category: "workloads", Status: model.Info, Facts: map[string]string{"udp_transport_detected": "true"}}
	for _, path := range []string{"/proc/sys/net/core/rmem_max", "/proc/sys/net/core/wmem_max", "/proc/sys/net/ipv4/udp_rmem_min", "/proc/sys/net/ipv4/udp_wmem_min"} {
		if value, err := readSmall(path, 1024); err == nil {
			f.Evidence = append(f.Evidence, model.Evidence{Source: path, Value: strings.TrimSpace(value)})
		}
	}
	if ctx.Commander.Exists("netstat") {
		r := ctx.Commander.Run(8*time.Second, "netstat", "-su")
		for _, line := range lines(r.Stdout) {
			if containsAny(strings.ToLower(line), "packet receive errors", "receive buffer errors", "send buffer errors", "rcvbuferrors", "sndbuferrors") {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "netstat -su", Key: "udp_counter", Value: truncate(line, 180)})
			}
		}
	}
	return f
}

func checkProxyEndpointRelations(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	inbounds := uniqueProxyInbounds(summaries)
	if len(inbounds) == 0 {
		return notApplicable("WORK-009", "workloads", "proxy configuration", "no supported configured proxy ingress found")
	}
	f := model.Finding{ID: "WORK-009", Category: "workloads", Status: model.Pass, Facts: map[string]string{"configured_endpoints": strconv.Itoa(len(inbounds))}}
	listeners, err := ctx.Facts.Listeners()
	if err != nil {
		return unknown("WORK-009", "workloads", "ss + proxy configuration", err.Error())
	}
	active := activeProxyProducts(ctx)
	ufw := readPanelUFW(ctx)
	graph := buildProxyEndpointGraph(inbounds, listeners, ufw)
	matched, missing, semanticProblems, relationUnknown := 0, 0, 0, 0
	for _, endpoint := range inbounds {
		if endpoint.RealityEnabled && (!endpoint.RealityKeySet || endpoint.RealityTargets == 0 || endpoint.RealityServerIDs == 0) {
			semanticProblems++
			f.Status, f.Severity = model.Risk, model.Medium
		}
		if endpoint.RealityEnabled {
			f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Path, Key: "reality_semantics", Value: fmt.Sprintf("product=%s port=%s private_key_set=%t target_set=%t server_name_or_short_id_count=%d", endpoint.Product, endpoint.Port, endpoint.RealityKeySet, endpoint.RealityTargets > 0, endpoint.RealityServerIDs)})
		}
	}
	for _, assessment := range assessProxyEndpointGraph(graph, active) {
		endpoint := assessment.Node
		if endpoint.Port == "" {
			f.Status = model.Info
			f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source, Key: "endpoint_unresolved", Value: fmt.Sprintf("product=%s protocol=%s reason=port_not_resolved", endpoint.Product, endpoint.Protocol)})
			continue
		}
		if assessment.Missing {
			missing++
			if assessment.Risk {
				f.Status, f.Severity = model.Risk, model.Medium
			} else if f.Status != model.Risk {
				f.Status = model.Info
			}
		} else {
			matched++
		}
		if assessment.Risk {
			f.Status, f.Severity = model.Risk, model.Medium
		}
		if assessment.Unknown {
			relationUnknown++
			if f.Status != model.Risk {
				f.Status, f.Unavailable = model.Unknown, true
				f.Error = "one or more proxy ingress firewall relationships could not be determined"
			}
		}
		inbound := proxyInbound{Product: endpoint.Product, Protocol: endpoint.Protocol, Port: endpoint.Port, Security: endpoint.Security}
		f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source + " + ss + host firewall", Key: "endpoint_relation", Value: endpointRelationValue(inbound, endpoint.Transport, valueOr(endpoint.Process, "none"), valueOr(endpoint.Scope, "none"), valueOr(endpoint.Firewall, "not-live"), assessment.Judgment)})
	}
	f.Facts["matched_listener_relations"] = strconv.Itoa(matched)
	f.Facts["missing_listener_relations"] = strconv.Itoa(missing)
	f.Facts["semantic_problems"] = strconv.Itoa(semanticProblems)
	f.Facts["unknown_firewall_relations"] = strconv.Itoa(relationUnknown)
	if connections, err := ctx.Facts.EstablishedConnections(); err == nil {
		ports := map[string]bool{}
		for _, endpoint := range inbounds {
			for _, transport := range endpoint.Transports {
				if transport == "tcp" {
					ports[endpoint.Port] = true
				}
			}
		}
		counts, total := proxyConnectionCounts(connections, ports)
		for port := range ports {
			if _, ok := counts[port]; !ok {
				counts[port] = 0
			}
		}
		f.Facts["established_proxy_tcp_connections"] = strconv.Itoa(total)
		for _, port := range sortedCountKeys(counts) {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss established + proxy ingress", Key: "connection_snapshot", Value: fmt.Sprintf("port=%s/tcp established=%d; peer addresses withheld from this workload summary", port, counts[port])})
		}
	} else {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ss established", Key: "connection_snapshot", Value: "unavailable: " + truncate(err.Error(), 180)})
	}
	return withIncompleteEvidence(f, "host firewall discovery", ufw.collectionErr)
}

func proxyConnectionCounts(connections []activeConnection, proxyPorts map[string]bool) (map[string]int, int) {
	counts, total := map[string]int{}, 0
	for _, connection := range connections {
		_, port := splitHostPortLoose(connection.local)
		if proxyPorts[port] {
			counts[port]++
			total++
		}
	}
	return counts, total
}

func sortedCountKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func checkWireGuardRuntime(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("wg") {
		return notApplicable("WORK-011", "workloads", "wg", "WireGuard tools are not installed")
	}
	interfacesResult := ctx.Commander.Run(8*time.Second, "wg", "show", "interfaces")
	if interfacesResult.Err != nil || interfacesResult.Truncated {
		return unknown("WORK-011", "workloads", "wg show interfaces", commandError(interfacesResult))
	}
	interfaces := strings.Fields(interfacesResult.Stdout)
	if len(interfaces) == 0 {
		return notApplicable("WORK-011", "workloads", "wg show interfaces", "no active WireGuard interface")
	}
	f := model.Finding{ID: "WORK-011", Category: "workloads", Status: model.Pass, Facts: map[string]string{"interfaces": strconv.Itoa(len(interfaces))}}
	listeners, listenerErr := ctx.Facts.Listeners()
	ufw := readPanelUFW(ctx)
	peers, recentPeers := 0, 0
	now := ctx.Now().Unix()
	var discoveryErr error
	discoveryErr = errors.Join(discoveryErr, listenerErr)
	for _, iface := range interfaces {
		if !validNetworkInterfaceName(iface) {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("wg returned an invalid interface name"))
			continue
		}
		portResult := ctx.Commander.Run(6*time.Second, "wg", "show", iface, "listen-port")
		if portResult.Err != nil || portResult.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("wg show %s listen-port: %s", iface, commandError(portResult)))
			f.Evidence = append(f.Evidence, model.Evidence{Source: "wg show", Key: "interface_unavailable", Value: fmt.Sprintf("interface=%s field=listen-port error=%s", iface, commandError(portResult))})
			continue
		}
		port := strings.TrimSpace(portResult.Stdout)
		if port != "0" && !validPort(port) {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("wg show %s listen-port returned an invalid port", iface))
			continue
		}
		live, scope, process := false, "none", "none"
		for _, listener := range listeners {
			if listener.Port == port && strings.HasPrefix(listener.Protocol, "udp") {
				live, scope, process = true, listener.Scope, listener.Process
			}
		}
		firewall := endpointFirewallDisposition(ufw, port, "udp")
		f.Evidence = append(f.Evidence, model.Evidence{Source: "wg + ss + ufw", Key: "wireguard_interface", Value: fmt.Sprintf("interface=%s port=%s/udp live=%t process=%s scope=%s firewall=%s", iface, port, live, truncate(process, 100), scope, firewall)})
		if listenerErr == nil && port != "" && port != "0" && !live {
			f.Status, f.Severity = model.Risk, model.Medium
		}
		peerResult := ctx.Commander.Run(6*time.Second, "wg", "show", iface, "peers")
		if peerResult.Err != nil || peerResult.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("wg show %s peers: %s", iface, commandError(peerResult)))
		} else {
			peers += len(strings.Fields(peerResult.Stdout))
		}
		handshakes := ctx.Commander.Run(6*time.Second, "wg", "show", iface, "latest-handshakes")
		if handshakes.Err != nil || handshakes.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("wg show %s latest-handshakes: %s", iface, commandError(handshakes)))
		} else {
			for _, line := range lines(handshakes.Stdout) {
				fields := strings.Fields(line)
				if len(fields) != 2 {
					continue
				}
				when, parseErr := strconv.ParseInt(fields[1], 10, 64)
				if parseErr != nil {
					discoveryErr = errors.Join(discoveryErr, fmt.Errorf("wg show %s latest-handshakes returned malformed metadata", iface))
					continue
				}
				if when > 0 && now-when <= int64(ctx.LogSince.Seconds()) {
					recentPeers++
				}
			}
		}
	}
	f.Facts["peers"] = strconv.Itoa(peers)
	f.Facts["peers_with_recent_handshake"] = strconv.Itoa(recentPeers)
	f.Evidence = append(f.Evidence, model.Evidence{Source: "wg show", Key: "peer_summary", Value: fmt.Sprintf("peers=%d recent_handshakes=%d; public keys and endpoints withheld", peers, recentPeers)})
	f = withIncompleteEvidence(f, "WireGuard runtime discovery", discoveryErr)
	return withIncompleteEvidence(f, "host firewall discovery", ufw.collectionErr)
}
