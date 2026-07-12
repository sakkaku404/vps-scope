package audit

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type proxyInbound struct {
	Product          string
	Protocol         string
	Listen           string
	Port             string
	Transports       []string
	Security         string
	RealityEnabled   bool
	RealityKeySet    bool
	RealityTargets   int
	RealityServerIDs int
}

type controlEndpoint struct {
	Product string
	Kind    string
	Listen  string
	Port    string
}

type proxyConfigSummary struct {
	Product   string
	Path      string
	Inbounds  []proxyInbound
	Controls  []controlEndpoint
	UsesUDP   bool
	Parseable bool
	Err       error
}

// configuredProxyInbound keeps the source path while allowing checks to
// collapse an identical ingress described by both a panel database and its
// generated runtime configuration. Panels such as 3x-ui intentionally keep
// those two views in sync; counting both would make the report misleading.
type configuredProxyInbound struct {
	Path string
	proxyInbound
}

var proxyProcessPattern = regexp.MustCompile(`(?i)\b(sing-box|xray|x-ui|s-ui|sui|hysteria|tuic|trojan|ss-server|sslocal|marzban|hiddify|outline-ss-server|wg-quick|openvpn)\b`)

func proxyChecks(ctx *Context) []model.Finding {
	summaries := discoverProxyConfigs(ctx)
	return []model.Finding{
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
	}
}

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
	databaseUnavailable, mismatches, roleCollisions, unclassified := 0, 0, 0, 0
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
			knownPorts[inbound.Port] = true
			if inbound.Enabled {
				enabledPorts[inbound.Port] = true
			}
		}
		for _, inbound := range panel.Inbounds {
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
		processNeedle := strings.ToLower(panel.Product)
		for _, listener := range listeners {
			process := strings.ToLower(listener.Process)
			owned := strings.Contains(process, "x-ui") && strings.Contains(processNeedle, "ui") || strings.Contains(process, "sui") && panel.Product == "S-UI"
			if owned && !knownPorts[listener.Port] {
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
	f.Facts["expired_inbounds"] = strconv.Itoa(expired)
	f.Facts["quota_exhausted_inbounds"] = strconv.Itoa(exhausted)
	if f.Status != model.Risk && (databaseUnavailable > 0 || unclassified > 0) {
		f.Status = model.Info
	}
	return f
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

func checkProxyInventory(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	f := model.Finding{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{}}
	products := map[string]bool{}
	if ctx.Facts != nil {
		processes, _ := ctx.Facts.Processes()
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
		f.Evidence = append(f.Evidence, model.Evidence{Source: inbound.Path, Key: "proxy_ingress", Value: fmt.Sprintf("product=%s protocol=%s listen=%s port=%s", inbound.Product, inbound.Protocol, inbound.Listen, inbound.Port)})
	}
	if ctx.Commander.Exists("docker") {
		r := ctx.Commander.Run(10*time.Second, "docker", "ps", "--format", "{{.Names}} {{.Image}}")
		for _, line := range lines(r.Stdout) {
			if proxyProcessPattern.MatchString(line) || containsAny(strings.ToLower(line), "marzban", "hiddify", "outline") {
				product := proxyProductFromText(line)
				products[product] = true
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker ps", Key: "proxy_container", Value: truncate(line, 240)})
			}
		}
	}
	if len(products) == 0 {
		return notApplicable("WORK-003", "workloads", "process, config, and container discovery", "no supported proxy workload detected")
	}
	names := make([]string, 0, len(products))
	for product := range products {
		names = append(names, product)
	}
	sort.Strings(names)
	f.Facts["products"] = strings.Join(names, ",")
	f.Facts["product_count"] = strconv.Itoa(len(names))
	f.Facts["configured_inbounds"] = strconv.Itoa(len(uniqueProxyInbounds(summaries)))
	return f
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
		if strings.HasSuffix(summary.Path, ".db") {
			continue
		}
		binary, args := proxySelfTest(summary.Product, summary.Path)
		if binary == "" || !ctx.Commander.Exists(binary) {
			continue
		}
		if summary.Product == "sing-box" && !strings.Contains(summary.Path, "/usr/local/s-ui/") {
			args = []string{"check", "-C", filepath.Dir(summary.Path)}
		}
		command := strings.Join(append([]string{binary}, args...), " ")
		if testedCommands[command] {
			continue
		}
		testedCommands[command] = true
		selfTests++
		r := ctx.Commander.Run(15*time.Second, binary, args...)
		if r.Err != nil {
			errorsFound++
			f.Evidence = append(f.Evidence, model.Evidence{Source: command, Key: "self_test_failed", Value: commandError(r)})
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
		for _, listener := range listeners {
			if listener.Port == endpoint.Port && strings.HasPrefix(listener.Protocol, "tcp") {
				live = true
				if listener.Scope == "public" || listener.Scope == "public-wildcard" {
					scope = listener.Scope
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
		switch panelFirewallDisposition(ufw, endpoint.Port, &f) {
		case "allow-anywhere", "inactive":
			f.Status, f.Severity = model.Risk, model.High
		case "restricted", "blocked-by-default":
		default:
			unknown++
		}
	}
	f.Facts["live_public_endpoints"] = strconv.Itoa(publicLive)
	if f.Status != model.Risk && unknown > 0 {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "control API exposure could not be fully determined from listener and host-firewall evidence"
	}
	return f
}

func checkProxySensitivePermissions(summaries []proxyConfigSummary) model.Finding {
	paths := map[string]fs.FileMode{}
	for _, summary := range summaries {
		paths[summary.Path] = 0o027 // allow controlled group read, never group write or other access
	}
	for _, path := range []string{
		"/usr/local/s-ui/db/s-ui.db", "/etc/s-ui/s-ui.db", "/etc/x-ui/x-ui.db", "/etc/wireguard/wg0.conf",
		"/etc/hysteria/config.yaml", "/etc/hysteria/config.yml", "/etc/tuic/config.json", "/etc/trojan/config.json",
	} {
		if regularFile(path) {
			paths[path] = 0o027
		}
	}
	if len(paths) == 0 {
		return notApplicable("WORK-006", "workloads", "filesystem discovery", "no supported proxy secret-bearing file found")
	}
	f := model.Finding{ID: "WORK-006", Category: "workloads", Status: model.Pass, Facts: map[string]string{"files_checked": strconv.Itoa(len(paths))}}
	problems := 0
	ordered := make([]string, 0, len(paths))
	for path := range paths {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	for _, path := range ordered {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "proxy_sensitive_file", Value: fmt.Sprintf("%s mode=%s", path, modeString(info))})
		if tooOpen(info, paths[path]) {
			problems++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "insecure_mode", Value: fmt.Sprintf("%s mode=%s", path, modeString(info))})
		}
	}
	f.Facts["permission_problems"] = strconv.Itoa(problems)
	if problems > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	return f
}

func checkProxyServiceIsolation(ctx *Context) model.Finding {
	units := proxyServiceUnits(ctx)
	if len(units) == 0 {
		return notApplicable("WORK-007", "workloads", "systemd", "no supported proxy systemd service found")
	}
	f := model.Finding{ID: "WORK-007", Category: "workloads", Status: model.Info, Facts: map[string]string{"services": strconv.Itoa(len(units))}}
	for _, unit := range units {
		r := ctx.Commander.Run(10*time.Second, "systemctl", "show", unit,
			"--property=ActiveState,SubState,User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CapabilityBoundingSet,AmbientCapabilities,LimitNOFILE,NRestarts,FragmentPath")
		if r.Err != nil {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl show " + unit, Key: "unavailable", Value: commandError(r)})
			continue
		}
		values := parseKeyValues(r.Stdout)
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
	return f
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
	matched, missing, semanticProblems := 0, 0, 0
	for _, endpoint := range inbounds {
		transports := endpoint.Transports
		if len(transports) == 0 {
			transports = proxyTransports(endpoint.Protocol, "")
		}
		if endpoint.Port == "" {
			f.Status = model.Info
			f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Path, Key: "endpoint_unresolved", Value: fmt.Sprintf("product=%s protocol=%s reason=port_not_resolved", endpoint.Product, endpoint.Protocol)})
			continue
		}
		if endpoint.RealityEnabled && (!endpoint.RealityKeySet || endpoint.RealityTargets == 0 || endpoint.RealityServerIDs == 0) {
			semanticProblems++
			f.Status, f.Severity = model.Risk, model.Medium
		}
		for _, transport := range transports {
			var live []Listener
			for _, listener := range listeners {
				if listener.Port == endpoint.Port && strings.HasPrefix(listener.Protocol, transport) {
					live = append(live, listener)
				}
			}
			if len(live) == 0 {
				missing++
				status := "configured_not_listening"
				if active[strings.ToLower(endpoint.Product)] {
					f.Status, f.Severity = model.Risk, model.Medium
					status = "active_product_but_not_listening"
				} else if f.Status != model.Risk {
					f.Status = model.Info
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Path + " + ss", Key: "endpoint_relation", Value: endpointRelationValue(endpoint.proxyInbound, transport, "none", "none", "not-live", status)})
				continue
			}
			matched++
			for _, listener := range live {
				firewall := endpointFirewallDisposition(ufw, endpoint.Port, transport)
				judgment := "expected-proxy-ingress"
				if product, known := listenerProxyProduct(listener.Process); known && !sameProxyProduct(product, endpoint.Product) {
					judgment = "listener-owner-does-not-match-configured-product"
					f.Status, f.Severity = model.Risk, model.Medium
				}
				if (listener.Scope == "public" || listener.Scope == "public-wildcard") && firewall == "blocked-by-default" {
					judgment = "configured-public-ingress-blocked-by-host-firewall"
					f.Status, f.Severity = model.Risk, model.Medium
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Path + " + ss + ufw", Key: "endpoint_relation", Value: endpointRelationValue(endpoint.proxyInbound, transport, listener.Process, listener.Scope, firewall, judgment)})
			}
		}
		if endpoint.RealityEnabled {
			f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Path, Key: "reality_semantics", Value: fmt.Sprintf("product=%s port=%s private_key_set=%t target_set=%t server_name_or_short_id_count=%d", endpoint.Product, endpoint.Port, endpoint.RealityKeySet, endpoint.RealityTargets > 0, endpoint.RealityServerIDs)})
		}
	}
	f.Facts["matched_listener_relations"] = strconv.Itoa(matched)
	f.Facts["missing_listener_relations"] = strconv.Itoa(missing)
	f.Facts["semantic_problems"] = strconv.Itoa(semanticProblems)
	return f
}

func listenerProxyProduct(process string) (string, bool) {
	product := proxyProductFromText(process)
	return product, product != "unknown-proxy"
}

func sameProxyProduct(a, b string) bool {
	normalize := func(value string) string {
		value = strings.ToLower(value)
		switch {
		case containsAny(value, "x-ui", "xray"):
			return "xray-family"
		case containsAny(value, "s-ui", "sing-box"):
			return "sing-box-family"
		default:
			return value
		}
	}
	return normalize(a) == normalize(b)
}

func checkWireGuardRuntime(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("wg") {
		return notApplicable("WORK-011", "workloads", "wg", "WireGuard tools are not installed")
	}
	interfacesResult := ctx.Commander.Run(8*time.Second, "wg", "show", "interfaces")
	if interfacesResult.Err != nil {
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
	for _, iface := range interfaces {
		portResult := ctx.Commander.Run(6*time.Second, "wg", "show", iface, "listen-port")
		port := strings.TrimSpace(portResult.Stdout)
		live, scope, process := false, "none", "none"
		for _, listener := range listeners {
			if listener.Port == port && strings.HasPrefix(listener.Protocol, "udp") {
				live, scope, process = true, listener.Scope, listener.Process
			}
		}
		firewall := endpointFirewallDisposition(ufw, port, "udp")
		f.Evidence = append(f.Evidence, model.Evidence{Source: "wg + ss + ufw", Key: "wireguard_interface", Value: fmt.Sprintf("interface=%s port=%s/udp live=%t process=%s scope=%s firewall=%s", iface, port, live, truncate(process, 100), scope, firewall)})
		if listenerErr != nil {
			f.Status, f.Unavailable = model.Unknown, true
			f.Error = listenerErr.Error()
		} else if port != "" && port != "0" && !live {
			f.Status, f.Severity = model.Risk, model.Medium
		}
		peerResult := ctx.Commander.Run(6*time.Second, "wg", "show", iface, "peers")
		peers += len(strings.Fields(peerResult.Stdout))
		handshakes := ctx.Commander.Run(6*time.Second, "wg", "show", iface, "latest-handshakes")
		for _, line := range lines(handshakes.Stdout) {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				continue
			}
			when, _ := strconv.ParseInt(fields[1], 10, 64)
			if when > 0 && now-when <= int64(ctx.LogSince.Seconds()) {
				recentPeers++
			}
		}
	}
	f.Facts["peers"] = strconv.Itoa(peers)
	f.Facts["peers_with_recent_handshake"] = strconv.Itoa(recentPeers)
	f.Evidence = append(f.Evidence, model.Evidence{Source: "wg show", Key: "peer_summary", Value: fmt.Sprintf("peers=%d recent_handshakes=%d; public keys and endpoints withheld", peers, recentPeers)})
	return f
}

func proxyTransports(protocol, network string) []string {
	p := strings.ToLower(protocol)
	n := strings.ToLower(network)
	if containsAny(p+" "+n, "hysteria", "tuic", "quic", "kcp") {
		return []string{"udp"}
	}
	if strings.Contains(p, "shadowsocks") || strings.Contains(p, "mixed") {
		if n == "tcp" || n == "udp" {
			return []string{n}
		}
		return []string{"tcp", "udp"}
	}
	if n == "udp" {
		return []string{"udp"}
	}
	return []string{"tcp"}
}

func endpointRelationValue(in proxyInbound, transport, process, scope, firewall, judgment string) string {
	security := in.Security
	if in.RealityEnabled {
		security = "reality"
	}
	if security == "" {
		security = "none-or-protocol-native"
	}
	return fmt.Sprintf("port=%s/%s process=%s purpose=%s/%s security=%s scope=%s firewall=%s judgment=%s", in.Port, transport, truncate(process, 120), in.Product, in.Protocol, security, scope, firewall, judgment)
}

func endpointFirewallDisposition(ufw panelUFW, port, protocol string) string {
	if !ufw.available {
		return "unknown"
	}
	if !ufw.active {
		return "inactive"
	}
	allowed := false
	for _, line := range ufw.lines {
		idx := strings.Index(line, "ALLOW IN")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(line[:idx])
		if target == port || strings.HasPrefix(target, port+"/"+protocol) {
			allowed = true
			if strings.HasPrefix(strings.TrimSpace(line[idx+len("ALLOW IN"):]), "Anywhere") {
				return "allow-anywhere"
			}
		}
	}
	if allowed {
		return "allow-restricted"
	}
	if ufw.defaultDeny {
		return "blocked-by-default"
	}
	return "no-explicit-rule"
}

func discoverProxyConfigs(ctx *Context) []proxyConfigSummary {
	paths := existingFiles(
		"/etc/sing-box/config.json", "/etc/sing-box/*.json", "/usr/local/etc/sing-box/config.json", "/usr/local/etc/sing-box/*.json",
		"/etc/xray/config.json", "/etc/xray/*.json", "/usr/local/etc/xray/config.json", "/usr/local/etc/xray/*.json",
		"/usr/local/x-ui/bin/config.json", "/usr/local/s-ui/bin/config.json",
		"/etc/hysteria/config.yaml", "/etc/hysteria/config.yml", "/etc/tuic/config.json", "/etc/trojan/config.json",
		"/etc/shadowsocks/config.json", "/etc/shadowsocks-libev/config.json", "/etc/shadowsocks-libev/*.json",
		"/etc/openvpn/*.conf", "/etc/openvpn/server/*.conf",
	)
	out := make([]proxyConfigSummary, 0, len(paths))
	for _, path := range paths {
		data, err := readSmall(path, 16<<20)
		if err != nil {
			out = append(out, proxyConfigSummary{Product: proxyProductFromPath(path), Path: path, Err: err})
			continue
		}
		product := proxyProductFromPath(path)
		summary := proxyConfigSummary{Product: product, Path: path}
		switch product {
		case "sing-box":
			summary = parseSingBoxSummary(path, []byte(data))
		case "Xray":
			summary = parseXraySummary(path, []byte(data))
		case "Hysteria2":
			summary = parseHysteriaSummary(path, data)
		case "TUIC":
			summary = parseTUICSummary(path, []byte(data))
		case "Trojan":
			summary = parseTrojanSummary(path, []byte(data))
		case "Shadowsocks":
			summary = parseShadowsocksSummary(path, []byte(data))
		case "OpenVPN":
			summary = parseOpenVPNSummary(path, data)
		default:
			summary.Parseable = json.Valid([]byte(data))
			if !summary.Parseable {
				summary.Err = fmt.Errorf("invalid JSON")
			}
		}
		out = append(out, summary)
	}
	for _, panel := range ctx.Facts.Panels() {
		if summary, ok := panelProxySummary(panel); ok {
			out = append(out, summary)
		}
	}
	return out
}

func panelProxySummary(panel panelSnapshot) (proxyConfigSummary, bool) {
	if !panel.DatabaseAvailable || len(panel.Inbounds) == 0 {
		return proxyConfigSummary{}, false
	}
	product := "Xray"
	if panel.Product == "S-UI" {
		product = "sing-box"
	}
	s := proxyConfigSummary{Product: product, Path: panel.Database, Parseable: true}
	for _, item := range panel.Inbounds {
		if !item.Enabled {
			continue
		}
		transports := proxyTransports(item.Protocol, item.Network)
		reality := strings.EqualFold(item.Security, "reality")
		s.Inbounds = append(s.Inbounds, proxyInbound{
			Product: product, Protocol: item.Protocol, Listen: item.Listen, Port: item.Port,
			Transports: transports, Security: item.Security, RealityEnabled: reality,
			RealityKeySet: item.RealityKeySet, RealityTargets: item.RealityTargets, RealityServerIDs: item.RealityIDs,
		})
		for _, transport := range transports {
			s.UsesUDP = s.UsesUDP || transport == "udp"
		}
	}
	return s, true
}

func parseSingBoxSummary(path string, data []byte) proxyConfigSummary {
	type inbound struct {
		Type       string          `json:"type"`
		Listen     string          `json:"listen"`
		ListenPort json.RawMessage `json:"listen_port"`
		Network    string          `json:"network"`
		TLS        struct {
			Enabled bool `json:"enabled"`
			Reality struct {
				Enabled    bool     `json:"enabled"`
				PrivateKey string   `json:"private_key"`
				ShortID    []string `json:"short_id"`
				Handshake  struct {
					Server     string `json:"server"`
					ServerPort int    `json:"server_port"`
				} `json:"handshake"`
			} `json:"reality"`
		} `json:"tls"`
	}
	var cfg struct {
		Inbounds     []inbound `json:"inbounds"`
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
			} `json:"clash_api"`
			V2RayAPI struct {
				Listen string `json:"listen"`
			} `json:"v2ray_api"`
		} `json:"experimental"`
	}
	s := proxyConfigSummary{Product: "sing-box", Path: path}
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.Err = err
		return s
	}
	s.Parseable = true
	for _, item := range cfg.Inbounds {
		port := jsonPort(item.ListenPort)
		listen := normalizeListen(item.Listen)
		security := ""
		if item.TLS.Enabled {
			security = "tls"
		}
		realityTargets := 0
		if item.TLS.Reality.Handshake.Server != "" || item.TLS.Reality.Handshake.ServerPort != 0 {
			realityTargets = 1
		}
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: item.Type, Listen: listen, Port: port,
			Transports: proxyTransports(item.Type, item.Network), Security: security,
			RealityEnabled: item.TLS.Reality.Enabled, RealityKeySet: item.TLS.Reality.PrivateKey != "",
			RealityTargets: realityTargets, RealityServerIDs: len(item.TLS.Reality.ShortID)})
		if containsAny(strings.ToLower(item.Type+" "+item.Network), "hysteria", "tuic", "shadowsocks", "udp") {
			s.UsesUDP = true
		}
	}
	for _, endpoint := range []struct{ kind, value string }{
		{"clash-api", cfg.Experimental.ClashAPI.ExternalController},
		{"v2ray-api", cfg.Experimental.V2RayAPI.Listen},
	} {
		if host, port, ok := splitEndpoint(endpoint.value); ok {
			s.Controls = append(s.Controls, controlEndpoint{Product: s.Product, Kind: endpoint.kind, Listen: host, Port: port})
		}
	}
	return s
}

func parseXraySummary(path string, data []byte) proxyConfigSummary {
	var cfg struct {
		Inbounds []struct {
			Listen   string          `json:"listen"`
			Port     json.RawMessage `json:"port"`
			Protocol string          `json:"protocol"`
			Tag      string          `json:"tag"`
			Settings struct {
				Network string `json:"network"`
			} `json:"settings"`
			StreamSettings struct {
				Network  string `json:"network"`
				Security string `json:"security"`
				Reality  struct {
					Target      string   `json:"target"`
					Dest        string   `json:"dest"`
					PrivateKey  string   `json:"privateKey"`
					ServerNames []string `json:"serverNames"`
					ShortIDs    []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	s := proxyConfigSummary{Product: "Xray", Path: path}
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.Err = err
		return s
	}
	s.Parseable = true
	for _, item := range cfg.Inbounds {
		port := jsonPort(item.Port)
		listen := normalizeListen(item.Listen)
		reality := strings.EqualFold(item.StreamSettings.Security, "reality")
		targets := 0
		if item.StreamSettings.Reality.Target != "" || item.StreamSettings.Reality.Dest != "" {
			targets = 1
		}
		network := item.StreamSettings.Network
		if strings.EqualFold(item.Protocol, "shadowsocks") && item.Settings.Network != "" {
			network = item.Settings.Network
		}
		transports := proxyTransports(item.Protocol, network)
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: item.Protocol, Listen: listen, Port: port,
			Transports: transports, Security: item.StreamSettings.Security,
			RealityEnabled: reality, RealityKeySet: item.StreamSettings.Reality.PrivateKey != "",
			RealityTargets: targets, RealityServerIDs: len(item.StreamSettings.Reality.ServerNames) + len(item.StreamSettings.Reality.ShortIDs)})
		for _, transport := range transports {
			s.UsesUDP = s.UsesUDP || transport == "udp"
		}
		if strings.Contains(strings.ToLower(item.Tag), "api") {
			s.Controls = append(s.Controls, controlEndpoint{Product: s.Product, Kind: "api-inbound", Listen: listen, Port: port})
		}
	}
	return s
}

func parseHysteriaSummary(path, data string) proxyConfigSummary {
	s := proxyConfigSummary{Product: "Hysteria2", Path: path, Parseable: true, UsesUDP: true}
	match := regexp.MustCompile(`(?mi)^\s*listen\s*:\s*["']?([^\s#"']+)`).FindStringSubmatch(data)
	if len(match) == 2 {
		host, port, ok := splitEndpoint(match[1])
		if ok {
			s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "hysteria2", Listen: host, Port: port, Transports: []string{"udp"}})
		}
	}
	return s
}

func parseTUICSummary(path string, data []byte) proxyConfigSummary {
	var cfg struct {
		Server string `json:"server"`
	}
	s := proxyConfigSummary{Product: "TUIC", Path: path, UsesUDP: true}
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.Err = err
		return s
	}
	s.Parseable = true
	if host, port, ok := splitEndpoint(cfg.Server); ok {
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "tuic", Listen: host, Port: port, Transports: []string{"udp"}})
	}
	return s
}

func parseTrojanSummary(path string, data []byte) proxyConfigSummary {
	var cfg struct {
		LocalAddress string          `json:"local_addr"`
		LocalPort    json.RawMessage `json:"local_port"`
	}
	s := proxyConfigSummary{Product: "Trojan", Path: path}
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.Err = err
		return s
	}
	s.Parseable = true
	if port := jsonPort(cfg.LocalPort); port != "" {
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "trojan", Listen: normalizeListen(cfg.LocalAddress), Port: port, Transports: []string{"tcp"}, Security: "tls"})
	}
	return s
}

func parseShadowsocksSummary(path string, data []byte) proxyConfigSummary {
	var cfg struct {
		Server     json.RawMessage `json:"server"`
		ServerPort json.RawMessage `json:"server_port"`
		Mode       string          `json:"mode"`
	}
	s := proxyConfigSummary{Product: "Shadowsocks", Path: path}
	if err := json.Unmarshal(data, &cfg); err != nil {
		s.Err = err
		return s
	}
	s.Parseable = true
	listen := "::"
	var host string
	if json.Unmarshal(cfg.Server, &host) == nil && host != "" {
		listen = normalizeListen(host)
	}
	transports := []string{"tcp", "udp"}
	mode := strings.ToLower(cfg.Mode)
	if mode == "tcp_only" || mode == "tcp" {
		transports = []string{"tcp"}
	} else if mode == "udp_only" || mode == "udp" {
		transports = []string{"udp"}
	}
	if port := jsonPort(cfg.ServerPort); port != "" {
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "shadowsocks", Listen: listen, Port: port, Transports: transports})
		s.UsesUDP = len(transports) > 1 || transports[0] == "udp"
	}
	return s
}

func parseOpenVPNSummary(path, data string) proxyConfigSummary {
	s := proxyConfigSummary{Product: "OpenVPN", Path: path, Parseable: true}
	listen, port, transport := "::", "1194", "udp"
	for _, line := range lines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "local":
			listen = normalizeListen(fields[1])
		case "port":
			if value, err := strconv.Atoi(fields[1]); err == nil && value > 0 && value <= 65535 {
				port = fields[1]
			}
		case "proto":
			if strings.HasPrefix(strings.ToLower(fields[1]), "tcp") {
				transport = "tcp"
			} else if strings.HasPrefix(strings.ToLower(fields[1]), "udp") {
				transport = "udp"
			}
		}
	}
	s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "openvpn", Listen: listen, Port: port, Transports: []string{transport}, Security: "tls"})
	s.UsesUDP = transport == "udp"
	return s
}

func proxyServiceUnits(ctx *Context) []string {
	if !ctx.Commander.Exists("systemctl") {
		return nil
	}
	r := ctx.Commander.Run(12*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain")
	seen := map[string]bool{}
	for _, line := range lines(r.Stdout) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		if proxyProcessPattern.MatchString(fields[0]) || containsAny(strings.ToLower(fields[0]), "marzban", "hiddify", "outline") {
			seen[fields[0]] = true
		}
	}
	units := make([]string, 0, len(seen))
	for unit := range seen {
		units = append(units, unit)
	}
	sort.Strings(units)
	return units
}

func activeProxyProducts(ctx *Context) map[string]bool {
	out := map[string]bool{}
	processes, err := ctx.Facts.Processes()
	if err != nil {
		return out
	}
	for _, process := range processes {
		line := processLine(process)
		if product, ok := proxyProcessLineWithoutPID(line); ok {
			out[strings.ToLower(product)] = true
		}
	}
	return out
}

func currentListeners(ctx *Context) ([]Listener, bool) {
	listeners, err := ctx.Facts.Listeners()
	if err != nil {
		return nil, false
	}
	return listeners, true
}

func proxyProductFromText(value string) string {
	lower := strings.ToLower(value)
	switch {
	case containsAny(lower, "3x-ui", "x-ui"):
		return "x-ui/3x-ui"
	case lower == "sui", containsAny(lower, "s-ui", "/sui", " sui"):
		return "S-UI"
	case strings.Contains(lower, "sing-box"):
		return "sing-box"
	case strings.Contains(lower, "xray"):
		return "Xray"
	case strings.Contains(lower, "hysteria"):
		return "Hysteria2"
	case strings.Contains(lower, "tuic"):
		return "TUIC"
	case strings.Contains(lower, "trojan"):
		return "Trojan"
	case containsAny(lower, "ss-server", "sslocal"):
		return "Shadowsocks"
	case strings.Contains(lower, "marzban"):
		return "Marzban"
	case strings.Contains(lower, "hiddify"):
		return "Hiddify"
	case strings.Contains(lower, "outline"):
		return "Outline"
	case strings.Contains(lower, "wg-quick"):
		return "WireGuard"
	case strings.Contains(lower, "openvpn"):
		return "OpenVPN"
	default:
		return "unknown-proxy"
	}
}

func proxyProductFromPath(path string) string {
	lower := strings.ToLower(filepath.ToSlash(path))
	switch {
	case strings.Contains(lower, "/x-ui/bin/config.json"):
		return "Xray"
	case strings.Contains(lower, "/s-ui/bin/config.json"):
		return "sing-box"
	case strings.Contains(lower, "/sing-box/"):
		return "sing-box"
	case strings.Contains(lower, "/xray/"):
		return "Xray"
	case strings.Contains(lower, "/hysteria/"):
		return "Hysteria2"
	case strings.Contains(lower, "/tuic/"):
		return "TUIC"
	case strings.Contains(lower, "/trojan/"):
		return "Trojan"
	case strings.Contains(lower, "/shadowsocks"):
		return "Shadowsocks"
	case strings.Contains(lower, "/openvpn/"):
		return "OpenVPN"
	default:
		return "unknown-proxy"
	}
}

func sanitizeProcessEvidence(value string) string {
	// Command lines can contain UUIDs, passwords, tokens, or subscription URLs.
	// Keep only PID/user/comm-sized context and never export full arguments.
	fields := strings.Fields(value)
	if len(fields) > 3 {
		fields = fields[:3]
	}
	return strings.Join(fields, " ")
}

func workloadProcessLine(value string) bool {
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return false
	}
	comm := strings.ToLower(fields[2])
	if workloadProcesses.MatchString(comm) {
		return true
	}
	// Some panels are launched by an interpreter. Inspect arguments only for
	// those interpreters, but never export the arguments themselves.
	if containsAny(comm, "python", "gunicorn", "uvicorn", "node") {
		return containsAny(strings.ToLower(value), "marzban", "hiddify", "outline")
	}
	return false
}

func proxyProcessLine(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return "", false
	}
	return proxyProcessIdentity(fields[2], value)
}

func proxyProcessLineWithoutPID(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}
	return proxyProcessIdentity(fields[0], value)
}

func proxyProcessIdentity(comm, fullLine string) (string, bool) {
	comm = strings.ToLower(filepath.Base(comm))
	if proxyProcessPattern.MatchString(comm) {
		return proxyProductFromText(comm), true
	}
	if containsAny(comm, "python", "gunicorn", "uvicorn", "node") {
		lower := strings.ToLower(fullLine)
		if containsAny(lower, "marzban", "hiddify", "outline") {
			return proxyProductFromText(lower), true
		}
	}
	return "", false
}

func proxySelfTest(product, path string) (string, []string) {
	switch product {
	case "sing-box":
		if strings.Contains(path, "/usr/local/s-ui/") && regularFile("/usr/local/s-ui/bin/sing-box") {
			return "/usr/local/s-ui/bin/sing-box", []string{"check", "-c", path}
		}
		return "sing-box", []string{"check", "-c", path}
	case "Xray":
		if strings.Contains(path, "/usr/local/x-ui/") && regularFile("/usr/local/x-ui/bin/xray-linux-amd64") {
			return "/usr/local/x-ui/bin/xray-linux-amd64", []string{"run", "-test", "-config", path}
		}
		return "xray", []string{"run", "-test", "-config", path}
	}
	return "", nil
}

func normalizeListen(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "::"
	}
	return strings.Trim(value, "[]")
}

func splitEndpoint(value string) (string, string, bool) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" {
		return "", "", false
	}
	if strings.HasPrefix(value, ":") {
		port := strings.TrimPrefix(value, ":")
		return "::", port, validPort(port)
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		return normalizeListen(host), port, validPort(port)
	}
	if !strings.Contains(value, ":") && validPort(value) {
		return "::", value, true
	}
	host, port := splitHostPortLoose(value)
	return normalizeListen(host), port, validPort(port)
}

func validPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port > 0 && port <= 65535
}

func jsonPort(raw json.RawMessage) string {
	value := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if validPort(value) {
		return value
	}
	return "unknown"
}

func uniqueProxyInbounds(summaries []proxyConfigSummary) []configuredProxyInbound {
	seen := map[string]bool{}
	out := make([]configuredProxyInbound, 0)
	for _, summary := range summaries {
		for _, inbound := range summary.Inbounds {
			transports := append([]string(nil), inbound.Transports...)
			sort.Strings(transports)
			key := strings.Join([]string{
				strings.ToLower(inbound.Product), strings.ToLower(inbound.Protocol), canonicalIngressListen(inbound.Listen), inbound.Port,
				strings.Join(transports, ","), strings.ToLower(inbound.Security), strconv.FormatBool(inbound.RealityEnabled),
			}, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			inbound.Transports = transports
			out = append(out, configuredProxyInbound{Path: summary.Path, proxyInbound: inbound})
		}
	}
	return out
}

func canonicalIngressListen(value string) string {
	value = normalizeListen(value)
	if value == "0.0.0.0" || value == "::" {
		return "wildcard"
	}
	return value
}
