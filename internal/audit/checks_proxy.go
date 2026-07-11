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
	Product  string
	Protocol string
	Listen   string
	Port     string
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

var proxyProcessPattern = regexp.MustCompile(`(?i)\b(sing-box|xray|x-ui|s-ui|sui|hysteria|tuic|trojan|ss-server|sslocal|marzban|hiddify|outline-ss-server|wg-quick)\b`)

func proxyChecks(ctx *Context) []model.Finding {
	summaries := discoverProxyConfigs()
	return []model.Finding{
		checkProxyInventory(ctx, summaries),
		checkProxyConfiguration(ctx, summaries),
		checkProxyControlEndpoints(ctx, summaries),
		checkProxySensitivePermissions(summaries),
		checkProxyServiceIsolation(ctx),
		checkProxyTransportContext(ctx, summaries),
	}
}

func checkProxyInventory(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	f := model.Finding{ID: "WORK-003", Category: "workloads", Status: model.Info, Facts: map[string]string{}}
	products := map[string]bool{}
	if ctx.Commander.Exists("ps") {
		r := ctx.Commander.Run(8*time.Second, "ps", "-eo", "pid=,user=,comm=,args=")
		for _, line := range lines(r.Stdout) {
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
		for _, inbound := range summary.Inbounds {
			f.Evidence = append(f.Evidence, model.Evidence{Source: summary.Path, Key: "proxy_ingress", Value: fmt.Sprintf("product=%s protocol=%s listen=%s port=%s", inbound.Product, inbound.Protocol, inbound.Listen, inbound.Port)})
		}
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
	f.Facts["configured_inbounds"] = strconv.Itoa(countProxyInbounds(summaries))
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

func discoverProxyConfigs() []proxyConfigSummary {
	paths := existingFiles(
		"/etc/sing-box/config.json", "/etc/sing-box/*.json", "/usr/local/etc/sing-box/config.json", "/usr/local/etc/sing-box/*.json",
		"/etc/xray/config.json", "/etc/xray/*.json", "/usr/local/etc/xray/config.json", "/usr/local/etc/xray/*.json",
		"/usr/local/x-ui/bin/config.json", "/usr/local/s-ui/bin/config.json",
		"/etc/hysteria/config.yaml", "/etc/hysteria/config.yml", "/etc/tuic/config.json", "/etc/trojan/config.json",
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
		default:
			summary.Parseable = json.Valid([]byte(data))
			if !summary.Parseable {
				summary.Err = fmt.Errorf("invalid JSON")
			}
		}
		out = append(out, summary)
	}
	return out
}

func parseSingBoxSummary(path string, data []byte) proxyConfigSummary {
	type inbound struct {
		Type       string          `json:"type"`
		Listen     string          `json:"listen"`
		ListenPort json.RawMessage `json:"listen_port"`
		Network    string          `json:"network"`
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
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: item.Type, Listen: listen, Port: port})
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
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: item.Protocol, Listen: listen, Port: port})
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
			s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "hysteria2", Listen: host, Port: port})
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
		s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: "tuic", Listen: host, Port: port})
	}
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
	if !ctx.Commander.Exists("ps") {
		return out
	}
	r := ctx.Commander.Run(8*time.Second, "ps", "-eo", "comm=,args=")
	for _, line := range lines(r.Stdout) {
		if product, ok := proxyProcessLineWithoutPID(line); ok {
			out[strings.ToLower(product)] = true
		}
	}
	return out
}

func currentListeners(ctx *Context) ([]Listener, bool) {
	if !ctx.Commander.Exists("ss") {
		return nil, false
	}
	r := ctx.Commander.Run(12*time.Second, "ss", "-H", "-lntup")
	if r.Err != nil {
		return nil, false
	}
	return parseListeners(r.Stdout), true
}

func proxyProductFromText(value string) string {
	lower := strings.ToLower(value)
	switch {
	case containsAny(lower, "3x-ui", "x-ui"):
		return "x-ui/3x-ui"
	case containsAny(lower, "s-ui", "/sui", " sui"):
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

func countProxyInbounds(summaries []proxyConfigSummary) int {
	total := 0
	for _, summary := range summaries {
		total += len(summary.Inbounds)
	}
	return total
}
