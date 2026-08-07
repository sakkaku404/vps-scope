package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func validNetworkInterfaceName(value string) bool {
	if value == "" || len(value) > 15 || strings.HasPrefix(value, "-") {
		return false
	}
	for _, r := range value {
		if r <= ' ' || strings.ContainsRune(`/\`, r) {
			return false
		}
	}
	return true
}

func discoverProxyConfigs(ctx *Context) ([]proxyConfigSummary, error) {
	paths, discoveryErr := discoverExistingFiles(512,
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
	panels, panelDiscoveryErr := ctx.Facts.Panels()
	discoveryErr = errors.Join(discoveryErr, panelDiscoveryErr)
	for _, panel := range panels {
		if summary, ok := panelProxySummary(panel); ok {
			out = append(out, summary)
		}
	}
	return out, discoveryErr
}

func panelProxySummary(panel panelSnapshot) (proxyConfigSummary, bool) {
	if !panel.DatabaseAvailable || len(panel.Inbounds) == 0 {
		return proxyConfigSummary{}, false
	}
	product := "Xray"
	if panel.Product == "S-UI" {
		product = "sing-box"
	} else if panel.Product == "Outline" {
		product = "Outline"
	}
	s := proxyConfigSummary{Product: product, Path: panel.Database, SensitiveFiles: append([]string(nil), panel.SensitiveFiles...), Parseable: true}
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

func proxyServiceUnits(ctx *Context) ([]string, error) {
	if ctx.Facts != nil {
		return ctx.Facts.ProxyServiceUnits()
	}
	return collectProxyServiceUnits(ctx.Commander)
}

func collectProxyServiceUnits(cmd Commander) ([]string, error) {
	if !cmd.Exists("systemctl") {
		return nil, fmt.Errorf("systemctl command not found")
	}
	r := cmd.Run(12*time.Second, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain")
	if r.Err != nil || r.Truncated {
		return nil, fmt.Errorf("systemctl list-units: %s", commandError(r))
	}
	seen := map[string]bool{}
	for _, line := range lines(r.Stdout) {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		if proxyProcessPattern.MatchString(fields[0]) || containsAny(strings.ToLower(fields[0]), "marzban", "hiddify", "outline", "nginx", "caddy", "haproxy") {
			seen[fields[0]] = true
		}
	}
	units := make([]string, 0, len(seen))
	for unit := range seen {
		units = append(units, unit)
	}
	sort.Strings(units)
	return units, nil
}

func activeProxyProducts(ctx *Context) map[string]bool {
	out := map[string]bool{}
	processes, err := ctx.Facts.Processes()
	if err != nil {
		return out
	}
	for _, process := range processes {
		line := processLine(process)
		if product, ok := proxyProcessLine(line); ok {
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
