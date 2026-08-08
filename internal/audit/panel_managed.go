package audit

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func collectMarzbanFactsFromFiles(files *fileEvidenceSnapshot) panelSnapshot {
	s := panelSnapshot{Product: "Marzban", Binary: "container or Python service", Database: "/opt/marzban/.env", SchemaVersion: "marzban-config-v1", SchemaSupported: true, SchemaCapabilities: []string{"management-endpoint", "generated-xray", "container-context"}, SensitiveFiles: []string{"/opt/marzban/.env"}}
	values, err := readEnvWhitelistFromFiles(files, "/opt/marzban/.env", map[string]bool{
		"UVICORN_HOST": true, "UVICORN_PORT": true, "UVICORN_UDS": true,
		"UVICORN_SSL_CERTFILE": true, "UVICORN_SSL_KEYFILE": true,
		"XRAY_JSON": true, "XRAY_EXECUTABLE_PATH": true, "XRAY_SUBSCRIPTION_URL_PREFIX": true,
	})
	if err != nil {
		s.DatabaseError = err.Error()
	} else {
		s.DatabaseAvailable = true
		if values["UVICORN_UDS"] == "" {
			port := values["UVICORN_PORT"]
			if port == "" {
				port = "8000"
			}
			listen := values["UVICORN_HOST"]
			if listen == "" {
				listen = "0.0.0.0"
			}
			cert := values["UVICORN_SSL_CERTFILE"]
			s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: normalizeListen(listen), Port: port, TLSKnown: true, TLS: cert != "" && values["UVICORN_SSL_KEYFILE"] != "", CertFile: cert, Source: "/opt/marzban/.env", PathKnown: false})
		}
	}
	xrayPath := values["XRAY_JSON"]
	if xrayPath == "" {
		xrayPath = "/var/lib/marzban/xray_config.json"
	} else if !filepath.IsAbs(xrayPath) {
		xrayPath = filepath.Join("/var/lib/marzban", xrayPath)
	}
	applyManagedProxyConfigFromFiles(files, &s, xrayPath, "Xray")
	sortPanelFacts(&s)
	return s
}

func collectHiddifyFactsFromFiles(files *fileEvidenceSnapshot) panelSnapshot {
	s := panelSnapshot{Product: "Hiddify", Binary: "/opt/hiddify-manager", Database: "/opt/hiddify-manager", SchemaVersion: "hiddify-config-v1", SchemaSupported: true, SchemaCapabilities: []string{"management-endpoint", "generated-xray", "generated-sing-box", "reverse-proxy-context"}, DatabaseAvailable: true}
	if data, err := files.ReadSmall("/opt/hiddify-manager/VERSION", 1024); err == nil {
		s.Version = strings.TrimSpace(data)
	}
	if values, err := readKeyValueWhitelistFromFiles(files, "/opt/hiddify-manager/hiddify-panel/app.cfg", map[string]bool{"RUN_PORT": true}); err == nil {
		if port := values["RUN_PORT"]; validPort(port) {
			s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: "127.0.0.1", Port: port, TLSKnown: true, TLS: false, Source: "/opt/hiddify-manager/hiddify-panel/app.cfg", PathKnown: false})
		}
	}
	paths, discoveryErr := discoverExistingFilesFromSnapshot(files, 64,
		"/opt/hiddify-manager/*xray*.json", "/opt/hiddify-manager/*sing-box*.json",
		"/opt/hiddify-manager/*/*xray*.json", "/opt/hiddify-manager/*/*sing-box*.json",
		"/opt/hiddify-manager/*/*/xray*.json", "/opt/hiddify-manager/*/*/sing-box*.json",
		"/opt/hiddify-manager/xray/configs/*.json", "/opt/hiddify-manager/singbox/configs/*.json",
	)
	if discoveryErr != nil {
		s.DiscoveryError = "generated proxy configuration discovery: " + truncate(discoveryErr.Error(), 240)
	}
	for _, path := range paths {
		product := "Xray"
		if strings.Contains(strings.ToLower(filepath.ToSlash(path)), "/singbox/") || strings.Contains(strings.ToLower(filepath.Base(path)), "sing") {
			product = "sing-box"
		}
		applyManagedProxyConfigFromFiles(files, &s, path, product)
	}
	for _, path := range paths {
		// Generated routing, DNS, logging, and outbound fragments generally do
		// not contain client credentials. Inbound fragments can contain UUIDs,
		// passwords, and Reality private keys and therefore need strict modes.
		if strings.Contains(strings.ToLower(filepath.Base(path)), "inbound") {
			s.SensitiveFiles = append(s.SensitiveFiles, path)
		}
	}
	if len(paths) == 0 {
		s.DatabaseAvailable = false
		s.DatabaseError = "no supported generated Xray or sing-box configuration found"
	}
	sortPanelFacts(&s)
	return s
}

func collectContainerPanelSnapshotsFromFiles(containers []dockerInspect, files *fileEvidenceSnapshot) []panelSnapshot {
	var out []panelSnapshot
	for _, container := range containers {
		image := strings.ToLower(container.Config.Image)
		if strings.Contains(image, "quay.io/outline/shadowbox") {
			out = append(out, collectOutlineFactsFromFiles(container, files))
		}
	}
	return out
}

func collectOutlineFactsFromFiles(container dockerInspect, files *fileEvidenceSnapshot) panelSnapshot {
	name := strings.TrimPrefix(container.Name, "/")
	s := panelSnapshot{Product: "Outline", Binary: name, Adapter: "outline/container-v1", SchemaVersion: "outline-shadowbox-v1", SchemaSupported: true, SchemaCapabilities: []string{"management-endpoint", "shadowsocks-ingress", "container-context"}}
	values := outlineEnvValues(container.Config.Env)
	apiPort := values["SB_API_PORT"]
	if validPort(apiPort) {
		s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: "*", Port: apiPort, TLSKnown: true, TLS: true, Source: "docker inspect allowlisted Outline environment", PathKnown: true, PathIsDefault: false})
	}
	stateDir := filepath.Clean(values["SB_STATE_DIR"])
	if filepath.IsAbs(stateDir) && (strings.HasPrefix(stateDir, "/opt/") || strings.HasPrefix(stateDir, "/var/lib/")) {
		s.Database = filepath.Join(stateDir, "shadowbox_server_config.json")
		s.SensitiveFiles = append(s.SensitiveFiles, s.Database)
		if data, err := files.ReadSmall(s.Database, 1<<20); err == nil {
			if port, ok := parseOutlineState([]byte(data)); ok {
				s.DatabaseAvailable = true
				s.Inbounds = append(s.Inbounds, panelInboundFact{Enabled: true, Listen: "*", Port: port, Protocol: "shadowsocks", Network: "tcp,udp"})
			} else {
				s.DatabaseError = "Outline state did not contain a valid access-key port"
			}
		} else {
			s.DatabaseError = "Outline state file unavailable"
		}
	} else {
		s.DatabaseError = "Outline state directory unavailable or outside supported roots"
	}
	if len(s.Endpoints) == 0 && s.DatabaseError == "" {
		s.DatabaseError = "Outline management API port unavailable"
	}
	sortPanelFacts(&s)
	return s
}

func outlineEnvValues(environment []string) map[string]string {
	allowed := map[string]bool{"SB_API_PORT": true, "SB_STATE_DIR": true}
	values := map[string]string{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if ok && allowed[key] {
			values[key] = value
		}
	}
	return values
}

func parseOutlineState(data []byte) (string, bool) {
	var config struct {
		PortForNewAccessKeys int `json:"portForNewAccessKeys"`
	}
	if unmarshalProxyJSON(data, &config) != nil {
		return "", false
	}
	port := strconv.Itoa(config.PortForNewAccessKeys)
	return port, validPort(port)
}

func applyManagedProxyConfig(snapshot *panelSnapshot, path, product string) {
	applyManagedProxyConfigFromFiles(newFileEvidenceSnapshot(osFileEvidenceSource{}), snapshot, path, product)
}

func applyManagedProxyConfigFromFiles(files *fileEvidenceSnapshot, snapshot *panelSnapshot, path, product string) {
	data, err := files.ReadSmall(path, 16<<20)
	if err != nil {
		if snapshot.DatabaseError == "" {
			snapshot.DatabaseError = fmt.Sprintf("%s: %v", path, err)
		}
		return
	}
	var summary proxyConfigSummary
	if product == "sing-box" {
		summary = parseSingBoxSummary(path, []byte(data))
	} else {
		summary = parseXraySummary(path, []byte(data))
	}
	if summary.Err != nil {
		if snapshot.DatabaseError == "" {
			snapshot.DatabaseError = fmt.Sprintf("%s: %v", path, summary.Err)
		}
		return
	}
	for _, inbound := range summary.Inbounds {
		if !validPort(inbound.Port) {
			continue
		}
		network := strings.Join(inbound.Transports, ",")
		snapshot.Inbounds = append(snapshot.Inbounds, panelInboundFact{Enabled: true, Listen: inbound.Listen, Port: inbound.Port, Protocol: inbound.Protocol, Network: network, Security: inbound.Security, RealityKeySet: inbound.RealityKeySet, RealityTargets: inbound.RealityTargets, RealityIDs: inbound.RealityServerIDs})
	}
	for _, control := range summary.Controls {
		snapshot.Endpoints = append(snapshot.Endpoints, panelEndpoint{Role: "control-api", Listen: control.Listen, Port: control.Port, Source: path})
	}
}

func readEnvWhitelist(path string, allowed map[string]bool) (map[string]string, error) {
	return readEnvWhitelistFromFiles(newFileEvidenceSnapshot(osFileEvidenceSource{}), path, allowed)
}

func readEnvWhitelistFromFiles(files *fileEvidenceSnapshot, path string, allowed map[string]bool) (map[string]string, error) {
	data, err := files.ReadSmall(path, 1<<20)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range lines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(strings.TrimPrefix(key, "export "))
		if !ok || !allowed[key] {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '\'' && value[len(value)-1] == '\'') || (value[0] == '"' && value[len(value)-1] == '"')) {
			value = value[1 : len(value)-1]
		}
		out[key] = value
	}
	return out, nil
}

func readKeyValueWhitelist(path string, allowed map[string]bool) (map[string]string, error) {
	return readKeyValueWhitelistFromFiles(newFileEvidenceSnapshot(osFileEvidenceSource{}), path, allowed)
}

func readKeyValueWhitelistFromFiles(files *fileEvidenceSnapshot, path string, allowed map[string]bool) (map[string]string, error) {
	data, err := files.ReadSmall(path, 1<<20)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range lines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if ok && allowed[key] {
			out[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return out, nil
}

func sortPanelFacts(snapshot *panelSnapshot) {
	sort.Slice(snapshot.Endpoints, func(i, j int) bool {
		left, right := snapshot.Endpoints[i], snapshot.Endpoints[j]
		if left.Role != right.Role {
			return left.Role < right.Role
		}
		leftPort, _ := strconv.Atoi(left.Port)
		rightPort, _ := strconv.Atoi(right.Port)
		if leftPort != rightPort {
			return leftPort < rightPort
		}
		return left.Listen < right.Listen
	})
	sort.Slice(snapshot.Inbounds, func(i, j int) bool {
		left, right := snapshot.Inbounds[i], snapshot.Inbounds[j]
		leftPort, _ := strconv.Atoi(left.Port)
		rightPort, _ := strconv.Atoi(right.Port)
		if leftPort != rightPort {
			return leftPort < rightPort
		}
		if left.Protocol != right.Protocol {
			return left.Protocol < right.Protocol
		}
		return left.Listen < right.Listen
	})
}
