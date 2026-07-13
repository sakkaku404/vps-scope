package audit

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

func parseSingBoxSummary(path string, data []byte) proxyConfigSummary {
	type inbound struct {
		Type         string          `json:"type"`
		Listen       string          `json:"listen"`
		ListenPort   json.RawMessage `json:"listen_port"`
		Network      string          `json:"network"`
		PortBindings []struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
		} `json:"portBindings"`
		TLS struct {
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
		appendInbound := func(port string, transports []string) {
			s.Inbounds = append(s.Inbounds, proxyInbound{Product: s.Product, Protocol: item.Type, Listen: listen, Port: port,
				Transports: transports, Security: security,
				RealityEnabled: item.TLS.Reality.Enabled, RealityKeySet: item.TLS.Reality.PrivateKey != "",
				RealityTargets: realityTargets, RealityServerIDs: len(item.TLS.Reality.ShortID)})
		}
		if validPort(port) {
			appendInbound(port, proxyTransports(item.Type, item.Network))
		}
		for _, binding := range item.PortBindings {
			bindingPort := strconv.Itoa(binding.Port)
			if !validPort(bindingPort) {
				continue
			}
			transport := strings.ToLower(binding.Protocol)
			if transport != "tcp" && transport != "udp" {
				continue
			}
			appendInbound(bindingPort, []string{transport})
			s.UsesUDP = s.UsesUDP || transport == "udp"
		}
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
