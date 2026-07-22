package audit

import (
	"fmt"
	"strings"
)

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func listenerProxyProduct(process string) (string, bool) {
	product := proxyProductFromText(process)
	return product, product != "unknown-proxy"
}

func sameProxyProduct(a, b string) bool {
	// Hiddify's generated Xray/sing-box inbounds can be served by its unified
	// hiddify-core process, but unrelated process mismatches remain meaningful.
	if strings.EqualFold(a, "Hiddify") && containsAny(strings.ToLower(b), "xray", "sing-box", "hiddify") {
		return true
	}
	if strings.EqualFold(b, "Hiddify") && containsAny(strings.ToLower(a), "xray", "sing-box", "hiddify") {
		return true
	}
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

func proxyTransports(protocol, network string) []string {
	p, n := strings.ToLower(protocol), strings.ToLower(network)
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

func endpointFirewallDisposition(ufw hostFirewallSnapshot, port, protocol string) string {
	return firewallDisposition(ufw, port, protocol)
}
