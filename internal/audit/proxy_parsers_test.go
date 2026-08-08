package audit

import (
	"fmt"
	"strings"
	"testing"
)

func TestSingBoxProtocolMatrixKeepsOnlySemantics(t *testing.T) {
	data := []byte(`{
  "inbounds": [
    {"type":"hysteria2","listen":"::","listen_port":24443,"users":[{"password":"secret-hy2"}],"tls":{"enabled":true,"key_path":"/secret/hy2.key"}},
    {"type":"tuic","listen":"::","listen_port":24444,"users":[{"uuid":"00000000-0000-0000-0000-000000000001","password":"secret-tuic"}],"tls":{"enabled":true,"key_path":"/secret/tuic.key"}},
    {"type":"trojan","listen":"::","listen_port":24445,"users":[{"password":"secret-trojan"}],"tls":{"enabled":true,"key_path":"/secret/trojan.key"}},
    {"type":"shadowsocks","listen":"::","listen_port":24446,"method":"chacha20-ietf-poly1305","password":"secret-ss"}
  ]
}`)
	summary := parseSingBoxSummary("fixture.json", data)
	if summary.Err != nil || len(summary.Inbounds) != 4 || !summary.UsesUDP {
		t.Fatalf("summary=%+v", summary)
	}
	wantTransports := map[string]string{"24443": "[udp]", "24444": "[udp]", "24445": "[tcp]", "24446": "[tcp udp]"}
	for _, inbound := range summary.Inbounds {
		if got := fmt.Sprint(inbound.Transports); got != wantTransports[inbound.Port] {
			t.Errorf("port %s transports=%s", inbound.Port, got)
		}
	}
	serialized := fmt.Sprintf("%+v", summary)
	for _, secret := range []string{"secret-hy2", "secret-tuic", "secret-trojan", "secret-ss", "00000000-0000", "/secret/"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret leaked: %q", secret)
		}
	}
}

func TestNativeProxyParserMatrix(t *testing.T) {
	tests := []struct {
		name       string
		summary    proxyConfigSummary
		port       string
		transports string
	}{
		{name: "tuic", summary: parseTUICSummary("fixture.json", []byte(`{"server":"[::]:10443","users":{"id":"secret"}}`)), port: "10443", transports: "[udp]"},
		{name: "trojan", summary: parseTrojanSummary("fixture.json", []byte(`{"local_addr":"0.0.0.0","local_port":20443,"password":["secret"]}`)), port: "20443", transports: "[tcp]"},
		{name: "shadowsocks", summary: parseShadowsocksSummary("fixture.json", []byte(`{"server":"::","server_port":8388,"mode":"tcp_and_udp","password":"secret"}`)), port: "8388", transports: "[tcp udp]"},
		{name: "openvpn", summary: parseOpenVPNSummary("fixture.conf", "local 0.0.0.0\nport 1194\nproto udp6\nsecret /private/key\n"), port: "1194", transports: "[udp]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.summary.Err != nil || len(test.summary.Inbounds) != 1 || test.summary.Inbounds[0].Port != test.port || fmt.Sprint(test.summary.Inbounds[0].Transports) != test.transports {
				t.Fatalf("summary=%+v", test.summary)
			}
			if strings.Contains(fmt.Sprintf("%+v", test.summary), "secret") || strings.Contains(fmt.Sprintf("%+v", test.summary), "/private/key") {
				t.Fatal("credential-bearing input leaked into summary")
			}
		})
	}
}

func TestProxyJSONParsersRejectAmbiguousDuplicateMembers(t *testing.T) {
	input := []byte(`{"server":"[::]:443","server":"secret-value","inbounds":[]}`)
	for name, summary := range map[string]proxyConfigSummary{
		"sing-box":    parseSingBoxSummary("fixture.json", input),
		"xray":        parseXraySummary("fixture.json", input),
		"tuic":        parseTUICSummary("fixture.json", input),
		"trojan":      parseTrojanSummary("fixture.json", input),
		"shadowsocks": parseShadowsocksSummary("fixture.json", input),
	} {
		t.Run(name, func(t *testing.T) {
			if summary.Err == nil || summary.Parseable {
				t.Fatalf("ambiguous JSON was accepted: %+v", summary)
			}
			if strings.Contains(summary.Err.Error(), "secret-value") {
				t.Fatal("parse error disclosed duplicate-member content")
			}
		})
	}
	if port, ok := parseOutlineState(input); ok || port != "" {
		t.Fatalf("Outline accepted ambiguous JSON: port=%q ok=%t", port, ok)
	}
}

func TestHysteriaParserUsesOnlyOneValidTopLevelListen(t *testing.T) {
	valid := parseHysteriaSummary("config.yaml", "listen: :443\nquic:\n  listen: ignored\n")
	if valid.Err != nil || !valid.Parseable || len(valid.Inbounds) != 1 || valid.Inbounds[0].Port != "443" {
		t.Fatalf("valid summary=%+v", valid)
	}
	for name, input := range map[string]string{
		"duplicate": "listen: :443\nlisten: :8443\n",
		"invalid":   "listen: not-an-endpoint\n",
	} {
		t.Run(name, func(t *testing.T) {
			summary := parseHysteriaSummary("config.yaml", input)
			if summary.Err == nil || summary.Parseable || len(summary.Inbounds) != 0 {
				t.Fatalf("ambiguous or invalid listen was accepted: %+v", summary)
			}
		})
	}
}
