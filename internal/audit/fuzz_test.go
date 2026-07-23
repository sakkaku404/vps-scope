package audit

import "testing"

func FuzzProxyConfigParsersDoNotPanic(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"inbounds":[]}`),
		[]byte(`{"server":"[::]:443"}`),
		[]byte(`not-json`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = parseSingBoxSummary("/etc/sing-box/config.json", data)
		_ = parseXraySummary("/etc/xray/config.json", data)
		_ = parseTUICSummary("/etc/tuic/config.json", data)
		_ = parseTrojanSummary("/etc/trojan/config.json", data)
		_ = parseShadowsocksSummary("/etc/shadowsocks/config.json", data)
	})
}

func FuzzEvidenceTextParsersDoNotPanic(f *testing.F) {
	for _, seed := range []string{
		"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
		"tcp ESTAB 0 0 10.0.0.1:443 203.0.113.1:50000",
		"table inet filter { chain input { type filter hook input priority 0; policy drop; tcp dport 443 accept } }",
		"*filter\n:INPUT DROP [0:0]\n:USER - [0:0]\n-A INPUT -j USER\n-A USER -p tcp --dport 443 -j ACCEPT\nCOMMIT",
		"Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n443/tcp ALLOW IN Anywhere",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_, _ = parseListeners(input)
		_, _ = parseEstablishedConnections(input)
		_ = parseNFTFirewall(input)
		_, _, _ = parseIPTablesFirewallDetailed(input, "ipv4")
		_, _, _, _, _ = parseDockerIPTables(input, "ipv4")
		_ = parsePanelUFW(input)
	})
}
