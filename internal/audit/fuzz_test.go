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
