package audit

import "testing"

func TestEndpointGraphPolicyMatrix(t *testing.T) {
	inbound := configuredProxyInbound{Path: "/etc/sing-box/config.json", proxyInbound: proxyInbound{Product: "sing-box", Protocol: "hysteria2", Port: "443", Transports: []string{"udp"}}}
	tests := []struct {
		name      string
		listeners []Listener
		active    map[string]bool
		firewall  panelUFW
		judgment  string
		risk      bool
		missing   bool
	}{
		{name: "expected public ingress", listeners: []Listener{{Protocol: "udp", Address: "::", Port: "443", Scope: "public-wildcard", Process: "sing-box"}}, firewall: parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n443/udp (v6) ALLOW IN Anywhere (v6)"), judgment: "expected-proxy-ingress"},
		{name: "wrong process", listeners: []Listener{{Protocol: "udp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "xray"}}, firewall: parsePanelUFW("Status: inactive"), judgment: "listener-owner-does-not-match-configured-product", risk: true},
		{name: "blocked udp", listeners: []Listener{{Protocol: "udp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "sing-box"}}, firewall: parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)"), judgment: "configured-public-ingress-blocked-by-host-firewall", risk: true},
		{name: "active but missing", active: map[string]bool{"sing-box": true}, firewall: parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)"), judgment: "active_product_but_not_listening", risk: true, missing: true},
		{name: "inactive stale config", firewall: parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)"), judgment: "configured_not_listening", missing: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := assessProxyEndpointGraph(buildProxyEndpointGraph([]configuredProxyInbound{inbound}, test.listeners, test.firewall), test.active)
			if len(got) != 1 {
				t.Fatalf("assessments=%d, want 1", len(got))
			}
			if got[0].Judgment != test.judgment || got[0].Risk != test.risk || got[0].Missing != test.missing {
				t.Fatalf("assessment=%+v", got[0])
			}
		})
	}
}

func TestEndpointGraphKeepsTCPAndUDPSeparate(t *testing.T) {
	inbound := configuredProxyInbound{Path: "fixture", proxyInbound: proxyInbound{Product: "Shadowsocks", Protocol: "shadowsocks", Port: "8388", Transports: []string{"tcp", "udp"}}}
	listeners := []Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: "8388", Scope: "loopback", Process: "ss-server"}}
	got := assessProxyEndpointGraph(buildProxyEndpointGraph([]configuredProxyInbound{inbound}, listeners, panelUFW{}), map[string]bool{"shadowsocks": true})
	if len(got) != 2 || got[0].Node.Transport == got[1].Node.Transport {
		t.Fatalf("TCP/UDP relations collapsed: %+v", got)
	}
	missing := 0
	for _, item := range got {
		if item.Missing {
			missing++
		}
	}
	if missing != 1 {
		t.Fatalf("missing=%d, want 1", missing)
	}
}
