package audit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestPanelRuntimeListenerCorrelationUsesTransportAndAddress(t *testing.T) {
	listeners := []Listener{
		{Protocol: "udp", Address: "0.0.0.0", Port: "2095", Scope: "public-wildcard", Process: "sing-box"},
		{Protocol: "tcp4", Address: "127.0.0.1", Port: "2095", Scope: "loopback", Process: "sui"},
		{Protocol: "tcp6", Address: "::1", Port: "2095", Scope: "loopback", Process: "sui"},
		{Protocol: "tcp6", Address: "::", Port: "2095", Scope: "public-wildcard", Process: "sui"},
		{Protocol: "tcp-extra", Address: "127.0.0.1", Port: "2095", Scope: "loopback", Process: "invalid"},
		{Protocol: "udp", Address: "192.0.2.1", Port: "2095", Scope: "public", Process: "sing-box"},
	}
	tests := []struct {
		name, address, transport string
		want                     []int
	}{
		{name: "transport mismatch", address: "192.0.2.1", transport: "tcp", want: nil},
		{name: "explicit address mismatch", address: "10.0.0.1", transport: "tcp", want: nil},
		{name: "exact IPv4 and normalized tcp4", address: "127.0.0.1", transport: "tcp", want: []int{1}},
		{name: "bracketed IPv6", address: "[::1]", transport: "tcp", want: []int{2}},
		{name: "IPv6 wildcard stays in IPv6 family", address: "::", transport: "tcp", want: []int{3}},
		{name: "IPv4 wildcard requires a wildcard listener", address: "0.0.0.0", transport: "udp", want: []int{0}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := panelRuntimeListenerIndexes(listeners, test.address, "2095", test.transport)
			if fmt.Sprint(got) != fmt.Sprint(test.want) {
				t.Fatalf("indexes=%v, want %v", got, test.want)
			}
		})
	}
}

func TestPanelRuntimeListenerCorrelationTreatsSSStarAsWildcard(t *testing.T) {
	listeners := []Listener{{Protocol: "tcp", Address: "*", Port: "2095", Scope: "public-wildcard", Process: "sui"}}
	for _, address := range []string{"0.0.0.0", "::", "*", ""} {
		if got := panelRuntimeListenerIndexes(listeners, address, "2095", "tcp"); fmt.Sprint(got) != "[0]" {
			t.Fatalf("address=%q indexes=%v, want [0]", address, got)
		}
	}
}

func TestPanelRuntimeRoleCollisionUsesSocketIdentity(t *testing.T) {
	tests := []struct {
		name            string
		endpointAddress string
		inboundAddress  string
		protocol        string
		network         string
		wantStatus      model.Status
		wantCollisions  string
	}{
		{name: "same TCP socket conflicts", endpointAddress: "::", inboundAddress: "::", protocol: "vless", network: "tcp", wantStatus: model.Risk, wantCollisions: "1"},
		{name: "TCP management and UDP ingress may share port", endpointAddress: "::", inboundAddress: "::", protocol: "hysteria2", network: "udp", wantStatus: model.Pass, wantCollisions: "0"},
		{name: "different concrete addresses do not conflict", endpointAddress: "127.0.0.1", inboundAddress: "10.0.0.1", protocol: "vless", network: "tcp", wantStatus: model.Pass, wantCollisions: "0"},
		{name: "same-family wildcard overlaps a concrete address", endpointAddress: "0.0.0.0", inboundAddress: "192.0.2.1", protocol: "vless", network: "tcp", wantStatus: model.Risk, wantCollisions: "1"},
		{name: "IPv4 and IPv6 wildcards are different sockets", endpointAddress: "0.0.0.0", inboundAddress: "::", protocol: "vless", network: "tcp", wantStatus: model.Pass, wantCollisions: "0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transports := proxyTransports(test.protocol, test.network)
			listeners := []Listener{{Protocol: "tcp", Address: test.endpointAddress, Port: "2095", Scope: classifyAddress(test.endpointAddress), Process: "sui"}}
			for _, transport := range transports {
				listeners = append(listeners, Listener{Protocol: transport, Address: test.inboundAddress, Port: "2095", Scope: classifyAddress(test.inboundAddress), Process: "sing-box"})
			}
			panel := panelSnapshot{
				Product: "S-UI", Database: "/usr/local/s-ui/db/s-ui.db", DatabaseAvailable: true,
				Endpoints: []panelEndpoint{{Role: "management", Listen: test.endpointAddress, Port: "2095", Source: "fixture"}},
				Inbounds:  []panelInboundFact{{Enabled: true, Listen: test.inboundAddress, Port: "2095", Protocol: test.protocol, Network: test.network}},
			}
			summary := proxyConfigSummary{Inbounds: []proxyInbound{{Protocol: test.protocol, Listen: test.inboundAddress, Port: "2095", Transports: transports}}}
			finding := panelRuntimeFindingForTest(t, panel, listeners, []proxyConfigSummary{summary})
			if finding.Status != test.wantStatus || finding.Facts["role_collisions"] != test.wantCollisions {
				t.Fatalf("status=%s collisions=%s evidence=%+v", finding.Status, finding.Facts["role_collisions"], finding.Evidence)
			}
		})
	}
}

func TestDisabledPanelInboundIsOnlyMaskedByTheSameRuntimeSocket(t *testing.T) {
	tests := []struct {
		name             string
		enabled          panelInboundFact
		disabled         panelInboundFact
		listeners        []Listener
		wantStatus       model.Status
		wantStillRunning string
	}{
		{
			name:     "enabled TCP does not mask disabled UDP on the same port",
			enabled:  panelInboundFact{Enabled: true, Listen: "*", Port: "8443", Protocol: "vless", Network: "tcp"},
			disabled: panelInboundFact{Listen: "*", Port: "8443", Protocol: "hysteria2", Network: "udp"},
			listeners: []Listener{
				{Protocol: "tcp", Address: "0.0.0.0", Port: "8443", Scope: "public-wildcard", Process: "sing-box"},
				{Protocol: "udp", Address: "0.0.0.0", Port: "8443", Scope: "public-wildcard", Process: "sing-box"},
			},
			wantStatus: model.Risk, wantStillRunning: "1",
		},
		{
			name:     "enabled loopback does not mask disabled private address",
			enabled:  panelInboundFact{Enabled: true, Listen: "127.0.0.1", Port: "8443", Protocol: "vless", Network: "tcp"},
			disabled: panelInboundFact{Listen: "10.0.0.1", Port: "8443", Protocol: "vless", Network: "tcp"},
			listeners: []Listener{
				{Protocol: "tcp", Address: "127.0.0.1", Port: "8443", Scope: "loopback", Process: "sing-box"},
				{Protocol: "tcp", Address: "10.0.0.1", Port: "8443", Scope: "private", Process: "sing-box"},
			},
			wantStatus: model.Risk, wantStillRunning: "1",
		},
		{
			name:             "duplicate disabled record shares an enabled socket",
			enabled:          panelInboundFact{Enabled: true, Listen: "*", Port: "8443", Protocol: "vless", Network: "tcp"},
			disabled:         panelInboundFact{Listen: "*", Port: "8443", Protocol: "vless", Network: "tcp"},
			listeners:        []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "8443", Scope: "public-wildcard", Process: "sing-box"}},
			wantStatus:       model.Pass,
			wantStillRunning: "0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			panel := panelSnapshot{Product: "S-UI", Database: "/usr/local/s-ui/db/s-ui.db", DatabaseAvailable: true, Inbounds: []panelInboundFact{test.enabled, test.disabled}}
			summary := proxyConfigSummary{Inbounds: []proxyInbound{{Protocol: test.enabled.Protocol, Listen: test.enabled.Listen, Port: test.enabled.Port, Transports: proxyTransports(test.enabled.Protocol, test.enabled.Network)}}}
			finding := panelRuntimeFindingForTest(t, panel, test.listeners, []proxyConfigSummary{summary})
			if finding.Status != test.wantStatus || finding.Facts["disabled_inbounds_still_listening"] != test.wantStillRunning {
				t.Fatalf("status=%s still_running=%s facts=%v evidence=%+v", finding.Status, finding.Facts["disabled_inbounds_still_listening"], finding.Facts, finding.Evidence)
			}
		})
	}
}

func TestSummaryHasPanelInboundRequiresAddressAndAllTransports(t *testing.T) {
	wanted := panelInboundFact{Enabled: true, Listen: "127.0.0.1", Port: "443", Protocol: "shadowsocks", Network: ""}
	tests := []struct {
		name      string
		summaries []proxyConfigSummary
		want      bool
	}{
		{name: "wrong address", summaries: []proxyConfigSummary{{Inbounds: []proxyInbound{{Listen: "0.0.0.0", Port: "443", Protocol: "shadowsocks", Transports: []string{"tcp", "udp"}}}}}},
		{name: "missing UDP transport", summaries: []proxyConfigSummary{{Inbounds: []proxyInbound{{Listen: "127.0.0.1", Port: "443", Protocol: "shadowsocks", Transports: []string{"tcp"}}}}}},
		{name: "transports may be represented by separate normalized rows", summaries: []proxyConfigSummary{{Inbounds: []proxyInbound{
			{Listen: "127.0.0.1", Port: "443", Protocol: "shadowsocks", Transports: []string{"tcp"}},
			{Listen: "127.0.0.1", Port: "443", Protocol: "shadowsocks", Transports: []string{"udp"}},
		}}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := summaryHasPanelInbound(test.summaries, wanted); got != test.want {
				t.Fatalf("summaryHasPanelInbound=%t, want %t", got, test.want)
			}
		})
	}
}

func TestPanelRuntimeEvidenceBudgetKeepsActionableRows(t *testing.T) {
	panel := panelSnapshot{Product: "S-UI", Database: "/usr/local/s-ui/db/s-ui.db", DatabaseAvailable: true}
	for port := 10000; port < 10100; port++ {
		panel.Endpoints = append(panel.Endpoints, panelEndpoint{Role: "management", Listen: "127.0.0.1", Port: fmt.Sprint(port), Source: "fixture"})
	}
	listeners := []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "65000", Scope: "public-wildcard", Process: "sui"}}
	finding := panelRuntimeFindingForTest(t, panel, listeners, nil)
	if len(finding.Evidence) != maxPanelRuntimeEvidence {
		t.Fatalf("evidence rows=%d, want %d", len(finding.Evidence), maxPanelRuntimeEvidence)
	}
	if !evidenceHas(finding, "unclassified_panel_listener", "65000/tcp") {
		t.Fatalf("late actionable evidence was dropped: %+v", finding.Evidence)
	}
	last := finding.Evidence[len(finding.Evidence)-1]
	if last.Key != "evidence_truncated" || !strings.Contains(last.Value, "limit=80") {
		t.Fatalf("missing evidence budget marker: %+v", last)
	}
}

func panelRuntimeFindingForTest(t *testing.T, panel panelSnapshot, listeners []Listener, summaries []proxyConfigSummary) model.Finding {
	t.Helper()
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() { ctx.Facts.listeners = listeners })
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)")
	})
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	return checkPanelRuntimeConsistency(ctx, summaries)
}
