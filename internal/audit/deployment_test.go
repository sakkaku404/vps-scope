package audit

import (
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/contract"
	"github.com/sakkaku404/vps-scope/internal/model"
)

func deploymentFixture(t *testing.T, reverse bool) (*Context, []proxyConfigSummary) {
	t.Helper()
	cmd := newScenarioCommander(nil, nil)
	facts := newFactStoreAt(cmd, false, time.Unix(1, 0), mapFileEvidenceSource{})
	facts.listeners = []Listener{
		{Protocol: "tcp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "sing-box"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: "2053", Scope: "loopback", Process: "s-ui"},
		{Protocol: "tcp", Address: "0.0.0.0", Port: "8443", Scope: "public-wildcard", Process: "nginx"},
		{Protocol: "tcp", Address: "127.0.0.1", Port: "9090", Scope: "loopback", Process: "sing-box"},
	}
	facts.listenersOnce.Do(func() {})
	facts.connections = []activeConnection{{protocol: "tcp", local: "192.0.2.10:443"}}
	facts.connectionsOnce.Do(func() {})
	facts.processes = []ProcessInfo{{PID: "10", User: "root", Command: "sing-box", Args: "/usr/bin/sing-box run"}}
	facts.processesOnce.Do(func() {})
	facts.hostFirewall = hostFirewallSnapshot{
		available: true, active: true, defaultDeny: true, backend: "ufw",
		defaultDenyByFamily:   map[string]bool{"ipv4": true, "ipv6": true},
		defaultPolicyByFamily: map[string]string{"ipv4": "deny", "ipv6": "deny"},
		rules: []firewallRule{
			{Family: "ipv4", Protocol: "tcp", Port: "443", Source: "any", Action: "allow"},
			{Family: "ipv4", Protocol: "tcp", Port: "8443", Source: "any", Action: "allow"},
		},
	}
	facts.hostFirewallOnce.Do(func() {})
	facts.panels = []panelSnapshot{{
		Product: "S-UI", Adapter: "s-ui/native-v1", Database: "/usr/local/s-ui/db/s-ui.db",
		Endpoints: []panelEndpoint{{Role: "management", Listen: "127.0.0.1", Port: "2053", Source: "S-UI database", TLSKnown: true, TLS: true, PathKnown: true, PathIsDefault: false}},
	}}
	facts.panelsOnce.Do(func() {})
	facts.reverseProxy = []reverseProxyRoute{{
		Product: "Nginx", Source: "/etc/nginx/sites-enabled/panel.conf",
		FrontendAddress: "0.0.0.0", FrontendPort: "8443", FrontendTransport: "tcp",
		BackendAddress: "127.0.0.1", BackendPort: "2053", Access: "path-gated",
	}}
	facts.reverseProxyOnce.Do(func() {})

	summaries := []proxyConfigSummary{
		{
			Product: "sing-box", Path: "/etc/sing-box/config.json", Parseable: true,
			Inbounds: []proxyInbound{{Product: "sing-box", Protocol: "vless", Listen: "0.0.0.0", Port: "443", Transports: []string{"tcp"}, Security: "reality", RealityEnabled: true, RealityKeySet: true, RealityTargets: 1, RealityServerIDs: 1}},
			Controls: []controlEndpoint{{Product: "sing-box", Kind: "clash-api", Listen: "127.0.0.1", Port: "9090"}},
		},
		{Product: "Xray", Path: "/usr/local/etc/xray/config.json", Parseable: true},
	}
	if reverse {
		slices.Reverse(facts.listeners)
		slices.Reverse(facts.hostFirewall.rules)
		slices.Reverse(summaries)
	}
	return &Context{Options: Options{Commander: cmd}, Facts: facts}, summaries
}

func TestBuildDeploymentIsStableAcrossEvidenceOrdering(t *testing.T) {
	leftContext, leftSummaries := deploymentFixture(t, false)
	rightContext, rightSummaries := deploymentFixture(t, true)
	left := buildDeployment(leftContext, leftSummaries, nil)
	right := buildDeployment(rightContext, rightSummaries, nil)
	if left == nil || right == nil {
		t.Fatal("fixture produced no deployment")
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("deployment depends on evidence ordering:\nleft=%+v\nright=%+v", left, right)
	}
	if failures := validateDeployment(left); len(failures) != 0 {
		t.Fatalf("deployment contract failures=%v", failures)
	}
	if len(left.Components) != 5 || len(left.Endpoints) != 5 || len(left.Links) != 6 {
		t.Fatalf("unexpected topology size: components=%d endpoints=%d links=%d", len(left.Components), len(left.Endpoints), len(left.Links))
	}
}

func TestDeploymentBuilderRejectsOversizedTopologyWithoutExceedingContract(t *testing.T) {
	b := newDeploymentBuilder()
	b.deployment.Coverage = model.DeploymentCoverage{
		Configuration: "complete", Runtime: "complete", Firewall: "complete",
		Panels: "complete", ReverseProxy: "complete", Docker: "complete",
	}
	for i := 0; i <= contract.MaxDeploymentComponents; i++ {
		b.component(fmt.Sprintf("component-%d", i), "proxy-core", "fixture", true, "native", "confirmed")
	}
	if got := len(b.deployment.Components); got != contract.MaxDeploymentComponents {
		t.Fatalf("components=%d want=%d", got, contract.MaxDeploymentComponents)
	}
	componentID := b.deployment.Components[0].ID
	for i := 0; i <= contract.MaxDeploymentEndpoints; i++ {
		b.endpoint(model.ServiceEndpoint{
			ComponentID: componentID, Product: "fixture", Role: "proxy-ingress",
			Transport: "tcp", Port: i + 1, Address: "127.0.0.1", State: "live", Confidence: "confirmed",
		})
	}
	if got := len(b.deployment.Endpoints); got != contract.MaxDeploymentEndpoints {
		t.Fatalf("endpoints=%d want=%d", got, contract.MaxDeploymentEndpoints)
	}
	for i := 0; i <= contract.MaxDeploymentLinks; i++ {
		from := b.deployment.Components[(i/contract.MaxDeploymentEndpoints)%len(b.deployment.Components)].ID
		to := b.deployment.Endpoints[i%len(b.deployment.Endpoints)].ID
		b.link(from, to, "declares")
	}
	if got := len(b.deployment.Links); got != contract.MaxDeploymentLinks {
		t.Fatalf("links=%d want=%d", got, contract.MaxDeploymentLinks)
	}
	if b.budgetRejects != 3 {
		t.Fatalf("budget rejects=%d want=3", b.budgetRejects)
	}
	b.finish()
	for name, state := range map[string]string{
		"configuration": b.deployment.Coverage.Configuration,
		"runtime":       b.deployment.Coverage.Runtime,
		"firewall":      b.deployment.Coverage.Firewall,
		"panels":        b.deployment.Coverage.Panels,
		"reverse_proxy": b.deployment.Coverage.ReverseProxy,
		"docker":        b.deployment.Coverage.Docker,
	} {
		if state != "partial" {
			t.Errorf("coverage %s=%q want partial", name, state)
		}
	}
}

func TestCanonicalRuntimeProductUsesDetectedPanelVariant(t *testing.T) {
	if got := canonicalRuntimeProductName("x-ui/3x-ui", []panelSnapshot{{Product: "3x-ui"}}); got != "3x-ui" {
		t.Fatalf("3x-ui runtime product = %q", got)
	}
	if got := canonicalRuntimeProductName("x-ui/3x-ui", []panelSnapshot{{Product: "x-ui"}}); got != "x-ui" {
		t.Fatalf("x-ui runtime product = %q", got)
	}
	if got := canonicalRuntimeProductName("Xray", []panelSnapshot{{Product: "3x-ui"}}); got != "Xray" {
		t.Fatalf("Xray runtime product = %q", got)
	}
}

func TestDeploymentProductCanonicalizesWebProxyContainerImages(t *testing.T) {
	for input, want := range map[string]string{
		"nginx:1.27-alpine": "nginx",
		"caddy:2.9":         "caddy",
		"haproxy:lts":       "haproxy",
	} {
		if got := deploymentProductFromText(input); got != want {
			t.Fatalf("deploymentProductFromText(%q) = %q, want %q", input, got, want)
		}
	}
}
