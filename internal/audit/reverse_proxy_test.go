package audit

import (
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestParseNginxRoutes(t *testing.T) {
	data := `server {
  listen 443 ssl;
  location /panel/ {
    proxy_pass http://127.0.0.1:2053;
  }
}`
	routes := parseNginxRoutes("/etc/nginx/sites-enabled/panel", data)
	if len(routes) != 1 || routes[0].FrontendPort != "443" || routes[0].BackendAddress != "127.0.0.1" || routes[0].BackendPort != "2053" {
		t.Fatalf("routes=%+v", routes)
	}
}

func TestParseCaddyRoutes(t *testing.T) {
	routes := parseCaddyRoutes("/etc/caddy/Caddyfile", `panel.example.test {
  reverse_proxy 127.0.0.1:2053
}`)
	if len(routes) != 1 || routes[0].FrontendPort != "443" || routes[0].BackendPort != "2053" {
		t.Fatalf("routes=%+v", routes)
	}
}

func TestParseHAProxyRoutes(t *testing.T) {
	routes := parseHAProxyRoutes("/etc/haproxy/haproxy.cfg", `frontend public
  bind *:443 ssl
  default_backend panel
backend panel
  server local 127.0.0.1:2053 check
`)
	if len(routes) != 1 || routes[0].FrontendPort != "443" || routes[0].BackendPort != "2053" {
		t.Fatalf("routes=%+v", routes)
	}
}

func TestParseHAProxyConditionalBackendAndDualBind(t *testing.T) {
	routes := parseHAProxyRoutes("fixture", `frontend public
  bind :80,:::80 v4v6
  use_backend panel if panel_path
backend panel
  server local 127.0.0.1:9000 check
`)
	if len(routes) != 1 {
		t.Fatalf("routes=%+v", routes)
	}
	for _, route := range routes {
		if route.FrontendPort != "80" || route.BackendAddress != "127.0.0.1" || route.BackendPort != "9000" || route.Access != "path-gated" {
			t.Fatalf("route=%+v", route)
		}
	}
}

func TestReverseProxyPolicyDetectsBroadBackend(t *testing.T) {
	routes := []reverseProxyRoute{{Product: "nginx", Source: "fixture", FrontendAddress: "::", FrontendPort: "443", FrontendTransport: "tcp", BackendAddress: "127.0.0.1", BackendPort: "2053"}}
	if got := uniqueReverseProxyRoutes(routes); len(got) != 1 {
		t.Fatalf("routes=%+v", got)
	}
	listeners := []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "nginx"}, {Protocol: "tcp", Address: "0.0.0.0", Port: "2053", Scope: "public-wildcard", Process: "x-ui"}}
	backend := matchingListener(listeners, "2053", "tcp")
	if backend == nil || backend.Scope != "public-wildcard" || classifyAddress(routes[0].BackendAddress) != "loopback" {
		t.Fatal("broad backend scenario was not represented")
	}
}

func TestExternalReverseProxyBackendNeverMatchesLocalPort(t *testing.T) {
	listeners := []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "80", Scope: "public-wildcard", Process: "haproxy"}}
	if got := matchingBackendListener(listeners, "example.com", "80", "tcp"); got != nil {
		t.Fatalf("external backend matched local listener: %+v", got)
	}
}

func TestReverseProxyPolicyMatrix(t *testing.T) {
	route := reverseProxyRoute{Product: "nginx", Source: "fixture", FrontendAddress: "::", FrontendPort: "443", FrontendTransport: "tcp", BackendAddress: "127.0.0.1", BackendPort: "2053"}
	publicFrontend := Listener{Protocol: "tcp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "nginx"}
	loopbackBackend := Listener{Protocol: "tcp", Address: "127.0.0.1", Port: "2053", Scope: "loopback", Process: "x-ui"}
	allowed := parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n443/tcp ALLOW IN Anywhere")
	panels := []panelSnapshot{{Product: "3x-ui", Endpoints: []panelEndpoint{{Role: "management", Port: "2053"}}}}
	tests := []struct {
		name      string
		routes    []reverseProxyRoute
		listeners []Listener
		firewall  panelUFW
		panels    []panelSnapshot
		status    model.Status
		severity  model.Severity
		judgment  string
	}{
		{name: "consistent restricted chain", routes: []reverseProxyRoute{route}, listeners: []Listener{publicFrontend, loopbackBackend}, firewall: parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)"), panels: panels, status: model.Pass, judgment: "reverse-proxy-chain-consistent"},
		{name: "public management route", routes: []reverseProxyRoute{route}, listeners: []Listener{publicFrontend, loopbackBackend}, firewall: allowed, panels: panels, status: model.Risk, severity: model.High, judgment: "public-reverse-proxy-exposes-3x-ui-management"},
		{name: "path gated public management route", routes: []reverseProxyRoute{{Product: "haproxy", Source: "fixture", FrontendAddress: "::", FrontendPort: "443", FrontendTransport: "tcp", BackendAddress: "127.0.0.1", BackendPort: "2053", Access: "path-gated"}}, listeners: []Listener{publicFrontend, loopbackBackend}, firewall: allowed, panels: panels, status: model.Risk, severity: model.High, judgment: "public-path-gated-reverse-proxy-reaches-3x-ui-management"},
		{name: "missing frontend", routes: []reverseProxyRoute{route}, listeners: []Listener{loopbackBackend}, firewall: allowed, status: model.Risk, severity: model.Medium, judgment: "configured-frontend-not-listening"},
		{name: "missing backend", routes: []reverseProxyRoute{route}, listeners: []Listener{publicFrontend}, firewall: allowed, status: model.Risk, severity: model.Medium, judgment: "configured-backend-not-listening"},
		{name: "broad backend and public management", routes: []reverseProxyRoute{route}, listeners: []Listener{publicFrontend, {Protocol: "tcp", Address: "0.0.0.0", Port: "2053", Scope: "public-wildcard", Process: "x-ui"}}, firewall: allowed, panels: panels, status: model.Risk, severity: model.High, judgment: "backend-listens-more-broadly-than-configured+public-reverse-proxy-exposes-3x-ui-management"},
		{name: "external upstream", routes: []reverseProxyRoute{{Product: "haproxy", Source: "fixture", FrontendAddress: "::", FrontendPort: "443", FrontendTransport: "tcp", BackendAddress: "example.com", BackendPort: "80"}}, listeners: []Listener{publicFrontend}, firewall: allowed, status: model.Pass, judgment: "external-upstream-not-verified-from-local-listeners"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := assessReverseProxyRoutes(test.routes, test.listeners, test.firewall, test.panels)
			if finding.Status != test.status || finding.Severity != test.severity {
				t.Fatalf("finding=%+v", finding)
			}
			if len(finding.Evidence) != 1 || !strings.Contains(finding.Evidence[0].Value, "judgment="+test.judgment) {
				t.Fatalf("evidence=%+v", finding.Evidence)
			}
		})
	}
}
