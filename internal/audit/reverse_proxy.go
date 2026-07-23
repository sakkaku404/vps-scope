package audit

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type reverseProxyRoute struct {
	Product           string
	Source            string
	FrontendAddress   string
	FrontendPort      string
	FrontendTransport string
	BackendAddress    string
	BackendPort       string
	Access            string
}

var (
	nginxListenRE = regexp.MustCompile(`(?i)^\s*listen\s+([^;]+)`)
	nginxProxyRE  = regexp.MustCompile(`(?i)^\s*(?:proxy_pass|grpc_pass)\s+([^;]+)`)
	caddySiteRE   = regexp.MustCompile(`^\s*([^\s{]+)\s*\{\s*$`)
	caddyProxyRE  = regexp.MustCompile(`(?i)^\s*reverse_proxy\s+([^\s{]+)`)
)

func discoverReverseProxyRoutes(cmd Commander) ([]reverseProxyRoute, error) {
	var routes []reverseProxyRoute
	var discoveryErr error
	if cmd.Exists("nginx") {
		result := cmd.Run(20*time.Second, "nginx", "-T")
		if result.Err != nil || result.Truncated {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("nginx -T: %s", commandError(result)))
		} else {
			routes = append(routes, parseNginxRoutes("nginx -T (effective configuration)", result.Stdout+"\n"+result.Stderr)...)
			discoveryErr = errors.Join(discoveryErr, reverseProxySyntaxGaps("nginx", result.Stdout+"\n"+result.Stderr))
		}
	} else {
		nginxPaths, err := discoverExistingFiles(512, "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf")
		discoveryErr = errors.Join(discoveryErr, err)
		for _, path := range nginxPaths {
			data, readErr := readSmall(path, 4<<20)
			if readErr != nil {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, readErr))
				continue
			}
			routes = append(routes, parseNginxRoutes(path, data)...)
			discoveryErr = errors.Join(discoveryErr, reverseProxySyntaxGaps("nginx", data))
		}
	}
	caddyPaths, err := discoverExistingFiles(16, "/etc/caddy/Caddyfile", "/usr/local/etc/caddy/Caddyfile")
	discoveryErr = errors.Join(discoveryErr, err)
	for _, path := range caddyPaths {
		data, readErr := readSmall(path, 4<<20)
		if readErr != nil {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, readErr))
			continue
		}
		routes = append(routes, parseCaddyRoutes(path, data)...)
		discoveryErr = errors.Join(discoveryErr, reverseProxySyntaxGaps("caddy", data))
	}
	haproxyPaths, err := discoverExistingFiles(512, "/etc/haproxy/haproxy.cfg", "/opt/hiddify-manager/haproxy/*.cfg")
	discoveryErr = errors.Join(discoveryErr, err)
	for _, path := range haproxyPaths {
		data, readErr := readSmall(path, 4<<20)
		if readErr != nil {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, readErr))
			continue
		}
		routes = append(routes, parseHAProxyRoutes(path, data)...)
		discoveryErr = errors.Join(discoveryErr, reverseProxySyntaxGaps("haproxy", data))
	}
	return uniqueReverseProxyRoutes(routes), discoveryErr
}

func reverseProxySyntaxGaps(product, data string) error {
	lower := strings.ToLower(data)
	switch product {
	case "nginx":
		for _, line := range lines(data) {
			match := nginxProxyRE.FindStringSubmatch(strings.SplitN(line, "#", 2)[0])
			if len(match) != 2 {
				continue
			}
			target := strings.TrimSpace(match[1])
			if strings.Contains(target, "$") {
				return fmt.Errorf("nginx reverse-proxy target uses variables and cannot be resolved statically")
			}
			if _, _, ok := parseProxyTarget(target); !ok {
				return fmt.Errorf("nginx reverse-proxy target could not be parsed")
			}
		}
	case "caddy":
		for _, line := range lines(data) {
			fields := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(fields) > 0 && strings.EqualFold(fields[0], "reverse_proxy") {
				if len(fields) < 2 || len(fields) > 2 || strings.Contains(fields[1], "{") {
					return fmt.Errorf("caddy reverse_proxy uses a dynamic or multi-upstream form that is not fully modeled")
				}
			}
		}
	case "haproxy":
		if strings.Contains(lower, "\nserver-template ") || strings.HasPrefix(strings.TrimSpace(lower), "server-template ") {
			return fmt.Errorf("haproxy server-template targets are not fully modeled")
		}
	}
	return nil
}

func parseNginxRoutes(path, data string) []reverseProxyRoute {
	type serverBlock struct{ listens, backends [][2]string }
	var blocks []serverBlock
	var current *serverBlock
	depth := 0
	for _, raw := range lines(data) {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if current == nil && strings.HasPrefix(strings.ToLower(line), "server") && strings.Contains(line, "{") {
			current, depth = &serverBlock{}, strings.Count(line, "{")-strings.Count(line, "}")
			continue
		}
		if current == nil {
			continue
		}
		if match := nginxListenRE.FindStringSubmatch(line); len(match) == 2 {
			if address, port, ok := parseNginxListen(match[1]); ok {
				current.listens = append(current.listens, [2]string{address, port})
			}
		}
		if match := nginxProxyRE.FindStringSubmatch(line); len(match) == 2 {
			if address, port, ok := parseProxyTarget(match[1]); ok {
				current.backends = append(current.backends, [2]string{address, port})
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			blocks, current = append(blocks, *current), nil
		}
	}
	var routes []reverseProxyRoute
	for _, block := range blocks {
		for _, frontend := range block.listens {
			for _, backend := range block.backends {
				routes = append(routes, reverseProxyRoute{Product: "nginx", Source: path, FrontendAddress: frontend[0], FrontendPort: frontend[1], FrontendTransport: "tcp", BackendAddress: backend[0], BackendPort: backend[1]})
			}
		}
	}
	return routes
}

func parseNginxListen(value string) (string, string, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", "", false
	}
	token := fields[0]
	if validPort(token) {
		return "::", token, true
	}
	return splitEndpoint(token)
}

func parseProxyTarget(value string) (string, string, bool) {
	value = strings.TrimSpace(strings.Trim(value, `"'`))
	if value == "" || strings.Contains(value, "$") {
		return "", "", false
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		host, port, ok := splitEndpoint(parsed.Host)
		if ok {
			return normalizeBackendHost(host), port, true
		}
		if parsed.Scheme == "https" {
			return normalizeBackendHost(parsed.Hostname()), "443", true
		}
		return normalizeBackendHost(parsed.Hostname()), "80", true
	}
	host, port, ok := splitEndpoint(value)
	return normalizeBackendHost(host), port, ok
}

func parseCaddyRoutes(path, data string) []reverseProxyRoute {
	var routes []reverseProxyRoute
	frontendAddress, frontendPort, depth := "", "", 0
	for _, raw := range lines(data) {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if depth == 0 {
			if match := caddySiteRE.FindStringSubmatch(line); len(match) == 2 {
				frontendAddress, frontendPort, _ = parseCaddySite(match[1])
				depth = 1
			}
			continue
		}
		if match := caddyProxyRE.FindStringSubmatch(line); len(match) == 2 {
			if host, port, ok := parseProxyTarget(match[1]); ok && frontendPort != "" {
				routes = append(routes, reverseProxyRoute{Product: "caddy", Source: path, FrontendAddress: frontendAddress, FrontendPort: frontendPort, FrontendTransport: "tcp", BackendAddress: host, BackendPort: port})
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
	}
	return routes
}

func parseCaddySite(value string) (string, string, bool) {
	value = strings.TrimSpace(strings.Split(value, ",")[0])
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return "", "", false
		}
		port := parsed.Port()
		if port == "" {
			port = map[bool]string{true: "443", false: "80"}[parsed.Scheme == "https"]
		}
		return "::", port, validPort(port)
	}
	if strings.HasPrefix(value, ":") {
		return splitEndpoint(value)
	}
	if _, port, ok := splitEndpoint(value); ok {
		return "::", port, true
	}
	return "::", "443", value != ""
}

func parseHAProxyRoutes(path, data string) []reverseProxyRoute {
	type backendRef struct {
		name       string
		conditions []string
	}
	type frontend struct {
		binds    [][2]string
		backends []backendRef
		pathACLs map[string]bool
	}
	frontends := map[string]*frontend{}
	backends := map[string][][2]string{}
	sectionType, sectionName := "", ""
	for _, raw := range lines(data) {
		line := strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "frontend":
			if len(fields) > 1 {
				sectionType, sectionName = "frontend", fields[1]
				frontends[sectionName] = &frontend{pathACLs: map[string]bool{}}
			}
		case "backend":
			if len(fields) > 1 {
				sectionType, sectionName = "backend", fields[1]
			}
		case "bind":
			if sectionType == "frontend" && len(fields) > 1 {
				for _, token := range strings.Split(fields[1], ",") {
					if host, port, ok := parseHAProxyAddress(token); ok {
						frontends[sectionName].binds = append(frontends[sectionName].binds, [2]string{host, port})
					}
				}
			}
		case "default_backend":
			if sectionType == "frontend" && len(fields) > 1 {
				frontends[sectionName].backends = append(frontends[sectionName].backends, backendRef{name: fields[1]})
			}
		case "use_backend":
			if sectionType == "frontend" && len(fields) > 1 && !strings.ContainsAny(fields[1], "[%]") {
				frontends[sectionName].backends = append(frontends[sectionName].backends, backendRef{name: fields[1], conditions: append([]string(nil), fields[2:]...)})
			}
		case "acl":
			if sectionType == "frontend" && len(fields) > 2 && (containsAny(strings.ToLower(fields[1]), "path", "url") || containsAny(strings.ToLower(fields[2]), "path", "url")) {
				frontends[sectionName].pathACLs[fields[1]] = true
			}
		case "server":
			if sectionType == "backend" && len(fields) > 2 {
				if host, port, ok := splitEndpoint(fields[2]); ok {
					backends[sectionName] = append(backends[sectionName], [2]string{normalizeBackendHost(host), port})
				}
			}
		}
	}
	var routes []reverseProxyRoute
	for _, frontend := range frontends {
		for _, reference := range frontend.backends {
			access := "unconditional"
			if len(reference.conditions) > 0 {
				access = "conditional"
				for _, condition := range reference.conditions {
					if frontend.pathACLs[condition] || containsAny(strings.ToLower(condition), "path", "url") {
						access = "path-gated"
						break
					}
				}
			}
			for _, backend := range backends[reference.name] {
				for _, bind := range frontend.binds {
					routes = append(routes, reverseProxyRoute{Product: "haproxy", Source: path, FrontendAddress: bind[0], FrontendPort: bind[1], FrontendTransport: "tcp", BackendAddress: backend[0], BackendPort: backend[1], Access: access})
				}
			}
		}
	}
	return routes
}

func parseHAProxyAddress(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	for _, prefix := range []string{"quic4@", "quic6@"} {
		value = strings.TrimPrefix(value, prefix)
	}
	if strings.HasPrefix(value, "abns@") || strings.HasPrefix(value, "unix@") {
		return "", "", false
	}
	return splitEndpoint(value)
}

func normalizeBackendHost(host string) string {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	switch strings.ToLower(host) {
	case "localhost":
		return "127.0.0.1"
	case "host.docker.internal":
		return "docker-host"
	}
	return host
}

func uniqueReverseProxyRoutes(routes []reverseProxyRoute) []reverseProxyRoute {
	seen := map[string]bool{}
	out := make([]reverseProxyRoute, 0, len(routes))
	for _, route := range routes {
		key := strings.Join([]string{route.Product, route.FrontendAddress, route.FrontendPort, route.BackendAddress, route.BackendPort, route.Access}, "\x00")
		if seen[key] || !validPort(route.FrontendPort) || !validPort(route.BackendPort) {
			continue
		}
		seen[key] = true
		out = append(out, route)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].FrontendPort+out[i].BackendPort < out[j].FrontendPort+out[j].BackendPort
	})
	return out
}

func checkReverseProxyRelations(ctx *Context) model.Finding {
	routes, discoveryErr := discoverReverseProxyRoutes(ctx.Commander)
	if len(routes) == 0 {
		if discoveryErr != nil {
			return unknown("WORK-013", "workloads", "reverse-proxy configuration discovery", discoveryErr.Error())
		}
		return notApplicable("WORK-013", "workloads", "Nginx, Caddy, and HAProxy configuration", "no supported reverse-proxy route found")
	}
	listeners, err := ctx.Facts.Listeners()
	if err != nil {
		return unknown("WORK-013", "workloads", "reverse-proxy configuration + ss + host firewall", err.Error())
	}
	panels, panelDiscoveryErr := ctx.Facts.Panels()
	ufw := readPanelUFW(ctx)
	f := assessReverseProxyRoutes(routes, listeners, ufw, panels)
	f = withIncompleteEvidence(f, "host firewall discovery", ufw.collectionErr)
	f = withIncompleteEvidence(f, "panel and container discovery", panelDiscoveryErr)
	return withIncompleteEvidence(f, "reverse-proxy configuration discovery", discoveryErr)
}

func assessReverseProxyRoutes(routes []reverseProxyRoute, listeners []Listener, firewall hostFirewallSnapshot, panels []panelSnapshot) model.Finding {
	f := model.Finding{ID: "WORK-013", Category: "workloads", Status: model.Pass, Facts: map[string]string{"routes": strconv.Itoa(len(routes))}}
	managementPorts := map[string]string{}
	for _, panel := range panels {
		for _, endpoint := range panel.Endpoints {
			if endpoint.Role == "management" && validPort(endpoint.Port) {
				managementPorts[endpoint.Port] = panel.Product
			}
		}
	}
	missingFrontends, missingBackends, exposedBackends, exposedManagement := 0, 0, 0, 0
	for _, route := range routes {
		frontend := matchingListener(listeners, route.FrontendPort, route.FrontendTransport)
		externalBackend := classifyAddress(route.BackendAddress) == "unknown" && route.BackendAddress != "docker-host"
		backend := matchingBackendListener(listeners, route.BackendAddress, route.BackendPort, "tcp")
		judgment := "reverse-proxy-chain-consistent"
		if frontend == nil {
			missingFrontends++
			judgment = "configured-frontend-not-listening"
			raiseRisk(&f, model.Medium)
		} else if externalBackend {
			judgment = "external-upstream-not-verified-from-local-listeners"
		} else if backend == nil {
			missingBackends++
			judgment = "configured-backend-not-listening"
			raiseRisk(&f, model.Medium)
		} else if classifyAddress(route.BackendAddress) == "loopback" && (backend.Scope == "public" || backend.Scope == "public-wildcard") {
			exposedBackends++
			judgment = "backend-listens-more-broadly-than-configured"
			raiseRisk(&f, model.Medium)
		}
		frontScope, frontFW, frontProcess := "not-live", "not-live", "none"
		if frontend != nil {
			frontScope, frontProcess = frontend.Scope, frontend.Process
			frontFW = firewallDispositionFamily(firewall, route.FrontendPort, "tcp", listenerAddressFamily(frontend.Address))
		}
		if product := managementPorts[route.BackendPort]; product != "" && frontend != nil && (frontScope == "public" || frontScope == "public-wildcard") && (frontFW == "allow-anywhere" || frontFW == "inactive") {
			exposedManagement++
			managementJudgment := "public-reverse-proxy-exposes-" + strings.ToLower(product) + "-management"
			if route.Access == "path-gated" {
				managementJudgment = "public-path-gated-reverse-proxy-reaches-" + strings.ToLower(product) + "-management"
			}
			if judgment == "reverse-proxy-chain-consistent" {
				judgment = managementJudgment
			} else {
				judgment += "+" + managementJudgment
			}
			// A non-default or conditional URL path reduces scan noise but is not
			// an authentication or network-access boundary.
			raiseRisk(&f, model.High)
		}
		backScope, backProcess := "not-live", "none"
		if backend != nil {
			backScope, backProcess = backend.Scope, backend.Process
		}
		access := route.Access
		if access == "" {
			access = "unknown"
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: route.Source + " + ss + host firewall", Key: "reverse_proxy_route", Value: fmt.Sprintf("frontend=%s:%s/tcp process=%s scope=%s firewall=%s proxy=%s access=%s backend=%s:%s/tcp process=%s scope=%s judgment=%s", route.FrontendAddress, route.FrontendPort, truncate(frontProcess, 80), frontScope, frontFW, route.Product, access, route.BackendAddress, route.BackendPort, truncate(backProcess, 80), backScope, judgment)})
	}
	f.Facts["missing_frontends"] = strconv.Itoa(missingFrontends)
	f.Facts["missing_backends"] = strconv.Itoa(missingBackends)
	f.Facts["overexposed_backends"] = strconv.Itoa(exposedBackends)
	f.Facts["public_management_routes"] = strconv.Itoa(exposedManagement)
	return f
}

func raiseRisk(f *model.Finding, severity model.Severity) {
	rank := map[model.Severity]int{model.Low: 1, model.Medium: 2, model.High: 3, model.Critical: 4}
	f.Status = model.Risk
	if rank[severity] > rank[f.Severity] {
		f.Severity = severity
	}
}

func matchingListener(listeners []Listener, port, transport string) *Listener {
	for index := range listeners {
		if listeners[index].Port == port && strings.HasPrefix(listeners[index].Protocol, transport) {
			return &listeners[index]
		}
	}
	return nil
}

func matchingBackendListener(listeners []Listener, address, port, transport string) *Listener {
	wantedScope := classifyAddress(address)
	if wantedScope == "unknown" || address == "docker-host" {
		return nil
	}
	var wildcard *Listener
	for index := range listeners {
		listener := &listeners[index]
		if listener.Port != port || !strings.HasPrefix(listener.Protocol, transport) {
			continue
		}
		if listener.Address == address || (wantedScope == "loopback" && listener.Scope == "loopback") {
			return listener
		}
		if listener.Scope == "public-wildcard" {
			wildcard = listener
		}
	}
	return wildcard
}
