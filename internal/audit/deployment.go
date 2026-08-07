package audit

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

const maxDeploymentEndpoints = 2048

// buildDeployment normalizes configuration, runtime, panel, reverse-proxy,
// Docker, and firewall facts into one typed view. It contains no policy side
// effects: stable findings remain the source of PASS/RISK/INFO/UNKNOWN.
func buildDeployment(ctx *Context, summaries []proxyConfigSummary, configurationErr error) *model.Deployment {
	b := newDeploymentBuilder()
	active := activeProxyProducts(ctx)

	listeners, listenerErr := ctx.Facts.Listeners()
	firewall := ctx.Facts.HostFirewall()
	panels, panelErr := ctx.Facts.Panels()
	routes, routeErr := ctx.Facts.ReverseProxyRoutes()
	containers, dockerErr := []dockerInspect(nil), error(nil)
	dockerInstalled := ctx.Commander.Exists("docker")
	if dockerInstalled {
		containers, dockerErr = ctx.Facts.DockerContainers()
	}

	b.deployment.Coverage = model.DeploymentCoverage{
		Configuration: coverageState(len(summaries) > 0, configurationErr),
		Runtime:       coverageState(len(listeners) > 0, listenerErr),
		Firewall:      coverageState(firewall.available, firewall.collectionErr),
		Panels:        coverageState(len(panels) > 0, panelErr),
		ReverseProxy:  coverageState(len(routes) > 0, routeErr),
		Docker:        "not-applicable",
	}
	if dockerInstalled {
		b.deployment.Coverage.Docker = coverageState(true, dockerErr)
	}

	for _, summary := range summaries {
		b.component(summary.Product, "proxy-core", summary.Path, productIsActive(active, summary.Product), "native-or-managed", confidenceForError(summary.Err))
	}
	for product := range active {
		b.component(canonicalProductName(product), "proxy-runtime", "process inventory", true, "native-or-managed", "confirmed")
	}
	for _, panel := range panels {
		source := panel.Database
		if source == "" {
			source = panel.Binary
		}
		b.component(panel.Product, "management-panel", source, productIsActive(active, panel.Product), deploymentKind(panel), panelConfidence(panel))
	}
	for _, route := range routes {
		b.component(route.Product, "reverse-proxy", route.Source, true, "native-or-managed", "confirmed")
	}

	claimed := map[string]bool{}
	connections, connectionErr := ctx.Facts.EstablishedConnections()
	connectionCounts := map[string]int{}
	if connectionErr == nil {
		for _, connection := range connections {
			_, port := splitHostPortLoose(connection.local)
			connectionCounts[port]++
		}
	}

	inbounds := uniqueProxyInbounds(summaries)
	for _, assessment := range assessProxyEndpointGraph(buildProxyEndpointGraph(inbounds, listeners, firewall), active) {
		node := assessment.Node
		port, err := strconv.Atoi(node.Port)
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		componentID := b.component(node.Product, "proxy-core", node.Source, productIsActive(active, node.Product), "native-or-managed", "confirmed")
		state, confidence := "configured", "confirmed"
		if node.Live {
			state = "live"
			claimed[listenerClaimKey(node.Transport, node.Port, node.Address)] = true
		}
		if assessment.Unknown {
			confidence = "unknown"
		} else if assessment.Missing && !assessment.Risk {
			confidence = "inferred"
		}
		endpoint := model.ServiceEndpoint{
			ComponentID: componentID, Product: node.Product, Role: "proxy-ingress", Protocol: node.Protocol,
			Transport: node.Transport, Port: port, Address: node.Address, Family: addressFamily(node.Address),
			Scope: valueOr(node.Scope, classifyAddress(node.Address)), Process: truncate(node.Process, 120),
			Security: node.Security, Firewall: valueOr(node.Firewall, "unknown"), State: state,
			Judgment: assessment.Judgment, Source: node.Source, Confidence: confidence,
		}
		if node.Live && strings.EqualFold(node.Transport, "tcp") && connectionErr == nil {
			count := connectionCounts[node.Port]
			endpoint.ConnectionCount = &count
		}
		endpointID := b.endpoint(endpoint)
		b.link(componentID, endpointID, "declares")
	}

	for _, summary := range summaries {
		componentID := b.component(summary.Product, "proxy-core", summary.Path, productIsActive(active, summary.Product), "native-or-managed", confidenceForError(summary.Err))
		for _, control := range summary.Controls {
			port, err := strconv.Atoi(control.Port)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			listener := configuredListener(listeners, control.Listen, control.Port, "tcp")
			endpoint := model.ServiceEndpoint{ComponentID: componentID, Product: control.Product, Role: "control-api", Protocol: control.Kind, Transport: "tcp", Port: port, Address: control.Listen, Scope: classifyAddress(control.Listen), State: "configured", Source: summary.Path, Confidence: "confirmed"}
			if listener != nil {
				endpoint.Address, endpoint.Family, endpoint.Scope, endpoint.Process, endpoint.State = listener.Address, listenerAddressFamily(listener.Address), listener.Scope, truncate(listener.Process, 120), "live"
				endpoint.Firewall = firewallDispositionFamily(firewall, control.Port, "tcp", endpoint.Family)
				claimed[listenerClaimKey("tcp", control.Port, listener.Address)] = true
			}
			endpoint.Judgment, endpoint.Confidence = controlJudgment(endpoint, listenerErr, firewall.collectionErr)
			endpointID := b.endpoint(endpoint)
			b.link(componentID, endpointID, "declares")
		}
	}

	panelEndpoints := map[string][]string{}
	for _, panel := range panels {
		componentID := b.component(panel.Product, "management-panel", valueOr(panel.Database, panel.Binary), productIsActive(active, panel.Product), deploymentKind(panel), panelConfidence(panel))
		for _, configured := range panel.Endpoints {
			port, err := strconv.Atoi(configured.Port)
			if err != nil || port < 1 || port > 65535 {
				continue
			}
			listener := configuredListener(listeners, configured.Listen, configured.Port, "tcp")
			endpoint := model.ServiceEndpoint{ComponentID: componentID, Product: panel.Product, Role: configured.Role, Transport: "tcp", Port: port, Address: configured.Listen, Scope: classifyAddress(configured.Listen), State: "configured", Source: configured.Source, Confidence: "confirmed", TLS: knownBool(configured.TLS, configured.TLSKnown), PathPosture: pathPosture(configured)}
			if listener != nil {
				endpoint.Address, endpoint.Family, endpoint.Scope, endpoint.Process, endpoint.State = listener.Address, listenerAddressFamily(listener.Address), listener.Scope, truncate(listener.Process, 120), "live"
				endpoint.Firewall = firewallDispositionFamily(firewall, configured.Port, "tcp", endpoint.Family)
				claimed[listenerClaimKey("tcp", configured.Port, listener.Address)] = true
			}
			endpoint.Judgment, endpoint.Confidence = panelEndpointJudgment(endpoint, listenerErr, firewall.collectionErr)
			endpointID := b.endpoint(endpoint)
			panelEndpoints[configured.Port] = append(panelEndpoints[configured.Port], endpointID)
			b.link(componentID, endpointID, "declares")
		}
	}

	for _, route := range routes {
		componentID := b.component(route.Product, "reverse-proxy", route.Source, true, "native-or-managed", "confirmed")
		frontPort, frontErr := strconv.Atoi(route.FrontendPort)
		backPort, backErr := strconv.Atoi(route.BackendPort)
		if frontErr != nil || backErr != nil {
			continue
		}
		frontListener := configuredListener(listeners, route.FrontendAddress, route.FrontendPort, valueOr(route.FrontendTransport, "tcp"))
		frontend := model.ServiceEndpoint{ComponentID: componentID, Product: route.Product, Role: "reverse-proxy-frontend", Protocol: route.Access, Transport: valueOr(route.FrontendTransport, "tcp"), Port: frontPort, Address: route.FrontendAddress, Scope: classifyAddress(route.FrontendAddress), State: "configured", Source: route.Source, Confidence: "confirmed"}
		if frontListener != nil {
			frontend.Address, frontend.Family, frontend.Scope, frontend.Process, frontend.State = frontListener.Address, listenerAddressFamily(frontListener.Address), frontListener.Scope, truncate(frontListener.Process, 120), "live"
			frontend.Firewall = firewallDispositionFamily(firewall, route.FrontendPort, frontend.Transport, frontend.Family)
			claimed[listenerClaimKey(frontend.Transport, route.FrontendPort, frontListener.Address)] = true
		}
		frontend.Judgment = reverseFrontendJudgment(frontend, frontListener, listenerErr, firewall.collectionErr)
		frontID := b.endpoint(frontend)

		backListener := configuredListener(listeners, route.BackendAddress, route.BackendPort, "tcp")
		backend := model.ServiceEndpoint{ComponentID: componentID, Product: route.Product, Role: "reverse-proxy-backend", Transport: "tcp", Port: backPort, Address: route.BackendAddress, Scope: classifyAddress(route.BackendAddress), State: "configured", Source: route.Source, Confidence: "confirmed"}
		if backListener != nil {
			backend.Address, backend.Family, backend.Scope, backend.Process, backend.State = backListener.Address, listenerAddressFamily(backListener.Address), backListener.Scope, truncate(backListener.Process, 120), "live"
			claimed[listenerClaimKey("tcp", route.BackendPort, backListener.Address)] = true
		}
		if backListener == nil && classifyAddress(route.BackendAddress) != "unknown" {
			backend.Judgment = "configured-backend-not-listening"
		} else if classifyAddress(route.BackendAddress) == "unknown" {
			backend.Judgment, backend.Confidence = "external-upstream-not-verified", "inferred"
		} else {
			backend.Judgment = "reverse-proxy-backend-live"
		}
		backID := b.endpoint(backend)
		b.link(componentID, frontID, "owns")
		b.link(frontID, backID, "proxies-to")
		for _, panelID := range panelEndpoints[route.BackendPort] {
			b.link(backID, panelID, "routes-to")
		}
	}

	if dockerInstalled && dockerErr == nil {
		dockerFirewall := ctx.Facts.DockerFirewall()
		for _, container := range containers {
			name := strings.TrimPrefix(container.Name, "/")
			identity := strings.TrimSpace(name + " " + container.Config.Image)
			if !proxyProcessPattern.MatchString(identity) && !containsAny(strings.ToLower(identity), "marzban", "hiddify", "outline", "nginx", "caddy", "haproxy") {
				continue
			}
			product := proxyProductFromText(identity)
			if product == "unknown-proxy" {
				product = valueOr(container.Config.Image, name)
			}
			componentID := b.component(product, "container", "docker inspect", true, valueOr(container.HostConfig.NetworkMode, "bridge"), "confirmed")
			for target, bindings := range container.NetworkSettings.Ports {
				targetPort, transport, ok := strings.Cut(target, "/")
				if !ok || !validPort(targetPort) {
					continue
				}
				for _, binding := range bindings {
					hostPort, err := strconv.Atoi(binding.HostPort)
					if err != nil || hostPort < 1 || hostPort > 65535 {
						continue
					}
					family := addressFamily(binding.HostIP)
					forward := dockerForwardDisposition(dockerFirewall, binding.HostPort, targetPort, transport, family)
					endpoint := model.ServiceEndpoint{ComponentID: componentID, Product: product, Role: "container-publish", Protocol: target, Transport: transport, Port: hostPort, Address: binding.HostIP, Family: family, Scope: classifyAddress(binding.HostIP), Process: name, Firewall: forward, State: "live", Judgment: "docker-published-port", Source: "docker inspect", Confidence: confidenceForDockerFirewall(forward)}
					endpointID := b.endpoint(endpoint)
					b.link(componentID, endpointID, "published-as")
					if listener := configuredListener(listeners, binding.HostIP, binding.HostPort, transport); listener != nil {
						claimed[listenerClaimKey(transport, binding.HostPort, listener.Address)] = true
					}
				}
			}
		}
	}

	for _, listener := range listeners {
		transport := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(listener.Protocol), "4"), "6")
		product, recognized := listenerProxyProduct(listener.Process)
		if claimed[listenerClaimKey(transport, listener.Port, listener.Address)] || (!recognized && listener.Scope != "public" && listener.Scope != "public-wildcard") {
			continue
		}
		port, err := strconv.Atoi(listener.Port)
		if err != nil {
			continue
		}
		role := "unclassified-listener"
		componentID := ""
		if recognized {
			role = "unclassified-product-listener"
			componentID = b.component(product, "proxy-runtime", "process inventory", true, "native-or-managed", "inferred")
		}
		endpointID := b.endpoint(model.ServiceEndpoint{ComponentID: componentID, Product: product, Role: role, Transport: transport, Port: port, Address: listener.Address, Family: listenerAddressFamily(listener.Address), Scope: listener.Scope, Process: truncate(listener.Process, 120), Firewall: firewallDispositionFamily(firewall, listener.Port, transport, listenerAddressFamily(listener.Address)), State: "live", Judgment: "listener-purpose-not-classified", Source: "ss", Confidence: "inferred"})
		if componentID != "" {
			b.link(componentID, endpointID, "owns")
		}
	}

	if len(b.deployment.Components) == 0 && len(b.deployment.Endpoints) == 0 {
		return nil
	}
	b.finish()
	return &b.deployment
}

type deploymentBuilder struct {
	deployment     model.Deployment
	componentIndex map[string]int
	endpointIndex  map[string]int
	links          map[string]bool
}

func newDeploymentBuilder() *deploymentBuilder {
	return &deploymentBuilder{componentIndex: map[string]int{}, endpointIndex: map[string]int{}, links: map[string]bool{}}
}

func (b *deploymentBuilder) component(product, kind, source string, runtime bool, deployment, confidence string) string {
	product = strings.TrimSpace(product)
	if product == "" {
		product = "unknown"
	}
	id := topologyID("component", strings.ToLower(product), kind, deployment)
	if index, ok := b.componentIndex[id]; ok {
		if runtime {
			b.deployment.Components[index].Runtime = true
		}
		if b.deployment.Components[index].Source == "" {
			b.deployment.Components[index].Source = source
		}
		if confidenceRank(confidence) > confidenceRank(b.deployment.Components[index].Confidence) {
			b.deployment.Components[index].Confidence = confidence
		}
		return id
	}
	b.componentIndex[id] = len(b.deployment.Components)
	b.deployment.Components = append(b.deployment.Components, model.Component{ID: id, Product: product, Kind: kind, Source: source, Runtime: runtime, Deployment: deployment, Confidence: valueOr(confidence, "unknown")})
	return id
}

func (b *deploymentBuilder) endpoint(endpoint model.ServiceEndpoint) string {
	if len(b.deployment.Endpoints) >= maxDeploymentEndpoints {
		b.deployment.Coverage.Runtime = "partial"
		return ""
	}
	endpoint.ID = topologyID("endpoint", endpoint.ComponentID, endpoint.Product, endpoint.Role, endpoint.Protocol, endpoint.Transport, strconv.Itoa(endpoint.Port), normalizeTopologyAddress(endpoint.Address))
	if index, ok := b.endpointIndex[endpoint.ID]; ok {
		if confidenceRank(endpoint.Confidence) > confidenceRank(b.deployment.Endpoints[index].Confidence) {
			b.deployment.Endpoints[index] = endpoint
		}
		return endpoint.ID
	}
	b.endpointIndex[endpoint.ID] = len(b.deployment.Endpoints)
	b.deployment.Endpoints = append(b.deployment.Endpoints, endpoint)
	return endpoint.ID
}

func (b *deploymentBuilder) link(from, to, kind string) {
	if from == "" || to == "" {
		return
	}
	key := from + "\x00" + to + "\x00" + kind
	if b.links[key] {
		return
	}
	b.links[key] = true
	b.deployment.Links = append(b.deployment.Links, model.TopologyLink{From: from, To: to, Kind: kind})
}

func (b *deploymentBuilder) finish() {
	sort.Slice(b.deployment.Components, func(i, j int) bool { return b.deployment.Components[i].ID < b.deployment.Components[j].ID })
	sort.Slice(b.deployment.Endpoints, func(i, j int) bool {
		left, right := b.deployment.Endpoints[i], b.deployment.Endpoints[j]
		if left.Port != right.Port {
			return left.Port < right.Port
		}
		if left.Transport != right.Transport {
			return left.Transport < right.Transport
		}
		return left.ID < right.ID
	})
	sort.Slice(b.deployment.Links, func(i, j int) bool {
		left, right := b.deployment.Links[i], b.deployment.Links[j]
		return left.From+"\x00"+left.To+"\x00"+left.Kind < right.From+"\x00"+right.To+"\x00"+right.Kind
	})
}

func topologyID(kind string, parts ...string) string {
	canonical := kind + "\x00" + strings.ToLower(strings.Join(parts, "\x00"))
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%s:%x", kind, sum[:8])
}

func coverageState(hasData bool, err error) string {
	if err != nil && hasData {
		return "partial"
	}
	if err != nil {
		return "unavailable"
	}
	if !hasData {
		return "not-applicable"
	}
	return "complete"
}

func productIsActive(active map[string]bool, product string) bool {
	for candidate := range active {
		if sameProxyProduct(candidate, product) {
			return true
		}
	}
	return false
}

func canonicalProductName(product string) string {
	switch strings.ToLower(product) {
	case "x-ui/3x-ui", "x-ui", "3x-ui":
		return "x-ui/3x-ui"
	case "s-ui":
		return "S-UI"
	case "xray":
		return "Xray"
	case "hysteria2":
		return "Hysteria2"
	case "tuic":
		return "TUIC"
	default:
		return product
	}
}

func confidenceForError(err error) string {
	if err != nil {
		return "partial"
	}
	return "confirmed"
}

func panelConfidence(panel panelSnapshot) string {
	if panel.DiscoveryError != "" || panel.DatabaseError != "" || panel.RuntimeCommandError != "" {
		return "partial"
	}
	return "confirmed"
}

func deploymentKind(panel panelSnapshot) string {
	if strings.HasPrefix(panel.Adapter, "docker") {
		return "container"
	}
	return "native-or-managed"
}

func listenerClaimKey(transport, port, address string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(transport, "4"), "6")) + "/" + port + "/" + normalizeTopologyAddress(address)
}

func configuredListener(listeners []Listener, address, port, transport string) *Listener {
	for index := range listeners {
		listener := &listeners[index]
		liveTransport := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(listener.Protocol), "4"), "6")
		if listener.Port == port && liveTransport == strings.ToLower(transport) && configuredAddressMatchesListener(address, listener.Address) {
			return listener
		}
	}
	return nil
}

func addressFamily(address string) string {
	address = strings.Trim(address, "[]")
	if strings.Contains(address, ":") {
		return "ipv6"
	}
	if address == "" || address == "*" {
		return "any"
	}
	return "ipv4"
}

func normalizeTopologyAddress(address string) string {
	address = strings.Trim(strings.TrimSpace(address), "[]")
	if address == "" || address == "*" {
		return "any"
	}
	return strings.ToLower(address)
}

func pathPosture(endpoint panelEndpoint) string {
	if !endpoint.PathKnown {
		return "unknown"
	}
	if endpoint.PathIsDefault {
		return "root-or-default"
	}
	return "non-default"
}

func controlJudgment(endpoint model.ServiceEndpoint, listenerErr, firewallErr error) (string, string) {
	if listenerErr != nil {
		return "runtime-listener-unknown", "unknown"
	}
	if endpoint.State != "live" {
		return "configured-control-not-listening", "confirmed"
	}
	if endpoint.Scope != "public" && endpoint.Scope != "public-wildcard" {
		return "internal-control-endpoint", "confirmed"
	}
	if firewallErr != nil || endpoint.Firewall == "unknown" || endpoint.Firewall == "conditional-unknown" {
		return "public-control-firewall-unknown", "unknown"
	}
	if endpoint.Firewall == "allow-anywhere" || endpoint.Firewall == "inactive" {
		return "public-control-exposed", "confirmed"
	}
	return "public-control-restricted", "confirmed"
}

func panelEndpointJudgment(endpoint model.ServiceEndpoint, listenerErr, firewallErr error) (string, string) {
	if listenerErr != nil {
		return "panel-listener-unknown", "unknown"
	}
	if endpoint.State != "live" {
		return "configured-panel-endpoint-not-listening", "confirmed"
	}
	if endpoint.Scope != "public" && endpoint.Scope != "public-wildcard" {
		return "internal-panel-endpoint", "confirmed"
	}
	if firewallErr != nil || endpoint.Firewall == "unknown" || endpoint.Firewall == "conditional-unknown" {
		return "public-panel-firewall-unknown", "unknown"
	}
	if endpoint.Firewall == "allow-anywhere" || endpoint.Firewall == "inactive" {
		return "public-" + endpoint.Role + "-exposed", "confirmed"
	}
	return "public-" + endpoint.Role + "-restricted", "confirmed"
}

func reverseFrontendJudgment(endpoint model.ServiceEndpoint, listener *Listener, listenerErr, firewallErr error) string {
	if listenerErr != nil {
		return "reverse-proxy-listener-unknown"
	}
	if listener == nil {
		return "configured-frontend-not-listening"
	}
	if firewallErr != nil || endpoint.Firewall == "unknown" || endpoint.Firewall == "conditional-unknown" {
		return "reverse-proxy-firewall-unknown"
	}
	return "reverse-proxy-frontend-live"
}

func confidenceForDockerFirewall(disposition string) string {
	if disposition == "unknown" || disposition == "conditional-unknown" || disposition == "docker-user-fallthrough" {
		return "partial"
	}
	return "confirmed"
}

func confidenceRank(value string) int {
	switch value {
	case "confirmed":
		return 3
	case "inferred":
		return 2
	case "partial":
		return 1
	default:
		return 0
	}
}
