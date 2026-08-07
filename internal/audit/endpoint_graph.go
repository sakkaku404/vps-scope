package audit

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// endpointGraph is the policy boundary between product-specific configuration
// adapters and report findings. Collectors describe intended endpoints,
// listeners describe runtime state, and the graph correlates both without
// making product parsers responsible for security conclusions.
type endpointGraph struct {
	Nodes []endpointNode
	Edges []endpointEdge
}

type endpointNode struct {
	ID        string
	Role      string
	Product   string
	Protocol  string
	Transport string
	Address   string
	Port      string
	Source    string
	Process   string
	Scope     string
	Firewall  string
	Live      bool
	Security  string
}

type endpointEdge struct {
	From string
	To   string
	Kind string
}

type endpointAssessment struct {
	Node     endpointNode
	Judgment string
	Risk     bool
	Missing  bool
	Unknown  bool
}

func buildProxyEndpointGraph(inbounds []configuredProxyInbound, listeners []Listener, firewall hostFirewallSnapshot) endpointGraph {
	graph := endpointGraph{}
	listenerIndex := make(map[string][]int, len(listeners))
	for index, listener := range listeners {
		transport := strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(listener.Protocol), "4"), "6")
		listenerIndex[transport+"/"+listener.Port] = append(listenerIndex[transport+"/"+listener.Port], index)
	}
	seenNodes := map[string]bool{}
	addNode := func(node endpointNode) {
		if seenNodes[node.ID] {
			return
		}
		seenNodes[node.ID] = true
		graph.Nodes = append(graph.Nodes, node)
	}
	seenEdges := map[string]bool{}
	addEdge := func(edge endpointEdge) {
		key := edge.From + "\x00" + edge.To + "\x00" + edge.Kind
		if seenEdges[key] {
			return
		}
		seenEdges[key] = true
		graph.Edges = append(graph.Edges, edge)
	}
	for _, inbound := range inbounds {
		transports := inbound.Transports
		if len(transports) == 0 {
			transports = proxyTransports(inbound.Protocol, "")
		}
		for _, transport := range transports {
			configuredID := stableEndpointNodeID("configured", inbound.Product, inbound.Protocol, transport, inbound.Listen, inbound.Port, inbound.Path)
			security := inbound.Security
			if inbound.RealityEnabled {
				security = "reality"
			}
			if security == "" {
				security = "none-or-protocol-native"
			}
			configured := endpointNode{
				ID: configuredID, Role: "proxy-ingress", Product: inbound.Product,
				Protocol: inbound.Protocol, Transport: transport, Address: inbound.Listen,
				Port: inbound.Port, Source: inbound.Path, Security: security,
			}
			addNode(configured)
			for _, index := range listenerIndex[strings.ToLower(transport)+"/"+inbound.Port] {
				listener := listeners[index]
				if !configuredAddressMatchesListener(inbound.Listen, listener.Address) {
					continue
				}
				runtimeID := stableEndpointNodeID("listener", transport, listener.Address, listener.Port, listener.Process)
				addNode(endpointNode{
					ID: runtimeID, Role: "listener", Transport: transport,
					Address: listener.Address, Port: listener.Port, Process: listener.Process,
					Scope: listener.Scope, Live: true,
					Firewall: firewallDispositionFamily(firewall, listener.Port, transport, listenerAddressFamily(listener.Address)),
				})
				addEdge(endpointEdge{From: configuredID, To: runtimeID, Kind: "realized-by"})
			}
		}
	}
	return graph
}

func assessProxyEndpointGraph(graph endpointGraph, active map[string]bool) []endpointAssessment {
	byID := make(map[string]endpointNode, len(graph.Nodes))
	edges := make(map[string][]endpointEdge)
	for _, node := range graph.Nodes {
		byID[node.ID] = node
	}
	for _, edge := range graph.Edges {
		edges[edge.From] = append(edges[edge.From], edge)
	}
	var out []endpointAssessment
	for _, configured := range graph.Nodes {
		if configured.Role != "proxy-ingress" {
			continue
		}
		linked := edges[configured.ID]
		if len(linked) == 0 {
			judgment := "configured_not_listening"
			risk := false
			if active[strings.ToLower(configured.Product)] {
				judgment, risk = "active_product_but_not_listening", true
			}
			out = append(out, endpointAssessment{Node: configured, Judgment: judgment, Risk: risk, Missing: true})
			continue
		}
		for _, edge := range linked {
			runtime := byID[edge.To]
			combined := configured
			combined.Address, combined.Process, combined.Scope, combined.Firewall, combined.Live = runtime.Address, runtime.Process, runtime.Scope, runtime.Firewall, true
			judgment, risk := "expected-proxy-ingress", false
			if product, known := listenerProxyProduct(runtime.Process); known && !sameProxyProduct(product, configured.Product) {
				judgment, risk = "listener-owner-does-not-match-configured-product", true
			} else if runtime.Scope == "public" || runtime.Scope == "public-wildcard" {
				switch runtime.Firewall {
				case "blocked-by-default", "blocked-by-explicit-rule":
					judgment, risk = "configured-public-ingress-blocked-by-host-firewall", true
				case "unknown", "conditional-unknown", "no-explicit-rule":
					judgment = "configured-public-ingress-firewall-unknown"
					out = append(out, endpointAssessment{Node: combined, Judgment: judgment, Unknown: true})
					continue
				}
			}
			out = append(out, endpointAssessment{Node: combined, Judgment: judgment, Risk: risk})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		left, _ := strconv.Atoi(out[i].Node.Port)
		right, _ := strconv.Atoi(out[j].Node.Port)
		if left != right {
			return left < right
		}
		if out[i].Node.Transport != out[j].Node.Transport {
			return out[i].Node.Transport < out[j].Node.Transport
		}
		return out[i].Node.ID < out[j].Node.ID
	})
	return out
}

func stableEndpointNodeID(kind string, parts ...string) string {
	canonical := kind + "\x00" + strings.ToLower(strings.Join(parts, "\x00"))
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%s:%x", kind, sum[:8])
}

func configuredAddressMatchesListener(configured, live string) bool {
	configured = strings.Trim(strings.TrimSpace(configured), "[]")
	live = strings.Trim(strings.TrimSpace(live), "[]")
	if configured == "" || configured == "*" || configured == "0.0.0.0" || configured == "::" {
		return true
	}
	if strings.EqualFold(configured, "localhost") {
		return classifyAddress(live) == "loopback"
	}
	configuredIP, liveIP := net.ParseIP(configured), net.ParseIP(live)
	if configuredIP != nil && liveIP != nil {
		return configuredIP.Equal(liveIP)
	}
	return strings.EqualFold(configured, live)
}
