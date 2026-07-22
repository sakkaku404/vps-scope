package audit

import (
	"fmt"
	"sort"
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
	for index, inbound := range inbounds {
		transports := inbound.Transports
		if len(transports) == 0 {
			transports = proxyTransports(inbound.Protocol, "")
		}
		for _, transport := range transports {
			configuredID := fmt.Sprintf("configured:%d:%s", index, transport)
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
			graph.Nodes = append(graph.Nodes, configured)
			for listenerIndex, listener := range listeners {
				if listener.Port != inbound.Port || !strings.HasPrefix(listener.Protocol, transport) {
					continue
				}
				runtimeID := fmt.Sprintf("listener:%d:%s", listenerIndex, transport)
				graph.Nodes = append(graph.Nodes, endpointNode{
					ID: runtimeID, Role: "listener", Transport: transport,
					Address: listener.Address, Port: listener.Port, Process: listener.Process,
					Scope: listener.Scope, Live: true,
					Firewall: firewallDispositionFamily(firewall, listener.Port, transport, listenerAddressFamily(listener.Address)),
				})
				graph.Edges = append(graph.Edges, endpointEdge{From: configuredID, To: runtimeID, Kind: "realized-by"})
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
			combined.Process, combined.Scope, combined.Firewall, combined.Live = runtime.Process, runtime.Scope, runtime.Firewall, true
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
		return out[i].Node.Port+out[i].Node.Transport < out[j].Node.Port+out[j].Node.Transport
	})
	return out
}
