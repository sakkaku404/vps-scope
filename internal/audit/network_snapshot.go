package audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// networkSnapshot is the immutable evidence boundary for the network category.
// Collection happens once; evaluators below are deterministic and never invoke
// commands or read the host filesystem.
type networkSnapshot struct {
	Listeners          []Listener
	ListenerErr        error
	Connections        []activeConnection
	ConnectionErr      error
	RuntimeExpected    map[string]bool
	RuntimeExpectedErr error
}

type networkPolicyView struct {
	Requested           string
	Effective           string
	ExpectedPublic      map[string]bool
	ProfileExpected     map[string]bool
	ProfileDiscoveryErr error
}

func collectNetworkSnapshot(ctx *Context) networkSnapshot {
	listeners, listenerErr := ctx.Facts.Listeners()
	connections, connectionErr := ctx.Facts.EstablishedConnections()
	runtimeExpected, runtimeExpectedErr := runtimeExpectedPublicListeners(ctx)
	return networkSnapshot{
		Listeners: listeners, ListenerErr: listenerErr,
		Connections: connections, ConnectionErr: connectionErr,
		RuntimeExpected: runtimeExpected, RuntimeExpectedErr: runtimeExpectedErr,
	}
}

func networkPolicyFromContext(ctx *Context) networkPolicyView {
	policyExpected := map[string]bool{}
	if ctx.Policy != nil {
		policyExpected = ctx.Policy.ExpectedPublicListeners()
	}
	return networkPolicyView{
		Requested: ctx.Profile.Requested, Effective: ctx.Profile.Effective,
		ExpectedPublic: ctx.ExpectedPublic, ProfileExpected: policyExpected,
		ProfileDiscoveryErr: ctx.ProfileDiscoveryError,
	}
}

func evaluateListenerInventory(snapshot networkSnapshot) model.Finding {
	if snapshot.ListenerErr != nil {
		return unknown("NET-001", "network", "ss -H -lntu[p]", snapshot.ListenerErr.Error())
	}
	f := model.Finding{ID: "NET-001", Category: "network", Status: model.Info, Facts: map[string]string{}}
	counts := map[string]int{}
	for _, listener := range snapshot.Listeners {
		counts[listener.Scope]++
		value := fmt.Sprintf("%s %s:%s scope=%s", listener.Protocol, listener.Address, listener.Port, listener.Scope)
		if listener.Process != "" {
			value += " process=" + truncate(listener.Process, 160)
		}
		if len(f.Evidence) < 80 {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Value: value})
		}
	}
	for key, count := range counts {
		f.Facts[key] = strconv.Itoa(count)
	}
	f.Facts["total"] = strconv.Itoa(len(snapshot.Listeners))
	return f
}

func evaluateUnexpectedListeners(snapshot networkSnapshot, policy networkPolicyView) model.Finding {
	if snapshot.ListenerErr != nil {
		return unknown("NET-002", "network", "ss -H -lntu[p]", snapshot.ListenerErr.Error())
	}
	f := model.Finding{ID: "NET-002", Category: "network", Status: model.Pass, Facts: map[string]string{}}
	unexpected, uncertainRuntimeUDP := 0, 0
	seen := map[string]bool{}
	for _, listener := range snapshot.Listeners {
		if listener.Scope != "public" && listener.Scope != "public-wildcard" {
			continue
		}
		proto := strings.TrimSuffix(strings.TrimSuffix(listener.Protocol, "6"), "4")
		key := listener.Port + "/" + proto
		if seen[key+"\x00"+listener.Process] {
			continue
		}
		seen[key+"\x00"+listener.Process] = true
		if snapshot.RuntimeExpected[key] || expectedListenerForPolicy(policy, listener, key) {
			continue
		}
		if snapshot.RuntimeExpectedErr != nil && proto == "udp" {
			uncertainRuntimeUDP++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss + runtime listener discovery", Key: "unclassified_public_udp_listener", Value: fmt.Sprintf("%s %s:%s process=%s profile=%s", proto, listener.Address, listener.Port, truncate(listener.Process, 180), policy.Effective)})
			continue
		}
		unexpected++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ss + profile policy", Key: "unexpected_public_listener", Value: fmt.Sprintf("%s %s:%s process=%s profile=%s", proto, listener.Address, listener.Port, truncate(listener.Process, 180), policy.Effective)})
	}
	f.Facts["unexpected_public_listeners"] = strconv.Itoa(unexpected)
	f.Facts["unclassified_public_udp_listeners"] = strconv.Itoa(uncertainRuntimeUDP)
	if unexpected > 0 {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	if uncertainRuntimeUDP > 0 && unexpected == 0 {
		f.Status, f.Severity, f.Unavailable = model.Unknown, "", true
		f.Error = "runtime listener classification could not be completed"
	}
	if policy.Requested == "auto" && policy.ProfileDiscoveryErr != nil {
		f.Status, f.Severity, f.Unavailable = model.Unknown, "", true
		f.Error = "automatic profile detection could not be completed"
	}
	f = withIncompleteEvidence(f, "runtime expected-listener discovery", snapshot.RuntimeExpectedErr)
	if policy.Requested == "auto" {
		f = withIncompleteEvidence(f, "automatic profile detection", policy.ProfileDiscoveryErr)
	}
	return f
}

func evaluateActiveConnections(snapshot networkSnapshot) model.Finding {
	if snapshot.ConnectionErr != nil {
		return unknown("NET-003", "network", "ss established", snapshot.ConnectionErr.Error())
	}
	f := model.Finding{ID: "NET-003", Category: "network", Status: model.Info, Facts: map[string]string{}}
	counts := map[string]int{}
	for i, connection := range snapshot.Connections {
		counts[connection.scope]++
		if i < 80 {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss established", Key: "connection", Value: fmt.Sprintf("%s local=%s peer=%s peer_scope=%s process=%s", connection.protocol, connection.local, connection.peer, connection.scope, truncate(connection.process, 160))})
		}
	}
	f.Facts["total"] = strconv.Itoa(len(snapshot.Connections))
	for scope, count := range counts {
		f.Facts["peer_"+scope] = strconv.Itoa(count)
	}
	return f
}

func expectedListenerForPolicy(policy networkPolicyView, listener Listener, key string) bool {
	if policy.ExpectedPublic[key] || policy.ProfileExpected[key] {
		return true
	}
	process := strings.ToLower(listener.Process)
	port, _ := strconv.Atoi(listener.Port)
	if (port == 68 || port == 546) && containsAny(process, "dhcp", "dhclient", "dhcpcd", "systemd-network") {
		return true
	}
	if port == 123 && strings.HasPrefix(strings.ToLower(listener.Protocol), "udp") && containsAny(process, "ntpd", "chronyd", "systemd-timesyncd") {
		return true
	}
	if strings.Contains(process, "sshd") {
		return true
	}
	switch policy.Effective {
	case "web":
		return containsAny(process, "nginx", "caddy", "apache2")
	case "docker":
		// A Docker host commonly exposes container publications through
		// docker-proxy or a host/container edge proxy. This only classifies the
		// listener as expected for the selected profile; DOCKER and WORK checks
		// still assess the publication, management role and firewall path.
		return containsAny(process, "docker-proxy", "nginx", "caddy", "apache2", "haproxy", "traefik")
	case "proxy":
		return containsAny(process, "sing-box", "xray", "sui", "s-ui", "x-ui", "hysteria", "tuic", "trojan", "ss-server", "outline-ss-server", "marzban", "hiddify", "haproxy", "dnstm")
	case "mixed":
		return containsAny(process, "nginx", "caddy", "apache2", "sing-box", "xray", "sui", "s-ui", "x-ui", "hysteria", "tuic", "trojan", "ss-server", "outline-ss-server", "marzban", "hiddify", "haproxy", "dnstm")
	}
	return false
}
