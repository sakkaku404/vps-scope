package audit

import (
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestParseDockerIPTablesForwardPath(t *testing.T) {
	fixture := `*filter
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]
:DOCKER-FORWARD - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER-USER -p tcp -s 203.0.113.0/24 --dport 8443 -j ACCEPT
-A DOCKER-USER -p tcp --dport 2053 -j DROP
-A DOCKER-USER -j RETURN
COMMIT`
	available, user, hook, drop, rules := parseDockerIPTables(fixture, "ipv4")
	if !available || !user || !hook || !drop || len(rules) != 2 {
		t.Fatalf("available=%t user=%t hook=%t drop=%t rules=%+v", available, user, hook, drop, rules)
	}
	facts := dockerFirewallFacts{Available: true, AvailableByFamily: map[string]bool{"ipv4": true}, ForwardHook: true, UserChain: true, Rules: rules}
	if got := dockerForwardDisposition(facts, "2053", "tcp", "ipv4"); got != "blocked-by-docker-user" {
		t.Fatalf("2053 disposition=%q", got)
	}
	if got := dockerForwardDisposition(facts, "8443", "tcp", "ipv4"); got != "restricted-by-docker-user" {
		t.Fatalf("8443 disposition=%q", got)
	}
	if got := dockerForwardDisposition(facts, "443", "tcp", "ipv4"); got != "docker-user-fallthrough" {
		t.Fatalf("443 disposition=%q", got)
	}
}

func TestDockerForwardDispositionDoesNotInferMissingAddressFamily(t *testing.T) {
	facts := dockerFirewallFacts{Available: true, AvailableByFamily: map[string]bool{"ipv4": true}, ForwardHook: true, UserChain: true}
	if got := dockerForwardDisposition(facts, "443", "tcp", "ipv6"); got != "unknown" {
		t.Fatalf("missing IPv6 evidence became %q", got)
	}
}

func TestNFTForwardHookDoesNotConsumeInputRules(t *testing.T) {
	fixture := `table inet filter {
 chain input { type filter hook input priority filter; policy drop;
   tcp dport 22 accept
 }
 chain forward { type filter hook forward priority filter; policy drop;
   tcp dport 8443 accept
 }
}`
	rules := parseNFTHookRules(lines(fixture), "forward")
	if len(rules) != 1 || rules[0].Port != "8443" || rules[0].Origin != "nft-forward" {
		t.Fatalf("forward rules=%+v", rules)
	}
}

func TestCheckDockerFirewallPathFindsInputPolicyBypass(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("iptables-save"):            {Stdout: "*filter\n:FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER\nCOMMIT\n"},
		scenarioCommandKey("ufw", "status", "verbose"): {Stdout: "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"iptables-save", "ufw"}, results))
	var container dockerInspect
	container.Name = "/web"
	container.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"80/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}}}
	f := checkDockerFirewallPath(ctx, []dockerInspect{container})
	if f.Status != model.Risk || f.Facts["input_policy_bypass_paths"] != "1" {
		t.Fatalf("unexpected finding: %#v", f)
	}
}

func TestCheckDockerFirewallPathKeepsMissingIPv6EvidenceUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("iptables-save"): {Stdout: "*filter\n:FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER\nCOMMIT\n"},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"iptables-save"}, results))
	var container dockerInspect
	container.Name = "/v6-web"
	container.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"443/tcp": {{HostIP: "::", HostPort: "8443"}}}
	f := checkDockerFirewallPath(ctx, []dockerInspect{container})
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["unknown_forward_paths"] != "1" {
		t.Fatalf("unexpected finding: %#v", f)
	}
}

func TestCheckDockerFirewallPathAcceptsSourceRestrictedDockerUserRule(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("iptables-save"):            {Stdout: "*filter\n:FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER\n-A DOCKER-USER -p tcp -s 203.0.113.0/24 --dport 8443 -j ACCEPT\nCOMMIT\n"},
		scenarioCommandKey("ufw", "status", "verbose"): {Stdout: "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"iptables-save", "ufw"}, results))
	var container dockerInspect
	container.Name = "/restricted-web"
	container.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"443/tcp": {{HostIP: "0.0.0.0", HostPort: "8443"}}}
	f := checkDockerFirewallPath(ctx, []dockerInspect{container})
	if f.Status != model.Pass || f.Facts["input_policy_bypass_paths"] != "0" {
		t.Fatalf("unexpected finding: %#v", f)
	}
}

func TestCheckDockerFirewallPathDoesNotPassWithIncompleteHostFirewallFacts(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("iptables-save"):            {Stdout: "*filter\n:FORWARD DROP [0:0]\n:DOCKER-USER - [0:0]\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER\n-A DOCKER-USER -p tcp -s 203.0.113.0/24 --dport 8443 -j ACCEPT\nCOMMIT\n"},
		scenarioCommandKey("ufw", "status", "verbose"): {Err: errCommandOutputTruncated, Truncated: true},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"iptables-save", "ufw"}, results))
	var container dockerInspect
	container.Name = "/restricted-web"
	container.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"443/tcp": {{HostIP: "0.0.0.0", HostPort: "8443"}}}
	f := checkDockerFirewallPath(ctx, []dockerInspect{container})
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("unexpected finding: %#v", f)
	}
}

func TestDockerFirewallFailureDoesNotInvalidateLoopbackOnlyPublishing(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.dockerFirewallOnce.Do(func() {
		ctx.Facts.dockerFirewall = dockerFirewallFacts{Error: "ip6tables unavailable"}
	})
	var container dockerInspect
	container.Name = "/loopback-only"
	container.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"80/tcp": {{HostIP: "127.0.0.1", HostPort: "3001"}}}
	f := checkDockerFirewallPath(ctx, []dockerInspect{container})
	if f.Status != model.Pass || f.Unavailable {
		t.Fatalf("loopback-only publication became %s: %+v", f.Status, f)
	}
}
