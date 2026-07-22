package audit

import "testing"

func TestNormalizedFirewallBackends(t *testing.T) {
	tests := []struct {
		name                 string
		facts                panelUFW
		port, protocol, want string
	}{
		{"nft public tcp", parseNFTFirewall("table inet filter { chain input { type filter hook input priority 0; policy drop; tcp dport 443 accept } }"), "443", "tcp", "allow-anywhere"},
		{"nft restricted udp", parseNFTFirewall("table inet filter { chain input { type filter hook input priority 0; policy drop; ip saddr 192.0.2.0/24 udp dport 8443 accept } }"), "8443", "udp", "allow-restricted"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := firewallDisposition(test.facts, test.port, test.protocol); got != test.want {
				t.Fatalf("got %q want %q", got, test.want)
			}
		})
	}
	rules, deny := parseIPTablesFirewall(":INPUT DROP [0:0]\n-A INPUT -p udp -s 0.0.0.0/0 --dport 443 -j ACCEPT", "ipv4")
	if !deny || len(rules) != 1 {
		t.Fatalf("iptables deny=%t rules=%d", deny, len(rules))
	}
	f := panelUFW{available: true, active: true, defaultDeny: deny, backend: "iptables", rules: rules}
	if got := firewallDisposition(f, "443", "udp"); got != "allow-anywhere" {
		t.Fatalf("iptables got %q", got)
	}
	if got := firewallDisposition(f, "443", "tcp"); got != "blocked-by-default" {
		t.Fatalf("tcp separation got %q", got)
	}
	if got := firewallDispositionFamily(f, "443", "udp", "ipv6"); got != "blocked-by-default" {
		t.Fatalf("IPv4 rule incorrectly covered IPv6: %q", got)
	}
}

func TestIPTablesDefaultPolicyIsAddressFamilySpecific(t *testing.T) {
	f := panelUFW{available: true, active: true, backend: "iptables", defaultDeny: true, defaultDenyByFamily: map[string]bool{"ipv4": true, "ipv6": false}}
	if got := firewallDispositionFamily(f, "443", "tcp", "ipv4"); got != "blocked-by-default" {
		t.Fatalf("ipv4=%q", got)
	}
	if got := firewallDispositionFamily(f, "443", "tcp", "ipv6"); got != "no-explicit-rule" {
		t.Fatalf("ipv6=%q", got)
	}
}

func TestNFTDefaultPolicyTracksTableFamily(t *testing.T) {
	f := parseNFTFirewall("table ip filter {\n chain input { type filter hook input priority 0; policy drop; }\n}\ntable ip6 filter {\n chain input { type filter hook input priority 0; policy accept; }\n}")
	if !defaultDenyForFamily(f, "ipv4") || defaultDenyForFamily(f, "ipv6") {
		t.Fatalf("family policies=%v", f.defaultDenyByFamily)
	}
}

func TestNFTParserUsesOnlyReachableInputChains(t *testing.T) {
	input := `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy drop;
		tcp dport 16659 accept
		jump user-input
	}
	chain user-input {
		udp dport 443 accept
	}
	chain OUTPUT {
		type filter hook output priority filter; policy accept;
		tcp dport 9999 accept
	}
}`
	f := parseNFTFirewall(input)
	if firewallDispositionFamily(f, "16659", "tcp", "ipv4") != "allow-anywhere" || firewallDispositionFamily(f, "443", "udp", "ipv4") != "allow-anywhere" {
		t.Fatalf("input path not parsed: %+v", f.rules)
	}
	if firewallDispositionFamily(f, "9999", "tcp", "ipv4") == "allow-anywhere" {
		t.Fatal("OUTPUT rule was mistaken for host ingress")
	}
}

func TestActiveUFWIncludesDirectNFTInputRules(t *testing.T) {
	ufw := "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n22/tcp ALLOW IN Anywhere"
	nft := `table ip filter {
	chain INPUT {
		type filter hook input priority filter; policy accept;
		tcp dport 16659 accept
	}
}`
	cmd := newScenarioCommander([]string{"ufw", "nft"}, map[string]CommandResult{
		scenarioCommandKey("ufw", "status", "verbose"): {Stdout: ufw},
		scenarioCommandKey("nft", "list", "ruleset"):   {Stdout: nft},
	})
	f := collectHostFirewall(cmd)
	if f.backend != "ufw+nftables" || firewallDispositionFamily(f, "16659", "tcp", "ipv4") != "allow-anywhere" {
		t.Fatalf("merged firewall=%+v", f)
	}
	if firewallDispositionFamily(f, "24443", "udp", "ipv4") != "blocked-by-default" {
		t.Fatal("UFW default deny was lost while merging nftables")
	}
	foundDirect := false
	for _, rule := range f.rules {
		if rule.Port == "16659" && includeFirewallExposureRule(f.backend, rule) {
			foundDirect = true
		}
	}
	if !foundDirect {
		t.Fatal("direct nftables rule was omitted from UFW exposure evidence")
	}
}

func TestUFWExposureEvidenceSeparatesGeneratedAndDirectNFTChains(t *testing.T) {
	if includeFirewallExposureRule("ufw+nftables", firewallRule{Origin: "nft-reachable", Chain: "ufw-user-input"}) {
		t.Fatal("generated UFW chain was duplicated as a direct nftables rule")
	}
	if !includeFirewallExposureRule("ufw+nftables", firewallRule{Origin: "nft-reachable", Chain: "VPS-SCOPE-LAB"}) {
		t.Fatal("independent nftables chain was hidden behind the UFW summary")
	}
}

func TestFirewallCollectorFallsBackToIPTablesWhenSaveIsUnavailable(t *testing.T) {
	cmd := newScenarioCommander([]string{"iptables"}, map[string]CommandResult{
		scenarioCommandKey("iptables", "-S"): {Stdout: "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT"},
	})
	f := collectHostFirewall(cmd)
	if !f.available || !f.active || f.backend != "iptables" || !f.defaultDeny {
		t.Fatalf("iptables fallback = %+v", f)
	}
	if got := firewallDispositionFamily(f, "22", "tcp", "ipv4"); got != "allow-anywhere" {
		t.Fatalf("iptables fallback SSH disposition=%q", got)
	}
}

func TestFirewallParsersPreserveAllPortAllows(t *testing.T) {
	ufw := parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nAnywhere ALLOW IN Anywhere")
	if got := firewallDisposition(ufw, "2095", "tcp"); got != "allow-anywhere" {
		t.Fatalf("UFW all-port disposition=%q", got)
	}
	rules, _ := parseIPTablesFirewall("*filter\n:INPUT DROP [0:0]\n-A INPUT -i eth0 -j ACCEPT\nCOMMIT", "ipv4")
	iptables := panelUFW{available: true, active: true, defaultDeny: true, rules: rules}
	if got := firewallDisposition(iptables, "2095", "tcp"); got != "conditional-unknown" {
		t.Fatalf("iptables all-port disposition=%q rules=%+v", got, rules)
	}
	nft := parseNFTFirewall("table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n  iifname \"eth0\" accept\n }\n}")
	if got := firewallDisposition(nft, "2095", "tcp"); got != "conditional-unknown" {
		t.Fatalf("nft all-port disposition=%q rules=%+v", got, nft.rules)
	}
}

func TestUFWExplicitDenyOverridesDefaultAllow(t *testing.T) {
	f := parsePanelUFW("Status: active\nDefault: allow (incoming), allow (outgoing), disabled (routed)\n2095/tcp DENY IN Anywhere")
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "blocked-by-explicit-rule" {
		t.Fatalf("explicit UFW deny became %q; rules=%+v", got, f.rules)
	}
}

func TestRestrictedAllowRespectsOrderedClosingDenyAndDefaultPolicy(t *testing.T) {
	restricted := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -s 203.0.113.0/24 --dport 2095 -j ACCEPT
-A INPUT -p tcp --dport 2095 -j DROP
COMMIT`
	rules, policy, _ := parseIPTablesFirewallDetailed(restricted, "ipv4")
	f := panelUFW{available: true, active: true, backend: "iptables", rules: rules, defaultPolicyByFamily: map[string]string{"ipv4": policy}}
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "allow-restricted" {
		t.Fatalf("closed source allow became %q; rules=%+v", got, rules)
	}

	defaultAllow := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -s 203.0.113.0/24 --dport 2095 -j ACCEPT
COMMIT`
	rules, policy, _ = parseIPTablesFirewallDetailed(defaultAllow, "ipv4")
	f = panelUFW{available: true, active: true, backend: "iptables", rules: rules, defaultPolicyByFamily: map[string]string{"ipv4": policy}}
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "allow-anywhere" {
		t.Fatalf("default ACCEPT was hidden by a source allow: %q", got)
	}
}

func TestIPTablesParserFollowsReachableUserChains(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
:PANEL-GUARD - [0:0]
-A INPUT -j PANEL-GUARD
-A PANEL-GUARD -p tcp --dport 2095 -j ACCEPT
COMMIT`
	rules, policy, unresolved := parseIPTablesFirewallDetailed(input, "ipv4")
	if policy != "deny" || unresolved != 0 {
		t.Fatalf("policy=%q unresolved=%d rules=%+v", policy, unresolved, rules)
	}
	f := panelUFW{available: true, active: true, backend: "iptables", defaultPolicyByFamily: map[string]string{"ipv4": policy}, rules: rules}
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "allow-anywhere" {
		t.Fatalf("custom-chain public allow was missed: %q rules=%+v", got, rules)
	}
}

func TestIPTablesParserPreservesRuleOrderForTerminalDecision(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 2095 -j DROP
-A INPUT -p tcp --dport 2095 -j ACCEPT
COMMIT`
	rules, policy, unresolved := parseIPTablesFirewallDetailed(input, "ipv4")
	if unresolved != 0 {
		t.Fatalf("unresolved=%d", unresolved)
	}
	f := panelUFW{available: true, active: true, backend: "iptables", defaultPolicyByFamily: map[string]string{"ipv4": policy}, rules: rules}
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "blocked-by-explicit-rule" {
		t.Fatalf("first terminal decision was not preserved: %q rules=%+v", got, rules)
	}
}

func TestNFTParserPreservesInlineCustomChainOrder(t *testing.T) {
	input := `table inet filter {
 chain input {
  type filter hook input priority filter; policy accept;
  jump panel_guard
 }
 chain panel_guard {
  tcp dport 2095 drop
  tcp dport 2095 accept
 }
}`
	f := parseNFTFirewall(input)
	if f.collectionErr != nil {
		t.Fatalf("unexpected parse error: %v", f.collectionErr)
	}
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "blocked-by-explicit-rule" {
		t.Fatalf("first custom-chain verdict was not preserved: %q rules=%+v", got, f.rules)
	}
}

func TestNFTConditionalJumpCannotBecomeUnconditionalAllow(t *testing.T) {
	input := `table inet filter {
 chain input {
  type filter hook input priority filter; policy drop;
  iifname "tailscale0" jump panel_guard
 }
 chain panel_guard {
  tcp dport 2095 accept
 }
}`
	f := parseNFTFirewall(input)
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "conditional-unknown" {
		t.Fatalf("conditional jump became %q; rules=%+v", got, f.rules)
	}
}

func TestConditionalFirewallRulesDoNotBecomePublicOrBlocked(t *testing.T) {
	iptablesInput := `*filter
:INPUT DROP [0:0]
-A INPUT -i tailscale0 -p tcp --dport 2095 -j ACCEPT
COMMIT`
	rules, policy, _ := parseIPTablesFirewallDetailed(iptablesInput, "ipv4")
	f := panelUFW{available: true, active: true, backend: "iptables", defaultPolicyByFamily: map[string]string{"ipv4": policy}, rules: rules}
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "conditional-unknown" {
		t.Fatalf("interface-constrained iptables rule=%q", got)
	}

	nft := parseNFTFirewall(`table inet filter {
 chain input {
  type filter hook input priority filter; policy drop;
  iifname "tailscale0" tcp dport 2095 accept
 }
}`)
	if got := firewallDispositionFamily(nft, "2095", "tcp", "ipv4"); got != "conditional-unknown" {
		t.Fatalf("interface-constrained nft rule=%q rules=%+v", got, nft.rules)
	}
}

func TestExplicitAcceptPolicyIsPublicWithoutAllowRule(t *testing.T) {
	f := parseNFTFirewall(`table inet filter {
 chain input {
  type filter hook input priority filter; policy accept;
 }
}`)
	if got := firewallDispositionFamily(f, "2095", "tcp", "ipv4"); got != "allow-anywhere" {
		t.Fatalf("explicit accept policy=%q policies=%v", got, f.defaultPolicyByFamily)
	}
}

func TestNFTAllPortParserIgnoresEstablishedAndLoopbackRules(t *testing.T) {
	for _, line := range []string{"ct state established,related accept", `iifname "lo" accept`, "icmp type echo-request accept"} {
		if rule, ok := parseNFTAllPortRule(line, "any", "nft-input"); ok {
			t.Fatalf("state/loopback rule became public all-port allow: %+v", rule)
		}
	}
}

func TestNFTParserMarksUnknownReachableExposureExpressionsIncomplete(t *testing.T) {
	f := parseNFTFirewall("table inet filter {\n chain input {\n type filter hook input priority 0; policy drop;\n tcp dport @public_ports accept\n }\n}")
	if f.collectionErr == nil {
		t.Fatal("unresolved reachable nftables accept expression was treated as complete")
	}
}

func TestNFTParserExpandsReachablePortSetsAndUniformVerdictMaps(t *testing.T) {
	input := `table inet filter {
 set proxy_ports { type inet_service; elements = { 8443, 9443 } }
 map allowed_ports { type inet_service : verdict; elements = { 2053 : accept, 2096 : accept } }
 chain input { type filter hook input priority filter; policy drop;
   tcp dport @proxy_ports accept
   tcp dport vmap @allowed_ports
 }
}`
	f := parseNFTFirewall(input)
	for _, port := range []string{"8443", "9443", "2053", "2096"} {
		if got := firewallDisposition(f, port, "tcp"); got != "allow-anywhere" {
			t.Fatalf("port %s = %q; rules=%+v", port, got, f.rules)
		}
	}
}
