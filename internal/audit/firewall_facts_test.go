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
