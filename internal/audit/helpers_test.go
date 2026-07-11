package audit

import (
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestClassifyAddress(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1": "loopback", "::1": "loopback", "10.0.0.2": "private",
		"172.16.2.3": "private", "192.168.1.1": "private", "fc00::1": "private",
		"169.254.1.2": "private", "0.0.0.0": "public-wildcard", "::": "public-wildcard",
		"*": "public-wildcard", "1.1.1.1": "public", "2001:4860:4860::8888": "public",
	}
	for input, want := range tests {
		if got := classifyAddress(input); got != want {
			t.Errorf("classifyAddress(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestParseListeners(t *testing.T) {
	input := `tcp LISTEN 0 4096 127.0.0.1:3001 0.0.0.0:* users:(("node",pid=12,fd=3))
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
udp UNCONN 0 0 [::1]:53 [::]:* users:(("dns",pid=2,fd=4))
udp UNCONN 0 0 [::]:8443 [::]:* users:(("sing-box",pid=3,fd=8))`
	got := parseListeners(input)
	if len(got) != 4 {
		t.Fatalf("got %d listeners, want 4", len(got))
	}
	wants := []struct{ address, port, scope string }{{"127.0.0.1", "3001", "loopback"}, {"0.0.0.0", "22", "public-wildcard"}, {"::1", "53", "loopback"}, {"::", "8443", "public-wildcard"}}
	for i, want := range wants {
		if got[i].Address != want.address || got[i].Port != want.port || got[i].Scope != want.scope {
			t.Errorf("listener[%d]=%+v, want %+v", i, got[i], want)
		}
	}
}

func TestParseKeyValues(t *testing.T) {
	got := parseKeyValues("ID=ubuntu\nVERSION_ID=\"24.04\"\n# comment\n")
	if got["ID"] != "ubuntu" || got["VERSION_ID"] != "24.04" {
		t.Fatalf("unexpected values: %#v", got)
	}
}

func TestParseDPKGVerifyClassifiesExcludedDocs(t *testing.T) {
	input := "missing     /usr/share/doc/pkg/README.gz\n??5?????? c /etc/example.conf\nmissing     /usr/bin/tool\n..5......   /usr/lib/libchanged.so\n"
	got := parseDPKGVerify(input)
	if got.total != 4 || got.excludedMissing != 1 || got.config != 1 || got.runtimeMissing != 1 || got.contentChanged != 1 {
		t.Fatalf("unexpected classification: %+v", got)
	}
}

func TestExpectedListenerUsesExplicitPort(t *testing.T) {
	ctx := &Context{Options: Options{ExpectedPublic: map[string]bool{"25565/tcp": true}}, Profile: model.Profile{Effective: "general"}}
	if !expectedListener(ctx, Listener{Protocol: "tcp", Port: "25565", Process: `users:(("java"))`}, "25565/tcp") {
		t.Fatal("explicit expected port was not accepted")
	}
	if expectedListener(ctx, Listener{Protocol: "tcp", Port: "3001", Process: `users:(("node"))`}, "3001/tcp") {
		t.Fatal("unexpected listener was accepted")
	}
}

func TestParsePanelPort(t *testing.T) {
	tests := []struct {
		product, output, want string
	}{
		{"S-UI", "Panel port: 2095\nSing-box port: 443", "2095"},
		{"3x-ui", "webBasePath: /secret/\nport: 2053", "2053"},
		{"x-ui", "webPort: 54321", "54321"},
	}
	for _, test := range tests {
		got, ok := parsePanelPort(test.product, test.output)
		if !ok || got != test.want {
			t.Errorf("parsePanelPort(%q)=(%q,%t), want %q", test.product, got, ok, test.want)
		}
	}
	for _, output := range []string{"port: 0", "port: 65536", "username: 2053", ""} {
		if got, ok := parsePanelPort("3x-ui", output); ok {
			t.Errorf("invalid panel port %q accepted as %q", output, got)
		}
	}
}

func TestPanelFirewallDisposition(t *testing.T) {
	tests := []struct {
		name string
		ufw  panelUFW
		want string
	}{
		{"inactive", panelUFW{available: true}, "inactive"},
		{"allow anywhere", panelUFW{available: true, active: true, defaultDeny: true, lines: []string{"2053/tcp ALLOW IN Anywhere"}}, "allow-anywhere"},
		{"trusted source", panelUFW{available: true, active: true, defaultDeny: true, lines: []string{"2053/tcp ALLOW IN 10.8.0.0/24"}}, "restricted"},
		{"default blocked", panelUFW{available: true, active: true, defaultDeny: true}, "blocked-by-default"},
		{"unsupported firewall", panelUFW{}, "unknown"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := model.Finding{}
			if got := panelFirewallDisposition(test.ufw, "2053", &finding); got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestPanelListenerScopePrefersPublicBinding(t *testing.T) {
	listeners := []Listener{
		{Protocol: "tcp", Address: "127.0.0.1", Port: "2053", Scope: "loopback"},
		{Protocol: "tcp", Address: "0.0.0.0", Port: "2053", Scope: "public-wildcard"},
	}
	finding := model.Finding{}
	got, found := panelListenerScope(listeners, "2053", &finding)
	if !found || got != "public-wildcard" {
		t.Fatalf("got (%q,%t), want public-wildcard", got, found)
	}
}
