package audit

import (
	"fmt"
	"os"
	"strings"
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

func TestExpectedInfrastructureListeners(t *testing.T) {
	ctx := &Context{Options: Options{ExpectedPublic: map[string]bool{}}, Profile: model.Profile{Effective: "general"}}
	tests := []Listener{
		{Protocol: "udp", Port: "68", Process: `users:(("dhclient",pid=1))`},
		{Protocol: "udp", Port: "123", Process: `users:(("ntpd",pid=2))`},
		{Protocol: "tcp", Port: "22", Process: `users:(("sshd",pid=3))`},
	}
	for _, listener := range tests {
		key := listener.Port + "/" + listener.Protocol
		if !expectedListener(ctx, listener, key) {
			t.Errorf("expected infrastructure listener was rejected: %+v", listener)
		}
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

func TestContainerPanelDetection(t *testing.T) {
	tests := map[string]string{
		"marzban-app gozargah/marzban:latest": "Marzban",
		"hiddify-manager hiddify/manager":     "Hiddify",
		"outline shadowbox":                   "Outline",
		"panel ghcr.io/mhsanaei/3x-ui":        "containerized x-ui/3x-ui",
	}
	for input, want := range tests {
		got, ok := panelProductFromContainer(input)
		if !ok || got != want {
			t.Errorf("panelProductFromContainer(%q)=(%q,%t), want %q", input, got, ok, want)
		}
	}
	if _, ok := panelProductFromContainer("nginx nginx:alpine"); ok {
		t.Fatal("ordinary web container was classified as a proxy panel")
	}
}

func TestResourceParsers(t *testing.T) {
	mem := parseMemInfo("MemTotal:       1024000 kB\nMemAvailable:    512000 kB\nSwapTotal:       128 kB\n")
	if mem["MemTotal"] != 1024000*1024 || mem["MemAvailable"] != 512000*1024 {
		t.Fatalf("unexpected meminfo: %#v", mem)
	}
	if model := parseCPUModel("processor: 0\nmodel name: Example CPU 2.0 GHz\n"); model != "Example CPU 2.0 GHz" {
		t.Fatalf("unexpected CPU model %q", model)
	}
	ticks, ok := parseCPUStat("cpu  100 10 20 400 20 0 0 0 0 0\ncpu0 50 5 10 200 10\n")
	if !ok || ticks.total != 550 || ticks.idle != 420 {
		t.Fatalf("unexpected CPU ticks: %+v ok=%t", ticks, ok)
	}
	disk, ok := parseDF("1B-blocks Used Available Use%\n10737418240 2147483648 8589934592 20%\n")
	if !ok || disk.total != 10737418240 || disk.available != 8589934592 || disk.usedPercent != 20 {
		t.Fatalf("unexpected disk result: %+v ok=%t", disk, ok)
	}
}

func TestContextualPasswordPolicyParsers(t *testing.T) {
	login := map[string]bool{"root": true, "alice": true, "daemon": false}
	users := parseShadowPasswordUsers("root:!:1:2:3\nalice:$y$hash:1:2:3\ndaemon:$6$hash:1:2:3\n", login)
	if len(users) != 1 || users[0] != "alice" {
		t.Fatalf("unexpected password-bearing users: %#v", users)
	}
	if !hasPasswordQualityPolicy("password requisite pam_pwquality.so retry=3\n") {
		t.Fatal("active pam_pwquality was not detected")
	}
	if hasPasswordQualityPolicy("# password requisite pam_pwquality.so\npassword sufficient pam_unix.so\n") {
		t.Fatal("commented pam_pwquality was detected")
	}
}

func TestParseEstablishedConnections(t *testing.T) {
	input := `tcp ESTAB 0 0 10.0.0.2:22 203.0.113.5:50123 users:(("sshd",pid=9,fd=3))
tcp 0 0 127.0.0.1:3001 127.0.0.1:44220 users:(("node",pid=8,fd=4))`
	connections := parseEstablishedConnections(input)
	if len(connections) != 2 || connections[0].scope != "public" || connections[1].scope != "loopback" {
		t.Fatalf("unexpected connections: %#v", connections)
	}
}

func TestFirewalldParsers(t *testing.T) {
	zones := parseFirewalldActiveZones("public (default, active)\n  interfaces: eth0\ntrusted\n  sources: 10.8.0.0/24\n")
	if len(zones) != 2 || zones[0] != "public" || zones[1] != "trusted" {
		t.Fatalf("unexpected active zones: %#v", zones)
	}
	zone := parseFirewalldZone("public (active)\n  target: default\n  services: ssh https\n  ports: 8443/tcp\n  rich rules:\n")
	if zone.unrestricted || len(zone.services) != 2 || len(zone.ports) != 1 {
		t.Fatalf("unexpected zone: %+v", zone)
	}
	accept := parseFirewalldZone("trusted\n  target: ACCEPT\n")
	if !accept.unrestricted {
		t.Fatal("ACCEPT zone was not classified as unrestricted")
	}
	richAccept := parseFirewalldZone("public\n  rich rules:\n    rule family=ipv4 source address=0.0.0.0/0 accept\n")
	if !richAccept.unrestricted {
		t.Fatal("unrestricted rich rule was not classified")
	}
}

func TestCrowdSecBouncerDetection(t *testing.T) {
	if crowdSecHasBouncer("[]") || crowdSecHasBouncer("null") || !crowdSecHasBouncer(`[{"name":"firewall"}]`) {
		t.Fatal("unexpected CrowdSec bouncer detection")
	}
}

func TestParseSingBoxSummaryDoesNotExposeSecrets(t *testing.T) {
	input := []byte(`{
	  "inbounds": [{"type":"hysteria2","tag":"private-tag","listen":"::","listen_port":443,"users":[{"password":"do-not-export"}]}],
	  "experimental": {
	    "clash_api": {"external_controller":"127.0.0.1:9090","secret":"also-private"},
	    "v2ray_api": {"listen":"0.0.0.0:8080"}
	  }
	}`)
	got := parseSingBoxSummary("/etc/sing-box/config.json", input)
	if got.Err != nil || len(got.Inbounds) != 1 || !got.UsesUDP || len(got.Controls) != 2 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	serialized := fmt.Sprintf("%+v", got)
	for _, secret := range []string{"do-not-export", "also-private", "private-tag"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret %q leaked into summary: %s", secret, serialized)
		}
	}
	if got.Controls[0].Port != "9090" || got.Inbounds[0].Port != "443" {
		t.Fatalf("unexpected endpoint parsing: %+v", got)
	}
}

func TestParseXrayAPIInbound(t *testing.T) {
	input := []byte(`{"inbounds":[{"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door"},{"port":"443","protocol":"vless"}]}`)
	got := parseXraySummary("/etc/xray/config.json", input)
	if got.Err != nil || len(got.Inbounds) != 2 || len(got.Controls) != 1 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if got.Controls[0].Listen != "127.0.0.1" || got.Controls[0].Port != "10085" {
		t.Fatalf("unexpected API endpoint: %+v", got.Controls[0])
	}
}

func TestRealitySemanticsWithoutSecretRetention(t *testing.T) {
	input := []byte(`{"inbounds":[{"listen":"0.0.0.0","port":443,"protocol":"vless","streamSettings":{"network":"tcp","security":"reality","realitySettings":{"target":"example.invalid:443","privateKey":"never-export-this-key","serverNames":["private.example"],"shortIds":["01234567"]}}}]}`)
	got := parseXraySummary("/etc/xray/config.json", input)
	if got.Err != nil || len(got.Inbounds) != 1 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	inbound := got.Inbounds[0]
	if !inbound.RealityEnabled || !inbound.RealityKeySet || inbound.RealityTargets != 1 || inbound.RealityServerIDs != 2 || fmt.Sprint(inbound.Transports) != "[tcp]" {
		t.Fatalf("unexpected Reality semantics: %+v", inbound)
	}
	serialized := fmt.Sprintf("%+v", got)
	for _, secret := range []string{"never-export-this-key", "private.example", "01234567", "example.invalid"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("Reality secret-bearing value leaked: %q", secret)
		}
	}
}

func TestProxyTransportSemantics(t *testing.T) {
	tests := map[string][]string{
		"hysteria2": {"udp"},
		"tuic":      {"udp"},
		"vless":     {"tcp"},
	}
	for protocol, want := range tests {
		if got := proxyTransports(protocol, ""); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("proxyTransports(%q)=%v, want %v", protocol, got, want)
		}
	}
	if got := proxyTransports("shadowsocks", ""); fmt.Sprint(got) != "[tcp udp]" {
		t.Fatalf("shadowsocks transports=%v", got)
	}
}

func TestNativeTrojanAndShadowsocksPrivacy(t *testing.T) {
	trojan := parseTrojanSummary("/etc/trojan/config.json", []byte(`{"local_addr":"0.0.0.0","local_port":443,"password":["trojan-secret"],"ssl":{"key":"/private/key"}}`))
	shadowsocks := parseShadowsocksSummary("/etc/shadowsocks-libev/config.json", []byte(`{"server":"::","server_port":8388,"password":"ss-secret","method":"aes-256-gcm","mode":"tcp_and_udp"}`))
	if trojan.Err != nil || len(trojan.Inbounds) != 1 || trojan.Inbounds[0].Security != "tls" {
		t.Fatalf("unexpected Trojan summary: %+v", trojan)
	}
	if shadowsocks.Err != nil || len(shadowsocks.Inbounds) != 1 || fmt.Sprint(shadowsocks.Inbounds[0].Transports) != "[tcp udp]" {
		t.Fatalf("unexpected Shadowsocks summary: %+v", shadowsocks)
	}
	serialized := fmt.Sprintf("%+v %+v", trojan, shadowsocks)
	for _, secret := range []string{"trojan-secret", "ss-secret", "/private/key", "aes-256-gcm"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("native proxy secret leaked: %q", secret)
		}
	}
}

func TestOpenVPNSummaryIgnoresSecretPaths(t *testing.T) {
	got := parseOpenVPNSummary("/etc/openvpn/server/main.conf", "port 443\nproto tcp-server\nlocal 0.0.0.0\nkey /private/server.key\nauth-user-pass-verify /secret/script via-env\n")
	if len(got.Inbounds) != 1 || got.Inbounds[0].Port != "443" || fmt.Sprint(got.Inbounds[0].Transports) != "[tcp]" {
		t.Fatalf("unexpected OpenVPN summary: %+v", got)
	}
	serialized := fmt.Sprintf("%+v", got)
	for _, secret := range []string{"/private/server.key", "/secret/script"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("OpenVPN secret path leaked: %q", secret)
		}
	}
}

func TestEndpointFirewallDispositionSeparatesTCPAndUDP(t *testing.T) {
	ufw := panelUFW{available: true, active: true, defaultDeny: true, lines: []string{"443/tcp ALLOW IN Anywhere", "8443/udp ALLOW IN 10.0.0.0/8"}}
	if got := endpointFirewallDisposition(ufw, "443", "tcp"); got != "allow-anywhere" {
		t.Fatalf("tcp disposition=%q", got)
	}
	if got := endpointFirewallDisposition(ufw, "443", "udp"); got != "blocked-by-default" {
		t.Fatalf("udp disposition=%q", got)
	}
	if got := endpointFirewallDisposition(ufw, "8443", "udp"); got != "allow-restricted" {
		t.Fatalf("restricted udp disposition=%q", got)
	}
}

func TestSplitProxyEndpoint(t *testing.T) {
	tests := []struct{ input, host, port string }{
		{"127.0.0.1:9090", "127.0.0.1", "9090"},
		{"[::]:443", "::", "443"},
		{":8080", "::", "8080"},
		{"8443", "::", "8443"},
	}
	for _, test := range tests {
		host, port, ok := splitEndpoint(test.input)
		if !ok || host != test.host || port != test.port {
			t.Errorf("splitEndpoint(%q)=(%q,%q,%t), want (%q,%q,true)", test.input, host, port, ok, test.host, test.port)
		}
	}
	if _, _, ok := splitEndpoint("127.0.0.1:99999"); ok {
		t.Fatal("invalid port accepted")
	}
}

func TestProxyProcessEvidenceNeverIncludesArguments(t *testing.T) {
	line := `2970 root bash bash -c x-ui --password super-secret`
	if _, ok := proxyProcessLine(line); ok {
		t.Fatal("generic shell was misidentified as a proxy process")
	}
	line = `2877 root x-ui /usr/local/x-ui/x-ui --token super-secret`
	product, ok := proxyProcessLine(line)
	if !ok || product != "x-ui/3x-ui" {
		t.Fatalf("proxy process not detected: product=%q ok=%t", product, ok)
	}
	evidence := sanitizeProcessEvidence(line)
	if strings.Contains(evidence, "super-secret") || evidence != "2877 root x-ui" {
		t.Fatalf("unsafe process evidence: %q", evidence)
	}
}

func TestSingBoxFixturePrivacyBoundary(t *testing.T) {
	data, err := os.ReadFile("testdata/sing-box-hysteria2.json")
	if err != nil {
		t.Fatal(err)
	}
	got := parseSingBoxSummary("/etc/sing-box/config.json", data)
	if got.Err != nil || len(got.Inbounds) != 1 || len(got.Controls) != 1 || !got.UsesUDP {
		t.Fatalf("unexpected fixture summary: %+v", got)
	}
	serialized := fmt.Sprintf("%+v", got)
	for _, secret := range []string{"fixture-only-not-a-real-secret", "fixture-only-control-secret", "lab-hysteria2"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("fixture secret or tag leaked: %q", secret)
		}
	}
}

func TestSSHKeyFingerprintAndOptionsPrivacy(t *testing.T) {
	item, ok := parseSSHKeygenFingerprint("256 SHA256:abc123 real-person@example.com (ED25519)")
	if !ok || item.bits != 256 || item.fingerprint != "SHA256:abc123" || item.algorithm != "ED25519" {
		t.Fatalf("unexpected fingerprint parse: %+v ok=%t", item, ok)
	}
	if strings.Contains(fmt.Sprintf("%+v", item), "example.com") {
		t.Fatal("SSH key comment leaked into fingerprint model")
	}
	options := authorizedKeyOptionNames(`from="192.0.2.0/24",command="backup --token secret,still-secret",no-port-forwarding ssh-ed25519 AAAATEST private-email@example.com`)
	want := []string{"command", "from", "no-port-forwarding"}
	if fmt.Sprint(options) != fmt.Sprint(want) {
		t.Fatalf("options=%v, want %v", options, want)
	}
	joined := strings.Join(options, ",")
	for _, secret := range []string{"192.0.2.0", "backup", "secret", "still-secret", "private-email"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("authorized-key option value leaked: %q", secret)
		}
	}
	if authorizedKeyTextHasEntries("\n# cloud image placeholder\n") {
		t.Fatal("empty/comment-only authorized_keys was treated as a parse failure candidate")
	}
	if !authorizedKeyTextHasEntries("# comment\nssh-ed25519 AAAATEST\n") {
		t.Fatal("real authorized key entry was not detected")
	}
}

func TestAPTSourceEvidenceRemovesCredentialsAndPathTokens(t *testing.T) {
	input := `deb [signed-by=/etc/apt/keyrings/vendor.gpg] https://alice:password@example.com/private/token123 stable main`
	got := sanitizeAPTSourceLine(input)
	if !strings.Contains(got, "origin=https://example.com") || !strings.Contains(got, "signed-by=true") {
		t.Fatalf("missing safe repository context: %q", got)
	}
	for _, secret := range []string{"alice", "password", "private", "token123"} {
		if strings.Contains(got, secret) {
			t.Fatalf("repository secret leaked: %q in %q", secret, got)
		}
	}
}
