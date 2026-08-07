package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestReadSmallBoundsTheOpenedDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSmall(path, 4); err == nil {
		t.Fatal("expected limit error")
	}
	got, err := readSmall(path, 5)
	if err != nil || got != "12345" {
		t.Fatalf("readSmall = %q, %v", got, err)
	}
}

func TestReadSmallRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := readSmall(dir, 1024); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory read error=%v", err)
	}
}

func TestDiscoverExistingFilesIsSortedDeduplicatedAndFollowsDirectorySymlinks(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"b.json", "a.json"} {
		if err := os.WriteFile(filepath.Join(realDir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	paths, err := discoverExistingFiles(8,
		filepath.Join(root, "*", "*.json"),
		filepath.Join(link, "a.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(link, "a.json"),
		filepath.Join(link, "b.json"),
		filepath.Join(realDir, "a.json"),
		filepath.Join(realDir, "b.json"),
	}
	if fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("paths=%v, want %v", paths, want)
	}
}

func TestDiscoverExistingFilesRejectsMatchOverflow(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.conf", "b.conf", "c.conf"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := discoverExistingFilesWithBudget(2, 16, filepath.Join(root, "*.conf"))
	if !errors.Is(err, errFileDiscoveryLimit) {
		t.Fatalf("error=%v, want discovery limit", err)
	}
	if paths != nil {
		t.Fatalf("partial paths escaped on overflow: %v", paths)
	}
}

func TestDiscoverExistingFilesRejectsDirectoryEntryOverflow(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := discoverExistingFilesWithBudget(8, 2, filepath.Join(root, "*.json"))
	if !errors.Is(err, errFileDiscoveryLimit) {
		t.Fatalf("error=%v, want directory entry limit", err)
	}
	if paths != nil {
		t.Fatalf("partial paths escaped on overflow: %v", paths)
	}
}

func TestDiscoverExistingFilesIgnoresBrokenAliasInDirectorySegment(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "removed.service")
	if err := os.Symlink(filepath.Join(root, "does-not-exist"), broken); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	paths, err := discoverExistingFiles(8, filepath.Join(root, "*", "*.conf"))
	if err != nil {
		t.Fatalf("broken non-directory alias made discovery incomplete: %v", err)
	}
	if len(paths) != 0 {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func TestWithIncompleteEvidenceCannotRemainPass(t *testing.T) {
	f := withIncompleteEvidence(model.Finding{ID: "PKG-001", Category: "packages", Status: model.Pass}, "fixture", errFileDiscoveryLimit)
	if f.Status != model.Unknown || !f.Unavailable || f.NotApplicable || f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	risk := withIncompleteEvidence(model.Finding{ID: "PKG-001", Category: "packages", Status: model.Risk, Severity: model.High}, "fixture", errFileDiscoveryLimit)
	if risk.Status != model.Risk || risk.Unavailable || risk.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("proven risk was lost or made semantically invalid: %+v", risk)
	}
}

func TestPersistenceDiscoveryIgnoresMaskedAndBrokenUnitAliases(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "broken.service")
	masked := filepath.Join(root, "masked.service")
	if err := os.Symlink(filepath.Join(root, "missing"), broken); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(os.DevNull, masked); err != nil {
		t.Skipf("device symlink unavailable: %v", err)
	}
	for _, path := range []string{broken, masked} {
		_, readErr := readSmall(path, 1024)
		if readErr == nil {
			t.Fatalf("expected read failure for %s", path)
		}
		if persistenceReadFailureIncomplete(path, readErr, true) {
			t.Fatalf("disabled systemd alias became incomplete evidence: %s: %v", path, readErr)
		}
	}
}

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
	got, err := parseListeners(input)
	if err != nil {
		t.Fatal(err)
	}
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

func TestDockerProfileExpectedListenersRemainProcessScoped(t *testing.T) {
	ctx := &Context{Profile: model.Profile{Effective: "docker"}}
	for _, process := range []string{`users:(("docker-proxy"))`, `users:(("nginx"))`, `users:(("traefik"))`} {
		if !expectedListener(ctx, Listener{Protocol: "tcp", Port: "8443", Process: process}, "8443/tcp") {
			t.Errorf("Docker edge listener was rejected: %s", process)
		}
	}
	if expectedListener(ctx, Listener{Protocol: "tcp", Port: "8443", Process: `users:(("unknown-admin"))`}, "8443/tcp") {
		t.Fatal("Docker profile accepted an unrelated public process")
	}
}

func TestRuntimeExpectedWireGuardListener(t *testing.T) {
	cmd := newScenarioCommander([]string{"wg"}, map[string]CommandResult{
		scenarioCommandKey("wg", "show", "all", "listen-port"): {Stdout: "hiddifywg\t32247\n"},
	})
	ctx := &Context{Options: Options{Commander: cmd}}
	expected, err := runtimeExpectedPublicListeners(ctx)
	if err != nil || !expected["32247/udp"] {
		t.Fatal("active WireGuard listen port was not recognized")
	}
}

func TestSocketParsersRejectMalformedRows(t *testing.T) {
	if _, err := parseListeners("tcp LISTEN 0 128 malformed"); err == nil {
		t.Fatal("malformed listener endpoint was accepted")
	}
	if _, err := parseEstablishedConnections("tcp ESTAB 0 0 malformed also-malformed"); err == nil {
		t.Fatal("malformed established endpoint was accepted")
	}
}

func TestFirewallExposureReportsStaleAllowRule(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "22", Scope: "public-wildcard", Process: "sshd"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n22/tcp ALLOW IN Anywhere\n31001/tcp ALLOW IN Anywhere")
	})
	f := checkFirewallExposure(ctx)
	if f.Status != model.Risk || f.Severity != model.Medium || f.Facts["stale_allow_rules"] != "1" {
		t.Fatalf("stale firewall finding=%+v", f)
	}
}

func TestSensitivePermissionCheckSkipsManagerDirectory(t *testing.T) {
	dir := t.TempDir()
	config := filepath.Join(dir, "generated.json")
	if err := os.WriteFile(config, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := checkProxySensitivePermissionsWithDefaults([]proxyConfigSummary{{Path: dir, SensitiveFiles: []string{config}}}, nil)
	if f.Facts["files_checked"] != "1" {
		t.Fatalf("directory counted as secret-bearing file: %+v", f)
	}
	for _, evidence := range f.Evidence {
		if evidence.Value == dir || strings.Contains(evidence.Value, dir+" mode=") {
			t.Fatalf("manager directory was assessed as a secret file: %+v", evidence)
		}
	}
}

func TestDeletedExecutableClassification(t *testing.T) {
	count, severity := classifyDeletedExecutables([]string{
		"pid=1 exe=/usr/bin/python3.14 (deleted)",
		"pid=2 exe=/opt/hiddify-manager/singbox/hiddify-core (deleted)",
	})
	if count != 1 || severity != model.Medium {
		t.Fatalf("count=%d severity=%s", count, severity)
	}
	count, severity = classifyDeletedExecutables([]string{"pid=3 exe=/tmp/worker (deleted)"})
	if count != 1 || severity != model.High {
		t.Fatalf("temporary executable count=%d severity=%s", count, severity)
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
		ufw  hostFirewallSnapshot
		want string
	}{
		{"inactive", hostFirewallSnapshot{available: true}, "inactive"},
		{"allow anywhere", hostFirewallSnapshot{available: true, active: true, defaultDeny: true, lines: []string{"2053/tcp ALLOW IN Anywhere"}}, "allow-anywhere"},
		{"trusted source", hostFirewallSnapshot{available: true, active: true, defaultDeny: true, lines: []string{"2053/tcp ALLOW IN 10.8.0.0/24"}}, "restricted"},
		{"default blocked", hostFirewallSnapshot{available: true, active: true, defaultDeny: true}, "blocked-by-default"},
		{"unsupported firewall", hostFirewallSnapshot{}, "inactive"},
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
	users, err := parseShadowPasswordUsers("root:!:1:2:3\nalice:$y$hash:1:2:3\ndaemon:$6$hash:1:2:3\n", login)
	if err != nil {
		t.Fatal(err)
	}
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
	connections, err := parseEstablishedConnections(input)
	if err != nil {
		t.Fatal(err)
	}
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
	input := []byte(`{"api":{"tag":"internal-control"},"metrics":{"listen":"127.0.0.1:11111"},"inbounds":[{"tag":"internal-control","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door"},{"tag":"rapid-entry","port":"443","protocol":"vless"}]}`)
	got := parseXraySummary("/etc/xray/config.json", input)
	if got.Err != nil || len(got.Inbounds) != 1 || len(got.Controls) != 2 {
		t.Fatalf("unexpected summary: %+v", got)
	}
	if got.Controls[0].Listen != "127.0.0.1" || got.Controls[0].Port != "10085" {
		t.Fatalf("unexpected API endpoint: %+v", got.Controls[0])
	}
	if got.Controls[1].Kind != "metrics" || got.Controls[1].Port != "11111" {
		t.Fatalf("unexpected metrics endpoint: %+v", got.Controls[1])
	}
	if got.Inbounds[0].Port != "443" {
		t.Fatalf("ordinary inbound containing 'api' in its tag was excluded: %+v", got.Inbounds)
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

func TestXrayShadowsocksUsesProtocolNetwork(t *testing.T) {
	input := []byte(`{"inbounds":[{"listen":"::","port":31003,"protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-256-gcm","password":"withheld","network":"tcp,udp"},"streamSettings":{"network":"tcp","security":"none"}}]}`)
	got := parseXraySummary("/usr/local/x-ui/bin/config.json", input)
	if got.Err != nil || len(got.Inbounds) != 1 {
		t.Fatalf("unexpected Xray summary: %+v", got)
	}
	if fmt.Sprint(got.Inbounds[0].Transports) != "[tcp udp]" || !got.UsesUDP {
		t.Fatalf("Shadowsocks transport semantics lost: %+v", got.Inbounds[0])
	}
	if strings.Contains(fmt.Sprintf("%+v", got), "withheld") {
		t.Fatal("Shadowsocks password leaked into Xray summary")
	}
}

func TestPanelInboundMetadataParserKeepsOnlyPolicyFacts(t *testing.T) {
	rows := [][]string{{"1", "::", "443", "vless", "tcp", "reality", "2", "0", "0", "1", "1", "2"}, {"0", "127.0.0.1", "8443", "trojan", "tcp", "tls", "1", "1", "1", "0", "0", "0"}}
	got, err := parsePanelInboundRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Enabled || got[0].ClientCount != 2 || !got[1].Expired || !got[1].QuotaExhausted {
		t.Fatalf("unexpected panel inbound metadata: %+v", got)
	}
	serialized := fmt.Sprintf("%+v", got)
	for _, secretField := range []string{"uuid", "password", "email", "privateKey", "shortId"} {
		if strings.Contains(strings.ToLower(serialized), strings.ToLower(secretField)) {
			t.Fatalf("secret-bearing field retained in panel facts: %s", secretField)
		}
	}
}

func TestPanelInboundMetadataParserRejectsMalformedRows(t *testing.T) {
	tests := [][][]string{
		{{"1", "::", "not-a-port", "vless", "tcp", "reality", "2", "0", "0", "1", "1", "2"}},
		{{"1", "::", "443", "vless", "tcp", "reality", "not-a-count", "0", "0", "1", "1", "2"}},
		{{"yes", "::", "443", "vless", "tcp", "reality", "2", "0", "0", "1", "1", "2"}},
		{{"1", "::", "443"}},
	}
	for _, rows := range tests {
		if _, err := parsePanelInboundRows(rows); err == nil {
			t.Fatalf("accepted malformed rows: %#v", rows)
		}
	}
}

func TestAccountParsersRejectMalformedRecords(t *testing.T) {
	if _, err := parsePasswd(strings.NewReader("root:x:not-a-uid:0:root:/root:/bin/bash\n")); err == nil {
		t.Fatal("malformed passwd UID was accepted")
	}
	if _, err := parsePasswd(strings.NewReader("broken\n")); err == nil {
		t.Fatal("malformed passwd row was accepted")
	}
	if _, err := parseShadowPasswordUsers("broken\n", map[string]bool{"root": true}); err == nil {
		t.Fatal("malformed shadow row was accepted")
	}
}

func TestCPUUsagePercentRejectsInconsistentAndExtremeDeltas(t *testing.T) {
	if got, ok := cpuUsagePercent(cpuTicks{total: 100, idle: 40}, cpuTicks{total: 200, idle: 80}); !ok || got != 60 {
		t.Fatalf("percent=%d ok=%t", got, ok)
	}
	if _, ok := cpuUsagePercent(cpuTicks{total: 100, idle: 40}, cpuTicks{total: 110, idle: 80}); ok {
		t.Fatal("idle delta larger than total delta was accepted")
	}
	if got, ok := cpuUsagePercent(cpuTicks{}, cpuTicks{total: ^uint64(0), idle: 0}); !ok || got != 100 {
		t.Fatalf("extreme percent=%d ok=%t", got, ok)
	}
	if got, ok := ratioPercent(^uint64(0)/2, ^uint64(0)); !ok || got != 50 {
		t.Fatalf("large ratio percent=%d ok=%t", got, ok)
	}
	if _, ok := ratioPercent(2, 1); ok {
		t.Fatal("ratio above 100 percent was accepted")
	}
}

func TestPanelProxySummaryIncludesOnlyEnabledInbounds(t *testing.T) {
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true, Inbounds: []panelInboundFact{
		{Enabled: true, Listen: "::", Port: "443", Protocol: "vless", Network: "tcp", Security: "reality", RealityKeySet: true, RealityTargets: 1, RealityIDs: 2},
		{Enabled: false, Listen: "::", Port: "8443", Protocol: "trojan", Network: "tcp", Security: "tls"},
	}}
	got, ok := panelProxySummary(panel)
	if !ok || got.Product != "Xray" || len(got.Inbounds) != 1 || !got.Inbounds[0].RealityEnabled || !got.Inbounds[0].RealityKeySet {
		t.Fatalf("unexpected panel proxy summary: %+v ok=%t", got, ok)
	}
}

func TestEmbeddedSQLiteReaderIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE inbounds (protocol TEXT, port INTEGER); INSERT INTO inbounds VALUES ('vless',443);`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	rows, err := querySQLite(path, `SELECT protocol,port FROM inbounds;`)
	if err != nil || len(rows) != 1 || fmt.Sprint(rows[0]) != "[vless 443]" {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if _, err := querySQLite(path, `DELETE FROM inbounds;`); err == nil {
		t.Fatal("read-only SQLite connection accepted a mutation")
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
	ufw := hostFirewallSnapshot{available: true, active: true, defaultDeny: true, lines: []string{"443/tcp ALLOW IN Anywhere", "8443/udp ALLOW IN 10.0.0.0/8"}}
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

func TestParseNamedTextKnownDistinguishesEmptyFromMissing(t *testing.T) {
	if value, known := parseNamedTextKnown("Panel path:\n", "Panel path"); !known || value != "" {
		t.Fatalf("empty path value=%q known=%t", value, known)
	}
	if _, known := parseNamedTextKnown("Panel port: 2053\n", "Panel path"); known {
		t.Fatal("missing path was reported as known")
	}
}

func TestApplyPanelSettingsReadsPathsFromDatabase(t *testing.T) {
	snapshot := panelSnapshot{}
	applyPanelSettings(&snapshot, [][]string{{"webPort", "2095"}, {"webBasePath", ""}, {"subPort", "2096"}, {"subPath", "/secret-sub/"}}, "fixture")
	management, ok := managementEndpoint(snapshot)
	if !ok || !management.PathKnown || !management.PathIsDefault {
		t.Fatalf("management=%+v ok=%t", management, ok)
	}
	if len(snapshot.Endpoints) != 2 || !snapshot.Endpoints[1].PathKnown || snapshot.Endpoints[1].PathIsDefault {
		t.Fatalf("endpoints=%+v", snapshot.Endpoints)
	}
}

func TestApplySUIDefaultsTreatsMissingWebBasePathAsRoot(t *testing.T) {
	rows := [][]string{{"webPort", "2095"}, {"subPort", "2096"}, {"subPath", "/sub/"}}
	snapshot := panelSnapshot{}
	applyPanelSettings(&snapshot, rows, "S-UI database")
	applySUIDefaults(&snapshot, rows)

	management, ok := managementEndpoint(snapshot)
	if !ok || !management.PathKnown || !management.PathIsDefault || management.Source != "S-UI database + built-in default" {
		t.Fatalf("management=%+v ok=%t", management, ok)
	}

	rows = append(rows, []string{"webBasePath", "/private/"})
	snapshot = panelSnapshot{}
	applyPanelSettings(&snapshot, rows, "S-UI database")
	applySUIDefaults(&snapshot, rows)
	management, ok = managementEndpoint(snapshot)
	if !ok || !management.PathKnown || management.PathIsDefault || management.Source != "S-UI database" {
		t.Fatalf("persisted management path was overwritten: %+v ok=%t", management, ok)
	}
}

func TestApplyPanelSettingsMergesDefaultsAndHonorsSubscriptionDisable(t *testing.T) {
	snapshot := panelSnapshot{}
	apply3XUIDefaults(&snapshot)
	applyPanelSettings(&snapshot, [][]string{{"subPath", "/private-sub/"}, {"subListen", "127.0.0.1"}}, "fixture")
	endpoint, ok := panelEndpointByRole(snapshot, "subscription")
	if !ok || endpoint.Port != "2096" || endpoint.Listen != "127.0.0.1" || !endpoint.PathKnown || endpoint.PathIsDefault || endpoint.Source != "fixture" {
		t.Fatalf("merged endpoint=%+v ok=%t", endpoint, ok)
	}
	applyPanelSettings(&snapshot, [][]string{{"subEnable", "false"}}, "fixture")
	if _, ok := panelEndpointByRole(snapshot, "subscription"); ok {
		t.Fatalf("disabled subscription endpoint was retained: %+v", snapshot.Endpoints)
	}
}

func TestProxyConnectionCountsOnlyConfiguredIngressWithoutPeers(t *testing.T) {
	input := "tcp ESTAB 0 0 10.0.0.1:443 198.51.100.1:50000 users:((\"sing-box\",pid=1))\n" +
		"tcp ESTAB 0 0 10.0.0.1:22 198.51.100.2:50001 users:((\"sshd\",pid=2))\n"
	connections, err := parseEstablishedConnections(input)
	if err != nil {
		t.Fatal(err)
	}
	counts, total := proxyConnectionCounts(connections, map[string]bool{"443": true})
	if total != 1 || counts["443"] != 1 || counts["22"] != 0 {
		t.Fatalf("counts=%v total=%d", counts, total)
	}
}

func TestSudoNOPASSWDEvidenceWithholdsCommandArguments(t *testing.T) {
	value := sudoNOPASSWDEvidence(`deploy ALL=(root) NOPASSWD: /usr/local/bin/backup --token super-secret`)
	if !strings.Contains(value, "subject=deploy") || !strings.Contains(value, "runas=root") || !strings.Contains(value, "command_details=withheld") {
		t.Fatalf("unexpected sudo evidence: %q", value)
	}
	for _, secret := range []string{"super-secret", "backup", "--token"} {
		if strings.Contains(value, secret) {
			t.Fatalf("sudo evidence leaked %q: %q", secret, value)
		}
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
