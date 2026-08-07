package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// scenarioCommander is a deterministic command fixture for policy tests. A
// command that was not declared in the scenario is considered unavailable so
// tests never accidentally depend on the developer workstation.
type scenarioCommander struct {
	mu      sync.Mutex
	exists  map[string]bool
	results map[string]CommandResult
	calls   map[string]int
}

func newScenarioCommander(exists []string, results map[string]CommandResult) *scenarioCommander {
	c := &scenarioCommander{exists: map[string]bool{}, results: results, calls: map[string]int{}}
	for _, name := range exists {
		c.exists[name] = true
	}
	return c
}

func (c *scenarioCommander) Exists(name string) bool { return c.exists[name] }

func (c *scenarioCommander) Run(_ time.Duration, name string, args ...string) CommandResult {
	key := scenarioCommandKey(name, args...)
	c.mu.Lock()
	c.calls[key]++
	c.mu.Unlock()
	if result, ok := c.results[key]; ok {
		return result
	}
	return CommandResult{Err: fmt.Errorf("undeclared scenario command: %s", key), Code: -1}
}

func scenarioCommandKey(name string, args ...string) string {
	key := name
	for _, arg := range args {
		key += "\x00" + arg
	}
	return key
}

func scenarioResult(name string, args []string, stdout string) map[string]CommandResult {
	return map[string]CommandResult{scenarioCommandKey(name, args...): {Stdout: stdout}}
}

func scenarioContext(cmd Commander) *Context {
	return &Context{
		Options: Options{Locale: "en", Profile: "proxy", LogSince: 24 * time.Hour, Commander: cmd, Now: func() time.Time { return time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC) }},
		Host:    model.Host{OS: "ubuntu", OSVersion: "24.04", IsRoot: true},
		Profile: model.Profile{Requested: "proxy", Detected: "proxy", Effective: "proxy"},
		Facts:   NewFactStore(cmd, false),
	}
}

func findingByID(t *testing.T, findings []model.Finding, id string) model.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.ID == id {
			return finding
		}
	}
	t.Fatalf("finding %s not returned", id)
	return model.Finding{}
}

func requireStatus(t *testing.T, findings []model.Finding, id string, want model.Status) {
	t.Helper()
	if got := findingByID(t, findings, id).Status; got != want {
		t.Fatalf("%s status=%s, want %s", id, got, want)
	}
}

func TestScenarioEffectiveSSHAndPasswordContext(t *testing.T) {
	args := []string{"-T"}
	cmd := newScenarioCommander([]string{"sshd"}, scenarioResult("sshd", args, "passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\npubkeyauthentication yes"))
	ctx := scenarioContext(cmd)
	findings := checkSSH(ctx)
	requireStatus(t, findings, "SSH-001", model.Pass)
	requireStatus(t, findings, "SSH-002", model.Info)
	requireStatus(t, findings, "SSH-003", model.Pass)
	if got := cmd.calls[scenarioCommandKey("sshd", "-T")]; got != 1 {
		t.Fatalf("sshd -T calls=%d, want one", got)
	}
}

func TestScenarioFirewallUpdatesAndAuthentication(t *testing.T) {
	ufwVerbose := "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n22/tcp ALLOW IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)"
	results := map[string]CommandResult{
		scenarioCommandKey("ufw", "status", "verbose"):                                {Stdout: ufwVerbose},
		scenarioCommandKey("ufw", "status"):                                           {Stdout: "Status: active"},
		scenarioCommandKey("ss", "-H", "-lntu"):                                       {Stdout: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"},
		scenarioCommandKey("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"): {Stdout: "Inst openssl [1.0] (1.1 Ubuntu:24.04/noble-security [amd64])"},
		scenarioCommandKey("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"): {Stdout: "install ok installed"},
		scenarioCommandKey("systemctl", "is-enabled", "apt-daily-upgrade.timer"):      {Stdout: "enabled"},
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"): {Stdout: "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2\nInvalid user admin from 203.0.113.7"},
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "_COMM=sudo"):                                                                  {Stdout: "sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/id"},
	}
	cmd := newScenarioCommander([]string{"ufw", "ss", "apt-get", "dpkg-query", "systemctl", "journalctl"}, results)
	ctx := scenarioContext(cmd)
	requireStatus(t, checkFirewall(ctx), "FW-001", model.Pass)
	requireStatus(t, checkFirewall(ctx), "FW-002", model.Pass)
	requireStatus(t, checkUpdates(ctx), "UPD-001", model.Risk)
	requireStatus(t, checkUpdates(ctx), "UPD-002", model.Pass)
	auth := checkAuth(ctx)
	requireStatus(t, auth, "AUTH-001", model.Info)
	requireStatus(t, auth, "AUTH-002", model.Pass)
	if got := findingByID(t, auth, "AUTH-001").Facts["unique_sources"]; got != "1" {
		t.Fatalf("unique_sources=%q, want 1", got)
	}
	if got := cmd.calls[scenarioCommandKey("ufw", "status", "verbose")]; got != 1 {
		t.Fatalf("ufw snapshot calls=%d, want one shared firewall snapshot", got)
	}
}

func TestScenarioPanelAndDockerRiskRelations(t *testing.T) {
	cmd := newScenarioCommander([]string{"ss", "ufw", "docker"}, map[string]CommandResult{})
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "2053", Scope: "public-wildcard", Process: "x-ui"}, {Protocol: "tcp", Address: "0.0.0.0", Port: "31001", Scope: "public-wildcard", Process: "xray"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n2053/tcp ALLOW IN Anywhere\n31001/tcp ALLOW IN Anywhere")
	})
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true, Endpoints: []panelEndpoint{{Role: "management", Listen: "::", Port: "2053", Source: "fixture", TLSKnown: true, TLS: true}}, Inbounds: []panelInboundFact{{Enabled: true, Listen: "::", Port: "31001", Protocol: "vless", Network: "tcp", Security: "reality", RealityKeySet: true, RealityTargets: 1, RealityIDs: 1}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	container := dockerInspect{Name: "risky"}
	container.HostConfig.Privileged = true
	container.HostConfig.NetworkMode = "host"
	ctx.Facts.dockerOnce.Do(func() { ctx.Facts.docker = []dockerInspect{container} })

	requireStatus(t, []model.Finding{checkPanelManagement(ctx)}, "WORK-002", model.Risk)
	summary, ok := panelProxySummary(panel)
	if !ok {
		t.Fatal("panel proxy summary missing")
	}
	requireStatus(t, []model.Finding{checkProxyEndpointRelations(ctx, []proxyConfigSummary{summary})}, "WORK-009", model.Pass)
	requireStatus(t, []model.Finding{checkPanelRuntimeConsistency(ctx, []proxyConfigSummary{summary})}, "WORK-012", model.Pass)
	requireStatus(t, checkDocker(ctx), "DOCKER-001", model.Risk)
}

func TestScenarioPublicPanelAllowedThroughCustomIPTablesChainIsRisk(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "2095", Scope: "public-wildcard", Process: "x-ui"}}
	})
	rules, policy, unresolved := parseIPTablesFirewallDetailed(`*filter
:INPUT DROP [0:0]
:PANEL-IN - [0:0]
-A INPUT -j PANEL-IN
-A PANEL-IN -p tcp --dport 2095 -j ACCEPT
COMMIT`, "ipv4")
	if unresolved != 0 {
		t.Fatalf("iptables fixture unresolved=%d", unresolved)
	}
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = hostFirewallSnapshot{available: true, active: true, backend: "iptables", defaultPolicyByFamily: map[string]string{"ipv4": policy}, rules: rules}
	})
	panel := panelSnapshot{Product: "3x-ui", DatabaseAvailable: true, Endpoints: []panelEndpoint{{Role: "management", Port: "2095", Listen: "0.0.0.0", Source: "fixture", TLSKnown: true, TLS: true, PathKnown: true}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelManagement(ctx)
	if f.Status != model.Risk || f.Severity != model.High {
		t.Fatalf("custom-chain panel exposure status=%s severity=%s evidence=%+v", f.Status, f.Severity, f.Evidence)
	}
}

func TestScenarioConnectionSnapshotIsSharedAcrossNetworkAndProxyFindings(t *testing.T) {
	key := scenarioCommandKey("ss", "-H", "-ntup", "state", "established")
	cmd := newScenarioCommander([]string{"ss", "ps"}, map[string]CommandResult{
		key: {Stdout: `tcp ESTAB 0 0 10.0.0.1:443 8.8.8.8:50000 users:(("sing-box",pid=1,fd=3))`},
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "1 root sing-box /usr/bin/sing-box run"},
	})
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "sing-box"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n443/tcp ALLOW IN Anywhere")
	})
	summary := proxyConfigSummary{Product: "sing-box", Path: "/etc/sing-box/config.json", Inbounds: []proxyInbound{{Product: "sing-box", Protocol: "vless", Port: "443", Transports: []string{"tcp"}}}}

	if got := checkActiveConnections(ctx).Facts["peer_public"]; got != "1" {
		t.Fatalf("public connection count=%q, want 1", got)
	}
	finding := checkProxyEndpointRelations(ctx, []proxyConfigSummary{summary})
	if got := finding.Facts["established_proxy_tcp_connections"]; got != "1" {
		t.Fatalf("proxy connection count=%q, want 1", got)
	}
	if got := cmd.calls[key]; got != 1 {
		t.Fatalf("established snapshot calls=%d, want exactly one", got)
	}
}

func TestScenarioIncompleteEvidenceNeverBecomesPass(t *testing.T) {
	truncated := CommandResult{Stdout: "partial", Truncated: true, Err: errCommandOutputTruncated}
	cmd := newScenarioCommander([]string{"journalctl", "ufw", "ss"}, map[string]CommandResult{
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"): truncated,
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "_COMM=sudo"):                                                                  truncated,
		scenarioCommandKey("ufw", "status", "verbose"): truncated,
		scenarioCommandKey("ss", "-H", "-lntup"):       truncated,
	})
	ctx := scenarioContext(cmd)
	if got := findingByID(t, checkAuth(ctx), "AUTH-001").Status; got == model.Pass {
		t.Fatalf("partial SSH journal became PASS")
	}
	requireStatus(t, checkAuth(ctx), "AUTH-002", model.Unknown)
	requireStatus(t, checkFirewall(ctx), "FW-001", model.Unknown)

	summary := proxyConfigSummary{Product: "sing-box", Path: "/etc/sing-box/config.json", Inbounds: []proxyInbound{{Product: "sing-box", Protocol: "vless", Port: "443", Transports: []string{"tcp"}}}}
	requireStatus(t, []model.Finding{checkProxyEndpointRelations(ctx, []proxyConfigSummary{summary})}, "WORK-009", model.Unknown)
}

func TestScenarioPartialAuthenticationAndUpdateEvidenceIsUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"): {Stdout: "Failed password for root", Err: fmt.Errorf("journal interrupted")},
		scenarioCommandKey("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"):                                                                                {Stdout: "Inst openssl [1.0] (1.1)", Err: fmt.Errorf("apt lists unavailable")},
		scenarioCommandKey("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"):                                                                                {Err: fmt.Errorf("dpkg database unavailable")},
		scenarioCommandKey("systemctl", "is-enabled", "apt-daily-upgrade.timer"):                                                                                     {Stdout: "enabled"},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"journalctl", "apt-get", "dpkg-query", "systemctl"}, results))
	if got := findingByID(t, checkAuth(ctx), "AUTH-001").Status; got == model.Pass {
		t.Fatalf("partial SSH journal became PASS")
	}
	requireStatus(t, checkUpdates(ctx), "UPD-001", model.Unknown)
	requireStatus(t, checkUpdates(ctx), "UPD-002", model.Unknown)
}

func TestScenarioIntrusionPreventionCommandFailureIsUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "is-active", "fail2ban"): {
			Err: fmt.Errorf("systemd unavailable"), Code: 1,
		},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"fail2ban-client", "systemctl"}, results))
	f := checkIntrusionPrevention(ctx)
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("failed intrusion-prevention discovery became %s: %+v", f.Status, f)
	}
}

func TestScenarioKnownInactiveIntrusionPreventionIsRisk(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "is-active", "fail2ban"): {
			Stdout: "inactive", Err: fmt.Errorf("exit status 3"), Code: 3,
		},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"fail2ban-client", "systemctl"}, results))
	f := checkIntrusionPrevention(ctx)
	if f.Status != model.Risk || f.Severity != model.Medium || f.Unavailable {
		t.Fatalf("known inactive intrusion prevention became %s: %+v", f.Status, f)
	}
}

func TestPackageOwnershipSeparatesAbsentFromUnavailable(t *testing.T) {
	tests := []struct {
		name    string
		result  CommandResult
		owned   bool
		wantErr bool
	}{
		{name: "owned", result: CommandResult{Stdout: "package: /opt/tool"}, owned: true},
		{name: "unowned", result: CommandResult{Stderr: "dpkg-query: no path found matching pattern /opt/tool", Err: fmt.Errorf("exit status 1"), Code: 1}},
		{name: "unavailable", result: CommandResult{Stderr: "dpkg database unavailable", Err: fmt.Errorf("exit status 2"), Code: 2}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := newScenarioCommander([]string{"dpkg-query"}, map[string]CommandResult{
				scenarioCommandKey("dpkg-query", "-S", "/opt/tool"): test.result,
			})
			owned, err := packageOwns(cmd, "/opt/tool")
			if owned != test.owned || (err != nil) != test.wantErr {
				t.Fatalf("owned=%t err=%v, want owned=%t error=%t", owned, err, test.owned, test.wantErr)
			}
		})
	}
}

func TestScenarioPartialProcessAndPrivilegeEvidenceIsUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "--failed", "--no-legend", "--plain"):                         {Stdout: "bad.service loaded failed failed", Err: fmt.Errorf("systemd disconnected")},
		scenarioCommandKey("find", "/usr", "/opt", "-xdev", "-type", "f", "-perm", "/6000", "-print"): {Stdout: "/usr/bin/passwd", Err: fmt.Errorf("find interrupted")},
		scenarioCommandKey("getcap", "-r", "/usr", "/opt"):                                            {Stdout: "/usr/bin/ping cap_net_raw=ep", Err: fmt.Errorf("getcap interrupted")},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"systemctl", "find", "getcap"}, results))
	ctx.Deep = true
	requireStatus(t, checkProcesses(ctx), "PROC-001", model.Unknown)
	requireStatus(t, checkPrivileges(ctx), "PRIV-002", model.Unknown)
}

func TestCollectSSHFailureJournalSlicesBusyLookback(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander([]string{"journalctl"}, nil))
	ctx.LogSince = 7 * 24 * time.Hour
	windows := sshFailureJournalWindows(ctx.Now(), ctx.LogSince)
	if len(windows) != 4 {
		t.Fatalf("windows=%d, want 4", len(windows))
	}
	results := map[string]CommandResult{}
	for index, window := range windows {
		args := []string{"--since", journalTimestamp(window.since), "--until", journalTimestamp(window.until), "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"}
		results[scenarioCommandKey("journalctl", args...)] = CommandResult{Stdout: fmt.Sprintf("Failed password for root from 203.0.113.%d", index+1)}
	}
	ctx.Commander = newScenarioCommander([]string{"journalctl"}, results)
	activity, slices, err := collectSSHFailureJournal(ctx)
	if err != nil || slices != len(windows) || activity.failedPassword != len(windows) || len(activity.ips) != len(windows) {
		t.Fatalf("activity=%+v slices=%d err=%v", activity, slices, err)
	}
}

func TestCollectSSHFailureJournalRejectsIncompleteSlice(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander([]string{"journalctl"}, nil))
	ctx.LogSince = 7 * 24 * time.Hour
	window := sshFailureJournalWindows(ctx.Now(), ctx.LogSince)[0]
	args := []string{"--since", journalTimestamp(window.since), "--until", journalTimestamp(window.until), "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"}
	ctx.Commander = newScenarioCommander([]string{"journalctl"}, map[string]CommandResult{scenarioCommandKey("journalctl", args...): {Stdout: "Failed password for root", Err: fmt.Errorf("journal interrupted")}})
	_, _, err := collectSSHFailureJournal(ctx)
	if err == nil || !strings.Contains(err.Error(), "slice 1/4") {
		t.Fatalf("incomplete journal slice was accepted: %v", err)
	}
}

func TestCollectSSHFailureJournalAcceptsNoMatchExit(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander([]string{"journalctl"}, map[string]CommandResult{
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"): {Err: fmt.Errorf("exit status 1"), Code: 1},
	}))
	activity, slices, err := collectSSHFailureJournal(ctx)
	if err != nil || slices != 1 || activity.failedPassword != 0 {
		t.Fatalf("no-match journal result=%+v slices=%d err=%v", activity, slices, err)
	}
}

func TestCollectSSHFailureJournalRejectsPartialShortLookback(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander([]string{"journalctl"}, map[string]CommandResult{
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "--grep", sshFailureJournalPattern, "-u", "ssh.service", "-u", "sshd.service"): {Stdout: "Failed password for root", Err: fmt.Errorf("journal interrupted")},
	}))
	_, _, err := collectSSHFailureJournal(ctx)
	if err == nil {
		t.Fatal("partial short journal lookback was accepted")
	}
}

func TestScenarioUnreadableFirewallIsUnknownForBothFirewallFindings(t *testing.T) {
	cmd := newScenarioCommander([]string{"ufw"}, map[string]CommandResult{
		scenarioCommandKey("ufw", "status", "verbose"): {Err: fmt.Errorf("permission denied"), Code: 1},
	})
	ctx := scenarioContext(cmd)
	findings := checkFirewall(ctx)
	requireStatus(t, findings, "FW-001", model.Unknown)
	requireStatus(t, findings, "FW-002", model.Unknown)
	if got := cmd.calls[scenarioCommandKey("ufw", "status", "verbose")]; got != 1 {
		t.Fatalf("ufw snapshot calls=%d, want one", got)
	}
}

func TestFirewallMissingIPv6ConfigurationCannotBecomePass(t *testing.T) {
	f := evaluateFirewallExposure(firewallAuditSnapshot{
		Host: hostFirewallSnapshot{
			available: true, active: true, defaultDeny: true, backend: "ufw",
			defaultDenyByFamily: map[string]bool{"ipv4": true},
		},
		Listeners:        []Listener{{Protocol: "tcp6", Address: "::", Port: "443", Scope: "public-wildcard", Process: "sing-box"}},
		UFWIPv6ConfigErr: fmt.Errorf("permission denied"),
	})
	if f.Status != model.Unknown || !f.Unavailable {
		t.Fatalf("missing UFW IPv6 evidence became %s unavailable=%t: %+v", f.Status, f.Unavailable, f)
	}
	if f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("missing UFW IPv6 evidence was not recorded: %+v", f.Facts)
	}
}

func TestScenarioIncompleteFirewallFactsPropagateToWorkloadFindings(t *testing.T) {
	cmd := newScenarioCommander([]string{"wg"}, map[string]CommandResult{
		scenarioCommandKey("wg", "show", "interfaces"):               {Stdout: "wg0"},
		scenarioCommandKey("wg", "show", "wg0", "listen-port"):       {Stdout: "51820"},
		scenarioCommandKey("wg", "show", "wg0", "peers"):             {},
		scenarioCommandKey("wg", "show", "wg0", "latest-handshakes"): {},
	})
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{
			{Protocol: "tcp", Address: "127.0.0.1", Port: "2053", Scope: "loopback", Process: "x-ui"},
			{Protocol: "tcp", Address: "0.0.0.0", Port: "443", Scope: "public-wildcard", Process: "sing-box"},
			{Protocol: "tcp", Address: "0.0.0.0", Port: "9090", Scope: "public-wildcard", Process: "sing-box"},
			{Protocol: "udp", Address: "0.0.0.0", Port: "51820", Scope: "public-wildcard", Process: "wireguard"},
		}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		f := parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n443/tcp ALLOW IN Anywhere\n9090/tcp ALLOW IN Anywhere\n51820/udp ALLOW IN Anywhere")
		f.collectionErr = fmt.Errorf("nft list ruleset: permission denied")
		ctx.Facts.hostFirewall = f
	})
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true, Endpoints: []panelEndpoint{{Role: "management", Listen: "127.0.0.1", Port: "2053", Source: "fixture"}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	summary := proxyConfigSummary{Product: "sing-box", Path: "fixture", Inbounds: []proxyInbound{{Product: "sing-box", Protocol: "vless", Port: "443", Transports: []string{"tcp"}}}, Controls: []controlEndpoint{{Product: "sing-box", Kind: "clash-api", Listen: "0.0.0.0", Port: "9090"}}}

	requireStatus(t, []model.Finding{checkPanelManagement(ctx)}, "WORK-002", model.Unknown)
	control := checkProxyControlEndpoints(ctx, []proxyConfigSummary{summary})
	if control.Status != model.Risk || control.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("control finding=%#v, want proven RISK with incomplete evidence", control)
	}
	requireStatus(t, []model.Finding{checkProxyEndpointRelations(ctx, []proxyConfigSummary{summary})}, "WORK-009", model.Unknown)
	requireStatus(t, []model.Finding{checkPanelRuntimeConsistency(ctx, []proxyConfigSummary{summary})}, "WORK-012", model.Unknown)
	requireStatus(t, []model.Finding{checkWireGuardRuntime(ctx)}, "WORK-011", model.Unknown)
}

func TestScenarioUnknownPanelSchemaIsUnknown(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() {})
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", SchemaFingerprint: "0123456789abcdef", DatabaseError: "unsupported 3x-ui database schema"}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelRuntimeConsistency(ctx, nil)
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["unsupported_panel_schemas"] != "1" {
		t.Fatalf("status=%s unavailable=%t facts=%v", f.Status, f.Unavailable, f.Facts)
	}
}

func TestScenarioUnknownPanelSchemaDoesNotPassManagementCheck(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: "2053", Scope: "loopback", Process: "x-ui"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)")
	})
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", SchemaFingerprint: "0123456789abcdef", Endpoints: []panelEndpoint{{Role: "management", Listen: "127.0.0.1", Port: "2053", Source: "fixture"}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelManagement(ctx)
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["unsupported_panel_schemas"] != "1" || reasonCode(f) != "work.002.unsupported-panel-schema" {
		t.Fatalf("management finding=%#v", f)
	}
}

func TestScenarioPublicControlAPIAndPanelRuntimeMismatch(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "9090", Scope: "public-wildcard", Process: "sing-box"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n9090/tcp ALLOW IN Anywhere")
	})
	summary := proxyConfigSummary{Product: "sing-box", Path: "/etc/sing-box/config.json", Controls: []controlEndpoint{{Product: "sing-box", Kind: "clash-api", Listen: "0.0.0.0", Port: "9090"}}}
	requireStatus(t, []model.Finding{checkProxyControlEndpoints(ctx, []proxyConfigSummary{summary})}, "WORK-005", model.Risk)

	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true, Inbounds: []panelInboundFact{{Enabled: true, Port: "31001", Protocol: "vless", Network: "tcp", Security: "reality"}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	requireStatus(t, []model.Finding{checkPanelRuntimeConsistency(ctx, nil)}, "WORK-012", model.Risk)
}

func TestScenarioPublicPanelPostureIncludesDefaultPathAndPlaintext(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "56709", Scope: "public-wildcard", Process: "sui"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n56709/tcp ALLOW IN Anywhere")
	})
	panel := panelSnapshot{Product: "S-UI", DatabaseAvailable: true, Endpoints: []panelEndpoint{{Role: "management", Port: "56709", Listen: "::", Source: "fixture", TLSKnown: true, TLS: false, PathKnown: true, PathIsDefault: true}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelManagement(ctx)
	if f.Status != model.Risk || f.Severity != model.High {
		t.Fatalf("status=%s severity=%s", f.Status, f.Severity)
	}
	for key, want := range map[string]string{"public_unrestricted_management": "1", "public_plaintext_management": "1", "public_default_path_management": "1"} {
		if got := f.Facts[key]; got != want {
			t.Errorf("%s=%q, want %q", key, got, want)
		}
	}
	if !evidenceHas(f, "management_posture", "public-management-exposed+root-or-default-path+plaintext-panel") {
		t.Fatalf("management posture evidence missing: %+v", f.Evidence)
	}
}

func TestScenarioPublicUnclassifiedPanelListenerIsRisk(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "39999", Scope: "public-wildcard", Process: "xray"}}
	})
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelRuntimeConsistency(ctx, nil)
	if f.Status != model.Risk || f.Severity != model.Medium {
		t.Fatalf("status=%s severity=%s", f.Status, f.Severity)
	}
	if f.Facts["public_unclassified_panel_listeners"] != "1" {
		t.Fatalf("facts=%v", f.Facts)
	}
}

func TestScenarioPublicPlaintextSubscriptionIsHighRisk(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "2096", Scope: "public-wildcard", Process: "x-ui"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n2096/tcp ALLOW IN Anywhere")
	})
	panel := panelSnapshot{
		Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true,
		Endpoints: []panelEndpoint{{Role: "subscription", Port: "2096", Listen: "::", Source: "fixture", TLSKnown: true, TLS: false}},
	}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelRuntimeConsistency(ctx, nil)
	if f.Status != model.Risk || f.Severity != model.High || f.Facts["public_plaintext_subscription_listeners"] != "1" {
		t.Fatalf("status=%s severity=%s facts=%v evidence=%v", f.Status, f.Severity, f.Facts, f.Evidence)
	}
	if !evidenceHas(f, "plaintext_public_subscription", "bearer-like subscription URLs") {
		t.Fatalf("plaintext subscription evidence missing: %+v", f.Evidence)
	}
}

func TestScenarioXUIInternalXrayListenersAreInferredControls(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: "62789", Scope: "loopback", Process: "xray-linux-amd64"}}
	})
	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelRuntimeConsistency(ctx, nil)
	if f.Status != model.Pass || f.Facts["inferred_control_listeners"] != "1" || f.Facts["unclassified_panel_listeners"] != "0" {
		t.Fatalf("status=%s facts=%v evidence=%v", f.Status, f.Facts, f.Evidence)
	}
}

func TestScenarioPanelRoleCollisionWithProxyIngressIsHighRisk(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "2095", Scope: "public-wildcard", Process: "sui"}}
	})
	panel := panelSnapshot{
		Product: "S-UI", Database: "/usr/local/s-ui/db/s-ui.db", DatabaseAvailable: true,
		Endpoints: []panelEndpoint{{Role: "management", Port: "2095", Listen: "::"}},
		Inbounds:  []panelInboundFact{{Enabled: true, Port: "2095", Protocol: "vless", Network: "tcp"}},
	}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	f := checkPanelRuntimeConsistency(ctx, nil)
	if f.Status != model.Risk || f.Severity != model.High || f.Facts["role_collisions"] != "1" {
		t.Fatalf("status=%s severity=%s facts=%v evidence=%v", f.Status, f.Severity, f.Facts, f.Evidence)
	}
}

func TestScenarioProxyAbuseSignalsAreCountedWithoutRawLogs(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"):  {Stdout: "s-ui.service loaded active running S-UI"},
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "-u", "s-ui.service"): {Stdout: "panel login failed: wrong password\nAPI request unauthorized 401\n/sub/ invalid token 403\nGET /.git/config malformed request"},
	}
	cmd := newScenarioCommander([]string{"systemctl", "journalctl"}, results)
	f := checkProxyLogSignals(scenarioContext(cmd))
	if f.Status != model.Info || f.Facts["suspicious_activity_signals"] == "0" {
		t.Fatalf("status=%s facts=%v", f.Status, f.Facts)
	}
	for _, evidence := range f.Evidence {
		if strings.Contains(evidence.Value, "password") || strings.Contains(evidence.Value, "/.git/") {
			t.Fatalf("raw log leaked: %+v", evidence)
		}
	}
}

func TestScenarioIncompleteProxyLogsAreUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"):  {Stdout: "s-ui.service loaded active running S-UI"},
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "-u", "s-ui.service"): {Stdout: "panel login failed", Err: fmt.Errorf("access denied")},
	}
	f := checkProxyLogSignals(scenarioContext(newScenarioCommander([]string{"systemctl", "journalctl"}, results)))
	if f.Status != model.Unknown || !f.Unavailable {
		t.Fatalf("finding=%+v", f)
	}
}

func TestScenarioProxyServiceDiscoveryFailureIsUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain"): {
			Stdout: "s-ui.service loaded active running S-UI", Err: fmt.Errorf("systemd inventory interrupted"),
		},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"systemctl", "journalctl"}, results))
	for _, finding := range []model.Finding{checkProxyServiceIsolation(ctx), checkProxyLogSignals(ctx)} {
		if finding.Status != model.Unknown || !finding.Unavailable {
			t.Fatalf("partial systemd service inventory became %s: %+v", finding.Status, finding)
		}
	}
}

func TestScenarioWireGuardPartialRuntimeIsUnknown(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("wg", "show", "interfaces"):               {Stdout: "wg0"},
		scenarioCommandKey("wg", "show", "wg0", "listen-port"):       {Stdout: "51820"},
		scenarioCommandKey("wg", "show", "wg0", "peers"):             {Stdout: "withheld-public-key", Err: fmt.Errorf("peer inventory interrupted")},
		scenarioCommandKey("wg", "show", "wg0", "latest-handshakes"): {Stdout: "withheld-public-key 1783900800"},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"wg"}, results))
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "udp", Address: "0.0.0.0", Port: "51820", Scope: "public-wildcard", Process: "wireguard"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = hostFirewallSnapshot{available: true, active: true, defaultDeny: true, defaultDenyByFamily: map[string]bool{"ipv4": true}, backend: "fixture"}
	})
	f := checkWireGuardRuntime(ctx)
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("partial WireGuard runtime became %s: %+v", f.Status, f)
	}
	for _, evidence := range f.Evidence {
		if strings.Contains(evidence.Value, "withheld-public-key") {
			t.Fatalf("WireGuard public key leaked into evidence: %+v", evidence)
		}
	}
}

func TestScenarioWireGuardListenerInventoryFailureDoesNotBecomeRisk(t *testing.T) {
	cmd := newScenarioCommander([]string{"wg"}, map[string]CommandResult{
		scenarioCommandKey("wg", "show", "all", "listen-port"): {Err: fmt.Errorf("wireguard unavailable")},
	})
	ctx := scenarioContext(cmd)
	ctx.Profile.Requested = "proxy"
	f := checkUnexpectedListeners(ctx, []Listener{{Protocol: "udp", Address: "::", Port: "51820", Scope: "public-wildcard"}})
	if f.Status != model.Unknown || !f.Unavailable {
		t.Fatalf("status=%s unavailable=%t facts=%v", f.Status, f.Unavailable, f.Facts)
	}
}

func TestScenarioWireGuardInventoryFailurePreservesIndependentTCPRisk(t *testing.T) {
	cmd := newScenarioCommander([]string{"wg"}, map[string]CommandResult{
		scenarioCommandKey("wg", "show", "all", "listen-port"): {Err: fmt.Errorf("wireguard unavailable")},
	})
	ctx := scenarioContext(cmd)
	ctx.Profile.Requested = "proxy"
	f := checkUnexpectedListeners(ctx, []Listener{
		{Protocol: "udp", Address: "::", Port: "51820", Scope: "public-wildcard"},
		{Protocol: "tcp", Address: "0.0.0.0", Port: "65000", Scope: "public-wildcard", Process: "unknown-service"},
	})
	if f.Status != model.Risk || f.Severity != model.Medium || f.Unavailable {
		t.Fatalf("status=%s severity=%s unavailable=%t facts=%v", f.Status, f.Severity, f.Unavailable, f.Facts)
	}
	if f.Facts["unexpected_public_listeners"] != "1" || f.Facts["unclassified_public_udp_listeners"] != "1" || f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("facts=%v", f.Facts)
	}
}

func TestScenarioAutomaticProfileFailureInvalidatesPolicyPass(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Profile.Requested = "auto"
	ctx.ProfileDiscoveryError = fmt.Errorf("process inventory unavailable")
	f := checkUnexpectedListeners(ctx, nil)
	if f.Status != model.Unknown || !f.Unavailable {
		t.Fatalf("status=%s unavailable=%t", f.Status, f.Unavailable)
	}
	workload := checkWorkloads(ctx)[0]
	if workload.Status != model.Unknown || !workload.Unavailable {
		t.Fatalf("workload status=%s unavailable=%t", workload.Status, workload.Unavailable)
	}
}

func TestScenarioNetworkCollectionFailureKeepsIndependentFindings(t *testing.T) {
	cmd := newScenarioCommander([]string{"ss"}, map[string]CommandResult{
		scenarioCommandKey("ss", "-H", "-lntup"):                        {Err: fmt.Errorf("listener denied")},
		scenarioCommandKey("ss", "-H", "-lntu"):                         {Err: fmt.Errorf("listener denied")},
		scenarioCommandKey("ss", "-H", "-ntup", "state", "established"): {Stdout: "tcp ESTAB 0 0 10.0.0.2:22 198.51.100.10:40000\n"},
	})
	findings := checkNetwork(scenarioContext(cmd))
	if len(findings) != 4 {
		t.Fatalf("network category returned %d findings, want 4", len(findings))
	}
	requireStatus(t, findings, "NET-001", model.Unknown)
	requireStatus(t, findings, "NET-002", model.Unknown)
	requireStatus(t, findings, "NET-003", model.Info)
	requireStatus(t, findings, "NET-004", model.Info)
	if got := findingByID(t, findings, "NET-003").Facts["total"]; got != "1" {
		t.Fatalf("independent connection evidence was lost: total=%q", got)
	}
	if cmd.calls[scenarioCommandKey("ss", "-H", "-ntup", "state", "established")] != 1 {
		t.Fatalf("established connection inventory was not collected exactly once: calls=%v", cmd.calls)
	}
}

func TestScenarioPanelCapabilityFailuresDoNotBecomePass(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: "2053", Scope: "loopback", Process: "x-ui"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = hostFirewallSnapshot{available: true, active: true, defaultDeny: true, backend: "fixture"}
	})
	panel := panelSnapshot{
		Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true, SchemaSupported: true,
		SchemaCapabilities:      []string{"management-endpoint", "client-state"},
		Endpoints:               []panelEndpoint{{Role: "management", Listen: "127.0.0.1", Port: "2053", TLSKnown: true, TLS: true, PathKnown: true}},
		ManagementMetadataError: "settings query interrupted",
		ClientInventoryError:    "client query interrupted",
	}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	management := checkPanelManagement(ctx)
	if management.Status != model.Unknown || !management.Unavailable {
		t.Fatalf("partial panel management metadata became %s: %+v", management.Status, management)
	}
	runtime := checkPanelRuntimeConsistency(ctx, nil)
	if runtime.Status != model.Unknown || !runtime.Unavailable || runtime.Facts["client_inventories_unavailable"] != "1" {
		t.Fatalf("partial panel runtime metadata became %s: %+v", runtime.Status, runtime)
	}
	for _, evidence := range runtime.Evidence {
		if evidence.Key == "panel_client_summary" && strings.Contains(evidence.Value, "enabled_clients=0") {
			t.Fatalf("unavailable client inventory was reported as zero: %+v", evidence)
		}
	}
}

func TestScenarioUnavailableReliabilityEvidenceNeverPasses(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("journalctl", "-k", "--since", "-1d", "--no-pager", "-o", "cat"):      {Err: fmt.Errorf("journal unavailable")},
		scenarioCommandKey("coredumpctl", "list", "--since", "-1d", "--no-pager", "--no-legend"): {Err: fmt.Errorf("coredump unavailable")},
	}
	ctx := scenarioContext(newScenarioCommander([]string{"journalctl", "coredumpctl"}, results))
	f := findingByID(t, checkReliability(ctx), "REL-001")
	if f.Status != model.Unknown || !f.Unavailable || f.Facts["evidence_discovery_incomplete"] != "true" {
		t.Fatalf("finding=%+v", f)
	}
}

func TestScenarioDockerComposeAndEffectiveMounts(t *testing.T) {
	cmd := newScenarioCommander([]string{"docker"}, nil)
	ctx := scenarioContext(cmd)
	container := dockerInspect{Name: "/panel"}
	container.Config.Image = "example/panel:latest"
	container.Config.Labels = map[string]string{"com.docker.compose.project": "proxy", "com.docker.compose.service": "panel"}
	container.HostConfig.RestartPolicy.Name = "unless-stopped"
	container.NetworkSettings.Networks = map[string]json.RawMessage{"proxy_default": nil}
	container.Mounts = append(container.Mounts, struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	}{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: true})
	ctx.Facts.dockerOnce.Do(func() { ctx.Facts.docker = []dockerInspect{container} })
	f := findingByID(t, checkDocker(ctx), "DOCKER-001")
	if f.Status != model.Risk || f.Facts["compose_projects"] != "1" || f.Facts["compose_services"] != "1" {
		t.Fatalf("status=%s facts=%v", f.Status, f.Facts)
	}
	if !evidenceHas(f, "sensitive_mount", "/var/run/docker.sock") {
		t.Fatalf("mount evidence missing: %+v", f.Evidence)
	}
}

func TestScenarioRootProxyServiceIsContextButDangerousCapabilityIsRisk(t *testing.T) {
	listKey := scenarioCommandKey("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain")
	showArgs := []string{"show", "s-ui.service", "--property=ActiveState,SubState,User,Group,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,CapabilityBoundingSet,AmbientCapabilities,LimitNOFILE,NRestarts,FragmentPath"}
	results := map[string]CommandResult{
		listKey: {Stdout: "s-ui.service loaded active running S-UI"},
		scenarioCommandKey("systemctl", showArgs...): {Stdout: "ActiveState=active\nSubState=running\nUser=root\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE\nAmbientCapabilities=\nLimitNOFILE=1048576\n"},
	}
	cmd := newScenarioCommander([]string{"systemctl"}, results)
	f := checkProxyServiceIsolation(scenarioContext(cmd))
	if f.Status != model.Info || f.Facts["root_services"] != "1" || f.Facts["dangerous_capability_services"] != "0" {
		t.Fatalf("status=%s facts=%v", f.Status, f.Facts)
	}

	results[scenarioCommandKey("systemctl", showArgs...)] = CommandResult{Stdout: "ActiveState=active\nUser=root\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_SYS_ADMIN\n"}
	f = checkProxyServiceIsolation(scenarioContext(newScenarioCommander([]string{"systemctl"}, results)))
	if f.Status != model.Risk || f.Severity != model.High || f.Facts["dangerous_capability_services"] != "1" {
		t.Fatalf("status=%s severity=%s facts=%v", f.Status, f.Severity, f.Facts)
	}
}

func evidenceHas(f model.Finding, key, contains string) bool {
	for _, evidence := range f.Evidence {
		if evidence.Key == key && strings.Contains(evidence.Value, contains) {
			return true
		}
	}
	return false
}
