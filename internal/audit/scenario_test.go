package audit

import (
	"fmt"
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
		Facts:   NewFactStore(cmd),
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
}

func TestScenarioFirewallUpdatesAndAuthentication(t *testing.T) {
	ufwVerbose := "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\n22/tcp ALLOW IN Anywhere\n22/tcp (v6) ALLOW IN Anywhere (v6)"
	results := map[string]CommandResult{
		scenarioCommandKey("ufw", "status", "verbose"):                                                                           {Stdout: ufwVerbose},
		scenarioCommandKey("ufw", "status"):                                                                                      {Stdout: "Status: active"},
		scenarioCommandKey("ss", "-H", "-lntu"):                                                                                  {Stdout: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"},
		scenarioCommandKey("apt-get", "-s", "-o", "Debug::NoLocking=true", "upgrade"):                                            {Stdout: "Inst openssl [1.0] (1.1 Ubuntu:24.04/noble-security [amd64])"},
		scenarioCommandKey("dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"):                                            {Stdout: "install ok installed"},
		scenarioCommandKey("systemctl", "is-enabled", "apt-daily-upgrade.timer"):                                                 {Stdout: "enabled"},
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "-u", "ssh.service", "-u", "sshd.service"): {Stdout: "Failed password for invalid user admin from 203.0.113.7 port 22 ssh2\nInvalid user admin from 203.0.113.7"},
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "_COMM=sudo"):                              {Stdout: "sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/id"},
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
}

func TestScenarioPanelAndDockerRiskRelations(t *testing.T) {
	cmd := newScenarioCommander([]string{"ss", "ufw", "docker"}, map[string]CommandResult{})
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "2053", Scope: "public-wildcard", Process: "x-ui"}, {Protocol: "tcp", Address: "0.0.0.0", Port: "31001", Scope: "public-wildcard", Process: "xray"}}
	})
	ctx.Facts.ufwOnce.Do(func() {
		ctx.Facts.ufw = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n2053/tcp ALLOW IN Anywhere\n31001/tcp ALLOW IN Anywhere")
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

func TestScenarioIncompleteEvidenceNeverBecomesPass(t *testing.T) {
	truncated := CommandResult{Stdout: "partial", Truncated: true, Err: errCommandOutputTruncated}
	cmd := newScenarioCommander([]string{"journalctl", "ufw", "ss"}, map[string]CommandResult{
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "-u", "ssh.service", "-u", "sshd.service"): truncated,
		scenarioCommandKey("journalctl", "--since", "-1d", "--no-pager", "-o", "cat", "_COMM=sudo"):                              truncated,
		scenarioCommandKey("ufw", "status", "verbose"):                                                                           truncated,
		scenarioCommandKey("ss", "-H", "-lntup"):                                                                                 truncated,
	})
	ctx := scenarioContext(cmd)
	requireStatus(t, checkAuth(ctx), "AUTH-001", model.Unknown)
	requireStatus(t, checkAuth(ctx), "AUTH-002", model.Unknown)
	requireStatus(t, checkFirewall(ctx), "FW-001", model.Unknown)

	summary := proxyConfigSummary{Product: "sing-box", Path: "/etc/sing-box/config.json", Inbounds: []proxyInbound{{Product: "sing-box", Protocol: "vless", Port: "443", Transports: []string{"tcp"}}}}
	requireStatus(t, []model.Finding{checkProxyEndpointRelations(ctx, []proxyConfigSummary{summary})}, "WORK-009", model.Unknown)
}

func TestScenarioPublicControlAPIAndPanelRuntimeMismatch(t *testing.T) {
	cmd := newScenarioCommander(nil, nil)
	ctx := scenarioContext(cmd)
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "9090", Scope: "public-wildcard", Process: "sing-box"}}
	})
	ctx.Facts.ufwOnce.Do(func() {
		ctx.Facts.ufw = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n9090/tcp ALLOW IN Anywhere")
	})
	summary := proxyConfigSummary{Product: "sing-box", Path: "/etc/sing-box/config.json", Controls: []controlEndpoint{{Product: "sing-box", Kind: "clash-api", Listen: "0.0.0.0", Port: "9090"}}}
	requireStatus(t, []model.Finding{checkProxyControlEndpoints(ctx, []proxyConfigSummary{summary})}, "WORK-005", model.Risk)

	panel := panelSnapshot{Product: "3x-ui", Database: "/etc/x-ui/x-ui.db", DatabaseAvailable: true, Inbounds: []panelInboundFact{{Enabled: true, Port: "31001", Protocol: "vless", Network: "tcp", Security: "reality"}}}
	ctx.Facts.panelsOnce.Do(func() { ctx.Facts.panels = []panelSnapshot{panel} })
	requireStatus(t, []model.Finding{checkPanelRuntimeConsistency(ctx, nil)}, "WORK-012", model.Risk)
}
