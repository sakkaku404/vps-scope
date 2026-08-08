package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestProxyNativeSelfTestIsDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := scenarioCommandKey("sing-box", "check", "-C", dir)
	cmd := newScenarioCommander([]string{"sing-box"}, map[string]CommandResult{key: {}})

	finding := checkProxyConfiguration(scenarioContext(cmd), []proxyConfigSummary{{Product: "sing-box", Path: path, Parseable: true}})
	if finding.Status != "INFO" {
		t.Fatalf("status=%s, want INFO for static parsing without native execution", finding.Status)
	}
	if got := cmd.calls[key]; got != 0 {
		t.Fatalf("sing-box invocation count=%d, want 0 by default", got)
	}
	if finding.Facts["native_self_test_mode"] != "disabled_by_default" || finding.Facts["native_self_tests"] != "0" {
		t.Fatalf("unexpected native self-test facts: %#v", finding.Facts)
	}
	if !evidenceContains(finding.Evidence, "no audited workload binary was executed") {
		t.Fatalf("finding does not explain the default execution boundary: %#v", finding.Evidence)
	}
}

func TestProxyNativeSelfTestOptInExecutesWorkloadBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := scenarioCommandKey("sing-box", "check", "-C", dir)
	cmd := newScenarioCommander([]string{"sing-box"}, map[string]CommandResult{key: {}})
	ctx := scenarioContext(cmd)
	ctx.Options.NativeSelfTest = true
	ctx.Facts = NewFactStore(cmd, true)

	finding := checkProxyConfiguration(ctx, []proxyConfigSummary{{Product: "sing-box", Path: path, Parseable: true}})
	if finding.Status != "PASS" {
		t.Fatalf("status=%s, want PASS after a successful opted-in self-test", finding.Status)
	}
	if got := cmd.calls[key]; got != 1 {
		t.Fatalf("sing-box invocation count=%d, want 1 after opt-in", got)
	}
	if finding.Facts["native_self_test_mode"] != "enabled_executes_local_workload_code" || finding.Facts["native_self_tests"] != "1" {
		t.Fatalf("unexpected native self-test facts: %#v", finding.Facts)
	}
}

func TestProxyNativeSelfTestUsesInjectedFileSnapshot(t *testing.T) {
	const (
		config = "/usr/local/s-ui/config.json"
		binary = "/usr/local/s-ui/bin/sing-box"
	)
	key := scenarioCommandKey(binary, "check", "-c", config)
	cmd := newScenarioCommander([]string{binary}, map[string]CommandResult{key: {}})
	source := &recordingFileEvidence{}
	ctx := scenarioContext(cmd)
	ctx.Options.NativeSelfTest = true
	ctx.Facts = newFactStoreAt(cmd, true, time.Unix(1, 0), source)

	finding := checkProxyConfiguration(ctx, []proxyConfigSummary{{Product: "sing-box", Path: config, Parseable: true}})
	if finding.Status != model.Pass || cmd.calls[key] != 1 {
		t.Fatalf("status=%s calls=%d, want PASS and one injected self-test", finding.Status, cmd.calls[key])
	}
	if source.stats != 1 {
		t.Fatalf("file snapshot stat calls=%d, want 1", source.stats)
	}
}

func TestAuditedWorkloadBinariesAreNotExecutedByDefault(t *testing.T) {
	cmd := newScenarioCommander([]string{"/usr/local/s-ui/sui", "/usr/local/x-ui/x-ui", "nginx", "sing-box", "ps"}, map[string]CommandResult{
		scenarioCommandKey("/usr/local/s-ui/sui", "-v"):           {},
		scenarioCommandKey("/usr/local/x-ui/x-ui", "-v"):          {},
		scenarioCommandKey("nginx", "-T"):                         {},
		scenarioCommandKey("sing-box", "version"):                 {Stdout: "sing-box version 1.13.0"},
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "100 root sing-box /usr/bin/sing-box run -c /etc/sing-box/config.json"},
	})
	_ = collectSUIFacts(cmd, false)
	_ = collectXUIFacts(cmd, false)
	_, _ = discoverReverseProxyRoutes(cmd, false)
	_ = checkProxyAdvisories(scenarioContext(cmd), nil)
	for _, key := range []string{
		scenarioCommandKey("/usr/local/s-ui/sui", "-v"),
		scenarioCommandKey("/usr/local/x-ui/x-ui", "-v"),
		scenarioCommandKey("nginx", "-T"),
		scenarioCommandKey("sing-box", "version"),
	} {
		if count := cmd.calls[key]; count != 0 {
			t.Fatalf("workload command %q invocation count=%d, want 0 by default", key, count)
		}
	}
}

func evidenceContains(evidence []model.Evidence, needle string) bool {
	for _, item := range evidence {
		if strings.Contains(item.Value, needle) {
			return true
		}
	}
	return false
}
