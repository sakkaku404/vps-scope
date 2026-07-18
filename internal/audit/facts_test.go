package audit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestFactStoreCachesListenerProcessConnectionAndSSHDSnapshots(t *testing.T) {
	cmd := newScenarioCommander([]string{"ss", "ps", "sshd"}, map[string]CommandResult{
		scenarioCommandKey("ss", "-H", "-lntup"):                        {Stdout: `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`},
		scenarioCommandKey("ss", "-H", "-ntup", "state", "established"): {Stdout: `tcp ESTAB 0 0 10.0.0.2:22 203.0.113.5:50123 users:(("sshd",pid=1,fd=3))`},
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="):       {Stdout: "1 root sshd /usr/sbin/sshd -D"},
		scenarioCommandKey("sshd", "-T"):                                {Stdout: "passwordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\npubkeyauthentication yes"},
	})
	facts := NewFactStore(cmd)
	for i := 0; i < 2; i++ {
		if _, err := facts.Listeners(); err != nil {
			t.Fatal(err)
		}
		if _, err := facts.Processes(); err != nil {
			t.Fatal(err)
		}
		if _, err := facts.EstablishedConnections(); err != nil {
			t.Fatal(err)
		}
		settings, err := facts.SSHDSettings()
		if err != nil || settings["passwordauthentication"] != "no" {
			t.Fatalf("sshd settings=%v err=%v", settings, err)
		}
		settings["passwordauthentication"] = "yes"
	}
	if cmd.calls[scenarioCommandKey("ss", "-H", "-lntup")] != 1 || cmd.calls[scenarioCommandKey("ss", "-H", "-ntup", "state", "established")] != 1 || cmd.calls[scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args=")] != 1 || cmd.calls[scenarioCommandKey("sshd", "-T")] != 1 {
		t.Fatalf("snapshot calls = %#v, want one each", cmd.calls)
	}
}

func TestSSHDSettingsRejectsIncompleteEffectiveConfiguration(t *testing.T) {
	cmd := newScenarioCommander([]string{"sshd"}, map[string]CommandResult{
		scenarioCommandKey("sshd", "-T"): {Stdout: "passwordauthentication no\nkbdinteractiveauthentication no\npubkeyauthentication yes"},
	})
	if settings, err := NewFactStore(cmd).SSHDSettings(); err == nil || len(settings) != 0 {
		t.Fatalf("settings=%v err=%v", settings, err)
	}
}

func TestFactStoreRejectsTruncatedSnapshots(t *testing.T) {
	truncated := CommandResult{Stdout: "partial", Truncated: true, Err: errCommandOutputTruncated}
	cmd := newScenarioCommander([]string{"ss", "ps", "sshd"}, map[string]CommandResult{
		scenarioCommandKey("ss", "-H", "-lntup"):                        truncated,
		scenarioCommandKey("ss", "-H", "-ntup", "state", "established"): truncated,
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="):       truncated,
		scenarioCommandKey("sshd", "-T"):                                truncated,
	})
	facts := NewFactStore(cmd)
	if _, err := facts.Listeners(); err == nil {
		t.Fatal("expected truncated listener snapshot error")
	}
	if _, err := facts.Processes(); err == nil {
		t.Fatal("expected truncated process snapshot error")
	}
	if _, err := facts.EstablishedConnections(); err == nil {
		t.Fatal("expected truncated established connection snapshot error")
	}
	if _, err := facts.SSHDSettings(); err == nil {
		t.Fatal("expected truncated sshd settings snapshot error")
	}
}

func TestDockerContainerIDsRejectsIncompleteInventory(t *testing.T) {
	ids := make([]string, maxDockerContainerInventory+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i)
	}
	if _, err := dockerContainerIDs(strings.Join(ids, "\n")); err == nil || !strings.Contains(err.Error(), "safety limit") {
		t.Fatalf("dockerContainerIDs error = %v, want safety limit", err)
	}
}

func TestFactStoreBatchesDockerInspectWithoutReturningPartialInventory(t *testing.T) {
	ids := make([]string, dockerInspectBatchSize+1)
	results := map[string]CommandResult{}
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}
	results[scenarioCommandKey("docker", "ps", "-q")] = CommandResult{Stdout: strings.Join(ids, "\n")}
	results[scenarioCommandKey("docker", append([]string{"inspect"}, ids[:dockerInspectBatchSize]...)...)] = CommandResult{Stdout: "[]"}
	results[scenarioCommandKey("docker", "inspect", ids[dockerInspectBatchSize])] = CommandResult{Stdout: "[]"}
	cmd := newScenarioCommander([]string{"docker"}, results)
	containers, err := NewFactStore(cmd).DockerContainers()
	if err == nil || !strings.Contains(err.Error(), "returned 0 containers for 32 requested") {
		t.Fatalf("DockerContainers error = %v, want incomplete batch error", err)
	}
	if len(containers) != 0 {
		t.Fatalf("DockerContainers returned %d partial containers, want zero", len(containers))
	}
}

func TestFactStoreBatchesDockerInspect(t *testing.T) {
	ids := make([]string, dockerInspectBatchSize+1)
	results := map[string]CommandResult{}
	for i := range ids {
		ids[i] = fmt.Sprintf("%064x", i+1)
	}
	results[scenarioCommandKey("docker", "ps", "-q")] = CommandResult{Stdout: strings.Join(ids, "\n")}
	first := make([]string, dockerInspectBatchSize)
	for i := range first {
		first[i] = fmt.Sprintf(`{"Name":"/c%d"}`, i)
	}
	results[scenarioCommandKey("docker", append([]string{"inspect"}, ids[:dockerInspectBatchSize]...)...)] = CommandResult{Stdout: "[" + strings.Join(first, ",") + "]"}
	results[scenarioCommandKey("docker", "inspect", ids[dockerInspectBatchSize])] = CommandResult{Stdout: `[{"Name":"/last"}]`}
	cmd := newScenarioCommander([]string{"docker"}, results)
	containers, err := NewFactStore(cmd).DockerContainers()
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != len(ids) || containers[len(containers)-1].Name != "/last" {
		t.Fatalf("DockerContainers = %#v, want %d batched containers", containers, len(ids))
	}
}

func TestProxyInventoryUsesBoundedDockerFacts(t *testing.T) {
	id := fmt.Sprintf("%064x", 1)
	cmd := newScenarioCommander([]string{"docker", "ps"}, map[string]CommandResult{
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "1 root init /sbin/init"},
		scenarioCommandKey("docker", "ps", "-q"):                  {Stdout: id},
		scenarioCommandKey("docker", "inspect", id):               {Stdout: `[{"Name":"/outline","Config":{"Image":"quay.io/outline/shadowbox"}}]`},
	})
	f := checkProxyInventory(scenarioContext(cmd), nil)
	if f.Status != model.Info || f.Facts["products"] != "Outline" {
		t.Fatalf("proxy inventory = %#v, want Outline INFO", f)
	}
	if cmd.calls[scenarioCommandKey("docker", "ps", "--format", "{{.Names}} {{.Image}}")] != 0 {
		t.Fatalf("legacy docker ps format command was called: %#v", cmd.calls)
	}
}

func TestProxyInventoryDoesNotHideDockerCollectionFailure(t *testing.T) {
	cmd := newScenarioCommander([]string{"docker", "ps"}, map[string]CommandResult{
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "1 root init /sbin/init"},
		scenarioCommandKey("docker", "ps", "-q"):                  {Err: fmt.Errorf("daemon unavailable"), Code: 1},
	})
	f := checkProxyInventory(scenarioContext(cmd), nil)
	if f.Status != model.Unknown || !f.Unavailable || f.NotApplicable {
		t.Fatalf("proxy inventory = %#v, want unavailable UNKNOWN", f)
	}
}

func TestDockerPanelDiscoveryFailureIsNotReportedAsNoPanel(t *testing.T) {
	cmd := newScenarioCommander([]string{"docker"}, map[string]CommandResult{
		scenarioCommandKey("docker", "ps", "-q"): {Err: fmt.Errorf("daemon unavailable"), Code: 1},
	})
	ctx := scenarioContext(cmd)
	panels, err := ctx.Facts.Panels()
	if err == nil || !strings.Contains(err.Error(), "docker-backed panel discovery") {
		t.Fatalf("Panels error = %v, want Docker-backed discovery error", err)
	}
	if len(panels) != 0 {
		t.Fatalf("Panels = %#v, want no native panels in fixture", panels)
	}
	requireStatus(t, []model.Finding{checkPanelManagement(ctx)}, "WORK-002", model.Unknown)
	requireStatus(t, []model.Finding{checkPanelRuntimeConsistency(ctx, nil)}, "WORK-012", model.Unknown)
}

func TestPanelDiscoveryDoesNotRequireDocker(t *testing.T) {
	panels, err := NewFactStore(newScenarioCommander(nil, nil)).Panels()
	if err != nil {
		t.Fatalf("Panels error = %v, want nil when Docker is absent", err)
	}
	if len(panels) != 0 {
		t.Fatalf("Panels = %#v, want no panels in fixture", panels)
	}
}
