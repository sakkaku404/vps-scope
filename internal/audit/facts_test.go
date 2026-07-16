package audit

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestFactStoreCachesListenerAndProcessSnapshots(t *testing.T) {
	cmd := newScenarioCommander([]string{"ss", "ps"}, map[string]CommandResult{
		scenarioCommandKey("ss", "-H", "-lntup"):                  {Stdout: `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`},
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "1 root sshd /usr/sbin/sshd -D"},
	})
	facts := NewFactStore(cmd)
	for i := 0; i < 2; i++ {
		if _, err := facts.Listeners(); err != nil {
			t.Fatal(err)
		}
		if _, err := facts.Processes(); err != nil {
			t.Fatal(err)
		}
	}
	if cmd.calls[scenarioCommandKey("ss", "-H", "-lntup")] != 1 || cmd.calls[scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args=")] != 1 {
		t.Fatalf("snapshot calls = %#v, want one each", cmd.calls)
	}
}

func TestFactStoreRejectsTruncatedSnapshots(t *testing.T) {
	truncated := CommandResult{Stdout: "partial", Truncated: true, Err: errCommandOutputTruncated}
	cmd := newScenarioCommander([]string{"ss", "ps"}, map[string]CommandResult{
		scenarioCommandKey("ss", "-H", "-lntup"):                  truncated,
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): truncated,
	})
	facts := NewFactStore(cmd)
	if _, err := facts.Listeners(); err == nil {
		t.Fatal("expected truncated listener snapshot error")
	}
	if _, err := facts.Processes(); err == nil {
		t.Fatal("expected truncated process snapshot error")
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
