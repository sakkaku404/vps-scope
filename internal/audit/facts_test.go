package audit

import (
	"testing"
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
