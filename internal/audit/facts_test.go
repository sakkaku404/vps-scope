package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeCommander struct {
	mu    sync.Mutex
	calls map[string]int
	run   func(string, ...string) CommandResult
}

func (f *fakeCommander) Exists(string) bool { return true }

func (f *fakeCommander) Run(_ time.Duration, name string, args ...string) CommandResult {
	f.mu.Lock()
	f.calls[name]++
	f.mu.Unlock()
	return f.run(name, args...)
}

func TestFactStoreCachesListenerAndProcessSnapshots(t *testing.T) {
	cmd := &fakeCommander{calls: map[string]int{}, run: func(name string, _ ...string) CommandResult {
		switch name {
		case "ss":
			return CommandResult{Stdout: `tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`}
		case "ps":
			return CommandResult{Stdout: "1 root sshd /usr/sbin/sshd -D"}
		default:
			return CommandResult{Err: fmt.Errorf("unexpected command %s", name)}
		}
	}}
	facts := NewFactStore(cmd)
	for i := 0; i < 2; i++ {
		if _, err := facts.Listeners(); err != nil {
			t.Fatal(err)
		}
		if _, err := facts.Processes(); err != nil {
			t.Fatal(err)
		}
	}
	if cmd.calls["ss"] != 1 || cmd.calls["ps"] != 1 {
		t.Fatalf("snapshot calls = %#v, want one each", cmd.calls)
	}
}

func TestFactStoreRejectsTruncatedSnapshots(t *testing.T) {
	cmd := &fakeCommander{calls: map[string]int{}, run: func(name string, _ ...string) CommandResult {
		return CommandResult{Stdout: "partial", Truncated: true, Err: errCommandOutputTruncated}
	}}
	facts := NewFactStore(cmd)
	if _, err := facts.Listeners(); err == nil {
		t.Fatal("expected truncated listener snapshot error")
	}
	if _, err := facts.Processes(); err == nil {
		t.Fatal("expected truncated process snapshot error")
	}
}
