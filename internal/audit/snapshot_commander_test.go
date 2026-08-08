package audit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type snapshotRecordingCommander struct {
	mu           sync.Mutex
	runs         int
	exists       int
	trusted      int
	trustedError error
}

type panickingSnapshotCommander struct{}

func (panickingSnapshotCommander) Run(time.Duration, string, ...string) CommandResult {
	panic("secret")
}
func (panickingSnapshotCommander) Exists(string) bool { panic("secret") }

func (c *snapshotRecordingCommander) Run(time.Duration, string, ...string) CommandResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runs++
	return CommandResult{Stdout: "first"}
}

func (c *snapshotRecordingCommander) Exists(string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exists++
	return true
}

func (c *snapshotRecordingCommander) TrustedExecutable(name string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trusted++
	return "/usr/bin/" + name, c.trustedError
}

func TestSnapshotCommanderReusesIdenticalEvidence(t *testing.T) {
	delegate := &snapshotRecordingCommander{}
	commander := newSnapshotCommander(delegate)
	for range 3 {
		if got := commander.Run(time.Second, "systemctl", "is-active", "ssh").Stdout; got != "first" {
			t.Fatalf("stdout=%q", got)
		}
		if !commander.Exists("systemctl") {
			t.Fatal("expected command to exist")
		}
		if path, err := commander.TrustedExecutable("systemctl"); err != nil || path != "/usr/bin/systemctl" {
			t.Fatalf("path=%q err=%v", path, err)
		}
	}
	if delegate.runs != 1 || delegate.exists != 1 || delegate.trusted != 1 {
		t.Fatalf("delegate calls: run=%d exists=%d trusted=%d", delegate.runs, delegate.exists, delegate.trusted)
	}
	stats := commander.Stats()
	if stats.CommandCalls != 3 || stats.CommandHits != 2 || stats.ExistsHits != 2 || stats.TrustedHits != 2 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestSnapshotCommanderSeparatesArgumentVectorsAndCachesFailures(t *testing.T) {
	delegate := &snapshotRecordingCommander{trustedError: errors.New("untrusted")}
	commander := newSnapshotCommander(delegate)
	commander.Run(time.Second, "systemctl", "is-active", "ssh")
	commander.Run(time.Second, "systemctl", "is-active", "docker")
	for range 2 {
		if _, err := commander.TrustedExecutable("panel"); err == nil {
			t.Fatal("expected cached trust failure")
		}
	}
	if delegate.runs != 2 || delegate.trusted != 1 {
		t.Fatalf("delegate calls: run=%d trusted=%d", delegate.runs, delegate.trusted)
	}
}

func TestSnapshotCommanderIsSafeUnderConcurrentCollectors(t *testing.T) {
	delegate := &snapshotRecordingCommander{}
	commander := newSnapshotCommander(delegate)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = commander.Run(time.Second, "ss", "-H", "-lntup")
		}()
	}
	wg.Wait()
	if delegate.runs != 1 {
		t.Fatalf("delegate runs=%d", delegate.runs)
	}
	if got := commander.Run(time.Second, "ss", "-H", "-lntup").Stdout; got != "first" {
		t.Fatalf("stdout=%q", got)
	}
}

func TestSnapshotCommanderConvertsDelegatePanicsWithoutDeadlockOrLeak(t *testing.T) {
	commander := newSnapshotCommander(panickingSnapshotCommander{})
	for range 2 {
		result := commander.Run(time.Second, "fixture")
		if result.Err == nil || result.Code != -1 || result.Err.Error() != "collector command failed internally" {
			t.Fatalf("result=%+v", result)
		}
		if commander.Exists("fixture") {
			t.Fatal("panicking lookup must fail closed")
		}
	}
}

func TestSnapshotCommanderFailsClosedWhenAggregateMemoryBudgetIsExhausted(t *testing.T) {
	delegate := &snapshotRecordingCommander{}
	commander := newSnapshotCommander(delegate)
	commander.retainedBytes = maxCommandSnapshotRetainedBytes - 1

	result := commander.Run(time.Second, "fixture")
	if !errors.Is(result.Err, errCommandSnapshotBudget) || !result.Truncated || result.Stdout != "" {
		t.Fatalf("result=%+v", result)
	}
	if again := commander.Run(time.Second, "fixture"); !errors.Is(again.Err, errCommandSnapshotBudget) {
		t.Fatalf("cached result=%+v", again)
	}
	stats := commander.Stats()
	if stats.BudgetRejects != 1 || stats.CommandHits != 1 || stats.RetainedBytes != maxCommandSnapshotRetainedBytes-1 {
		t.Fatalf("stats=%+v", stats)
	}
}
