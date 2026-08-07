package audit

import (
	"strings"
	"testing"
	"time"
)

type timeoutRecordingCommander struct{ timeout time.Duration }

func (c *timeoutRecordingCommander) Exists(string) bool { return true }
func (c *timeoutRecordingCommander) Run(timeout time.Duration, _ string, _ ...string) CommandResult {
	c.timeout = timeout
	return CommandResult{}
}

func TestDeadlineCommanderCapsPerCommandTimeout(t *testing.T) {
	delegate := &timeoutRecordingCommander{}
	commander := newDeadlineCommander(delegate, 100*time.Millisecond)
	commander.Run(10*time.Second, "fixture")
	if delegate.timeout <= 0 || delegate.timeout > 100*time.Millisecond {
		t.Fatalf("delegated timeout=%s", delegate.timeout)
	}
}

func TestDeadlineCommanderStopsAfterBudget(t *testing.T) {
	delegate := &timeoutRecordingCommander{}
	commander := &deadlineCommander{delegate: delegate, deadline: time.Now().Add(-time.Second)}
	result := commander.Run(time.Second, "fixture")
	if result.Code != 124 || result.Err == nil || !strings.Contains(result.Err.Error(), "budget exhausted") {
		t.Fatalf("result=%#v", result)
	}
}
