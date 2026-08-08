package audit

import (
	"context"
	"errors"
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

type blockingContextCommander struct {
	started chan struct{}
}

func (c *blockingContextCommander) Exists(string) bool { return true }
func (c *blockingContextCommander) Run(time.Duration, string, ...string) CommandResult {
	return CommandResult{Err: errors.New("non-context path used")}
}
func (c *blockingContextCommander) RunContext(ctx context.Context, _ time.Duration, _ string, _ ...string) CommandResult {
	close(c.started)
	<-ctx.Done()
	return canceledCommandResult(ctx.Err())
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

func TestDeadlineCommanderStopsBeforeCanceledCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	delegate := &timeoutRecordingCommander{}
	result := newDeadlineCommander(delegate, time.Minute, ctx).Run(time.Second, "fixture")
	if result.Code != 130 || !errors.Is(result.Err, context.Canceled) || delegate.timeout != 0 {
		t.Fatalf("result=%+v delegated timeout=%s", result, delegate.timeout)
	}
}

func TestDeadlineCommanderPropagatesCancellationToActiveCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	delegate := &blockingContextCommander{started: make(chan struct{})}
	resultChannel := make(chan CommandResult, 1)
	go func() {
		resultChannel <- newDeadlineCommander(delegate, time.Minute, ctx).Run(time.Minute, "fixture")
	}()
	<-delegate.started
	cancel()
	select {
	case result := <-resultChannel:
		if result.Code != 130 || !errors.Is(result.Err, context.Canceled) {
			t.Fatalf("result=%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("active command did not observe cancellation")
	}
}
