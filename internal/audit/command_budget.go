package audit

import (
	"context"
	"fmt"
	"time"
)

// deadlineCommander enforces a wall-clock budget across all collectors. Each
// command retains its tighter local timeout, while a slow or hostile host can
// no longer stretch one audit to the sum of every per-command maximum.
type deadlineCommander struct {
	delegate Commander
	deadline time.Time
	ctx      context.Context
}

func newDeadlineCommander(delegate Commander, budget time.Duration, ctx ...context.Context) Commander {
	parent := context.Background()
	if len(ctx) > 0 && ctx[0] != nil {
		parent = ctx[0]
	}
	return &deadlineCommander{delegate: delegate, deadline: time.Now().Add(budget), ctx: parent}
}

func (c *deadlineCommander) Exists(name string) bool {
	return c.delegate.Exists(name)
}

func (c *deadlineCommander) Run(timeout time.Duration, name string, args ...string) CommandResult {
	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return canceledCommandResult(err)
	}
	remaining := time.Until(c.deadline)
	if remaining <= 0 {
		return CommandResult{Err: fmt.Errorf("audit command budget exhausted before %s", name), Code: 124}
	}
	if timeout <= 0 || timeout > remaining {
		timeout = remaining
	}
	if contextual, ok := c.delegate.(contextCommander); ok {
		return contextual.RunContext(ctx, timeout, name, args...)
	}
	return c.delegate.Run(timeout, name, args...)
}

func canceledCommandResult(err error) CommandResult {
	code := 130
	if err == context.DeadlineExceeded {
		code = 124
	}
	return CommandResult{Err: err, Code: code}
}

func (c *deadlineCommander) TrustedExecutable(name string) (string, error) {
	trusted, ok := c.delegate.(trustedCommander)
	if !ok {
		if !c.delegate.Exists(name) {
			return "", fmt.Errorf("executable not found: %s", name)
		}
		return name, nil
	}
	return trusted.TrustedExecutable(name)
}
