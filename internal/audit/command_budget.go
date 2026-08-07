package audit

import (
	"fmt"
	"time"
)

// deadlineCommander enforces a wall-clock budget across all collectors. Each
// command retains its tighter local timeout, while a slow or hostile host can
// no longer stretch one audit to the sum of every per-command maximum.
type deadlineCommander struct {
	delegate Commander
	deadline time.Time
}

func newDeadlineCommander(delegate Commander, budget time.Duration) Commander {
	return &deadlineCommander{delegate: delegate, deadline: time.Now().Add(budget)}
}

func (c *deadlineCommander) Exists(name string) bool {
	return c.delegate.Exists(name)
}

func (c *deadlineCommander) Run(timeout time.Duration, name string, args ...string) CommandResult {
	remaining := time.Until(c.deadline)
	if remaining <= 0 {
		return CommandResult{Err: fmt.Errorf("audit command budget exhausted before %s", name), Code: 124}
	}
	if timeout <= 0 || timeout > remaining {
		timeout = remaining
	}
	return c.delegate.Run(timeout, name, args...)
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
