//go:build !linux

package audit

import (
	"os/exec"
	"time"
)

func hardenCommandExecution(cmd *exec.Cmd) {
	cmd.WaitDelay = 2 * time.Second
}
