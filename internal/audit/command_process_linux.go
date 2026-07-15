//go:build linux

package audit

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// hardenCommandExecution gives every collector command its own process group.
// CommandContext only kills the immediate process by default; a helper that
// forks could otherwise keep inherited output pipes open after the deadline.
func hardenCommandExecution(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		return nil
	}
	cmd.WaitDelay = 2 * time.Second
}
