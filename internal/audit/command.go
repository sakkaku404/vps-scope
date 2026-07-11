package audit

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

type CommandResult struct {
	Stdout string
	Stderr string
	Code   int
	Err    error
}

type Commander interface {
	Run(timeout time.Duration, name string, args ...string) CommandResult
	Exists(name string) bool
}

type OSCommander struct{}

func (OSCommander) Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (OSCommander) Run(timeout time.Duration, name string, args ...string) CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C")
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	r := CommandResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String()), Err: err}
	if err == nil {
		return r
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		r.Err = ctx.Err()
		r.Code = 124
		return r
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		r.Code = exitErr.ExitCode()
	} else {
		r.Code = -1
	}
	return r
}
