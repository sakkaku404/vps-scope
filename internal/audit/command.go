package audit

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// maxCommandOutputBytes bounds each captured stream. Audits can inspect noisy
// journals and firewall rules; a timeout alone does not stop a huge output
// from exhausting memory on a small VPS.
const maxCommandOutputBytes = 8 << 20

var errCommandOutputTruncated = errors.New("command output exceeded the capture limit")

type CommandResult struct {
	Stdout string
	Stderr string
	Code   int
	Err    error
	// Truncated means one or both command streams exceeded the capture limit.
	// Callers that need complete inventories must report UNKNOWN rather than
	// treating a partial result as a clean finding.
	Truncated bool
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
	stdout := limitedBuilder{limit: maxCommandOutputBytes}
	stderr := limitedBuilder{limit: maxCommandOutputBytes}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	r := CommandResult{Stdout: strings.TrimSpace(stdout.String()), Stderr: strings.TrimSpace(stderr.String()), Err: err, Truncated: stdout.truncated || stderr.truncated}
	if r.Truncated && r.Err == nil {
		r.Err = errCommandOutputTruncated
	}
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

type limitedBuilder struct {
	builder   strings.Builder
	limit     int
	written   int
	truncated bool
}

func (b *limitedBuilder) Write(p []byte) (int, error) {
	remaining := b.limit - b.written
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.builder.Write(p[:remaining])
			b.written += remaining
			b.truncated = true
			return len(p), nil
		}
		_, _ = b.builder.Write(p)
		b.written += len(p)
		return len(p), nil
	}
	b.truncated = true
	return len(p), nil
}

func (b *limitedBuilder) String() string { return b.builder.String() }
