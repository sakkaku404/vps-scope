package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

// trustedCommander is deliberately optional so deterministic scenario
// fixtures remain small. Real-host execution uses the stricter implementation
// below before invoking workload-owned binaries as root.
type trustedCommander interface {
	TrustedExecutable(name string) (string, error)
}

func trustedExecutable(cmd Commander, name string) (string, error) {
	if trusted, ok := cmd.(trustedCommander); ok {
		return trusted.TrustedExecutable(name)
	}
	if !cmd.Exists(name) {
		return "", fmt.Errorf("executable not found: %s", name)
	}
	return name, nil
}

func (OSCommander) Exists(name string) bool {
	_, err := resolveSystemExecutable(name)
	return err == nil
}

func (OSCommander) TrustedExecutable(name string) (string, error) {
	path, err := resolveSystemExecutable(name)
	if err != nil {
		return "", err
	}
	return verifyTrustedExecutable(path)
}

func (OSCommander) Run(timeout time.Duration, name string, args ...string) CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	path, lookupErr := resolveSystemExecutable(name)
	if lookupErr != nil {
		return CommandResult{Err: lookupErr, Code: -1}
	}
	cmd := exec.CommandContext(ctx, path, args...)
	// A fixed search path avoids accidental command resolution through a
	// caller-controlled PATH while retaining standard Debian/Ubuntu locations.
	cmd.Env = append(os.Environ(), "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C")
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

func resolveSystemExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		return filepath.EvalSymlinks(name)
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("relative executable paths are not allowed: %s", name)
	}
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return filepath.EvalSymlinks(candidate)
		}
	}
	return "", fmt.Errorf("executable not found in system PATH: %s", name)
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
