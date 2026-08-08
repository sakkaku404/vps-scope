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

type contextCommander interface {
	RunContext(context.Context, time.Duration, string, ...string) CommandResult
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
	return OSCommander{}.RunContext(context.Background(), timeout, name, args...)
}

func (OSCommander) RunContext(parent context.Context, timeout time.Duration, name string, args ...string) CommandResult {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	path, lookupErr := resolveSystemExecutable(name)
	if lookupErr != nil {
		return CommandResult{Err: lookupErr, Code: -1}
	}
	path, trustErr := verifyTrustedExecutable(path)
	if trustErr != nil {
		return CommandResult{Err: fmt.Errorf("refusing untrusted executable %q: %w", name, trustErr), Code: -1}
	}
	// #nosec G204 -- path resolves through a fixed system search path, every
	// component is root-owned and non-writable, and collectors supply argv
	// directly without a shell.
	cmd := exec.CommandContext(ctx, path, args...)
	// A fixed search path avoids accidental command resolution through a
	// caller-controlled PATH while retaining standard Debian/Ubuntu locations.
	cmd.Env = commandEnvironment()
	hardenCommandExecution(cmd)
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
	if errors.Is(ctx.Err(), context.Canceled) {
		r.Err = ctx.Err()
		r.Code = 130
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

// commandEnvironment is deliberately an allowlist. Caller-controlled values
// such as DOCKER_HOST, DOCKER_CONTEXT, APT_CONFIG, DPKG_ROOT, LD_PRELOAD, and
// pager settings can redirect evidence collection, load unintended code, or
// make a trusted executable behave differently from the audited host's local
// default. Collectors pass every required target explicitly instead.
func commandEnvironment() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"LANG=C",
		"LANGUAGE=C",
		"TZ=UTC",
		"TERM=dumb",
		"PAGER=cat",
		"SYSTEMD_PAGER=cat",
		"SYSTEMD_COLORS=0",
		"NO_COLOR=1",
	}
}

func resolveSystemExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		info, err := os.Stat(name)
		if err != nil {
			return "", err
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("not an executable file: %s", name)
		}
		return filepath.Clean(name), nil
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return "", fmt.Errorf("relative executable paths are not allowed: %s", name)
	}
	for _, dir := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			// Preserve the invoked name. Multi-call programs such as
			// xtables-nft-multi select iptables-save/ip6tables-save behavior
			// from argv[0]. verifyTrustedExecutable still validates the final
			// target and every parent directory before execution.
			return candidate, nil
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
