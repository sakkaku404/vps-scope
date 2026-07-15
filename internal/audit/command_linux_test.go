//go:build linux

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOSCommanderCapturesExitAndUsesFixedEnvironment(t *testing.T) {
	t.Setenv("PATH", "/tmp/untrusted-path")
	t.Setenv("LC_ALL", "user-controlled")
	t.Setenv("LANG", "user-controlled")

	r := (OSCommander{}).Run(2*time.Second, "sh", "-c", `printf '%s|%s|%s' "$PATH" "$LC_ALL" "$LANG"; printf 'diagnostic' >&2; exit 7`)
	if r.Code != 7 || r.Err == nil {
		t.Fatalf("Run code=%d err=%v", r.Code, r.Err)
	}
	if r.Stdout != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|C|C" {
		t.Fatalf("unexpected fixed environment: %q", r.Stdout)
	}
	if r.Stderr != "diagnostic" {
		t.Fatalf("stderr=%q", r.Stderr)
	}
}

func TestOSCommanderTimeoutKillsForkedProcessGroup(t *testing.T) {
	started := time.Now()
	r := (OSCommander{}).Run(100*time.Millisecond, "sh", "-c", "sleep 5 & wait")
	if !errors.Is(r.Err, context.DeadlineExceeded) || r.Code != 124 {
		t.Fatalf("Run code=%d err=%v", r.Code, r.Err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("forked command survived deadline for %s", elapsed)
	}
}

func TestOSCommanderRejectsWritableExecutablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake-command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := (OSCommander{}).Run(time.Second, path)
	if r.Code != -1 || r.Err == nil || !strings.Contains(r.Err.Error(), "refusing untrusted executable") {
		t.Fatalf("Run code=%d err=%v", r.Code, r.Err)
	}
}

func TestOSCommanderTruncatesNoisyCommand(t *testing.T) {
	script := "head -c " + strconv.Itoa(maxCommandOutputBytes+1024) + " /dev/zero | tr '\\000' x"
	r := (OSCommander{}).Run(5*time.Second, "sh", "-c", script)
	if !r.Truncated || !errors.Is(r.Err, errCommandOutputTruncated) {
		t.Fatalf("truncated=%t err=%v", r.Truncated, r.Err)
	}
	if len(r.Stdout) != maxCommandOutputBytes {
		t.Fatalf("captured=%d, want %d", len(r.Stdout), maxCommandOutputBytes)
	}
}

func TestTrustedSystemExecutableAccepted(t *testing.T) {
	path, err := (OSCommander{}).TrustedExecutable("sh")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("trusted path is not absolute: %q", path)
	}
}
