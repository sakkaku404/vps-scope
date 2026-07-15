//go:build linux

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestReadSmallAllowsSymlinkToRegularFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "config-link")
	if err := os.WriteFile(target, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, err := readSmall(link, 6); err != nil || got != "config" {
		t.Fatalf("symlink read=%q, %v", got, err)
	}
}

func TestReadSmallRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := readSmall(path, 1024)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("readSmall error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("FIFO open blocked for %s", elapsed)
	}
}
