//go:build linux

package audit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// verifyTrustedExecutable rejects a binary or any parent directory that a
// non-root user can modify. This matters because audits commonly run as root
// and panel/core binaries are often installed outside package management.
func verifyTrustedExecutable(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("not an executable regular file: %s", resolved)
	}
	if err := rootOwnedAndNotWritable(info, resolved); err != nil {
		return "", err
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return "", err
		}
		if err := rootOwnedAndNotWritable(info, dir); err != nil {
			return "", err
		}
		if dir == "/" {
			break
		}
	}
	return resolved, nil
}

func rootOwnedAndNotWritable(info fs.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return fmt.Errorf("not root-owned: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("group/other writable: %s", path)
	}
	return nil
}
