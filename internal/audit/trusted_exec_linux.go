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
	if err := trustedDirectoryChain(filepath.Dir(resolved)); err != nil {
		return "", err
	}
	// The original symlink path is executed to preserve argv[0], so its parent
	// chain must be protected too; otherwise a non-root user could swap the
	// link after the target was verified.
	if filepath.Clean(path) != resolved {
		if err := trustedDirectoryChain(filepath.Dir(filepath.Clean(path))); err != nil {
			return "", err
		}
	}
	// Execute through the verified original path so multi-call binaries retain
	// the argv[0] selected by their system symlink.
	return filepath.Clean(path), nil
}

func trustedDirectoryChain(start string) error {
	for dir := start; ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if err := rootOwnedAndNotWritable(info, dir); err != nil {
			return err
		}
		if dir == "/" {
			break
		}
	}
	return nil
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
