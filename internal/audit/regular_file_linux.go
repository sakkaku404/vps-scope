//go:build linux

package audit

import (
	"fmt"
	"os"
	"syscall"
)

// openRegularReadOnly opens a path without waiting for a FIFO writer, then
// validates the opened descriptor rather than trusting a path-level stat.
// Symlinks remain supported when their resolved target is a regular file.
func openRegularReadOnly(path string) (*os.File, error) {
	// #nosec G304 -- callers provide fixed audit paths or bounded discovered
	// paths; the descriptor is opened read-only/nonblocking and accepted only
	// when f.Stat confirms a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	return f, nil
}
