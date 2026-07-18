//go:build !linux

package audit

import (
	"fmt"
	"os"
)

func openRegularReadOnly(path string) (*os.File, error) {
	// #nosec G304 -- the caller supplies a fixed audit path; the opened
	// descriptor is validated as a regular file before any bounded read.
	f, err := os.Open(path)
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
