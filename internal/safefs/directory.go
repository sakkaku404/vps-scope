package safefs

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ReadDirectoryBounded returns a complete directory snapshot or an error. It
// never exposes a prefix when the directory exceeds the caller's entry budget.
func ReadDirectoryBounded(path string, maxEntries int) ([]os.DirEntry, error) {
	if maxEntries <= 0 {
		return nil, fmt.Errorf("invalid directory entry budget")
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, readErr := dir.ReadDir(maxEntries + 1)
	if len(entries) > maxEntries {
		return nil, fmt.Errorf("directory %q exceeds %d-entry safety limit", path, maxEntries)
	}
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	return entries, nil
}
