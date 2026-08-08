//go:build !linux

package audit

import "os"

func sqliteOpenPath(_ *os.File, absolutePath string) (string, *os.File, error) {
	// Live collection is Linux-only. Other platforms use this path solely for
	// deterministic unit tests and offline development.
	return absolutePath, nil, nil
}
