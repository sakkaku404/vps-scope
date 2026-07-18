//go:build !linux

package audit

import "io/fs"

func fileOwnerUID(fs.FileInfo) (int, error) {
	// Production audits run on Linux. Other platforms retain deterministic
	// parser tests without pretending to expose Unix ownership metadata.
	return 0, nil
}
