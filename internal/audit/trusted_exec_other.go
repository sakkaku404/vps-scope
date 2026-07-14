//go:build !linux

package audit

import "fmt"

func verifyTrustedExecutable(path string) (string, error) {
	return "", fmt.Errorf("trusted workload execution is supported on Linux only: %s", path)
}
