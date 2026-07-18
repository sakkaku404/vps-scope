//go:build linux

package audit

import "syscall"

func diskFreePercent(path string) int {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil || stat.Blocks == 0 {
		return -1
	}
	percent, ok := ratioPercent(stat.Bavail, stat.Blocks)
	if !ok {
		return -1
	}
	return percent
}
