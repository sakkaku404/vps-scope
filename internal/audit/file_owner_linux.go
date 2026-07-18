//go:build linux

package audit

import (
	"fmt"
	"io/fs"
	"syscall"
)

func fileOwnerUID(info fs.FileInfo) (int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("owner metadata unavailable")
	}
	return int(stat.Uid), nil
}
