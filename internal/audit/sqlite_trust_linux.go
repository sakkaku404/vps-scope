//go:build linux

package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// sqliteOpenPath anchors the database's immediate directory with an open file
// descriptor. SQLite can therefore read a live -wal/-shm beside the database,
// while replacement of any ancestor path cannot redirect the privileged
// audit to another file. The immediate directory and database must still be
// controlled by root (or by the non-root test runner) and not group/other
// writable.
func sqliteOpenPath(file *os.File, absolutePath string) (string, *os.File, error) {
	resolved, err := filepath.EvalSymlinks(absolutePath)
	if err != nil {
		return "", nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		return "", nil, err
	}
	current, err := os.Stat(resolved)
	if err != nil {
		return "", nil, err
	}
	if !os.SameFile(opened, current) {
		return "", nil, fmt.Errorf("database changed while it was being inspected")
	}
	if err := sqliteOwnerControlled(current, resolved); err != nil {
		return "", nil, err
	}
	directory := filepath.Dir(resolved)
	// #nosec G304 -- resolved is the canonical path of the already-open
	// database; the directory descriptor is subsequently checked for ownership,
	// writable permissions, and stable file identity before SQLite can use it.
	anchor, err := os.Open(directory)
	if err != nil {
		return "", nil, err
	}
	directoryInfo, err := anchor.Stat()
	if err != nil {
		_ = anchor.Close()
		return "", nil, err
	}
	if err := sqliteOwnerControlled(directoryInfo, directory); err != nil {
		_ = anchor.Close()
		return "", nil, err
	}
	anchored := fmt.Sprintf("/proc/self/fd/%d/%s", anchor.Fd(), filepath.Base(resolved))
	anchoredInfo, err := os.Stat(anchored)
	if err != nil || !os.SameFile(opened, anchoredInfo) {
		_ = anchor.Close()
		return "", nil, fmt.Errorf("database identity changed while anchoring its directory")
	}
	return anchored, anchor, nil
}

func sqliteOwnerControlled(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine owner: %s", path)
	}
	euid := int64(os.Geteuid())
	if int64(stat.Uid) != euid && stat.Uid != 0 {
		return fmt.Errorf("not controlled by the audit user: %s", path)
	}
	if info.Mode().Perm()&0o022 == 0 {
		return nil
	}
	return fmt.Errorf("group/other writable: %s", path)
}
