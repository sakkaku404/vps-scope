//go:build linux

package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveSystemExecutablePreservesInvocationSymlink(t *testing.T) {
	for _, name := range []string{"iptables-save", "ip6tables-save"} {
		path, err := resolveSystemExecutable(name)
		if err != nil {
			continue // Minimal CI images need not install iptables.
		}
		if filepath.Base(path) != name {
			t.Fatalf("%s resolved to invocation path %q; argv[0] would be lost", name, path)
		}
	}
}

func TestCommanderPreservesIPTablesMulticallArgv0(t *testing.T) {
	cmd := OSCommander{}
	if !cmd.Exists("iptables-save") {
		t.Skip("iptables-save is not installed")
	}
	r := cmd.Run(5*time.Second, "iptables-save", "--version")
	if r.Err != nil || !strings.Contains(strings.ToLower(r.Stdout+r.Stderr), "iptables-save") {
		t.Fatalf("iptables-save multicall dispatch failed: err=%v stdout=%q stderr=%q", r.Err, r.Stdout, r.Stderr)
	}
}
