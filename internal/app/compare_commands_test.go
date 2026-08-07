package app

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadReportRejectsSemanticCorruption(t *testing.T) {
	r := appContractReport()
	r.Summary.Pass++
	path := filepath.Join(t.TempDir(), "corrupt.json")
	writeJSONReport(t, path, r)

	_, err := readReport(path)
	if err == nil || !strings.Contains(err.Error(), "semantic validation failed") || !strings.Contains(err.Error(), "summary does not match findings") {
		t.Fatalf("err=%v", err)
	}
}

func TestDiffRejectsReportsFromDifferentStableHosts(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.json")
	newPath := filepath.Join(dir, "new.json")
	oldReport := appContractReport()
	newReport := appContractReport()
	newReport.Host.StableID = "different-machine"
	newReport.Host.Hostname = "different-host"
	writeJSONReport(t, oldPath, oldReport)
	writeJSONReport(t, newPath, newReport)

	var out bytes.Buffer
	err := Run([]string{"diff", oldPath, newPath}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "different hosts") {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func TestFleetKeepsCrossHostComparison(t *testing.T) {
	dir := t.TempDir()
	paths := make([]string, 0, 2)
	for _, identity := range []struct{ stableID, hostname string }{{"machine-a", "host-a"}, {"machine-b", "host-b"}} {
		r := appContractReport()
		r.Host.StableID = identity.stableID
		r.Host.Hostname = identity.hostname
		path := filepath.Join(dir, identity.hostname+".json")
		writeJSONReport(t, path, r)
		paths = append(paths, path)
	}

	args := append([]string{"fleet"}, paths...)
	var out bytes.Buffer
	if err := Run(args, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
	for _, hostname := range []string{"host-a", "host-b"} {
		if !strings.Contains(out.String(), hostname) {
			t.Fatalf("fleet output missing %s: %s", hostname, out.String())
		}
	}
}
