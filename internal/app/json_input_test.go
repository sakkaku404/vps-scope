package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadReportRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte(`{} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReport(path); err == nil || !strings.Contains(err.Error(), "unexpected data") {
		t.Fatalf("err=%v", err)
	}
}

func TestOpenLimitedJSONRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large.json")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxLocalJSONSize + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if _, err := openLimitedJSON(path); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err=%v", err)
	}
}
