package safefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDirectoryBoundedRejectsOverflowWithoutPartialEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := ReadDirectoryBounded(dir, 2)
	if err == nil || !strings.Contains(err.Error(), "2-entry safety limit") {
		t.Fatalf("error=%v, want directory limit", err)
	}
	if entries != nil {
		t.Fatalf("partial entries escaped on overflow: %v", entries)
	}
}

func TestReadDirectoryBoundedRejectsInvalidBudget(t *testing.T) {
	if entries, err := ReadDirectoryBounded(t.TempDir(), 0); err == nil || entries != nil {
		t.Fatalf("entries=%v error=%v", entries, err)
	}
}
