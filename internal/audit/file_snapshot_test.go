package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingFileEvidence struct {
	mu         sync.Mutex
	reads      int
	links      int
	stats      int
	lstats     int
	readValue  string
	readErr    error
	statErr    error
	panicReads bool
	lastLimit  int64
}

func (s *recordingFileEvidence) ReadSmall(_ string, limit int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	s.lastLimit = limit
	if s.panicReads {
		panic("private file content")
	}
	return s.readValue, s.readErr
}
func (s *recordingFileEvidence) Readlink(string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.links++
	return s.readValue, s.readErr
}
func (s *recordingFileEvidence) Stat(string) (fs.FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats++
	return fixtureFileInfo{name: "fixture"}, s.statErr
}
func (s *recordingFileEvidence) Lstat(string) (fs.FileInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lstats++
	return fixtureFileInfo{name: "fixture"}, s.statErr
}
func (s *recordingFileEvidence) ReadDirectory(string, int) ([]fs.DirEntry, error) {
	return nil, fs.ErrNotExist
}

type fixtureFileInfo struct{ name string }

func (i fixtureFileInfo) Name() string     { return i.name }
func (fixtureFileInfo) Size() int64        { return 1 }
func (fixtureFileInfo) Mode() fs.FileMode  { return 0o600 }
func (fixtureFileInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (fixtureFileInfo) IsDir() bool        { return false }
func (fixtureFileInfo) Sys() any           { return nil }

func TestFileEvidenceSnapshotReusesReadsAndMetadata(t *testing.T) {
	source := &recordingFileEvidence{readValue: "snapshot"}
	snapshot := newFileEvidenceSnapshot(source)
	for range 3 {
		if value, err := snapshot.ReadSmall("/etc/fixture", 1024); err != nil || value != "snapshot" {
			t.Fatalf("value=%q err=%v", value, err)
		}
		if _, err := snapshot.Stat("/etc/fixture"); err != nil {
			t.Fatal(err)
		}
		if _, err := snapshot.Lstat("/etc/fixture"); err != nil {
			t.Fatal(err)
		}
		if value, err := snapshot.Readlink("/proc/1/exe"); err != nil || value != "snapshot" {
			t.Fatalf("link=%q err=%v", value, err)
		}
	}
	if source.reads != 1 || source.links != 1 || source.stats != 1 || source.lstats != 1 {
		t.Fatalf("source calls: reads=%d links=%d stats=%d lstats=%d", source.reads, source.links, source.stats, source.lstats)
	}
	stats := snapshot.Stats()
	if stats.ReadRequests != 3 || stats.ReadHits != 2 || stats.LinkRequests != 3 || stats.LinkHits != 2 || stats.StatHits != 2 || stats.LstatHits != 2 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestFileEvidenceSnapshotSharesOnePathAcrossCallerLimitsAndContainsPanics(t *testing.T) {
	source := &recordingFileEvidence{readValue: "snapshot"}
	snapshot := newFileEvidenceSnapshot(source)
	if value, err := snapshot.ReadSmall("/etc/fixture", 100); err != nil || value != "snapshot" {
		t.Fatalf("first value=%q err=%v", value, err)
	}
	if value, err := snapshot.ReadSmall("/etc/fixture", 4); err == nil || value != "" || !strings.Contains(err.Error(), "larger than 4 bytes") {
		t.Fatalf("bounded value=%q err=%v", value, err)
	}
	if source.reads != 1 || source.lastLimit != maxSnapshotFileReadBytes {
		t.Fatalf("reads=%d", source.reads)
	}
	panicking := newFileEvidenceSnapshot(&recordingFileEvidence{panicReads: true})
	for range 2 {
		if _, err := panicking.ReadSmall("/secret", 10); err != fs.ErrInvalid {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestFileEvidenceSnapshotReusesDirectoryViewAndEnforcesCallerBudget(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := newFileEvidenceSnapshot(osFileEvidenceSource{})
	if entries, err := snapshot.ReadDirectory(root, 4); err != nil || len(entries) != 3 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	if _, err := snapshot.ReadDirectory(root, 2); !errors.Is(err, errFileDiscoveryLimit) {
		t.Fatalf("err=%v", err)
	}
	stats := snapshot.Stats()
	if stats.DirRequests != 2 || stats.DirHits != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestFileEvidenceSnapshotEnforcesPerFileAndAggregateMemoryBudgets(t *testing.T) {
	source := &recordingFileEvidence{readValue: "snapshot"}
	snapshot := newFileEvidenceSnapshot(source)
	snapshot.retainedBytes = maxFileSnapshotRetainedBytes - 1

	value, err := snapshot.ReadSmall("/var/log/auth.log", 100<<20)
	if !errors.Is(err, errFileSnapshotBudget) || value != "" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	if source.lastLimit != maxSnapshotFileReadBytes {
		t.Fatalf("source limit=%d", source.lastLimit)
	}
	if _, againErr := snapshot.ReadSmall("/var/log/auth.log", 100<<20); !errors.Is(againErr, errFileSnapshotBudget) {
		t.Fatalf("cached err=%v", againErr)
	}
	stats := snapshot.Stats()
	if stats.BudgetRejects != 1 || stats.ReadHits != 1 || stats.RetainedBytes != maxFileSnapshotRetainedBytes-1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestFileEvidenceSnapshotEnforcesAggregateDirectoryBudget(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "entry"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot := newFileEvidenceSnapshot(osFileEvidenceSource{})
	snapshot.retainedDirectoryEntries = maxSnapshotDirectoryEntries

	if _, err := snapshot.ReadDirectory(root, 10); !errors.Is(err, errFileSnapshotBudget) {
		t.Fatalf("err=%v", err)
	}
	if _, err := snapshot.ReadDirectory(root, 10); !errors.Is(err, errFileSnapshotBudget) {
		t.Fatalf("cached err=%v", err)
	}
	stats := snapshot.Stats()
	if stats.BudgetRejects != 1 || stats.DirHits != 1 || stats.RetainedDirectoryEntries != maxSnapshotDirectoryEntries {
		t.Fatalf("stats=%+v", stats)
	}
}
