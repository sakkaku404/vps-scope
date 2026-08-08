package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/sakkaku404/vps-scope/internal/safefs"
)

const (
	maxSnapshotFileReadBytes     = 32 << 20
	maxFileSnapshotRetainedBytes = 64 << 20
	maxSnapshotDirectoryEntries  = 64 << 10
)

var errFileSnapshotBudget = errors.New("audit file snapshot memory budget exceeded")

type fileEvidenceSource interface {
	ReadSmall(string, int64) (string, error)
	Readlink(string) (string, error)
	Stat(string) (fs.FileInfo, error)
	Lstat(string) (fs.FileInfo, error)
	ReadDirectory(string, int) ([]fs.DirEntry, error)
}

type osFileEvidenceSource struct{}

func (osFileEvidenceSource) ReadSmall(path string, limit int64) (string, error) {
	return readSmall(path, limit)
}
func (osFileEvidenceSource) Readlink(path string) (string, error)   { return os.Readlink(path) }
func (osFileEvidenceSource) Stat(path string) (fs.FileInfo, error)  { return os.Stat(path) }
func (osFileEvidenceSource) Lstat(path string) (fs.FileInfo, error) { return os.Lstat(path) }
func (osFileEvidenceSource) ReadDirectory(path string, limit int) ([]fs.DirEntry, error) {
	entries, err := safefs.ReadDirectoryBounded(path, limit)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

type fileReadSnapshotEntry struct {
	ready chan struct{}
	value string
	err   error
}

type fileInfoSnapshotEntry struct {
	ready chan struct{}
	info  fs.FileInfo
	err   error
}

type directorySnapshotEntry struct {
	ready   chan struct{}
	entries []fs.DirEntry
	err     error
}

type fileEvidenceSnapshot struct {
	source                   fileEvidenceSource
	mu                       sync.Mutex
	reads                    map[string]*fileReadSnapshotEntry
	links                    map[string]*fileReadSnapshotEntry
	stats                    map[string]*fileInfoSnapshotEntry
	lstats                   map[string]*fileInfoSnapshotEntry
	dirs                     map[string]*directorySnapshotEntry
	readRequests             int
	readHits                 int
	linkRequests             int
	linkHits                 int
	statRequests             int
	statHits                 int
	lstatRequests            int
	lstatHits                int
	dirRequests              int
	dirHits                  int
	retainedBytes            int
	retainedDirectoryEntries int
	budgetRejects            int
}

type fileSnapshotStats struct {
	ReadRequests             int
	ReadHits                 int
	LinkRequests             int
	LinkHits                 int
	StatRequests             int
	StatHits                 int
	LstatRequests            int
	LstatHits                int
	DirRequests              int
	DirHits                  int
	RetainedBytes            int
	RetainedDirectoryEntries int
	BudgetRejects            int
}

func newFileEvidenceSnapshot(source fileEvidenceSource) *fileEvidenceSnapshot {
	if source == nil {
		source = osFileEvidenceSource{}
	}
	return &fileEvidenceSnapshot{
		source: source,
		reads:  map[string]*fileReadSnapshotEntry{},
		links:  map[string]*fileReadSnapshotEntry{},
		stats:  map[string]*fileInfoSnapshotEntry{},
		lstats: map[string]*fileInfoSnapshotEntry{},
		dirs:   map[string]*directorySnapshotEntry{},
	}
}

func (s *fileEvidenceSnapshot) Readlink(path string) (string, error) {
	s.mu.Lock()
	s.linkRequests++
	if entry, ok := s.links[path]; ok {
		s.linkHits++
		s.mu.Unlock()
		<-entry.ready
		return entry.value, entry.err
	}
	entry := &fileReadSnapshotEntry{ready: make(chan struct{})}
	s.links[path] = entry
	s.mu.Unlock()
	value, readErr := snapshotReadlink(s.source, path)
	s.mu.Lock()
	if readErr == nil && len(value) > maxFileSnapshotRetainedBytes-s.retainedBytes {
		value, readErr = "", errFileSnapshotBudget
		s.budgetRejects++
	} else if readErr == nil {
		s.retainedBytes += len(value)
	}
	entry.value, entry.err = value, readErr
	close(entry.ready)
	s.mu.Unlock()
	return value, readErr
}

func (s *fileEvidenceSnapshot) ReadSmall(path string, limit int64) (string, error) {
	if limit < 0 {
		return "", fmt.Errorf("invalid file snapshot read limit")
	}
	if limit > maxSnapshotFileReadBytes {
		limit = maxSnapshotFileReadBytes
	}
	key := path
	s.mu.Lock()
	s.readRequests++
	if entry, ok := s.reads[key]; ok {
		s.readHits++
		s.mu.Unlock()
		<-entry.ready
		return boundedFileSnapshot(entry.value, entry.err, limit)
	}
	entry := &fileReadSnapshotEntry{ready: make(chan struct{})}
	s.reads[key] = entry
	s.mu.Unlock()
	// Capture one canonical bounded view per path. Reading the same path again
	// with a different caller limit could otherwise observe a replacement or
	// reload later in the audit. Individual callers still enforce their own
	// tighter limit below.
	value, readErr := snapshotReadSmall(s.source, path, maxSnapshotFileReadBytes)
	s.mu.Lock()
	if readErr == nil && len(value) > maxFileSnapshotRetainedBytes-s.retainedBytes {
		value, readErr = "", errFileSnapshotBudget
		s.budgetRejects++
	} else if readErr == nil {
		s.retainedBytes += len(value)
	}
	entry.value, entry.err = value, readErr
	close(entry.ready)
	s.mu.Unlock()
	return boundedFileSnapshot(value, readErr, limit)
}

func boundedFileSnapshot(value string, err error, limit int64) (string, error) {
	if err != nil {
		return "", err
	}
	if int64(len(value)) > limit {
		return "", fmt.Errorf("file larger than %d bytes", limit)
	}
	return value, nil
}

func (s *fileEvidenceSnapshot) Stat(path string) (fs.FileInfo, error) {
	return s.fileInfo(path, false)
}

func (s *fileEvidenceSnapshot) Lstat(path string) (fs.FileInfo, error) {
	return s.fileInfo(path, true)
}

func (s *fileEvidenceSnapshot) ReadDirectory(path string, limit int) ([]fs.DirEntry, error) {
	if limit <= 0 || limit > maxSnapshotDirectoryEntries {
		return nil, fmt.Errorf("invalid directory snapshot budget")
	}
	key := path
	s.mu.Lock()
	s.dirRequests++
	if entry, ok := s.dirs[key]; ok {
		s.dirHits++
		s.mu.Unlock()
		<-entry.ready
		return boundedDirectorySnapshot(entry.entries, entry.err, path, limit)
	}
	entry := &directorySnapshotEntry{ready: make(chan struct{})}
	s.dirs[key] = entry
	s.mu.Unlock()
	sourceLimit := fileDiscoveryEntryLimit
	if limit > sourceLimit {
		sourceLimit = limit
	}
	entries, readErr := snapshotReadDirectory(s.source, path, sourceLimit)
	s.mu.Lock()
	if readErr == nil && len(entries) > maxSnapshotDirectoryEntries-s.retainedDirectoryEntries {
		entries, readErr = nil, errFileSnapshotBudget
		s.budgetRejects++
	} else if readErr == nil {
		s.retainedDirectoryEntries += len(entries)
	}
	entry.entries, entry.err = entries, readErr
	close(entry.ready)
	s.mu.Unlock()
	return boundedDirectorySnapshot(entries, readErr, path, limit)
}

func boundedDirectorySnapshot(entries []fs.DirEntry, err error, path string, limit int) ([]fs.DirEntry, error) {
	if err != nil {
		return nil, err
	}
	if len(entries) > limit {
		return nil, fmt.Errorf("%w: directory %q exceeds the remaining %d-entry budget", errFileDiscoveryLimit, path, limit)
	}
	return append([]fs.DirEntry(nil), entries...), nil
}

func (s *fileEvidenceSnapshot) fileInfo(path string, link bool) (fs.FileInfo, error) {
	s.mu.Lock()
	entries := s.stats
	if link {
		entries = s.lstats
		s.lstatRequests++
	} else {
		s.statRequests++
	}
	if entry, ok := entries[path]; ok {
		if link {
			s.lstatHits++
		} else {
			s.statHits++
		}
		s.mu.Unlock()
		<-entry.ready
		return entry.info, entry.err
	}
	entry := &fileInfoSnapshotEntry{ready: make(chan struct{})}
	entries[path] = entry
	s.mu.Unlock()
	entry.info, entry.err = snapshotFileInfo(s.source, path, link)
	s.mu.Lock()
	close(entry.ready)
	s.mu.Unlock()
	return entry.info, entry.err
}

func (s *fileEvidenceSnapshot) Stats() fileSnapshotStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fileSnapshotStats{
		ReadRequests: s.readRequests, ReadHits: s.readHits,
		LinkRequests: s.linkRequests, LinkHits: s.linkHits,
		StatRequests: s.statRequests, StatHits: s.statHits,
		LstatRequests: s.lstatRequests, LstatHits: s.lstatHits,
		DirRequests: s.dirRequests, DirHits: s.dirHits,
		RetainedBytes: s.retainedBytes, RetainedDirectoryEntries: s.retainedDirectoryEntries, BudgetRejects: s.budgetRejects,
	}
}

func snapshotReadlink(source fileEvidenceSource, path string) (value string, err error) {
	defer func() {
		if recover() != nil {
			value, err = "", fs.ErrInvalid
		}
	}()
	return source.Readlink(path)
}

func snapshotReadDirectory(source fileEvidenceSource, path string, limit int) (entries []fs.DirEntry, err error) {
	defer func() {
		if recover() != nil {
			entries, err = nil, fs.ErrInvalid
		}
	}()
	entries, err = source.ReadDirectory(path, limit)
	if errors.Is(err, safefs.ErrDirectoryLimit) {
		return nil, fmt.Errorf("%w: %v", errFileDiscoveryLimit, err)
	}
	return entries, err
}

func snapshotReadSmall(source fileEvidenceSource, path string, limit int64) (value string, err error) {
	defer func() {
		if recover() != nil {
			value, err = "", fs.ErrInvalid
		}
	}()
	return source.ReadSmall(path, limit)
}

func snapshotFileInfo(source fileEvidenceSource, path string, link bool) (info fs.FileInfo, err error) {
	defer func() {
		if recover() != nil {
			info, err = nil, fs.ErrInvalid
		}
	}()
	if link {
		return source.Lstat(path)
	}
	return source.Stat(path)
}
