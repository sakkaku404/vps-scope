package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"sort"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type mapFileEvidenceSource struct {
	files      map[string]string
	links      map[string]string
	linkErrors map[string]error
	dirs       map[string][]fs.DirEntry
}

func (s mapFileEvidenceSource) ReadSmall(path string, limit int64) (string, error) {
	value, ok := s.files[path]
	if !ok {
		return "", fs.ErrNotExist
	}
	if int64(len(value)) > limit {
		return "", fs.ErrInvalid
	}
	return value, nil
}

func (s mapFileEvidenceSource) Stat(path string) (fs.FileInfo, error) {
	value, ok := s.files[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fixtureSizedFileInfo{name: path, size: int64(len(value))}, nil
}

func (s mapFileEvidenceSource) Lstat(path string) (fs.FileInfo, error) { return s.Stat(path) }
func (s mapFileEvidenceSource) Readlink(path string) (string, error) {
	if err := s.linkErrors[path]; err != nil {
		return "", err
	}
	value, ok := s.links[path]
	if !ok {
		return "", fs.ErrNotExist
	}
	return value, nil
}
func (s mapFileEvidenceSource) ReadDirectory(path string, limit int) ([]fs.DirEntry, error) {
	entries, ok := s.dirs[path]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if len(entries) > limit {
		return nil, fs.ErrInvalid
	}
	return append([]fs.DirEntry(nil), entries...), nil
}

type fixtureSizedFileInfo struct {
	name string
	size int64
}

func (i fixtureSizedFileInfo) Name() string     { return i.name }
func (i fixtureSizedFileInfo) Size() int64      { return i.size }
func (fixtureSizedFileInfo) Mode() fs.FileMode  { return 0o600 }
func (fixtureSizedFileInfo) ModTime() time.Time { return time.Unix(1, 0) }
func (fixtureSizedFileInfo) IsDir() bool        { return false }
func (fixtureSizedFileInfo) Sys() any           { return nil }

type fixtureDirEntry struct {
	name  string
	isDir bool
}

type deadlineObservingCommander struct {
	base        *scenarioCommander
	sawDeadline bool
}

func (c *deadlineObservingCommander) Exists(name string) bool { return c.base.Exists(name) }
func (c *deadlineObservingCommander) Run(timeout time.Duration, name string, args ...string) CommandResult {
	return c.base.Run(timeout, name, args...)
}
func (c *deadlineObservingCommander) RunContext(ctx context.Context, timeout time.Duration, name string, args ...string) CommandResult {
	if _, ok := ctx.Deadline(); ok {
		c.sawDeadline = true
	}
	return c.base.Run(timeout, name, args...)
}

func (entry fixtureDirEntry) Name() string { return entry.name }
func (entry fixtureDirEntry) IsDir() bool  { return entry.isDir }
func (entry fixtureDirEntry) Type() fs.FileMode {
	return map[bool]fs.FileMode{true: fs.ModeDir}[entry.isDir]
}
func (entry fixtureDirEntry) Info() (fs.FileInfo, error) {
	return fixtureSizedFileInfo{name: entry.name}, nil
}

func TestRunProducesFullSemanticContractFromIncompleteLinuxSnapshot(t *testing.T) {
	commander := newScenarioCommander(nil, map[string]CommandResult{
		scenarioCommandKey("uname", "-r"): {Stdout: "6.12.0-fixture"},
		scenarioCommandKey("uname", "-m"): {Stdout: "x86_64"},
	})
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	nowCalls := 0
	report, err := runForPlatform(Options{
		Locale: "en", Profile: "general", LogSince: 24 * time.Hour,
		Commander: commander, Build: Build{Version: "dev", Commit: "fixture"},
		Now: func() time.Time {
			value := now.Add(time.Duration(nowCalls) * time.Second)
			nowCalls++
			return value
		},
		hostname:     func() (string, error) { return "fixture-host", nil },
		effectiveUID: func() int { return 0 },
		fileSource: mapFileEvidenceSource{files: map[string]string{
			"/etc/os-release": `ID=ubuntu
VERSION_ID="24.04"
`,
			"/etc/machine-id": "fixture-machine-id\n",
			"/etc/passwd":     "root:x:0:0:root:/root:/bin/bash\n",
		}},
	}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if nowCalls != 2 || !report.StartedAt.Equal(now) || !report.FinishedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("audit clock calls=%d started=%s finished=%s", nowCalls, report.StartedAt, report.FinishedAt)
	}
	if report.Host.Hostname != "fixture-host" || !report.Host.IsRoot || report.Host.StableID != "d6a2440ebcbf3a0b" {
		t.Fatalf("injected host identity was not preserved: %+v", report.Host)
	}
	if len(report.Findings) != len(StableCheckIDs) {
		t.Fatalf("findings=%d stable IDs=%d", len(report.Findings), len(StableCheckIDs))
	}
	if failures := ValidateReport(report); len(failures) != 0 {
		t.Fatalf("semantic failures=%v", failures)
	}
	if report.Metadata["collector_command_requests"] == "" || report.Metadata["collector_lookup_requests"] == "" {
		t.Fatalf("collector snapshot metrics missing: %+v", report.Metadata)
	}
	for _, key := range []string{"collector_contract_repairs", "collector_command_budget_rejections", "collector_file_budget_rejections", "collector_topology_budget_rejections"} {
		if report.Metadata[key] != "0" {
			t.Fatalf("unexpected %s=%q", key, report.Metadata[key])
		}
	}
	var unsupportedPasses []string
	for _, finding := range report.Findings {
		if finding.Status == "PASS" && finding.ID != "ACC-001" && finding.ID != "SYS-001" {
			unsupportedPasses = append(unsupportedPasses, finding.ID)
		}
	}
	sort.Strings(unsupportedPasses)
	if len(unsupportedPasses) > 0 {
		t.Fatalf("evidence-starved full audit produced unsupported PASS findings: %v", unsupportedPasses)
	}
}

func TestRunRejectsNonLinuxBeforeCollectingEvidence(t *testing.T) {
	if _, err := runForPlatform(Options{}, "windows"); err == nil {
		t.Fatal("non-Linux platform accepted")
	}
}

func TestRunAppliesAuditDeadlineToCollectorContext(t *testing.T) {
	commander := &deadlineObservingCommander{base: newScenarioCommander(nil, map[string]CommandResult{
		scenarioCommandKey("uname", "-r"): {Stdout: "6.12.0-fixture"},
		scenarioCommandKey("uname", "-m"): {Stdout: "x86_64"},
	})}
	_, err := runForPlatform(Options{
		Locale: "en", Profile: "general", AuditTimeout: 30 * time.Second,
		Commander: commander, Build: Build{Version: "dev"},
		hostname: func() (string, error) { return "fixture", nil }, effectiveUID: func() int { return 0 },
		fileSource: mapFileEvidenceSource{files: map[string]string{
			"/etc/os-release": "ID=debian\nVERSION_ID=13\n", "/etc/machine-id": "fixture\n",
			"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
		}},
	}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if !commander.sawDeadline {
		t.Fatal("collector command did not receive the overall audit deadline")
	}
}

func TestRunPreservesCompletedEvidenceAndMarksRemainingChecksUnknownAtOwnDeadline(t *testing.T) {
	commander := newScenarioCommander(nil, map[string]CommandResult{
		scenarioCommandKey("uname", "-r"): {Stdout: "6.12.0-fixture"},
		scenarioCommandKey("uname", "-m"): {Stdout: "x86_64"},
	})
	var expire context.CancelCauseFunc
	report, err := runForPlatform(Options{
		Locale: "en", Profile: "general", AuditTimeout: 30 * time.Second,
		Commander: commander, Build: Build{Version: "dev"},
		hostname: func() (string, error) { return "fixture", nil }, effectiveUID: func() int { return 0 },
		fileSource: mapFileEvidenceSource{files: map[string]string{
			"/etc/os-release": "ID=debian\nVERSION_ID=13\n", "/etc/machine-id": "fixture\n",
			"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
		}},
		timeoutContext: func(parent context.Context, _ time.Duration, _ error) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancelCause(parent)
			expire = cancel
			return ctx, func() { cancel(context.Canceled) }
		},
		Progress: func(index, _ int, _ string) {
			if index == 1 {
				expire(errAuditDeadline)
			}
		},
	}, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if report.Metadata["collection_timed_out"] != "true" || report.Metadata["collector_contract_repairs"] != "0" {
		t.Fatalf("metadata=%+v", report.Metadata)
	}
	if len(report.Findings) != len(StableCheckIDs) {
		t.Fatalf("findings=%d want=%d", len(report.Findings), len(StableCheckIDs))
	}
	for _, finding := range report.Findings {
		if finding.Category == "system" {
			continue
		}
		if finding.Status != model.Unknown || !finding.Unavailable || finding.Error != "audit deadline reached before this check could run" {
			t.Fatalf("deadline finding=%+v", finding)
		}
	}
	if failures := ValidateReport(report); len(failures) != 0 {
		t.Fatalf("semantic failures=%v", failures)
	}
}

func TestRunDoesNotTurnOperatorCancellationIntoAReport(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	commander := newScenarioCommander(nil, map[string]CommandResult{
		scenarioCommandKey("uname", "-r"): {Stdout: "6.12.0-fixture"},
		scenarioCommandKey("uname", "-m"): {Stdout: "x86_64"},
	})
	_, err := runForPlatform(Options{
		Context: parent, Locale: "en", Profile: "general", Commander: commander, Build: Build{Version: "dev"},
		hostname: func() (string, error) { return "fixture", nil }, effectiveUID: func() int { return 0 },
		fileSource: mapFileEvidenceSource{files: map[string]string{
			"/etc/os-release": "ID=debian\nVERSION_ID=13\n", "/etc/machine-id": "fixture\n",
			"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
		}},
		Progress: func(int, int, string) { cancel() },
	}, "linux")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestRunFromSealedSnapshotIsByteDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	makeOptions := func() Options {
		return Options{
			Locale: "en", Profile: "general", LogSince: 24 * time.Hour,
			Commander: newScenarioCommander(nil, map[string]CommandResult{
				scenarioCommandKey("uname", "-r"): {Stdout: "6.12.0-fixture"},
				scenarioCommandKey("uname", "-m"): {Stdout: "x86_64"},
			}),
			Build: Build{Version: "dev", Commit: "fixture"}, Now: func() time.Time { return now },
			hostname: func() (string, error) { return "fixture-host", nil }, effectiveUID: func() int { return 1000 },
			fileSource: mapFileEvidenceSource{files: map[string]string{
				"/etc/os-release": "ID=debian\nVERSION_ID=13\n", "/etc/machine-id": "fixture-machine-id\n",
				"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
			}},
		}
	}
	left, err := runForPlatform(makeOptions(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	right, err := runForPlatform(makeOptions(), "linux")
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftJSON, rightJSON) {
		t.Fatal("identical sealed evidence produced different canonical reports")
	}
	for _, finding := range left.Findings {
		if finding.ID == "SYS-001" && (finding.Status != model.Info || finding.Evidence[0].Value != "1000") {
			t.Fatalf("effective UID snapshot drifted: %+v", finding)
		}
	}
}

func TestRunRejectsCanceledContextBeforeCollectingEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runForPlatform(Options{Context: ctx}, "linux"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
}

func TestProcessExecutableChecksConsumeInjectedProcSnapshot(t *testing.T) {
	source := mapFileEvidenceSource{
		dirs: map[string][]fs.DirEntry{"/proc": {
			fixtureDirEntry{name: "101", isDir: true},
			fixtureDirEntry{name: "102", isDir: true},
			fixtureDirEntry{name: "self", isDir: true},
		}},
		links: map[string]string{
			"/proc/101/exe": "/tmp/miner (deleted)",
			"/proc/102/exe": "/usr/bin/nginx (deleted)",
		},
	}
	facts := newFactStoreAt(newScenarioCommander(nil, nil), false, time.Unix(1, 0), source)
	ctx := &Context{Facts: facts}

	deleted := checkDeletedExecutables(ctx)
	if deleted.Status != "RISK" || deleted.Facts["deleted_executables"] != "2" || deleted.Facts["security_relevant_deleted_executables"] != "1" {
		t.Fatalf("deleted=%+v", deleted)
	}
	temporary := checkTemporaryExecutables(ctx)
	if temporary.Status != "RISK" || temporary.Facts["temporary_executables"] != "1" {
		t.Fatalf("temporary=%+v", temporary)
	}
	stats := facts.FileStats()
	if stats.DirHits != 1 || stats.LinkHits != 2 {
		t.Fatalf("snapshot stats=%+v", stats)
	}
}

func TestProcessExecutableChecksTreatUnreadableLinksAsIncomplete(t *testing.T) {
	source := mapFileEvidenceSource{
		dirs:       map[string][]fs.DirEntry{"/proc": {fixtureDirEntry{name: "101", isDir: true}}},
		linkErrors: map[string]error{"/proc/101/exe": fs.ErrPermission},
	}
	facts := newFactStoreAt(newScenarioCommander(nil, nil), false, time.Unix(1, 0), source)
	ctx := &Context{Facts: facts}
	for _, finding := range []model.Finding{checkDeletedExecutables(ctx), checkTemporaryExecutables(ctx)} {
		if finding.Status != model.Unknown || !finding.Unavailable || finding.Facts["evidence_discovery_incomplete"] != "true" {
			t.Fatalf("finding=%+v", finding)
		}
	}
}

func BenchmarkRunFromDeterministicIncompleteSnapshot(b *testing.B) {
	source := mapFileEvidenceSource{files: map[string]string{
		"/etc/os-release": "ID=debian\nVERSION_ID=13\n",
		"/etc/machine-id": "benchmark-machine-id\n",
		"/etc/passwd":     "root:x:0:0:root:/root:/bin/bash\n",
	}}
	now := time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC)
	b.ReportAllocs()
	for b.Loop() {
		commander := newScenarioCommander(nil, map[string]CommandResult{
			scenarioCommandKey("uname", "-r"): {Stdout: "6.12.0-benchmark"},
			scenarioCommandKey("uname", "-m"): {Stdout: "x86_64"},
		})
		if _, err := runForPlatform(Options{
			Locale: "en", Profile: "general", LogSince: 24 * time.Hour,
			Commander: commander, Build: Build{Version: "dev"},
			Now: func() time.Time { return now }, fileSource: source,
			hostname: func() (string, error) { return "benchmark-host", nil }, effectiveUID: func() int { return 0 },
		}, "linux"); err != nil {
			b.Fatal(err)
		}
	}
}
