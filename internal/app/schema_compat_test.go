package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoldenReportV1RemainsReadableAndStable(t *testing.T) {
	r, err := readReport(filepath.Join("testdata", "golden-report-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Host.StableID != "fixture-machine-id" || len(r.Findings) != 2 {
		t.Fatalf("unexpected golden report: host=%q findings=%d", r.Host.StableID, len(r.Findings))
	}
	baseline := makeBaseline(r)
	if baseline.SchemaVersion != "vps-scope-baseline/v2" || len(baseline.Items) != 2 {
		t.Fatalf("unexpected golden baseline: %#v", baseline)
	}
}

func TestReadReportRejectsUnknownSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"99.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readReport(path); err == nil || !strings.Contains(err.Error(), "unsupported report schema") {
		t.Fatalf("err=%v", err)
	}
}

func TestBaselineV1AndV2Compatibility(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct {
		name, body string
	}{
		{"v1", `{"schema_version":"vps-scope-baseline/v1","host":"fixture","created_at":"2026-01-01T00:00:00Z","items":[]}`},
		{"v2", `{"schema_version":"vps-scope-baseline/v2","host":"fixture","stable_id":"machine-1","created_at":"2026-01-01T00:00:00Z","items":[]}`},
	} {
		path := filepath.Join(dir, test.name+".json")
		if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
			t.Fatal(err)
		}
		doc, err := readBaseline(path)
		if err != nil || doc.SchemaVersion == "" {
			t.Fatalf("%s: doc=%#v err=%v", test.name, doc, err)
		}
	}
}
