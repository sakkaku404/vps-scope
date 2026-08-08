package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/redact"
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

func TestVersionAwareReportLoaderAcceptsAppendOnlyFutureID(t *testing.T) {
	r := appContractReport()
	r.ToolVersion = "2.0.0"
	r.Findings = append(r.Findings, model.Finding{
		ID: "WORK-999", Category: "workloads", Status: model.Info,
		ReasonCode: "work.999.future-inventory",
	})
	r.Recount()
	path := filepath.Join(t.TempDir(), "future.json")
	writeJSONReport(t, path, r)

	if _, err := readReport(path); err == nil || !strings.Contains(err.Error(), "unexpected check ID") {
		t.Fatalf("strict fixture reader accepted future ID or returned wrong error: %v", err)
	}
	env := environment{build: BuildInfo{Version: "1.5.0"}}
	if _, err := env.readReport(path); err != nil {
		t.Fatalf("version-aware loader rejected append-only future ID: %v", err)
	}
}

func TestUnknownReportExtensionsAreReadableButNeverSilentlyRewritten(t *testing.T) {
	dir := t.TempDir()
	payload, err := json.Marshal(appContractReport())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	document["future_private_extension"] = map[string]any{"access_token": "must-not-be-copied-or-dropped"}
	payload, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(dir, "future.json")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	env := environment{build: BuildInfo{Version: "1.0.0"}}
	if _, err := env.readReport(input); err != nil {
		t.Fatalf("read-only loader rejected an optional extension: %v", err)
	}

	markdown := filepath.Join(dir, "report.md")
	var out bytes.Buffer
	if err := Run([]string{"render", "--format", "markdown", "--output", markdown, input}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "1.0.0"}); err != nil {
		t.Fatalf("human renderer rejected an optional extension: %v", err)
	}
	for _, test := range []struct {
		name   string
		args   []string
		output string
	}{
		{"machine-readable render", []string{"render", "--format", "json", "--output", filepath.Join(dir, "copy.json"), input}, filepath.Join(dir, "copy.json")},
		{"redact", []string{"redact", "--output", filepath.Join(dir, "redacted.json"), input}, filepath.Join(dir, "redacted.json")},
		{"support", []string{"support", "--output", filepath.Join(dir, "support"), input}, filepath.Join(dir, "support")},
	} {
		t.Run(test.name, func(t *testing.T) {
			out.Reset()
			err := Run(test.args, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "1.0.0"})
			if err == nil || !strings.Contains(err.Error(), "cannot safely rewrite") {
				t.Fatalf("err=%v output=%s", err, out.String())
			}
			if _, statErr := os.Stat(test.output); !os.IsNotExist(statErr) {
				t.Fatalf("unsafe rewrite left output %q: %v", test.output, statErr)
			}
		})
	}
}

func TestReportReaderRejectsDuplicateMembersAtAnyDepth(t *testing.T) {
	payload, err := json.Marshal(appContractReport())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, body string
	}{
		{"top-level", strings.Replace(string(payload), `{`, `{"schema_version":"1.0",`, 1)},
		{"nested finding", strings.Replace(string(payload), `"id":"SYS-001"`, `"id":"SYS-001","id":"SYS-001"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "duplicate.json")
			if err := os.WriteFile(path, []byte(test.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readReport(path); err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
				t.Fatalf("err=%v", err)
			}
		})
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

func TestDiffRejectsIndependentlyRedactedReportsFromDifferentHosts(t *testing.T) {
	dir := t.TempDir()
	oldReport, newReport := appContractReport(), appContractReport()
	oldReport.Host.StableID, oldReport.Host.Hostname = "machine-a", "host-a"
	newReport.Host.StableID, newReport.Host.Hostname = "machine-b", "host-b"
	oldReport = redact.New().Report(oldReport)
	newReport = redact.New().Report(newReport)
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	writeJSONReport(t, oldPath, oldReport)
	writeJSONReport(t, newPath, newReport)

	var out bytes.Buffer
	err := Run([]string{"diff", oldPath, newPath}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "different hosts") {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func TestDiffRejectsLegacyRedactedHostPlaceholder(t *testing.T) {
	dir := t.TempDir()
	r := appContractReport()
	r.Host.StableID, r.Host.Hostname = "HOST_ID_1", "HOST_1"
	r.Metadata = map[string]string{"redacted": "true"}
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	writeJSONReport(t, oldPath, r)
	writeJSONReport(t, newPath, r)

	var out bytes.Buffer
	err := Run([]string{"diff", oldPath, newPath}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "non-unique host placeholder") {
		t.Fatalf("err=%v output=%s", err, out.String())
	}
}

func TestRedactRejectsLegacyNonUniqueHostPlaceholder(t *testing.T) {
	dir := t.TempDir()
	r := appContractReport()
	r.Host.StableID, r.Host.Hostname = "HOST_ID_1", "HOST_1"
	r.Metadata = map[string]string{"redacted": "true"}
	input, output := filepath.Join(dir, "legacy.json"), filepath.Join(dir, "new.json")
	writeJSONReport(t, input, r)

	var console bytes.Buffer
	err := Run([]string{"redact", "--output", output, input}, bytes.NewReader(nil), &console, &console, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "non-unique host placeholder") {
		t.Fatalf("err=%v output=%s", err, console.String())
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe rewritten report was created: %v", statErr)
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

func TestDiffLocalizesSemanticMessagesInRussianAndPersian(t *testing.T) {
	dir := t.TempDir()
	oldReport, newReport := appContractReport(), appContractReport()
	oldReport.Metadata, newReport.Metadata = map[string]string{"audit_depth": "standard"}, map[string]string{"audit_depth": "deep"}
	oldPath, newPath := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
	writeJSONReport(t, oldPath, oldReport)
	writeJSONReport(t, newPath, newReport)
	for _, test := range []struct{ locale, expected string }{
		{"ru-RU", "глубина аудита отличается"},
		{"fa-IR", "عمق ممیزی متفاوت است"},
	} {
		var out bytes.Buffer
		if err := Run([]string{"diff", "--lang", test.locale, oldPath, newPath}, bytes.NewReader(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), test.expected) {
			t.Fatalf("%s semantic diff was not localized: %s", test.locale, out.String())
		}
	}
}
