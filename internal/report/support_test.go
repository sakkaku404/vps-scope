package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestSupportBundleIsRedactedAndVerifiable(t *testing.T) {
	r := model.Report{
		SchemaVersion: "1.0", ToolVersion: "test",
		Host:    model.Host{Hostname: "panel.secret.example", StableID: "machine-secret", OS: "debian", OSVersion: "13", Architecture: "x86_64"},
		Profile: model.Profile{Effective: "proxy"},
		Findings: []model.Finding{
			{ID: "WORK-001", Status: model.Info, Facts: map[string]string{"products": "S-UI,sing-box"}},
			{ID: "WORK-002", Status: model.Risk, ReasonCode: "work.002.public-plaintext-management", Facts: map[string]string{"target": "198.51.100.22"}, Evidence: []model.Evidence{{Key: "product", Value: "product=S-UI version=1.5.3 adapter=native schema=1 schema_supported=true schema_fingerprint=abc capabilities=config,listener binary=/secret"}, {Value: "uuid=550e8400-e29b-41d4-a716-446655440000 host=panel.secret.example"}}},
		},
	}
	dir := filepath.Join(t.TempDir(), "support")
	manifest, err := SupportBundle(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != SupportSchema || len(manifest.Files) != 3 {
		t.Fatalf("manifest=%#v", manifest)
	}
	_, failures, err := VerifyBundle(dir)
	if err != nil || len(failures) != 0 {
		t.Fatalf("verify err=%v failures=%v", err, failures)
	}
	data, err := os.ReadFile(filepath.Join(dir, "report.redacted.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"198.51.100.22", "panel.secret.example", "machine-secret", "550e8400-e29b-41d4-a716-446655440000"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("secret %q survived: %s", secret, data)
		}
	}
	compatData, err := os.ReadFile(filepath.Join(dir, "compatibility.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snapshot SupportSnapshot
	if err := json.Unmarshal(compatData, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Panels) != 1 || snapshot.Panels[0].Product != "S-UI" || snapshot.Panels[0].SchemaFingerprint != "abc" {
		t.Fatalf("snapshot=%#v", snapshot)
	}
}

func TestSupportBundleRefusesOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := SupportBundle(dir, model.Report{}); err == nil {
		t.Fatal("expected existing directory to be rejected")
	}
}
