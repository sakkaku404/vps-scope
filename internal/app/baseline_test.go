package app

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestBaselineStableInventoryAndDrift(t *testing.T) {
	r := model.Report{Host: model.Host{Hostname: "fixture", StableID: "machine-1"}, Findings: []model.Finding{
		{ID: "NET-001", Evidence: []model.Evidence{{Source: "ss", Value: `tcp 0.0.0.0:443 scope=public-wildcard process=users:(("sing-box",pid=123,fd=7))`}, {Source: "ss", Value: "tcp 127.0.0.1:53 scope=loopback"}}},
		{ID: "SSH-004", Evidence: []model.Evidence{{Key: "authorized_key", Value: "root SHA256:fixture ED25519"}}},
		{ID: "FW-002", Evidence: []model.Evidence{{Key: "allow_rule", Value: "443/tcp ALLOW IN Anywhere"}}},
	}}
	base := makeBaseline(r)
	if base.SchemaVersion != "vps-scope-baseline/v2" || base.StableID != "machine-1" {
		t.Fatalf("unexpected baseline identity: %#v", base)
	}
	if len(base.Items) != 3 {
		t.Fatalf("items=%d", len(base.Items))
	}
	added, removed := compareBaseline(base.Items, makeBaseline(r).Items)
	if len(added)+len(removed) != 0 {
		t.Fatal("identical report drifted")
	}
	r.Findings[0].Evidence[0].Value = `tcp 0.0.0.0:443 scope=public-wildcard process=users:(("sing-box",pid=456,fd=9))`
	added, removed = compareBaseline(base.Items, makeBaseline(r).Items)
	if len(added)+len(removed) != 0 {
		t.Fatal("PID/fd-only listener change caused drift")
	}
	r.Findings[0].Evidence[0].Value = "tcp 0.0.0.0:8443 scope=public-wildcard process=sing-box"
	added, removed = compareBaseline(base.Items, makeBaseline(r).Items)
	if len(added) != 1 || len(removed) != 1 {
		t.Fatalf("added=%d removed=%d", len(added), len(removed))
	}
}

func TestBaselineCreateRefusesOverwriteWithoutChangingExistingFile(t *testing.T) {
	output := filepath.Join(t.TempDir(), "baseline.json")
	args := []string{"baseline", "create", filepath.Join("testdata", "golden-report-v1.json"), output}
	var stdout bytes.Buffer
	if err := Run(args, bytes.NewReader(nil), &stdout, &stdout, BuildInfo{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run(args, bytes.NewReader(nil), &stdout, &stdout, BuildInfo{Version: "test"}); err == nil {
		t.Fatal("existing baseline was overwritten")
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("existing baseline changed after refused overwrite")
	}
}

func TestBaselineRejectsLegacyRedactedHostPlaceholder(t *testing.T) {
	dir := t.TempDir()
	r := appContractReport()
	r.Host.StableID, r.Host.Hostname = "HOST_ID_1", "HOST_1"
	r.Metadata = map[string]string{"redacted": "true"}
	reportPath := filepath.Join(dir, "report.json")
	baselinePath := filepath.Join(dir, "baseline.json")
	writeJSONReport(t, reportPath, r)

	var output bytes.Buffer
	err := Run([]string{"baseline", "create", reportPath, baselinePath}, bytes.NewReader(nil), &output, &output, BuildInfo{Version: "test"})
	if err == nil || !strings.Contains(err.Error(), "non-unique host placeholder") {
		t.Fatalf("err=%v output=%s", err, output.String())
	}
	if _, statErr := os.Stat(baselinePath); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe baseline was written: %v", statErr)
	}
}

func TestBaselineUsesTypedCurrentReportFacts(t *testing.T) {
	r := model.Report{
		Host:      model.Host{Hostname: "fixture", StableID: "machine-1"},
		Endpoints: []model.Endpoint{{Protocol: "tcp", Port: 443, Family: "ipv4", Scope: "public-wildcard", Process: `users:(("sing-box",pid=123,fd=7))`}},
		Deployment: &model.Deployment{
			Components: []model.Component{
				{ID: "component:0123456789abcdef", Product: "sing-box", Kind: "proxy-core", Runtime: true, Deployment: "native", Confidence: "confirmed"},
				{ID: "component:1123456789abcdef", Product: "3x-ui", Kind: "container", Runtime: true, Deployment: "bridge", Confidence: "confirmed"},
			},
			Endpoints: []model.ServiceEndpoint{
				{ID: "endpoint:0123456789abcdef", ComponentID: "component:0123456789abcdef", Product: "sing-box", Role: "proxy-ingress", Protocol: "vless", Transport: "tcp", Port: 443, Address: "0.0.0.0", Family: "ipv4", Scope: "public-wildcard"},
				{ID: "endpoint:1123456789abcdef", ComponentID: "component:1123456789abcdef", Product: "3x-ui", Role: "management", Transport: "tcp", Port: 2053, Address: "127.0.0.1", Family: "ipv4", Scope: "loopback"},
			},
		},
		Findings: []model.Finding{{ID: "WORK-002", Evidence: []model.Evidence{{Key: "management_endpoint", Value: "forged legacy text"}}}},
	}
	baseline := makeBaseline(r)
	joined := ""
	for _, item := range baseline.Items {
		joined += item.Kind + "=" + item.Value + "\n"
	}
	for _, want := range []string{"public_listener=", "proxy_service=", "container=", "proxy_endpoint=", "panel_endpoint="} {
		if !strings.Contains(joined, want) {
			t.Fatalf("typed baseline lacks %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "forged legacy text") {
		t.Fatalf("current report fell back to legacy evidence:\n%s", joined)
	}
	if strings.Contains(joined, "pid=") || strings.Contains(joined, "fd=") {
		t.Fatalf("typed baseline retained volatile process IDs:\n%s", joined)
	}
}

func TestReadBaselineRejectsUnknownUnsafeDuplicateAndOversizedInput(t *testing.T) {
	tests := []string{
		`{"schema_version":"vps-scope-baseline/v2","host":"fixture","stable_id":"machine-1","created_at":"2026-01-01T00:00:00Z","unknown":true,"items":[]}`,
		`{"schema_version":"vps-scope-baseline/v2","host":"fixture","stable_id":"machine-1","created_at":"2026-01-01T00:00:00Z","items":[{"kind":"ssh_key","value":"bad\u001b[31m"}]}`,
		`{"schema_version":"vps-scope-baseline/v2","host":"fixture","stable_id":"machine-1","created_at":"2026-01-01T00:00:00Z","items":[{"kind":"ssh_key","value":"same"},{"kind":"ssh_key","value":"same"}]}`,
		`{"schema_version":"vps-scope-baseline/v2","host":"fixture","stable_id":"","created_at":"2026-01-01T00:00:00Z","items":[]}`,
	}
	for index, body := range tests {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("bad-%d.json", index))
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBaseline(path); err == nil {
			t.Fatalf("case %d was accepted", index)
		}
	}
}
