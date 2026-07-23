package redact

import (
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestReportStableTokens(t *testing.T) {
	in := model.Report{Host: model.Host{Hostname: "sgp.example.net", StableID: "abc"}, Findings: []model.Finding{{Evidence: []model.Evidence{{Source: "/opt/cert/sub.example.net.pem", Value: "1.2.3.4 sgp.example.net 1.2.3.4 127.0.0.1 /home/alice user=bob SHA256:AbCd123="}}}}}
	out := New().Report(in)
	if out.Host.Hostname != "HOST_1" {
		t.Fatalf("hostname=%q", out.Host.Hostname)
	}
	got := out.Findings[0].Evidence[0].Value
	if got != "IP_1 HOST_1 IP_1 127.0.0.1 /home/USER_1 user=USER_2 SSH_KEY_1" {
		t.Fatalf("redacted=%q", got)
	}
	if out.Findings[0].Evidence[0].Source != "/opt/cert/DOMAIN_1" {
		t.Fatalf("source=%q", out.Findings[0].Evidence[0].Source)
	}
	if out.Metadata["redacted"] != "true" {
		t.Fatal("missing redacted metadata")
	}
}

func TestReportRedactsFactsErrorsMetadataAndProfileReasons(t *testing.T) {
	in := model.Report{
		Profile:   model.Profile{Reasons: []string{"domain secret.example.net"}},
		Metadata:  map[string]string{"source": "198.51.100.23"},
		Endpoints: []model.Endpoint{{Protocol: "tcp", Port: 443, Family: "ipv4", Scope: "public", Process: "proxy at secret.example.net"}},
		Findings:  []model.Finding{{Facts: map[string]string{"target": "secret.example.net"}, Error: "connect 198.51.100.23 failed"}},
	}
	out := New().Report(in)
	combined := out.Profile.Reasons[0] + out.Metadata["source"] + out.Endpoints[0].Process + out.Findings[0].Facts["target"] + out.Findings[0].Error
	if strings.Contains(combined, "secret.example.net") || strings.Contains(combined, "198.51.100.23") {
		t.Fatalf("sensitive values survived redaction: %q", combined)
	}
}

func TestReportRedactsBareHostnameAndStableIDEverywhere(t *testing.T) {
	in := model.Report{
		Host:     model.Host{Hostname: "proxybox", StableID: "machine-opaque-id"},
		Findings: []model.Finding{{Facts: map[string]string{"owner": "proxybox"}, Evidence: []model.Evidence{{Value: "host=proxybox id=machine-opaque-id"}}}},
	}
	out := New().Report(in)
	combined := out.Findings[0].Facts["owner"] + out.Findings[0].Evidence[0].Value
	if strings.Contains(combined, "proxybox") || strings.Contains(combined, "machine-opaque-id") {
		t.Fatalf("host identity survived redaction: %q", combined)
	}
}

func TestReportRedactsStructuredAccountNamesAndModernUUIDs(t *testing.T) {
	in := model.Report{Findings: []model.Finding{
		{ID: "ACC-001", Evidence: []model.Evidence{{Key: "uid0_user", Value: "operator"}}},
		{ID: "ACC-003", Evidence: []model.Evidence{{Key: "password_bearing_login_account", Value: "deploy"}}},
		{ID: "WORK-003", Evidence: []model.Evidence{{Value: "019f4c1b-3c37-7eb1-9640-8889b25f08f4 owner@example.net"}}},
	}}
	out := New().Report(in)
	combined := out.Findings[0].Evidence[0].Value + " " + out.Findings[1].Evidence[0].Value + " " + out.Findings[2].Evidence[0].Value
	for _, sensitive := range []string{"operator", "deploy", "019f4c1b-3c37-7eb1-9640-8889b25f08f4", "owner@example.net"} {
		if strings.Contains(combined, sensitive) {
			t.Fatalf("sensitive value %q survived redaction: %q", sensitive, combined)
		}
	}
}
