package redact

import (
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
	if got != "IP_1 DOMAIN_2 IP_1 127.0.0.1 /home/USER_1 user=USER_2 SSH_KEY_1" {
		t.Fatalf("redacted=%q", got)
	}
	if out.Findings[0].Evidence[0].Source != "/opt/cert/DOMAIN_1" {
		t.Fatalf("source=%q", out.Findings[0].Evidence[0].Source)
	}
	if out.Metadata["redacted"] != "true" {
		t.Fatal("missing redacted metadata")
	}
}
