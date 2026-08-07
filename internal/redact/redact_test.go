package redact

import (
	"encoding/json"
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

func TestReportRedactsDeploymentWithoutBreakingTopologyLinks(t *testing.T) {
	count := 7
	in := model.Report{Deployment: &model.Deployment{
		Coverage: model.DeploymentCoverage{
			Configuration: "complete", Runtime: "complete", Firewall: "partial",
			Panels: "complete", ReverseProxy: "complete", Docker: "not-applicable",
		},
		Components: []model.Component{{
			ID: "component:0123456789abcdef", Product: "registry.secret.example.net/proxy",
			Kind: "proxy-core", Source: "/home/alice/secret.example.net/config.json",
			Deployment: "network=198.51.100.7", Confidence: "confirmed",
		}},
		Endpoints: []model.ServiceEndpoint{{
			ID: "endpoint:0123456789abcdef", ComponentID: "component:0123456789abcdef",
			Product: "panel.secret.example.net", Role: "management", Protocol: "api.secret.example.net",
			Transport: "tcp", Port: 8443, Address: "198.51.100.8", Process: "proxy for secret.example.net",
			Security: "certificate=secret.example.net", Firewall: "source=198.51.100.9",
			State: "live", Judgment: "routes to secret.example.net", Source: "/home/bob/secret.example.net",
			Confidence: "confirmed", ConnectionCount: &count,
		}},
		Links: []model.TopologyLink{{From: "component:0123456789abcdef", To: "endpoint:0123456789abcdef", Kind: "declares"}},
	}}
	out := New().Report(in)
	if out.Deployment == nil || out.Deployment == in.Deployment {
		t.Fatal("deployment was not deep-copied")
	}
	component, endpoint, link := out.Deployment.Components[0], out.Deployment.Endpoints[0], out.Deployment.Links[0]
	if component.ID != in.Deployment.Components[0].ID || endpoint.ID != in.Deployment.Endpoints[0].ID || endpoint.ComponentID != component.ID {
		t.Fatalf("topology IDs changed: component=%q endpoint=%q reference=%q", component.ID, endpoint.ID, endpoint.ComponentID)
	}
	if link.From != component.ID || link.To != endpoint.ID || link.Kind != "declares" {
		t.Fatalf("topology link changed: %+v", link)
	}
	combined := strings.Join([]string{
		component.Product, component.Source, component.Deployment,
		endpoint.Product, endpoint.Protocol, endpoint.Address, endpoint.Process,
		endpoint.Security, endpoint.Firewall, endpoint.Judgment, endpoint.Source,
	}, " ")
	for _, sensitive := range []string{"secret.example.net", "198.51.100.7", "198.51.100.8", "198.51.100.9", "/home/alice", "/home/bob"} {
		if strings.Contains(combined, sensitive) {
			t.Fatalf("deployment value %q survived redaction: %q", sensitive, combined)
		}
	}
	if out.Deployment.Endpoints[0].ConnectionCount == in.Deployment.Endpoints[0].ConnectionCount {
		t.Fatal("connection count pointer was not deep-copied")
	}
	if in.Deployment.Components[0].Product != "registry.secret.example.net/proxy" || in.Deployment.Endpoints[0].Address != "198.51.100.8" {
		t.Fatal("input deployment was mutated")
	}
}

func TestReportRedactsCredentialCorpus(t *testing.T) {
	privateKey := "-----BEGIN PRIVATE KEY-----\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n-----END PRIVATE KEY-----"
	values := []string{
		"password=hunter2",
		"passwd: 'swordfish'",
		`{"token":"tok_AbCd1234567890"}`,
		`{\"token\":\"escaped_AbCd123456\"}`,
		"secret = topSecret987654",
		"api_key=sk_live_51AbCdEfGh123456",
		`private-key: "pK_AbCd1234567890"`,
		"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
		"Bearer ghp_AbCd12345678901234567890",
		"https://alice:s3cr3t@example.net/path",
		"https://example.net/api?token=qwerty123456789&sig=abcdef123456789",
		"https://example.net/subscription/AbCdEf0123456789_-",
		privateKey,
	}
	evidence := make([]model.Evidence, len(values))
	for i, value := range values {
		evidence[i] = model.Evidence{Value: value}
	}
	in := model.Report{
		Metadata: map[string]string{"authorization": "Basic dXNlcjpwYXNz", "status": "enabled"},
		Findings: []model.Finding{{
			Facts:    map[string]string{"password": "abc", "private_key": "present", "token_state": "configured"},
			Evidence: evidence,
		}},
	}
	out := New().Report(in)
	if got := out.Findings[0].Facts["password"]; got == "abc" || !strings.HasPrefix(got, "CREDENTIAL_") {
		t.Fatalf("structured short password was not redacted: %q", got)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"hunter2", "swordfish", "tok_AbCd1234567890", "escaped_AbCd123456", "topSecret987654",
		"sk_live_51AbCdEfGh123456", "pK_AbCd1234567890",
		"eyJhbGciOiJIUzI1NiJ9.payload.signature", "ghp_AbCd12345678901234567890",
		"alice:s3cr3t", "qwerty123456789", "abcdef123456789", "AbCdEf0123456789_-",
		"dXNlcjpwYXNz", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
	} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("credential %q survived redaction: %s", secret, data)
		}
	}
	if err := ValidateNoResidualCredentials(string(data)); err != nil {
		t.Fatalf("redacted corpus failed residual validation: %v\n%s", err, data)
	}
}

func TestCredentialRedactionPreservesOrdinaryTechnicalLanguage(t *testing.T) {
	input := strings.Join([]string{
		"password authentication is disabled",
		"password=disabled",
		"token bucket rate limiting",
		"secret scanning enabled",
		"api_key permissions are 0600",
		"private_key=present",
		"authorization: required",
		"Bearer authentication",
		"https://github.com/docs?token=disabled",
		"/subscription/documentation-guide",
	}, " | ")
	if got := New().text(input); got != input {
		t.Fatalf("ordinary technical language changed:\n got: %q\nwant: %q", got, input)
	}
}

func TestResidualCredentialValidationRejectsSuspiciousPatterns(t *testing.T) {
	for _, value := range []string{
		`{"password":"hunter2"}`,
		`{\"token\":\"escaped_AbCd123456\"}`,
		`{"header":"Bearer abc.def.ghi"}`,
		`{"url":"https://alice:secret@example.net/"}`,
		`{"url":"https://example.net/?api_key=raw-secret"}`,
		`{"path":"/sub/AbCdEf0123456789_-"}`,
		`{"key":"-----BEGIN PRIVATE KEY-----"}`,
	} {
		if err := ValidateNoResidualCredentials(value); err == nil {
			t.Fatalf("residual credential was accepted: %s", value)
		}
	}
	if err := ValidateNoResidualCredentials(`{"password":"CREDENTIAL_1","header":"Bearer CREDENTIAL_2","path":"/sub/SUBSCRIPTION_1"}`); err != nil {
		t.Fatalf("redaction placeholders were rejected: %v", err)
	}
}
