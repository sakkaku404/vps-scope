package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestLoadPolicyRejectsDuplicateJSONMembersWithoutEchoingName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	input := `{"schema_version":"1.0","schema_version":"secret-member","endpoints":[]}`
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadPolicy(path)
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON object member") {
		t.Fatalf("LoadPolicy error=%v", err)
	}
	if strings.Contains(err.Error(), "secret-member") {
		t.Fatal("error disclosed attacker-controlled JSON content")
	}
}

func TestPolicyValidationAndEndpointLookup(t *testing.T) {
	policy := &Policy{SchemaVersion: PolicySchemaVersion, Endpoints: []EndpointPolicy{
		{Port: 443, Protocol: "TCP", Role: "proxy-ingress", Exposure: "public", Families: []string{"ipv6", "ipv4"}},
		{Port: 2095, Protocol: "tcp", Role: "management", Exposure: "restricted", AllowedSources: []string{"192.0.2.0/24"}},
	}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	endpoint, ok := policy.Endpoint(443, "tcp6", "ipv6")
	if !ok || endpoint.Role != "proxy-ingress" {
		t.Fatalf("endpoint lookup = %#v, %v", endpoint, ok)
	}
	if policy.ExpectedPublicListeners()["443/tcp"] != true {
		t.Fatal("public proxy ingress was not added to expected listeners")
	}
	if !policy.ExpectedPublicListeners()["2095/tcp"] {
		t.Fatal("declared restricted listener was not recognized as expected runtime exposure")
	}
}

func TestPolicyRejectsInvalidSourceAndDuplicateRole(t *testing.T) {
	invalid := &Policy{SchemaVersion: PolicySchemaVersion, Endpoints: []EndpointPolicy{{Port: 443, Protocol: "tcp", Role: "proxy-ingress", Exposure: "public", AllowedSources: []string{"not a CIDR"}}}}
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid allowed source was accepted")
	}
	duplicate := &Policy{SchemaVersion: PolicySchemaVersion, Endpoints: []EndpointPolicy{
		{Port: 443, Protocol: "tcp", Role: "proxy-ingress", Exposure: "public"},
		{Port: 443, Protocol: "tcp", Role: "proxy-ingress", Exposure: "public"},
	}}
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate endpoint role was accepted")
	}
	duplicateSource := &Policy{SchemaVersion: PolicySchemaVersion, Endpoints: []EndpointPolicy{{Port: 22, Protocol: "tcp", Role: "ssh", Exposure: "restricted", AllowedSources: []string{"192.0.2.0/24", "192.0.2.0/24"}}}}
	if err := duplicateSource.Validate(); err == nil {
		t.Fatal("duplicate allowed source was accepted")
	}
	duplicateInterface := &Policy{SchemaVersion: PolicySchemaVersion, Egress: EgressPolicy{IPv4Interfaces: []string{"eth0", "eth0"}}}
	if err := duplicateInterface.Validate(); err == nil {
		t.Fatal("duplicate egress interface was accepted")
	}
}

func TestPolicyExposureSemantics(t *testing.T) {
	if !policyExposureMatches("restricted", "public-wildcard", "allow-restricted") {
		t.Fatal("restricted UFW disposition did not match restricted policy")
	}
	if policyExposureMatches("restricted", "public-wildcard", "allow-anywhere") {
		t.Fatal("allow-anywhere matched restricted policy")
	}
	if !policyExposureMatches("blocked", "public-wildcard", "blocked-by-default") {
		t.Fatal("blocked firewall disposition did not match blocked policy")
	}
}

func TestAdvisorySemanticVersionRanges(t *testing.T) {
	db, err := loadEmbeddedAdvisories()
	if err != nil {
		t.Fatal(err)
	}
	find := func(product string) advisory {
		t.Helper()
		for _, item := range db.Advisories {
			if item.Product == product {
				return item
			}
		}
		t.Fatalf("missing advisory for %s", product)
		return advisory{}
	}
	for _, tc := range []struct {
		product, version string
		want             bool
	}{
		{"3x-ui", "3.3.0", true}, {"3x-ui", "3.3.1", false},
		{"sing-box", "1.4.4", true}, {"sing-box", "1.4.5", false},
		{"sing-box", "1.5.0-beta.1", true}, {"sing-box", "1.5.0-rc.4", true}, {"sing-box", "1.5.0-rc.5", false},
		{"xray", "26.1.12", false}, {"xray", "26.7.11", true},
	} {
		version, ok := parseSemanticVersion(tc.version)
		if !ok {
			t.Fatalf("could not parse %s", tc.version)
		}
		if got := advisoryAffects(find(tc.product), version); got != tc.want {
			t.Errorf("%s %s affects=%v, want %v", tc.product, tc.version, got, tc.want)
		}
	}
	if normalizeAdvisoryProduct("x-ui/3x-ui") != "3x-ui" {
		t.Fatal("combined panel product name was not normalized")
	}
}

func TestEgressDNSModes(t *testing.T) {
	if !dnsModeMatches("loopback-only", []string{"127.0.0.53", "::1"}) {
		t.Fatal("loopback resolvers did not match loopback-only")
	}
	if dnsModeMatches("private-only", []string{"1.1.1.1"}) {
		t.Fatal("public resolver matched private-only")
	}
	if !dnsModeMatches("private-only", []string{"10.0.0.2", "127.0.0.53"}) {
		t.Fatal("private and loopback resolvers did not match private-only")
	}
}

func TestAdvisorySeverityRaisesRisk(t *testing.T) {
	finding := model.Finding{Status: model.Pass}
	raiseRisk(&finding, model.High)
	if finding.Status != model.Risk || finding.Severity != model.High {
		t.Fatalf("risk = %s/%s", finding.Status, finding.Severity)
	}
}

func TestActiveProxyProductsParsesFullProcessRows(t *testing.T) {
	cmd := newScenarioCommander([]string{"ps"}, map[string]CommandResult{
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "4740 root sing-box /usr/local/bin/sing-box\n"},
	})
	ctx := scenarioContext(cmd)
	products := activeProxyProducts(ctx)
	if !products["sing-box"] {
		t.Fatalf("active products = %#v", products)
	}
}

func TestAdvisoryCheckMatchesRunningVulnerableVersion(t *testing.T) {
	cmd := newScenarioCommander([]string{"ps", "sing-box"}, map[string]CommandResult{
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "4740 root sing-box /usr/local/bin/sing-box\n"},
		scenarioCommandKey("sing-box", "version"):                 {Stdout: "sing-box version 1.4.4\n"},
	})
	ctx := scenarioContext(cmd)
	ctx.Options.NativeSelfTest = true
	ctx.Facts = NewFactStore(cmd, true)
	finding := checkProxyAdvisories(ctx, nil)
	if finding.Status != model.Risk || finding.Severity != model.Critical || finding.Facts["matched_advisories"] != "1" {
		t.Fatalf("advisory finding = %#v", finding)
	}
}

func TestAdvisoryUsesManagedCoreBinaryAndDeduplicatesProducts(t *testing.T) {
	const xrayBinary = "/usr/local/x-ui/bin/xray-linux-amd64"
	cmd := newScenarioCommander([]string{"ps", xrayBinary}, map[string]CommandResult{
		scenarioCommandKey("ps", "-eo", "pid=,user=,comm=,args="): {Stdout: "1 root x-ui /usr/local/x-ui/x-ui\n2 root xray-linux-amd64 /usr/local/x-ui/bin/xray-linux-amd64 run"},
		scenarioCommandKey(xrayBinary, "version"):                 {Stdout: "Xray 26.6.27"},
	})
	ctx := scenarioContext(cmd)
	ctx.Options.NativeSelfTest = true
	ctx.Facts = NewFactStore(cmd, true)
	ctx.Facts.panelsOnce.Do(func() {
		ctx.Facts.panels = []panelSnapshot{{Product: "3x-ui", Version: "3.4.2"}, {Product: "x-ui/3x-ui", Version: "3.4.2"}}
	})
	finding := checkProxyAdvisories(ctx, []proxyConfigSummary{{Product: "Xray", Path: "/usr/local/x-ui/bin/config.json"}})
	if finding.Status != model.Risk || finding.Facts["products_checked"] != "2" || finding.Facts["unknown_product_versions"] != "0" {
		t.Fatalf("advisory finding=%#v, want two deduplicated products with complete versions and the bundled Xray match", finding)
	}
	if got := cmd.calls[scenarioCommandKey(xrayBinary, "version")]; got != 1 {
		t.Fatalf("managed Xray version calls=%d, want 1", got)
	}
}

func TestDeploymentPolicyPublicAndBlockedListener(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.Facts.listenersOnce.Do(func() {
		ctx.Facts.listeners = []Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: "22", Scope: "public-wildcard", Process: "sshd"}}
	})
	ctx.Facts.hostFirewallOnce.Do(func() {
		ctx.Facts.hostFirewall = parsePanelUFW("Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n22/tcp ALLOW IN Anywhere")
	})
	ctx.Policy = &Policy{SchemaVersion: PolicySchemaVersion, Endpoints: []EndpointPolicy{{Port: 22, Protocol: "tcp", Role: "ssh", Exposure: "public"}}}
	if finding := checkDeploymentPolicy(ctx); finding.Status != model.Pass {
		t.Fatalf("public policy = %#v", finding)
	}
	ctx.Policy.Endpoints[0].Exposure = "blocked"
	if finding := checkDeploymentPolicy(ctx); finding.Status != model.Risk || finding.Facts["policy_mismatches"] != "1" {
		t.Fatalf("blocked policy = %#v", finding)
	}
}
