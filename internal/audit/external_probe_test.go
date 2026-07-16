package audit

import (
	"context"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type fakeExternalProber struct {
	observations map[string]externalObservation
}

func (f fakeExternalProber) Observe(_ context.Context, domain string) externalObservation {
	return f.observations[domain]
}

func TestExternalExposureIsDisabledByDefault(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	finding := checkExternalExposure(ctx)
	if finding.Status != model.Info || !finding.NotApplicable {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestExternalExposureCDNExpectation(t *testing.T) {
	cmd := newScenarioCommander([]string{"ip"}, map[string]CommandResult{
		scenarioCommandKey("ip", "-o", "addr", "show", "scope", "global"): {Stdout: "2: eth0 inet 203.0.113.10/24 scope global eth0"},
	})
	ctx := scenarioContext(cmd)
	ctx.ExternalDomains = []string{"panel.example.test"}
	ctx.ExpectCDN = true
	ctx.ExternalProber = fakeExternalProber{observations: map[string]externalObservation{
		"panel.example.test": {Domain: "panel.example.test", Addresses: []string{"203.0.113.10"}, TLSPresent: true, TLSNotAfter: time.Now().Add(90 * 24 * time.Hour)},
	}}
	finding := checkExternalExposure(ctx)
	if finding.Status != model.Risk || finding.Severity != model.High || finding.Facts["direct_origin_matches"] != "1" {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestExternalExposureFailureNeverPasses(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander(nil, nil))
	ctx.ExternalDomains = []string{"missing.example.test"}
	ctx.ExternalProber = fakeExternalProber{observations: map[string]externalObservation{
		"missing.example.test": {Domain: "missing.example.test", TLSError: "fixture lookup failed"},
	}}
	finding := checkExternalExposure(ctx)
	if finding.Status != model.Unknown || !finding.Unavailable {
		t.Fatalf("finding=%+v", finding)
	}
}

func TestExternalExposureTLSFailureNeverPasses(t *testing.T) {
	cmd := newScenarioCommander([]string{"ip"}, map[string]CommandResult{
		scenarioCommandKey("ip", "-o", "addr", "show", "scope", "global"): {Stdout: "2: eth0 inet 203.0.113.10/24 scope global eth0"},
	})
	ctx := scenarioContext(cmd)
	ctx.ExternalDomains = []string{"panel.example.test"}
	ctx.ExternalProber = fakeExternalProber{observations: map[string]externalObservation{
		"panel.example.test": {Domain: "panel.example.test", Addresses: []string{"198.51.100.20"}, TLSError: "TLS handshake timed out"},
	}}
	finding := checkExternalExposure(ctx)
	if finding.Status != model.Unknown || !finding.Unavailable || finding.Facts["tls_probe_failures"] != "1" {
		t.Fatalf("finding=%+v", finding)
	}
}
