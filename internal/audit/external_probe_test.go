package audit

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestExternalObservationPinsTLSDialToPublicResolvedAddress(t *testing.T) {
	var dialedAddress, dialedServerName string
	wantExpiry := time.Unix(2_000_000_000, 0).UTC()
	observation := observeExternalDomain(context.Background(), "panel.example.test",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("169.254.169.254")}, {IP: net.ParseIP("203.0.113.10")}}, nil
		},
		func(_ context.Context, address, serverName string) (time.Time, error) {
			dialedAddress, dialedServerName = address, serverName
			return wantExpiry, nil
		})
	if dialedAddress != "203.0.113.10" || dialedServerName != "panel.example.test" {
		t.Fatalf("dialed address=%q server_name=%q", dialedAddress, dialedServerName)
	}
	if len(observation.Addresses) != 1 || observation.Addresses[0] != "203.0.113.10" || !observation.TLSPresent || !observation.TLSNotAfter.Equal(wantExpiry) {
		t.Fatalf("observation=%+v", observation)
	}
}

func TestExternalObservationRefusesPrivateOnlyDNSAndDoesNotDial(t *testing.T) {
	dials := 0
	observation := observeExternalDomain(context.Background(), "internal.example.test",
		func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}, {IP: net.ParseIP("::1")}}, nil
		},
		func(context.Context, string, string) (time.Time, error) {
			dials++
			return time.Time{}, errors.New("must not run")
		})
	if dials != 0 || observation.TLSError != "dns lookup returned no public unicast address" {
		t.Fatalf("dials=%d observation=%+v", dials, observation)
	}
}

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
