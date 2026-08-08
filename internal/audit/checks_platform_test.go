package audit

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDiscoverCertificatePathsPropagatesNginxCommandFailure(t *testing.T) {
	ctx := scenarioContext(newScenarioCommander([]string{"nginx"}, map[string]CommandResult{
		scenarioCommandKey("nginx", "-T"): {Stdout: "server { ssl_certificate /partial.pem; }", Err: fmt.Errorf("configuration test failed")},
	}))
	ctx.Options.NativeSelfTest = true
	ctx.Facts = NewFactStore(ctx.Commander, true)
	_, err := discoverCertificatePaths(ctx)
	if err == nil || !strings.Contains(err.Error(), "nginx -T") {
		t.Fatalf("nginx command failure was not propagated: %v", err)
	}
}

func TestCertificateDaysRemainingTreatsPartialExpiredDayAsExpired(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	if got := certificateDaysRemaining(now.Add(-time.Hour), now); got != -1 {
		t.Fatalf("expired certificate days = %d, want -1", got)
	}
	if got := certificateDaysRemaining(now.Add(23*time.Hour), now); got != 0 {
		t.Fatalf("near-expiry certificate days = %d, want 0", got)
	}
}
