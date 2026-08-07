package audit

import (
	"fmt"
	"strings"
	"testing"
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
