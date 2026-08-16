package contract

import (
	"os"
	"strings"
	"testing"
)

func TestTemporaryRunnerChecksumFallbackIsNonInteractive(t *testing.T) {
	data, err := os.ReadFile("../../run.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)

	for _, forbidden := range []string{
		"Type continue",
		"read -r approval",
		"VPS_SCOPE_ALLOW_UNSIGNED",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("temporary runner still contains interactive fallback %q", forbidden)
		}
	}

	checksum := strings.Index(script, "sha256sum -c -")
	warning := strings.Index(script, "SHA-256 passed, but the publisher signature was not verified")
	execute := strings.Index(script, `"$asset_path" "$@"`)
	if checksum < 0 || warning < 0 || execute < 0 {
		t.Fatalf("runner is missing checksum, warning, or execution contract")
	}
	if !(checksum < warning && warning < execute) {
		t.Fatalf("runner must verify SHA-256, warn, and then execute in that order")
	}
	if !strings.Contains(script, "VPS_SCOPE_REQUIRE_SIGNATURE") {
		t.Fatal("runner must preserve strict signature mode")
	}
	if !strings.Contains(script, `exec 3<>/dev/tty`) || !strings.Contains(script, `"$asset_path" <&3`) {
		t.Fatal("runner must prove and reconnect interactive input to the controlling terminal")
	}
	if !strings.Contains(script, `ORIGINAL_DIR="$PWD"`) || !strings.Contains(script, `cd "$ORIGINAL_DIR"`) {
		t.Fatal("runner must restore the caller's working directory before execution")
	}
	if !strings.Contains(script, `set -- audit "$@"`) {
		t.Fatal("runner must treat leading flags as audit arguments")
	}
}
