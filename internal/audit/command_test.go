package audit

import (
	"strings"
	"testing"
)

func TestLimitedBuilderPreservesPrefixAndSignalsTruncation(t *testing.T) {
	b := limitedBuilder{limit: 5}
	if n, err := b.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("Write() = (%d, %v), want (6, nil)", n, err)
	}
	if got := b.String(); got != "abcde" {
		t.Fatalf("captured %q, want prefix", got)
	}
	if !b.truncated {
		t.Fatal("expected truncated")
	}
	if n, err := b.Write([]byte("more")); err != nil || n != 4 {
		t.Fatalf("Write after cap = (%d, %v), want (4, nil)", n, err)
	}
}

func TestCommandErrorExplainsTruncation(t *testing.T) {
	if got := commandError(CommandResult{Truncated: true}); !strings.Contains(got, "capture limit") {
		t.Fatalf("commandError = %q", got)
	}
}
