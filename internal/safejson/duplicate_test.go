package safejson

import (
	"strings"
	"testing"
)

func TestRejectDuplicateMembers(t *testing.T) {
	for _, test := range []struct {
		name, input string
		wantError   bool
	}{
		{"ordinary", `{"a":1,"nested":{"b":2},"array":[{"c":3}]}`, false},
		{"top-level duplicate", `{"a":1,"a":2}`, true},
		{"nested duplicate", `{"nested":{"secret-name":1,"secret-name":2}}`, true},
		{"multiple values", `{} {}`, true},
		{"excessive nesting", strings.Repeat("[", maxJSONNesting+2) + "0" + strings.Repeat("]", maxJSONNesting+2), true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := RejectDuplicateMembers(strings.NewReader(test.input))
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%t", err, test.wantError)
			}
			if err != nil && strings.Contains(err.Error(), "secret-name") {
				t.Fatal("error disclosed an attacker-controlled member name")
			}
		})
	}
}

func FuzzRejectDuplicateMembersDoesNotPanic(f *testing.F) {
	for _, seed := range []string{`{"a":1}`, `{"a":1,"a":2}`, `[[[]]]`, `not-json`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		_ = RejectDuplicateMembers(strings.NewReader(input))
	})
}
