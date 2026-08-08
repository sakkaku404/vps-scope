package contract

import (
	"slices"
	"testing"
)

func TestRegistryIsComplete(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	if got, want := len(StableIDs()), 55; got != want {
		t.Fatalf("stable check count = %d, want %d", got, want)
	}
	if got, want := len(Categories()), 16; got != want {
		t.Fatalf("category count = %d, want %d", got, want)
	}
	for _, id := range StableIDs() {
		if Category(id) == "" {
			t.Fatalf("stable check %s has no category", id)
		}
	}
	if got := Category("WORK-999"); got != "workloads" {
		t.Fatalf("future WORK category = %q, want workloads", got)
	}
}

func TestRegistryRejectsDuplicateIDsAndCategories(t *testing.T) {
	tests := []struct {
		name       string
		categories []string
		checks     []Check
	}{
		{name: "duplicate ID", categories: []string{"system"}, checks: []Check{{ID: "SYS-001", Category: "system"}, {ID: "SYS-001", Category: "system"}}},
		{name: "duplicate category", categories: []string{"system", "system"}, checks: []Check{{ID: "SYS-001", Category: "system"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validate(test.categories, test.checks); err == nil {
				t.Fatal("invalid registry accepted")
			}
		})
	}
}

func TestStableIDsForVersionPreservesPublishedContracts(t *testing.T) {
	legacy := StableIDsForVersion(0, 12)
	if len(legacy) != 51 {
		t.Fatalf("v0.12 contract has %d IDs; want 51", len(legacy))
	}
	current := StableIDsForVersion(1, 0)
	if len(current) != 55 {
		t.Fatalf("v1.0 contract has %d IDs; want 55", len(current))
	}
	for _, added := range []string{"NET-004", "WORK-015", "WORK-016", "WORK-017"} {
		if slices.Contains(legacy, added) {
			t.Fatalf("v0.12 contract unexpectedly contains %s", added)
		}
		if !slices.Contains(current, added) {
			t.Fatalf("v1.0 contract is missing %s", added)
		}
	}
}

func TestSpecialActionBands(t *testing.T) {
	for _, id := range []string{"PROC-001", "TLS-001", "WORK-009", "WORK-010", "REL-001"} {
		if got := SpecialActionBand(id); got != ActionBandAvailability {
			t.Fatalf("%s action band = %q, want %q", id, got, ActionBandAvailability)
		}
	}
	if got := SpecialActionBand("SSH-001"); got != ActionBandDefault {
		t.Fatalf("SSH-001 action band = %q, want default", got)
	}
}

func TestOrderFollowsStableIDsAndPlacesUnknownLast(t *testing.T) {
	for index, id := range StableIDs() {
		if got := Order(id); got != index {
			t.Fatalf("Order(%q)=%d, want %d", id, got, index)
		}
	}
	if got := Order("FUTURE-999"); got != len(StableIDs()) {
		t.Fatalf("unknown ID order=%d, want %d", got, len(StableIDs()))
	}
}
