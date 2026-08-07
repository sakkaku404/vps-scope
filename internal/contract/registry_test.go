package contract

import "testing"

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
