package audit

import "testing"

func TestStableCheckContract(t *testing.T) {
	if err := ValidateCheckContract(); err != nil {
		t.Fatal(err)
	}
	if got, want := len(StableCheckIDs), 51; got != want {
		t.Fatalf("stable check count = %d, want %d", got, want)
	}
}

func TestStableCheckContractRejectsCategoryOrderDrift(t *testing.T) {
	original := CategoryOrder
	CategoryOrder = append([]string(nil), original[1:]...)
	t.Cleanup(func() { CategoryOrder = original })
	if err := ValidateCheckContract(); err == nil {
		t.Fatal("contract accepted a missing category")
	}
}
