package audit

import "github.com/sakkaku404/vps-scope/internal/contract"

// StableCheckIDs is the public v1 finding-ID contract. Existing identifiers
// are never reused or silently removed within report schema 1.0; new checks
// are append-only.
var StableCheckIDs = contract.StableIDs()

// CategoryOrder is retained as an audit-package compatibility alias. New
// consumers should depend directly on the contract package.
var CategoryOrder = contract.Categories()

func ValidateCheckContract() error {
	return contract.ValidateCompatibility(StableCheckIDs, CategoryOrder)
}
