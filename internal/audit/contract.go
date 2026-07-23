package audit

import (
	"fmt"
	"regexp"
)

// StableCheckIDs is the public v1 finding-ID contract. Existing identifiers
// are never reused or silently removed within report schema 1.0; new checks
// are append-only.
var StableCheckIDs = []string{
	"SYS-001", "SYS-002", "SYS-003", "SYS-004",
	"ACC-001", "ACC-002", "ACC-003",
	"SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005",
	"PRIV-001", "PRIV-002",
	"NET-001", "NET-002", "NET-003", "NET-004",
	"FW-001", "FW-002",
	"AUTH-001", "AUTH-002", "AUTH-003",
	"UPD-001", "UPD-002",
	"PKG-001", "PKG-002",
	"PROC-001", "PROC-002",
	"DOCKER-001", "DOCKER-002",
	"TLS-001", "TLS-002",
	"WORK-001", "WORK-002", "WORK-003", "WORK-004", "WORK-005", "WORK-006", "WORK-007",
	"WORK-008", "WORK-009", "WORK-010", "WORK-011", "WORK-012", "WORK-013", "WORK-014", "WORK-015", "WORK-016", "WORK-017",
	"FS-001",
	"PERSIST-001", "PERSIST-002",
	"REL-001", "REL-002",
}

var stableCheckIDPattern = regexp.MustCompile(`^[A-Z]+-[0-9]{3}$`)

func ValidateCheckContract() error {
	seen := make(map[string]bool, len(StableCheckIDs))
	categoryCounts := make(map[string]int, len(CategoryOrder))
	for _, id := range StableCheckIDs {
		if !stableCheckIDPattern.MatchString(id) {
			return fmt.Errorf("invalid stable check ID %q", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate stable check ID %q", id)
		}
		seen[id] = true
		category := reportCategoryForID(id)
		if category == "" {
			return fmt.Errorf("stable check ID %q has no category mapping", id)
		}
		categoryCounts[category]++
	}
	seenCategories := make(map[string]bool, len(CategoryOrder))
	for _, category := range CategoryOrder {
		if seenCategories[category] {
			return fmt.Errorf("duplicate category %q", category)
		}
		seenCategories[category] = true
		if categoryCounts[category] == 0 {
			return fmt.Errorf("category %q has no stable check IDs", category)
		}
	}
	for category := range categoryCounts {
		if !seenCategories[category] {
			return fmt.Errorf("stable check category %q is absent from CategoryOrder", category)
		}
	}
	return nil
}
