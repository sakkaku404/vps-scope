// Package contract owns the stable, language-neutral audit check contract.
//
// Keeping check identity and presentation-independent metadata here prevents
// audit evaluators and report renderers from maintaining parallel ID lists.
package contract

import (
	"fmt"
	"regexp"
	"strings"
)

// ActionBand is an exceptional presentation band attached to a check. Most
// findings derive their action band from status and severity; only checks with
// a stronger semantic classification need a value here.
type ActionBand string

const (
	ActionBandDefault      ActionBand = ""
	ActionBandAvailability ActionBand = "availability"
)

// Check describes one stable report-v1 check.
type Check struct {
	ID         string
	Category   string
	ActionBand ActionBand
}

var categoryOrder = []string{
	"system", "accounts", "ssh", "privileges", "network", "firewall", "auth", "updates",
	"packages", "processes", "docker", "tls", "workloads", "filesystem", "persistence", "reliability",
}

var checks = []Check{
	{ID: "SYS-001", Category: "system"}, {ID: "SYS-002", Category: "system"}, {ID: "SYS-003", Category: "system"}, {ID: "SYS-004", Category: "system"},
	{ID: "ACC-001", Category: "accounts"}, {ID: "ACC-002", Category: "accounts"}, {ID: "ACC-003", Category: "accounts"},
	{ID: "SSH-001", Category: "ssh"}, {ID: "SSH-002", Category: "ssh"}, {ID: "SSH-003", Category: "ssh"}, {ID: "SSH-004", Category: "ssh"}, {ID: "SSH-005", Category: "ssh"},
	{ID: "PRIV-001", Category: "privileges"}, {ID: "PRIV-002", Category: "privileges"},
	{ID: "NET-001", Category: "network"}, {ID: "NET-002", Category: "network"}, {ID: "NET-003", Category: "network"}, {ID: "NET-004", Category: "network"},
	{ID: "FW-001", Category: "firewall"}, {ID: "FW-002", Category: "firewall"},
	{ID: "AUTH-001", Category: "auth"}, {ID: "AUTH-002", Category: "auth"}, {ID: "AUTH-003", Category: "auth"},
	{ID: "UPD-001", Category: "updates"}, {ID: "UPD-002", Category: "updates"},
	{ID: "PKG-001", Category: "packages"}, {ID: "PKG-002", Category: "packages"},
	{ID: "PROC-001", Category: "processes", ActionBand: ActionBandAvailability}, {ID: "PROC-002", Category: "processes"},
	{ID: "DOCKER-001", Category: "docker"}, {ID: "DOCKER-002", Category: "docker"},
	{ID: "TLS-001", Category: "tls", ActionBand: ActionBandAvailability}, {ID: "TLS-002", Category: "tls"},
	{ID: "WORK-001", Category: "workloads"}, {ID: "WORK-002", Category: "workloads"}, {ID: "WORK-003", Category: "workloads"},
	{ID: "WORK-004", Category: "workloads"}, {ID: "WORK-005", Category: "workloads"}, {ID: "WORK-006", Category: "workloads"},
	{ID: "WORK-007", Category: "workloads"}, {ID: "WORK-008", Category: "workloads"},
	{ID: "WORK-009", Category: "workloads", ActionBand: ActionBandAvailability},
	{ID: "WORK-010", Category: "workloads", ActionBand: ActionBandAvailability}, {ID: "WORK-011", Category: "workloads"}, {ID: "WORK-012", Category: "workloads"},
	{ID: "WORK-013", Category: "workloads"}, {ID: "WORK-014", Category: "workloads"}, {ID: "WORK-015", Category: "workloads"},
	{ID: "WORK-016", Category: "workloads"}, {ID: "WORK-017", Category: "workloads"},
	{ID: "FS-001", Category: "filesystem"},
	{ID: "PERSIST-001", Category: "persistence"}, {ID: "PERSIST-002", Category: "persistence"},
	{ID: "REL-001", Category: "reliability", ActionBand: ActionBandAvailability}, {ID: "REL-002", Category: "reliability"},
}

var checkIDPattern = regexp.MustCompile(`^[A-Z]+-[0-9]{3}$`)

var checksByID, categoriesByPrefix = indexChecks(checks)

func indexChecks(registered []Check) (map[string]Check, map[string]string) {
	byID := make(map[string]Check, len(registered))
	byPrefix := make(map[string]string)
	for _, check := range registered {
		byID[check.ID] = check
		prefix, _, _ := strings.Cut(check.ID, "-")
		if byPrefix[prefix] == "" {
			byPrefix[prefix] = check.Category
		}
	}
	return byID, byPrefix
}

// ValidCheckID reports whether an ID has the stable report check-ID shape.
// It is also used when an older verifier accepts append-only IDs from a newer
// report version.
func ValidCheckID(id string) bool { return checkIDPattern.MatchString(id) }

// Categories returns a copy of the stable category order.
func Categories() []string { return append([]string(nil), categoryOrder...) }

// StableIDs returns a copy of the stable report-v1 check-ID order.
func StableIDs() []string {
	ids := make([]string, len(checks))
	for i, check := range checks {
		ids[i] = check.ID
	}
	return ids
}

// Lookup returns the registered metadata for an ID.
func Lookup(id string) (Check, bool) {
	check, ok := checksByID[id]
	return check, ok
}

// Category returns the registered category for an ID. For a syntactically
// valid append-only ID from a newer report, the category is inferred from a
// known stable prefix so older verifiers retain their forward-compatibility
// checks without maintaining a second prefix switch.
func Category(id string) string {
	if check, ok := Lookup(id); ok {
		return check.Category
	}
	prefix, _, ok := strings.Cut(id, "-")
	if !ok {
		return ""
	}
	return categoriesByPrefix[prefix]
}

// SpecialActionBand returns presentation metadata that overrides the normal
// severity-derived action band for a registered check.
func SpecialActionBand(id string) ActionBand {
	check, _ := Lookup(id)
	return check.ActionBand
}

// Validate verifies the canonical registry.
func Validate() error { return validate(categoryOrder, checks) }

// ValidateCompatibility verifies legacy exported ID/category slices against
// the canonical registry. It exists so the audit package can retain its v1
// compatibility variables without becoming another metadata source.
func ValidateCompatibility(ids, categories []string) error {
	canonicalIDs := StableIDs()
	canonicalCategories := Categories()
	if len(ids) != len(canonicalIDs) {
		return fmt.Errorf("stable check compatibility list contains %d IDs; expected %d", len(ids), len(canonicalIDs))
	}
	if len(categories) != len(canonicalCategories) {
		return fmt.Errorf("category compatibility list contains %d categories; expected %d", len(categories), len(canonicalCategories))
	}
	for i := range canonicalIDs {
		if ids[i] != canonicalIDs[i] {
			return fmt.Errorf("stable check compatibility ID %d is %q; expected %q", i, ids[i], canonicalIDs[i])
		}
	}
	for i := range canonicalCategories {
		if categories[i] != canonicalCategories[i] {
			return fmt.Errorf("category compatibility entry %d is %q; expected %q", i, categories[i], canonicalCategories[i])
		}
	}
	registered := make([]Check, 0, len(ids))
	for _, id := range ids {
		check, ok := Lookup(id)
		if !ok {
			return fmt.Errorf("stable check ID %q is not registered", id)
		}
		registered = append(registered, check)
	}
	return validate(categories, registered)
}

func validate(categories []string, registered []Check) error {
	seenCategories := make(map[string]bool, len(categories))
	for _, category := range categories {
		if category == "" {
			return fmt.Errorf("empty category")
		}
		if seenCategories[category] {
			return fmt.Errorf("duplicate category %q", category)
		}
		seenCategories[category] = true
	}

	seenIDs := make(map[string]bool, len(registered))
	categoryByPrefix := make(map[string]string)
	categoryCounts := make(map[string]int, len(categories))
	for _, check := range registered {
		if !ValidCheckID(check.ID) {
			return fmt.Errorf("invalid stable check ID %q", check.ID)
		}
		if seenIDs[check.ID] {
			return fmt.Errorf("duplicate stable check ID %q", check.ID)
		}
		seenIDs[check.ID] = true
		prefix, _, _ := strings.Cut(check.ID, "-")
		if existing := categoryByPrefix[prefix]; existing != "" && existing != check.Category {
			return fmt.Errorf("stable check prefix %q maps to both %q and %q", prefix, existing, check.Category)
		}
		categoryByPrefix[prefix] = check.Category
		if !seenCategories[check.Category] {
			return fmt.Errorf("stable check %q references unknown category %q", check.ID, check.Category)
		}
		switch check.ActionBand {
		case ActionBandDefault, ActionBandAvailability:
		default:
			return fmt.Errorf("stable check %q has invalid action band %q", check.ID, check.ActionBand)
		}
		categoryCounts[check.Category]++
	}
	for _, category := range categories {
		if categoryCounts[category] == 0 {
			return fmt.Errorf("category %q has no stable check IDs", category)
		}
	}
	return nil
}
