package audit

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/safejson"
)

//go:embed advisory_db.json
var embeddedAdvisoryJSON []byte

type advisoryDatabase struct {
	SchemaVersion string     `json:"schema_version"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Advisories    []advisory `json:"advisories"`
}

type advisory struct {
	ID       string         `json:"id"`
	Product  string         `json:"product"`
	Severity model.Severity `json:"severity"`
	Summary  string         `json:"summary"`
	URL      string         `json:"url"`
	Affected []versionRange `json:"affected"`
	Fixed    string         `json:"fixed"`
}

type versionRange struct {
	MinInclusive string `json:"min_inclusive,omitempty"`
	MaxExclusive string `json:"max_exclusive,omitempty"`
	MaxInclusive string `json:"max_inclusive,omitempty"`
}

type advisoryVersion struct {
	major, minor, patch int
	pre                 []versionPart
}

type versionPart struct {
	number *int
	text   string
}

var versionTokenPattern = regexp.MustCompile(`(?i)\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9a-z.-]+)?)\b`)

func loadEmbeddedAdvisories() (advisoryDatabase, error) {
	var db advisoryDatabase
	if err := safejson.RejectDuplicateMembers(bytes.NewReader(embeddedAdvisoryJSON)); err != nil {
		return db, fmt.Errorf("invalid embedded advisory JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(embeddedAdvisoryJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&db); err != nil {
		return db, err
	}
	if db.SchemaVersion != "1.0" || db.GeneratedAt.IsZero() {
		return db, fmt.Errorf("invalid embedded advisory database metadata")
	}
	for _, item := range db.Advisories {
		if item.ID == "" || item.Product == "" || item.URL == "" || len(item.Affected) == 0 {
			return db, fmt.Errorf("invalid embedded advisory entry")
		}
		if item.Severity != model.Critical && item.Severity != model.High && item.Severity != model.Medium && item.Severity != model.Low {
			return db, fmt.Errorf("invalid advisory severity for %s", item.ID)
		}
	}
	return db, nil
}

func checkProxyAdvisories(ctx *Context, summaries []proxyConfigSummary) model.Finding {
	db, err := loadEmbeddedAdvisories()
	if err != nil {
		return unknown("WORK-017", "workloads", "embedded advisory database", err.Error())
	}
	detectedProducts := activeProxyProducts(ctx)
	panels, panelErr := ctx.Facts.Panels()
	versions := map[string]string{}
	for _, panel := range panels {
		product := normalizeAdvisoryProduct(panel.Product)
		if panel.Version != "" {
			versions[product] = extractVersion(panel.Version)
		}
		detectedProducts[product] = true
	}
	products := map[string]bool{}
	for product := range detectedProducts {
		products[normalizeAdvisoryProduct(product)] = true
	}
	if ctx.Options.NativeSelfTest {
		for _, spec := range []struct {
			product string
			command string
			args    []string
		}{{"sing-box", "sing-box", []string{"version"}}, {"xray", "xray", []string{"version"}}} {
			if !products[spec.product] {
				continue
			}
			binary := advisoryExecutable(spec.product, spec.command, summaries, ctx.Commander)
			if binary == "" {
				continue
			}
			trustedBinary, trustErr := trustedExecutable(ctx.Commander, binary)
			if trustErr != nil {
				continue
			}
			r := ctx.Commander.Run(8*time.Second, trustedBinary, spec.args...)
			if r.Err == nil && !r.Truncated {
				versions[spec.product] = extractVersion(r.Stdout + "\n" + r.Stderr)
			}
		}
	}
	relevant := map[string][]advisory{}
	for _, item := range db.Advisories {
		relevant[normalizeAdvisoryProduct(item.Product)] = append(relevant[normalizeAdvisoryProduct(item.Product)], item)
	}
	activeRelevant := []string{}
	for product := range products {
		if len(relevant[product]) > 0 {
			activeRelevant = append(activeRelevant, product)
		}
	}
	sort.Strings(activeRelevant)
	if len(activeRelevant) == 0 {
		return withIncompleteEvidence(notApplicable("WORK-017", "workloads", "embedded advisory database", "no running product has an advisory entry in the bundled database"), "panel discovery", panelErr)
	}
	f := model.Finding{ID: "WORK-017", Category: "workloads", Status: model.Pass, Facts: map[string]string{
		"database_generated_at": db.GeneratedAt.Format(time.RFC3339),
		"database_entries":      strconv.Itoa(len(db.Advisories)),
		"products_checked":      strconv.Itoa(len(activeRelevant)),
	}}
	unknownVersions, matched := 0, 0
	for _, product := range activeRelevant {
		version := versions[product]
		parsed, ok := parseSemanticVersion(version)
		if !ok {
			unknownVersions++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "runtime version + embedded advisories", Key: "version_unavailable", Value: "product=" + product})
			continue
		}
		productMatched := false
		for _, item := range relevant[product] {
			if advisoryAffects(item, parsed) {
				matched++
				productMatched = true
				raiseRisk(&f, item.Severity)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "embedded advisory database", Key: "affected_version", Value: fmt.Sprintf("product=%s version=%s advisory=%s severity=%s fixed=%s url=%s", product, version, item.ID, item.Severity, item.Fixed, item.URL)})
			}
		}
		if !productMatched {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "runtime version + embedded advisories", Key: "version_checked", Value: fmt.Sprintf("product=%s version=%s matched_advisories=0", product, version)})
		}
	}
	f.Facts["matched_advisories"] = strconv.Itoa(matched)
	f.Facts["unknown_product_versions"] = strconv.Itoa(unknownVersions)
	stale := ctx.evidenceTime().Sub(db.GeneratedAt) > 120*24*time.Hour
	f.Facts["database_stale"] = strconv.FormatBool(stale)
	if matched == 0 && (unknownVersions > 0 || stale) {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "advisory conclusion is incomplete because a relevant version is unavailable or the bundled database is stale"
	}
	return withIncompleteEvidence(f, "panel discovery", panelErr)
}

func advisoryExecutable(product, fallback string, summaries []proxyConfigSummary, cmd Commander) string {
	if cmd.Exists(fallback) {
		return fallback
	}
	for _, summary := range summaries {
		if normalizeAdvisoryProduct(summary.Product) != product {
			continue
		}
		var candidates []string
		if product == "xray" && strings.Contains(summary.Path, "/usr/local/x-ui/") {
			candidates = append(candidates, "/usr/local/x-ui/bin/xray-linux-amd64")
		}
		if product == "sing-box" && strings.Contains(summary.Path, "/usr/local/s-ui/") {
			candidates = append(candidates, "/usr/local/s-ui/bin/sing-box")
		}
		if binary, _ := proxySelfTest(summary.Product, summary.Path); binary != "" {
			candidates = append(candidates, binary)
		}
		for _, binary := range candidates {
			if cmd.Exists(binary) {
				return binary
			}
		}
	}
	return ""
}

func normalizeAdvisoryProduct(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "3x-ui", "x-ui", "x-ui/3x-ui":
		return "3x-ui"
	case "xray-core":
		return "xray"
	}
	return value
}

func extractVersion(value string) string {
	match := versionTokenPattern.FindStringSubmatch(value)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}

func parseSemanticVersion(value string) (advisoryVersion, bool) {
	value = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "v")
	if value == "" {
		return advisoryVersion{}, false
	}
	main, pre, _ := strings.Cut(value, "-")
	parts := strings.Split(main, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return advisoryVersion{}, false
	}
	numbers := []int{0, 0, 0}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return advisoryVersion{}, false
		}
		numbers[i] = n
	}
	version := advisoryVersion{major: numbers[0], minor: numbers[1], patch: numbers[2]}
	if pre != "" {
		for _, item := range strings.FieldsFunc(pre, func(r rune) bool { return r == '.' || r == '-' }) {
			if n, err := strconv.Atoi(item); err == nil {
				nCopy := n
				version.pre = append(version.pre, versionPart{number: &nCopy})
			} else {
				version.pre = append(version.pre, versionPart{text: item})
			}
		}
	}
	return version, true
}

func compareSemanticVersion(left, right advisoryVersion) int {
	for _, pair := range [][2]int{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if len(left.pre) == 0 && len(right.pre) == 0 {
		return 0
	}
	if len(left.pre) == 0 {
		return 1
	}
	if len(right.pre) == 0 {
		return -1
	}
	for i := 0; i < len(left.pre) && i < len(right.pre); i++ {
		a, b := left.pre[i], right.pre[i]
		if a.number != nil && b.number != nil {
			if *a.number < *b.number {
				return -1
			}
			if *a.number > *b.number {
				return 1
			}
			continue
		}
		if a.number != nil {
			return -1
		}
		if b.number != nil {
			return 1
		}
		if a.text < b.text {
			return -1
		}
		if a.text > b.text {
			return 1
		}
	}
	if len(left.pre) < len(right.pre) {
		return -1
	}
	if len(left.pre) > len(right.pre) {
		return 1
	}
	return 0
}

func advisoryAffects(item advisory, version advisoryVersion) bool {
	for _, affected := range item.Affected {
		if versionInRange(version, affected) {
			return true
		}
	}
	return false
}

func versionInRange(version advisoryVersion, affected versionRange) bool {
	if affected.MinInclusive != "" {
		minimum, ok := parseSemanticVersion(affected.MinInclusive)
		if !ok || compareSemanticVersion(version, minimum) < 0 {
			return false
		}
	}
	if affected.MaxExclusive != "" {
		maximum, ok := parseSemanticVersion(affected.MaxExclusive)
		if !ok || compareSemanticVersion(version, maximum) >= 0 {
			return false
		}
	}
	if affected.MaxInclusive != "" {
		maximum, ok := parseSemanticVersion(affected.MaxInclusive)
		if !ok || compareSemanticVersion(version, maximum) > 0 {
			return false
		}
	}
	return true
}
