package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/safejson"
)

func (e environment) diff(args []string) error {
	fs := e.newFlagSet("diff")
	lang := fs.String("lang", "auto", "language")
	all := fs.Bool("all", false, "include same-status raw evidence changes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: vps-scope diff OLD.json NEW.json")
	}
	oldReport, err := e.readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	newReport, err := e.readReport(fs.Arg(1))
	if err != nil {
		return err
	}
	if err := validateComparableHostIdentity(oldReport); err != nil {
		return fmt.Errorf("old report: %w", err)
	}
	if err := validateComparableHostIdentity(newReport); err != nil {
		return fmt.Errorf("new report: %w", err)
	}
	if oldReport.Host.StableID != newReport.Host.StableID {
		return errors.New("cannot diff reports from different hosts: stable_id mismatch")
	}
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
	oldMap, newMap := findingMap(oldReport), findingMap(newReport)
	semantic, covered := semanticDiff(oldReport, newReport)
	for _, change := range semantic {
		fmt.Fprintf(e.out, "%-11s %-12s %s\n", diffKindLabel(change.Kind, locale), change.ID, change.message(locale))
	}
	var ids []string
	seen := map[string]bool{}
	for id := range oldMap {
		seen[id] = true
		ids = append(ids, id)
	}
	for id := range newMap {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		if covered[id] {
			continue
		}
		o, okOld := oldMap[id]
		n, okNew := newMap[id]
		switch {
		case !okOld:
			fmt.Fprintf(e.out, "%-8s %-12s %-8s %s\n", diffKindLabel("NEW", locale), id, n.Status, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		case !okNew:
			fmt.Fprintf(e.out, "%-8s %-12s %-8s %s\n", diffKindLabel("REMOVED", locale), id, o.Status, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		case o.Status != n.Status || (*all && evidenceFingerprint(o) != evidenceFingerprint(n)):
			fmt.Fprintf(e.out, "%-8s %-12s %s -> %s  %s\n", diffKindLabel("CHANGED", locale), id, o.Status, n.Status, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		}
	}
	return nil
}

func diffKindLabel(kind, locale string) string {
	labels := map[string][4]string{
		"NEW":         {"新增", "NEW", "ДОБАВЛЕНО", "افزوده"},
		"REMOVED":     {"移除", "REMOVED", "УДАЛЕНО", "حذف"},
		"CHANGED":     {"变更", "CHANGED", "ИЗМЕНЕНО", "تغییر"},
		"CHANGE":      {"变更", "CHANGE", "ИЗМЕНЕНИЕ", "تغییر"},
		"CONTEXT":     {"上下文", "CONTEXT", "КОНТЕКСТ", "زمینه"},
		"REGRESSION":  {"退化", "REGRESSION", "УХУДШЕНИЕ", "پسرفت"},
		"IMPROVEMENT": {"改善", "IMPROVEMENT", "УЛУЧШЕНИЕ", "بهبود"},
	}
	value, ok := labels[kind]
	if !ok {
		return kind
	}
	switch locale {
	case "zh-CN":
		return value[0]
	case "ru-RU":
		return value[2]
	case "fa-IR":
		return value[3]
	default:
		return value[1]
	}
}

var legacyRedactedStableIDPattern = regexp.MustCompile(`^HOST_ID_[0-9]+$`)

func validateComparableHostIdentity(r model.Report) error {
	if r.Metadata["redacted"] == "true" && legacyRedactedStableIDPattern.MatchString(r.Host.StableID) {
		return errors.New("legacy redacted report has a non-unique host placeholder; re-redact the original unredacted report with the current version")
	}
	return nil
}

func (e environment) fleet(args []string) error {
	fs := e.newFlagSet("fleet")
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("usage: vps-scope fleet REPORT.json [REPORT.json ...]")
	}
	locale, err := parseLocaleFlag(*lang)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "%-24s %5s %5s %5s %8s %10s  %s\n", strings.ToUpper(i18n.UI(locale, "主机", "Host")), "RISK", "PASS", "INFO", "UNKNOWN", strings.ToUpper(i18n.UI(locale, "用途", "Profile")), i18n.UI(locale, "最高优先级结果", "Top finding"))
	for _, path := range fs.Args() {
		r, err := e.readReport(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		top := fleetTopFinding(r, locale)
		fmt.Fprintf(e.out, "%-24s %5d %5d %5d %8d %10s  %s\n", truncateDisplay(r.Host.Hostname, 24), r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown, r.Profile.Effective, top)
	}
	return nil
}

func fleetTopFinding(r model.Report, locale string) string {
	bestRank := 1 << 30
	best := model.Finding{}
	for _, finding := range r.Findings {
		if finding.NotApplicable || (finding.Status != model.Risk && finding.Status != model.Unknown) {
			continue
		}
		rank := 100
		if finding.Status == model.Risk {
			rank = map[model.Severity]int{model.Critical: 0, model.High: 10, model.Medium: 20, model.Low: 30}[finding.Severity]
		} else {
			rank = 40
		}
		if rank < bestRank || rank == bestRank && finding.ID < best.ID {
			bestRank, best = rank, finding
		}
	}
	if best.ID == "" {
		return i18n.UI(locale, "没有 RISK；如有 INFO 请按需查看", "no RISK; review INFO as needed")
	}
	label := string(best.Status)
	if best.Severity != "" {
		label += "/" + strings.ToUpper(string(best.Severity))
	}
	title := i18n.Pick(i18n.RuleForLocale(best.ID, locale).Title, locale)
	return fmt.Sprintf("[%s] %s %s", label, best.ID, truncateDisplay(title, 52))
}

func readReport(path string) (model.Report, error) {
	return readReportWithOptions(path, reportReadOptions{})
}

func (e environment) readReport(path string) (model.Report, error) {
	return readReportWithOptions(path, reportReadOptions{verifierVersion: e.build.Version})
}

// readReportForRewrite is used by commands that emit another machine-readable
// report. A reader may ignore optional fields added by a newer schema-1.0
// producer, but a redactor cannot preserve or sanitize fields it does not
// understand. Rejecting them is safer than silently losing data or copying an
// unreviewed secret into a shareable artifact.
func (e environment) readReportForRewrite(path string) (model.Report, error) {
	return readReportWithOptions(path, reportReadOptions{verifierVersion: e.build.Version, rejectUnknownFields: true})
}

type reportReadOptions struct {
	// allowSemanticFailures is reserved for the verify command, which must load
	// a damaged report in order to print every validation failure. All other
	// offline commands consume only reports that pass the semantic contract.
	allowSemanticFailures bool
	// verifierVersion enables the schema-1.0 append-only compatibility rule:
	// a newer report may add well-formed IDs but may not omit or redefine IDs
	// known to this executable. An empty value keeps fixture readers strict.
	verifierVersion string
	// rejectUnknownFields prevents lossy or privacy-unsafe serialization by a
	// command that will write the decoded report again.
	rejectUnknownFields bool
}

func readReportWithOptions(path string, options reportReadOptions) (model.Report, error) {
	file, err := openLimitedJSON(path)
	if err != nil {
		return model.Report{}, err
	}
	defer file.Close()
	var r model.Report
	if err := decodeSingleJSONWithOptions(file, &r, options.rejectUnknownFields); err != nil {
		if options.rejectUnknownFields {
			return r, fmt.Errorf("read report %q: cannot safely rewrite a report containing unsupported fields: %w", path, err)
		}
		return r, fmt.Errorf("read report %q: %w", path, err)
	}
	if r.SchemaVersion != "1.0" {
		return r, fmt.Errorf("read report %q: unsupported report schema %q", path, r.SchemaVersion)
	}
	var failures []string
	if options.verifierVersion == "" {
		failures = audit.ValidateReport(r)
	} else {
		failures = audit.ValidateReport(r, options.verifierVersion)
	}
	if len(failures) > 0 && !options.allowSemanticFailures {
		return r, fmt.Errorf("read report %q: semantic validation failed: %s", path, strings.Join(failures, "; "))
	}
	return r, nil
}

const maxLocalJSONSize = 64 << 20

func openLimitedJSON(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("JSON input %q is not a regular file", path)
	}
	if before.Size() < 0 || before.Size() > maxLocalJSONSize {
		return nil, fmt.Errorf("JSON input %q is too large (%d bytes; limit %d)", path, before.Size(), maxLocalJSONSize)
	}
	// #nosec G304 -- path is the explicit CLI input and is checked with Lstat,
	// a size limit, regular-file validation and SameFile after opening.
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		_ = file.Close()
		return nil, fmt.Errorf("JSON input %q changed while being opened", path)
	}
	return file, nil
}

func decodeSingleJSONWithOptions(r io.Reader, dst any, rejectUnknownFields bool) error {
	if seeker, ok := r.(io.ReadSeeker); ok {
		start, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}
		if err := safejson.RejectDuplicateMembers(io.LimitReader(r, maxLocalJSONSize+1)); err != nil {
			return err
		}
		if _, err := seeker.Seek(start, io.SeekStart); err != nil {
			return err
		}
	}
	decoder := json.NewDecoder(io.LimitReader(r, maxLocalJSONSize+1))
	if rejectUnknownFields {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected data after JSON document")
		}
		return err
	}
	return nil
}

func findingMap(r model.Report) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range r.Findings {
		out[f.ID] = f
	}
	return out
}
func evidenceFingerprint(f model.Finding) string {
	data, _ := json.Marshal(struct {
		Evidence []model.Evidence
		Facts    map[string]string
	}{f.Evidence, f.Facts})
	return string(data)
}
