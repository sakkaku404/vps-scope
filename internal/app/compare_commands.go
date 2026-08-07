package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
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
	oldReport, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	newReport, err := readReport(fs.Arg(1))
	if err != nil {
		return err
	}
	if oldReport.Host.StableID != newReport.Host.StableID {
		return errors.New("cannot diff reports from different hosts: stable_id mismatch")
	}
	locale := i18n.Locale(*lang)
	oldMap, newMap := findingMap(oldReport), findingMap(newReport)
	semantic, covered := semanticDiff(oldReport, newReport)
	for _, change := range semantic {
		message := change.MessageEN
		if locale == "zh-CN" {
			message = change.MessageZH
		}
		fmt.Fprintf(e.out, "%-11s %-12s %s\n", change.Kind, change.ID, message)
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
			fmt.Fprintf(e.out, "NEW      %-12s %-8s %s\n", id, n.Status, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		case !okNew:
			fmt.Fprintf(e.out, "REMOVED  %-12s %-8s %s\n", id, o.Status, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		case o.Status != n.Status || (*all && evidenceFingerprint(o) != evidenceFingerprint(n)):
			fmt.Fprintf(e.out, "CHANGED  %-12s %s -> %s  %s\n", id, o.Status, n.Status, i18n.Pick(i18n.RuleForLocale(id, locale).Title, locale))
		}
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
	locale := i18n.Locale(*lang)
	fmt.Fprintf(e.out, "%-24s %5s %5s %5s %8s %10s  %s\n", strings.ToUpper(i18n.UI(locale, "主机", "Host")), "RISK", "PASS", "INFO", "UNKNOWN", "PROFILE", i18n.UI(locale, "最高优先级结果", "TOP FINDING"))
	for _, path := range fs.Args() {
		r, err := readReport(path)
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

type reportReadOptions struct {
	// allowSemanticFailures is reserved for the verify command, which must load
	// a damaged report in order to print every validation failure. All other
	// offline commands consume only reports that pass the semantic contract.
	allowSemanticFailures bool
}

func readReportWithOptions(path string, options reportReadOptions) (model.Report, error) {
	file, err := openLimitedJSON(path)
	if err != nil {
		return model.Report{}, err
	}
	defer file.Close()
	var r model.Report
	if err := decodeSingleJSON(file, &r); err != nil {
		return r, fmt.Errorf("read report %q: %w", path, err)
	}
	if r.SchemaVersion != "1.0" {
		return r, fmt.Errorf("read report %q: unsupported report schema %q", path, r.SchemaVersion)
	}
	if failures := audit.ValidateReport(r); len(failures) > 0 && !options.allowSemanticFailures {
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

func decodeSingleJSON(r io.Reader, dst any) error {
	decoder := json.NewDecoder(io.LimitReader(r, maxLocalJSONSize+1))
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
