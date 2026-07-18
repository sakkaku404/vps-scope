package app

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
)

func (e environment) diff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
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
			fmt.Fprintf(e.out, "NEW      %-12s %-8s %s\n", id, n.Status, i18n.Pick(i18n.RuleFor(id).Title, locale))
		case !okNew:
			fmt.Fprintf(e.out, "REMOVED  %-12s %-8s %s\n", id, o.Status, i18n.Pick(i18n.RuleFor(id).Title, locale))
		case o.Status != n.Status || (*all && evidenceFingerprint(o) != evidenceFingerprint(n)):
			fmt.Fprintf(e.out, "CHANGED  %-12s %s -> %s  %s\n", id, o.Status, n.Status, i18n.Pick(i18n.RuleFor(id).Title, locale))
		}
	}
	return nil
}

func (e environment) fleet(args []string) error {
	fs := flag.NewFlagSet("fleet", flag.ContinueOnError)
	lang := fs.String("lang", "auto", "language")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = lang
	if fs.NArg() < 1 {
		return errors.New("usage: vps-scope fleet REPORT.json [REPORT.json ...]")
	}
	fmt.Fprintf(e.out, "%-24s %5s %5s %5s %8s %10s\n", "HOST", "RISK", "PASS", "INFO", "UNKNOWN", "PROFILE")
	for _, path := range fs.Args() {
		r, err := readReport(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Fprintf(e.out, "%-24s %5d %5d %5d %8d %10s\n", truncateDisplay(r.Host.Hostname, 24), r.Summary.Risk, r.Summary.Pass, r.Summary.Info, r.Summary.Unknown, r.Profile.Effective)
	}
	return nil
}

func readReport(path string) (model.Report, error) {
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
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		file.Close()
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
