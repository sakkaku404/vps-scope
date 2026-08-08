package audit

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestNormalizeFindingsBoundsNoisyEvidenceDeterministically(t *testing.T) {
	finding := model.Finding{ID: "WORK-010", Category: "workloads", Status: model.Info, Facts: map[string]string{}}
	for index := 0; index < maxFindingEvidenceEntries+20; index++ {
		finding.Evidence = append(finding.Evidence, model.Evidence{
			Source: strings.Repeat("s", maxEvidenceSourceBytes+20),
			Key:    strings.Repeat("k", maxEvidenceKeyBytes+20),
			Value:  strings.Repeat("值", maxEvidenceValueBytes),
		})
	}
	for index := 0; index < maxFindingFactEntries+20; index++ {
		finding.Facts["fact_"+strconv.Itoa(index)] = strings.Repeat("值", maxFindingFactValueBytes)
	}
	normalized := normalizeFindings([]model.Finding{finding})[0]
	if len(normalized.Evidence) != maxFindingEvidenceEntries || len(normalized.Facts) != maxFindingFactEntries {
		t.Fatalf("evidence=%d facts=%d", len(normalized.Evidence), len(normalized.Facts))
	}
	if normalized.Evidence[len(normalized.Evidence)-1].Key != "entries_omitted" {
		t.Fatalf("last evidence=%+v", normalized.Evidence[len(normalized.Evidence)-1])
	}
	for _, evidence := range normalized.Evidence {
		if !utf8.ValidString(evidence.Source) || !utf8.ValidString(evidence.Key) || !utf8.ValidString(evidence.Value) {
			t.Fatalf("normalization split UTF-8: %+v", evidence)
		}
		if len(evidence.Source) > maxEvidenceSourceBytes || len(evidence.Key) > maxEvidenceKeyBytes || len(evidence.Value) > maxEvidenceValueBytes {
			t.Fatalf("oversized evidence remains: source=%d key=%d value=%d", len(evidence.Source), len(evidence.Key), len(evidence.Value))
		}
	}
}

func TestValidateReportRejectsOversizedUntrustedFindingData(t *testing.T) {
	report := validContractReport()
	report.Findings[0].Evidence = make([]model.Evidence, maxFindingEvidenceEntries+1)
	report.Findings[0].Facts = map[string]string{"oversized": strings.Repeat("x", maxFindingFactValueBytes+1)}
	failures := ValidateReport(report)
	joined := strings.Join(failures, "\n")
	if !strings.Contains(joined, "evidence entries") || !strings.Contains(joined, "oversized fact") {
		t.Fatalf("failures=%v", failures)
	}
}

func TestValidateReportStopsAtOversizedTopLevelCollections(t *testing.T) {
	report := validContractReport()
	report.Findings = make([]model.Finding, maxReportFindings+1)
	failures := ValidateReport(report)
	if len(failures) != 1 || !strings.Contains(failures[0], "findings") {
		t.Fatalf("failures=%v", failures)
	}
}

func TestTruncatePreservesUTF8(t *testing.T) {
	got := truncate("用户名称包含中文", 7)
	if !utf8.ValidString(got) || !strings.HasSuffix(got, "...") {
		t.Fatalf("truncate=%q", got)
	}
}

func TestNormalizeFindingsMakesCollectedTextTerminalSafe(t *testing.T) {
	finding := model.Finding{
		ID:       "WORK-010",
		Category: "workloads",
		Status:   model.Info,
		Error:    "bad\x1b[2Jerror\u202e\u2028forged-line",
		Evidence: []model.Evidence{{
			Source: "journal\x07", Key: "message\u2066", Value: "safe\ntext\x1b[31m",
		}},
		Facts: map[string]string{"name\u202e": "value\x00"},
	}

	normalized := normalizeFindings([]model.Finding{finding})[0]
	for _, value := range []string{
		normalized.Error,
		normalized.Evidence[0].Source,
		normalized.Evidence[0].Key,
		normalized.Evidence[0].Value,
	} {
		if !validReportText(value) {
			t.Fatalf("unsafe normalized text remains: %q", value)
		}
	}
	for key, value := range normalized.Facts {
		if !validReportText(key) || !validReportText(value) {
			t.Fatalf("unsafe normalized fact remains: %q=%q", key, value)
		}
	}
}

func TestValidateReportRejectsTerminalAndBidiControlText(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.Report)
	}{
		{
			name: "terminal escape in evidence",
			mutate: func(report *model.Report) {
				report.Findings[0].Evidence = append(report.Findings[0].Evidence, model.Evidence{
					Source: "fixture", Value: "forged\x1b[2JPASS",
				})
			},
		},
		{
			name: "bidi override in hostname",
			mutate: func(report *model.Report) {
				report.Host.Hostname = "host\u202eexample"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := validContractReport()
			test.mutate(&report)
			if failures := ValidateReport(report); len(failures) == 0 {
				t.Fatal("unsafe report text was accepted")
			}
		})
	}
}
