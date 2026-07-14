package app

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/i18n"
)

func TestPublishedReportSchemaAndCatalogCoverStableIDs(t *testing.T) {
	data, err := os.ReadFile("../../schemas/report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("published report schema is invalid JSON: %v", err)
	}
	if schema["title"] == "" {
		t.Fatal("published report schema has no title")
	}
	for _, id := range audit.StableCheckIDs {
		rule := i18n.RuleFor(id)
		if rule.Title.ZH == "" || rule.Title.EN == "" || rule.Why.ZH == "" || rule.Why.EN == "" || rule.Recommendation.ZH == "" || rule.Recommendation.EN == "" {
			t.Errorf("stable check %s has an incomplete bilingual catalog entry", id)
		}
	}
}
