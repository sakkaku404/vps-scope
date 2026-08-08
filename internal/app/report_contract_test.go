package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/contract"
	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
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

func TestPublishedReportSchemaCoversEveryReportField(t *testing.T) {
	root := readPublishedReportSchema(t)
	properties, ok := root["properties"].(map[string]any)
	if !ok {
		t.Fatal("published report schema has no properties object")
	}
	typ := reflect.TypeOf(model.Report{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if _, exists := properties[name]; !exists {
			t.Errorf("published report schema does not document model.Report field %q", name)
		}
	}
}

func TestPublishedReportSchemaValidatesLegacyAndTypedReports(t *testing.T) {
	schema := compilePublishedReportSchema(t)
	legacy, err := os.ReadFile("testdata/golden-report-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	validateJSONAgainstSchema(t, schema, legacy)

	current := appContractReport()
	connections := 3
	current.Deployment = &model.Deployment{
		Coverage: model.DeploymentCoverage{
			Configuration: "complete", Runtime: "complete", Firewall: "partial",
			Panels: "not-applicable", ReverseProxy: "unavailable", Docker: "not-applicable",
		},
		Components: []model.Component{{
			ID: "component:fixture", Product: "sing-box", Kind: "proxy-core",
			Source: "/etc/sing-box/config.json", Runtime: true, Deployment: "native", Confidence: "confirmed",
		}},
		Endpoints: []model.ServiceEndpoint{{
			ID: "endpoint:fixture", ComponentID: "component:fixture", Product: "sing-box",
			Role: "proxy-ingress", Protocol: "vless", Transport: "tcp", Port: 443,
			Address: "0.0.0.0", Family: "ipv4", Scope: "public-wildcard", State: "live",
			Judgment: "expected-proxy-ingress", Source: "/etc/sing-box/config.json",
			Confidence: "confirmed", TLS: "true", PathPosture: "non-default", ConnectionCount: &connections,
		}},
		Links: []model.TopologyLink{{From: "component:fixture", To: "endpoint:fixture", Kind: "declares"}},
	}
	payload, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	validateJSONAgainstSchema(t, schema, payload)
}

func TestPublishedReportSchemaRejectsMalformedTypedDeployment(t *testing.T) {
	schema := compilePublishedReportSchema(t)
	for _, body := range []string{
		`{"coverage":{"configuration":"optimistic","runtime":"complete","firewall":"complete","panels":"complete","reverse_proxy":"complete","docker":"complete"}}`,
		`{"coverage":{"configuration":"complete","runtime":"complete","firewall":"complete","panels":"complete","reverse_proxy":"complete","docker":"complete"},"components":[{"id":"component:ok","product":"sing-box","kind":"proxy-core","confidence":"certain"}]}`,
		`{"coverage":{"configuration":"complete","runtime":"complete","firewall":"complete","panels":"complete","reverse_proxy":"complete","docker":"complete"},"endpoints":[{"id":"endpoint:ok","role":"management","transport":"icmp","port":70000,"state":"maybe","confidence":"confirmed"}]}`,
	} {
		var report map[string]any
		valid := appContractReport()
		payload, err := json.Marshal(valid)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(payload, &report); err != nil {
			t.Fatal(err)
		}
		var deployment any
		if err := json.Unmarshal([]byte(body), &deployment); err != nil {
			t.Fatal(err)
		}
		report["deployment"] = deployment
		if err := schema.Validate(report); err == nil {
			t.Fatalf("schema accepted malformed deployment: %s", body)
		}
	}
}

func TestPublishedReportSchemaEnforcesFindingResourceBudgets(t *testing.T) {
	schema := compilePublishedReportSchema(t)
	tests := []struct {
		name   string
		mutate func(*model.Report)
	}{
		{
			name: "evidence entries",
			mutate: func(report *model.Report) {
				report.Findings[0].Evidence = make([]model.Evidence, 257)
			},
		},
		{
			name: "fact entries",
			mutate: func(report *model.Report) {
				report.Findings[0].Facts = make(map[string]string, 257)
				for index := 0; index < 257; index++ {
					report.Findings[0].Facts[fmt.Sprintf("fact_%03d", index)] = "value"
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := appContractReport()
			test.mutate(&report)
			payload, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var value any
			if err := json.Unmarshal(payload, &value); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(value); err == nil {
				t.Fatal("published schema accepted an over-budget report")
			}
		})
	}
}

func TestPublishedReportSchemaBudgetsMatchRuntimeContract(t *testing.T) {
	root := readPublishedReportSchema(t)
	tests := []struct {
		want int
		path []string
	}{
		{contract.MaxReportFindings, []string{"properties", "findings", "maxItems"}},
		{contract.MaxReportEndpoints, []string{"properties", "endpoints", "maxItems"}},
		{contract.MaxReportMetadataEntries, []string{"properties", "metadata", "maxProperties"}},
		{contract.MaxReportProfileReasons, []string{"properties", "profile", "properties", "reasons", "maxItems"}},
		{contract.MaxFindingEvidenceEntries, []string{"properties", "findings", "items", "properties", "evidence", "maxItems"}},
		{contract.MaxFindingFactEntries, []string{"properties", "findings", "items", "properties", "facts", "maxProperties"}},
		{contract.MaxDeploymentComponents, []string{"$defs", "deployment", "properties", "components", "maxItems"}},
		{contract.MaxDeploymentEndpoints, []string{"$defs", "deployment", "properties", "endpoints", "maxItems"}},
		{contract.MaxDeploymentLinks, []string{"$defs", "deployment", "properties", "links", "maxItems"}},
		{contract.MaxEvidenceSourceBytes, []string{"$defs", "evidence", "properties", "source", "maxLength"}},
		{contract.MaxEvidenceKeyBytes, []string{"$defs", "evidence", "properties", "key", "maxLength"}},
		{contract.MaxEvidenceValueBytes, []string{"$defs", "evidence", "properties", "value", "maxLength"}},
	}
	for _, test := range tests {
		if got := schemaInteger(t, root, test.path...); got != test.want {
			t.Errorf("schema %s=%d want runtime contract %d", strings.Join(test.path, "."), got, test.want)
		}
	}
}

func schemaInteger(t *testing.T, root map[string]any, path ...string) int {
	t.Helper()
	var current any = root
	for _, segment := range path {
		object, ok := current.(map[string]any)
		if !ok {
			t.Fatalf("schema path %s is not an object", strings.Join(path, "."))
		}
		current, ok = object[segment]
		if !ok {
			t.Fatalf("schema path %s is missing", strings.Join(path, "."))
		}
	}
	number, ok := current.(float64)
	if !ok || number != float64(int(number)) {
		t.Fatalf("schema path %s is not an integer: %#v", strings.Join(path, "."), current)
	}
	return int(number)
}

func readPublishedReportSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../schemas/report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("published report schema is invalid JSON: %v", err)
	}
	return root
}

func compilePublishedReportSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, err := os.ReadFile("../../schemas/report-v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode published report schema: %v", err)
	}
	if err := compiler.AddResource("report-v1.schema.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("report-v1.schema.json")
	if err != nil {
		t.Fatalf("compile published report schema: %v", err)
	}
	return schema
}

func validateJSONAgainstSchema(t *testing.T, schema *jsonschema.Schema, payload []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("published report schema rejected report: %v", err)
	}
}
