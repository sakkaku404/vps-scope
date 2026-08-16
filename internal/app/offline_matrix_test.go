package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestOfflineReportCommandsAcrossLocalesAndSchemas(t *testing.T) {
	dir := t.TempDir()
	currentPath := filepath.Join(dir, "current.json")
	current := appContractReport()
	current.Deployment = &model.Deployment{
		Coverage: model.DeploymentCoverage{
			Configuration: "complete", Runtime: "complete", Firewall: "complete",
			Panels: "complete", ReverseProxy: "not-applicable", Docker: "not-applicable",
		},
		Components: []model.Component{{
			ID: "component:0123456789abcdef", Product: "sing-box", Kind: "proxy-core",
			Source: "/etc/sing-box/config.json", Runtime: true, Deployment: "native", Confidence: "confirmed",
		}},
		Endpoints: []model.ServiceEndpoint{{
			ID: "endpoint:0123456789abcdef", ComponentID: "component:0123456789abcdef",
			Product: "sing-box", Role: "proxy-ingress", Protocol: "vless", Transport: "tcp", Port: 443,
			Address: "0.0.0.0", Family: "ipv4", Scope: "public-wildcard", State: "live",
			Judgment: "expected-proxy-ingress", Source: "/etc/sing-box/config.json", Confidence: "confirmed",
		}},
		Links: []model.TopologyLink{{From: "component:0123456789abcdef", To: "endpoint:0123456789abcdef", Kind: "declares"}},
	}
	writeJSONReport(t, currentPath, current)

	reports := map[string]string{
		"current": currentPath,
		"legacy":  filepath.Join("testdata", "golden-report-v1.json"),
	}
	locales := []string{"zh-CN", "en", "ru-RU", "fa-IR"}
	formats := []string{"text", "markdown", "html", "json"}
	for schemaName, reportPath := range reports {
		t.Run(schemaName+"/verify", func(t *testing.T) {
			runOfflineCommand(t, []string{"verify", reportPath})
		})
		for _, locale := range locales {
			locale := locale
			t.Run(schemaName+"/"+locale, func(t *testing.T) {
				for _, format := range formats {
					extension := map[string]string{"text": ".txt", "markdown": ".md", "html": ".html", "json": ".json"}[format]
					output := filepath.Join(dir, schemaName+"-"+locale+"-"+format+extension)
					runOfflineCommand(t, []string{"render", "--lang", locale, "--format", format, "--output", output, reportPath})
					data, err := os.ReadFile(output)
					if err != nil || len(data) == 0 {
						t.Fatalf("render %s: bytes=%d err=%v", format, len(data), err)
					}
					if format == "html" && locale == "fa-IR" && !bytes.Contains(data, []byte(`dir="rtl"`)) {
						t.Fatal("Persian HTML is missing RTL document direction")
					}
				}

				redacted := filepath.Join(dir, schemaName+"-"+locale+"-redacted.json")
				runOfflineCommand(t, []string{"redact", "--lang", locale, "--format", "json", "--output", redacted, reportPath})
				runOfflineCommand(t, []string{"verify", redacted})
				fleet := runOfflineCommand(t, []string{"fleet", "--lang", locale, reportPath})
				if strings.TrimSpace(fleet) == "" {
					t.Fatal("fleet produced no output")
				}
				runOfflineCommand(t, []string{"diff", "--lang", locale, reportPath, reportPath})
			})
		}

		support := filepath.Join(dir, schemaName+"-support")
		supportOutput := runOfflineCommand(t, []string{"support", "--output", support, reportPath})
		if !strings.Contains(supportOutput, "4 files total: 3 content files plus manifest.json") {
			t.Fatalf("support bundle reported the wrong file count: %q", supportOutput)
		}
		runOfflineCommand(t, []string{"verify", support})
	}
}

func runOfflineCommand(t *testing.T, args []string) string {
	t.Helper()
	var output bytes.Buffer
	if err := Run(args, bytes.NewReader(nil), &output, &output, BuildInfo{Version: "test"}); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, output.String())
	}
	return output.String()
}
