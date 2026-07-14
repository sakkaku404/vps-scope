package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/redact"
)

const SupportSchema = "vps-scope-support/v1"

type SupportSnapshot struct {
	SchemaVersion string           `json:"schema_version"`
	CreatedAt     time.Time        `json:"created_at"`
	ToolVersion   string           `json:"tool_version"`
	ReportSchema  string           `json:"report_schema"`
	Host          SupportHost      `json:"host"`
	Profile       string           `json:"profile"`
	Products      []string         `json:"products,omitempty"`
	Panels        []SupportPanel   `json:"panels,omitempty"`
	Findings      []SupportFinding `json:"findings"`
	Privacy       string           `json:"privacy"`
}

type SupportHost struct {
	OS             string `json:"os"`
	OSVersion      string `json:"os_version"`
	Architecture   string `json:"architecture"`
	Virtualization string `json:"virtualization,omitempty"`
}

type SupportPanel struct {
	Product           string `json:"product"`
	Version           string `json:"version,omitempty"`
	Adapter           string `json:"adapter,omitempty"`
	Schema            string `json:"schema,omitempty"`
	SchemaFingerprint string `json:"schema_fingerprint,omitempty"`
	Capabilities      string `json:"capabilities,omitempty"`
	SchemaSupported   bool   `json:"schema_supported"`
}

type SupportFinding struct {
	ID            string            `json:"id"`
	Status        model.Status      `json:"status"`
	Severity      model.Severity    `json:"severity,omitempty"`
	ReasonCode    string            `json:"reason_code,omitempty"`
	NotApplicable bool              `json:"not_applicable,omitempty"`
	Unavailable   bool              `json:"unavailable,omitempty"`
	Facts         map[string]string `json:"facts,omitempty"`
}

func SupportBundle(dir string, source model.Report) (Manifest, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return Manifest{}, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	redacted := redact.New().Report(source)
	snapshot := supportSnapshot(redacted)
	files := map[string]func(io.Writer) error{
		"report.redacted.json": func(w io.Writer) error { return JSON(w, redacted) },
		"compatibility.json": func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(snapshot)
		},
		"README.txt": func(w io.Writer) error {
			_, err := io.WriteString(w, "VPS Scope compatibility support bundle\n\nThis bundle is generated from an already-redacted report. It contains no raw panel databases, configuration files, private keys, tokens, UUIDs, passwords, public host addresses, or SSH key fingerprints. Review every file before sharing.\n\nVPS Scope 兼容性支持包\n\n本目录由已脱敏报告生成，不包含原始面板数据库、配置文件、私钥、令牌、UUID、密码、公网主机地址或 SSH 密钥指纹。分享前仍应自行检查每个文件。\n")
			return err
		},
	}
	manifest := Manifest{SchemaVersion: SupportSchema, CreatedAt: time.Now().UTC()}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := atomicWriteLimited(path, maxBundleFileBytes, files[name]); err != nil {
			return Manifest{}, err
		}
		size, digest, err := fileDigest(path, maxBundleFileBytes)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Files = append(manifest.Files, ManifestFile{Name: name, Size: int(size), SHA256: digest})
	}
	if err := atomicWriteLimited(filepath.Join(dir, "manifest.json"), maxManifestBytes, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func supportSnapshot(r model.Report) SupportSnapshot {
	s := SupportSnapshot{
		SchemaVersion: SupportSchema,
		CreatedAt:     time.Now().UTC(),
		ToolVersion:   r.ToolVersion,
		ReportSchema:  r.SchemaVersion,
		Host: SupportHost{OS: r.Host.OS, OSVersion: r.Host.OSVersion,
			Architecture: r.Host.Architecture, Virtualization: r.Host.Virtualization},
		Profile: r.Profile.Effective,
		Privacy: "redacted compatibility metadata only; review before sharing",
	}
	productSet := map[string]bool{}
	panelSet := map[string]bool{}
	for _, f := range r.Findings {
		s.Findings = append(s.Findings, SupportFinding{ID: f.ID, Status: f.Status, Severity: f.Severity,
			ReasonCode: f.ReasonCode, NotApplicable: f.NotApplicable, Unavailable: f.Unavailable, Facts: f.Facts})
		if f.ID == "WORK-001" || f.ID == "WORK-003" {
			for _, product := range strings.Split(f.Facts["products"], ",") {
				if product = strings.TrimSpace(product); product != "" {
					productSet[product] = true
				}
			}
		}
		if f.ID != "WORK-002" {
			continue
		}
		for _, evidence := range f.Evidence {
			if evidence.Key != "product" {
				continue
			}
			fields := relationFields(evidence.Value)
			panel := SupportPanel{Product: fields["product"], Version: fields["version"], Adapter: fields["adapter"],
				Schema: fields["schema"], SchemaFingerprint: fields["schema_fingerprint"], Capabilities: fields["capabilities"],
				SchemaSupported: fields["schema_supported"] == "true"}
			if panel.Product == "" {
				continue
			}
			key := fmt.Sprintf("%#v", panel)
			if !panelSet[key] {
				panelSet[key] = true
				s.Panels = append(s.Panels, panel)
			}
		}
	}
	for product := range productSet {
		s.Products = append(s.Products, product)
	}
	sort.Strings(s.Products)
	sort.Slice(s.Panels, func(i, j int) bool { return s.Panels[i].Product < s.Panels[j].Product })
	return s
}

func relationFields(value string) map[string]string {
	result := map[string]string{}
	for _, field := range strings.Fields(value) {
		key, val, ok := strings.Cut(field, "=")
		if ok {
			result[key] = val
		}
	}
	return result
}
