package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type panelAdapter interface {
	Descriptor() panelAdapterDescriptor
	Detect(panelInventory) bool
	Collect(panelAdapterInput) panelSnapshot
}

type nativePanelAdapter struct {
	descriptor panelAdapterDescriptor
	collect    func(panelAdapterInput) panelSnapshot
}

type panelAdapterDescriptor struct {
	ID          string
	Product     string
	Binary      string
	Directories []string
	Deployment  string
}

type panelAdapterInput struct {
	Context        context.Context
	Commander      Commander
	NativeSelfTest bool
	AuditTime      time.Time
	Files          *fileEvidenceSnapshot
}

type panelInventory interface {
	RegularFile(string) bool
	DirectoryExists(string) bool
}

type snapshotPanelInventory struct{ files *fileEvidenceSnapshot }

func (i snapshotPanelInventory) RegularFile(path string) bool {
	info, err := i.files.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
func (i snapshotPanelInventory) DirectoryExists(path string) bool {
	info, err := i.files.Stat(path)
	return err == nil && info.IsDir()
}

func (a nativePanelAdapter) Descriptor() panelAdapterDescriptor { return a.descriptor }
func (a nativePanelAdapter) Detect(inventory panelInventory) bool {
	if a.descriptor.Binary != "" && inventory.RegularFile(a.descriptor.Binary) {
		return true
	}
	for _, directory := range a.descriptor.Directories {
		if inventory.DirectoryExists(directory) {
			return true
		}
	}
	return false
}
func (a nativePanelAdapter) Collect(input panelAdapterInput) panelSnapshot {
	return a.collect(input)
}

func panelAdapters() []panelAdapter {
	return []panelAdapter{
		nativePanelAdapter{descriptor: panelAdapterDescriptor{ID: "s-ui/native-v1", Product: "S-UI", Binary: "/usr/local/s-ui/sui", Deployment: "native"}, collect: func(input panelAdapterInput) panelSnapshot {
			return collectSUIFactsAtSourceContext(input.Context, input.Commander, input.NativeSelfTest, input.AuditTime, input.Files)
		}},
		nativePanelAdapter{descriptor: panelAdapterDescriptor{ID: "x-ui/native-v1", Product: "x-ui/3x-ui", Binary: "/usr/local/x-ui/x-ui", Deployment: "native"}, collect: func(input panelAdapterInput) panelSnapshot {
			return collectXUIFactsAtSourceContext(input.Context, input.Commander, input.NativeSelfTest, input.AuditTime, input.Files)
		}},
		nativePanelAdapter{descriptor: panelAdapterDescriptor{ID: "marzban/managed-v1", Product: "Marzban", Directories: []string{"/opt/marzban", "/var/lib/marzban"}, Deployment: "managed"}, collect: func(input panelAdapterInput) panelSnapshot { return collectMarzbanFactsFromFiles(input.Files) }},
		nativePanelAdapter{descriptor: panelAdapterDescriptor{ID: "hiddify/managed-v1", Product: "Hiddify", Directories: []string{"/opt/hiddify-manager"}, Deployment: "managed"}, collect: func(input panelAdapterInput) panelSnapshot { return collectHiddifyFactsFromFiles(input.Files) }},
	}
}

type panelSchemaInspection struct {
	Version      string
	Fingerprint  string
	Capabilities []string
}

type sqliteMetadataQuery func(string) ([][]string, error)

type panelSchemaDescriptor struct {
	Version      string
	Products     []string
	Required     map[string][]string
	Capabilities []string
}

var panelSchemaRegistry = []panelSchemaDescriptor{
	{
		Version:  "s-ui-db-v1",
		Products: []string{"s-ui"},
		Required: map[string][]string{
			"settings": {"key", "value"},
			"inbounds": {"type", "options", "tls_id"},
			"tls":      {"id", "server"},
		},
		Capabilities: []string{"management-endpoint", "subscription-endpoint", "inbound-state", "reality-metadata", "client-state", "certificate-path"},
	},
	{
		Version:  "x-ui-db-v1",
		Products: []string{"x-ui", "3x-ui"},
		Required: map[string][]string{
			"settings": {"key", "value"},
			"inbounds": {"enable", "port", "protocol", "settings", "stream_settings"},
		},
		Capabilities: []string{"management-endpoint", "subscription-endpoint", "inbound-state", "reality-metadata", "client-state", "certificate-path"},
	},
}

func inspectPanelSchemaWithQuery(query sqliteMetadataQuery, product string) (panelSchemaInspection, error) {
	rows, err := query(`SELECT name FROM sqlite_master WHERE type='table';`)
	if err != nil {
		return panelSchemaInspection{}, fmt.Errorf("panel schema tables: %w", err)
	}
	tables := map[string]map[string]bool{}
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		name := row[0]
		cols, queryErr := query(`PRAGMA table_info("` + strings.ReplaceAll(name, `"`, `""`) + `");`)
		if queryErr != nil {
			continue
		}
		tables[name] = map[string]bool{}
		for _, col := range cols {
			if len(col) > 1 {
				tables[name][col[1]] = true
			}
		}
	}
	fingerprint := panelSchemaFingerprint(tables)
	version, err := classifyPanelSchema(product, tables)
	inspection := panelSchemaInspection{Version: version, Fingerprint: fingerprint}
	if err != nil {
		return inspection, fmt.Errorf("%w (fingerprint=%s)", err, fingerprint)
	}
	inspection.Capabilities = panelSchemaCapabilities(version)
	return inspection, nil
}

func panelSchemaFingerprint(tables map[string]map[string]bool) string {
	var names []string
	for table, columns := range tables {
		for column := range columns {
			names = append(names, table+"."+column)
		}
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return hex.EncodeToString(sum[:8])
}

func panelSchemaCapabilities(version string) []string {
	for _, descriptor := range panelSchemaRegistry {
		if descriptor.Version == version {
			return append([]string(nil), descriptor.Capabilities...)
		}
	}
	return nil
}

func classifyPanelSchema(product string, tables map[string]map[string]bool) (string, error) {
	normalizedProduct := strings.ToLower(strings.TrimSpace(product))
	for _, descriptor := range panelSchemaRegistry {
		if !schemaSupportsProduct(descriptor.Products, normalizedProduct) {
			continue
		}
		matches := true
		for table, columns := range descriptor.Required {
			available, ok := tables[table]
			if !ok {
				matches = false
				break
			}
			for _, column := range columns {
				if !available[column] {
					matches = false
					break
				}
			}
			if !matches {
				break
			}
		}
		if matches {
			return descriptor.Version, nil
		}
	}
	return "", fmt.Errorf("unsupported %s database schema", product)
}

func schemaSupportsProduct(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
