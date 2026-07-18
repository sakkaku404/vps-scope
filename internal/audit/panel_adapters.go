package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type panelAdapter interface {
	ID() string
	Detect() bool
	Collect(Commander) panelSnapshot
}

type nativePanelAdapter struct {
	id, binary string
	detect     func() bool
	collect    func(Commander) panelSnapshot
}

func (a nativePanelAdapter) ID() string { return a.id }
func (a nativePanelAdapter) Detect() bool {
	if a.detect != nil {
		return a.detect()
	}
	return regularFile(a.binary)
}
func (a nativePanelAdapter) Collect(cmd Commander) panelSnapshot { return a.collect(cmd) }

func panelAdapters() []panelAdapter {
	return []panelAdapter{
		nativePanelAdapter{id: "s-ui/native-v1", binary: "/usr/local/s-ui/sui", collect: collectSUIFacts},
		nativePanelAdapter{id: "x-ui/native-v1", binary: "/usr/local/x-ui/x-ui", collect: collectXUIFacts},
		nativePanelAdapter{id: "marzban/managed-v1", detect: func() bool { return directoryExists("/opt/marzban") || directoryExists("/var/lib/marzban") }, collect: collectMarzbanFacts},
		nativePanelAdapter{id: "hiddify/managed-v1", detect: func() bool { return directoryExists("/opt/hiddify-manager") }, collect: collectHiddifyFacts},
	}
}

type panelSchemaInspection struct {
	Version      string
	Fingerprint  string
	Capabilities []string
}

func inspectPanelSchema(cmd Commander, database, product string) (panelSchemaInspection, error) {
	var lastErr error
	var last panelSchemaInspection
	for attempt, delay := range []time.Duration{0, 100 * time.Millisecond, 250 * time.Millisecond} {
		if attempt > 0 {
			time.Sleep(delay)
		}
		inspection, err := inspectPanelSchemaOnce(cmd, database, product)
		if err == nil {
			return inspection, nil
		}
		last = inspection
		lastErr = err
	}
	return last, lastErr
}

func inspectPanelSchemaOnce(cmd Commander, database, product string) (panelSchemaInspection, error) {
	rows, err := sqliteTSV(cmd, database, `SELECT name FROM sqlite_master WHERE type='table';`)
	if err != nil {
		return panelSchemaInspection{}, fmt.Errorf("panel schema tables: %w", err)
	}
	tables := map[string]map[string]bool{}
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		name := row[0]
		cols, queryErr := sqliteTSV(cmd, database, `PRAGMA table_info("`+strings.ReplaceAll(name, `"`, `""`)+`");`)
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
	switch version {
	case "s-ui-db-v1":
		return []string{"management-endpoint", "subscription-endpoint", "inbound-state", "reality-metadata", "client-state", "certificate-path"}
	case "x-ui-db-v1":
		return []string{"management-endpoint", "subscription-endpoint", "inbound-state", "reality-metadata", "client-state", "certificate-path"}
	default:
		return nil
	}
}

func classifyPanelSchema(product string, tables map[string]map[string]bool) (string, error) {
	has := func(table string, columns ...string) bool {
		available, ok := tables[table]
		if !ok {
			return false
		}
		for _, column := range columns {
			if !available[column] {
				return false
			}
		}
		return true
	}
	switch strings.ToLower(product) {
	case "s-ui":
		if has("settings", "key", "value") && has("inbounds", "type", "options", "tls_id") && has("tls", "id", "server") {
			return "s-ui-db-v1", nil
		}
	case "x-ui", "3x-ui":
		if has("settings", "key", "value") && has("inbounds", "enable", "port", "protocol", "settings", "stream_settings") {
			return "x-ui-db-v1", nil
		}
	}
	return "", fmt.Errorf("unsupported %s database schema", product)
}
