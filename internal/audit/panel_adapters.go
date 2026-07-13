package audit

import (
	"fmt"
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

func detectPanelSchema(cmd Commander, database, product string) (string, error) {
	var lastErr error
	for attempt, delay := range []time.Duration{0, 100 * time.Millisecond, 250 * time.Millisecond} {
		if attempt > 0 {
			time.Sleep(delay)
		}
		schema, err := detectPanelSchemaOnce(cmd, database, product)
		if err == nil {
			return schema, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func detectPanelSchemaOnce(cmd Commander, database, product string) (string, error) {
	rows, err := sqliteTSV(cmd, database, `SELECT name FROM sqlite_master WHERE type='table';`)
	if err != nil {
		return "", fmt.Errorf("panel schema tables: %w", err)
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
	return classifyPanelSchema(product, tables)
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
