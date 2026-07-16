package audit

import "testing"

func TestPanelSchemaAdapters(t *testing.T) {
	xui := map[string]map[string]bool{
		"settings": {"key": true, "value": true},
		"inbounds": {"enable": true, "port": true, "protocol": true, "settings": true, "stream_settings": true},
	}
	if got, err := classifyPanelSchema("3x-ui", xui); err != nil || got != "x-ui-db-v1" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	sui := map[string]map[string]bool{
		"settings": {"key": true, "value": true},
		"inbounds": {"type": true, "options": true, "tls_id": true},
		"tls":      {"id": true, "server": true},
	}
	if got, err := classifyPanelSchema("S-UI", sui); err != nil || got != "s-ui-db-v1" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	delete(xui["inbounds"], "stream_settings")
	if _, err := classifyPanelSchema("3x-ui", xui); err == nil {
		t.Fatal("unsupported schema accepted")
	}
}

func TestPanelSchemaFingerprintIsOrderIndependentAndCapabilityBound(t *testing.T) {
	a := map[string]map[string]bool{"settings": {"value": true, "key": true}, "inbounds": {"protocol": true}}
	b := map[string]map[string]bool{"inbounds": {"protocol": true}, "settings": {"key": true, "value": true}}
	if panelSchemaFingerprint(a) != panelSchemaFingerprint(b) || len(panelSchemaFingerprint(a)) != 16 {
		t.Fatal("schema fingerprint must be stable and privacy-safe")
	}
	capabilities := panelSchemaCapabilities("x-ui-db-v1")
	if len(capabilities) < 5 || len(panelSchemaCapabilities("future-schema")) != 0 {
		t.Fatalf("unexpected capabilities: %#v", capabilities)
	}
}

func TestInspectPanelSchemaReadsRealSQLiteMetadata(t *testing.T) {
	tests := []struct {
		name, product, schema, wantVersion string
	}{
		{
			name:        "s-ui",
			product:     "S-UI",
			schema:      `CREATE TABLE settings (key TEXT, value TEXT); CREATE TABLE inbounds (type TEXT, options TEXT, tls_id INTEGER); CREATE TABLE tls (id INTEGER, server TEXT);`,
			wantVersion: "s-ui-db-v1",
		},
		{
			name:        "3x-ui",
			product:     "3x-ui",
			schema:      `CREATE TABLE settings (key TEXT, value TEXT); CREATE TABLE inbounds (enable INTEGER, port INTEGER, protocol TEXT, settings TEXT, stream_settings TEXT);`,
			wantVersion: "x-ui-db-v1",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, db := newSQLiteFixture(t)
			if _, err := db.Exec(test.schema); err != nil {
				t.Fatal(err)
			}
			inspection, err := inspectPanelSchema(newScenarioCommander(nil, nil), path, test.product)
			if err != nil {
				t.Fatal(err)
			}
			if inspection.Version != test.wantVersion || len(inspection.Fingerprint) != 16 || len(inspection.Capabilities) == 0 {
				t.Fatalf("inspection=%+v", inspection)
			}
		})
	}
}

func TestInspectPanelSchemaKeepsUnknownLayoutUnsupported(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT, value TEXT); CREATE TABLE future_inbounds (port INTEGER);`); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectPanelSchema(newScenarioCommander(nil, nil), path, "3x-ui")
	if err == nil || inspection.Version != "" || len(inspection.Fingerprint) != 16 {
		t.Fatalf("inspection=%+v err=%v, want unsupported schema", inspection, err)
	}
}
