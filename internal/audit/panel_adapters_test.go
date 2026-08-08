package audit

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

type fixturePanelInventory struct {
	files       map[string]bool
	directories map[string]bool
}

func (i fixturePanelInventory) RegularFile(path string) bool     { return i.files[path] }
func (i fixturePanelInventory) DirectoryExists(path string) bool { return i.directories[path] }

func TestPanelAdapterDescriptorsDriveDetectionWithoutHostPaths(t *testing.T) {
	adapters := panelAdapters()
	seen := map[string]bool{}
	for _, adapter := range adapters {
		descriptor := adapter.Descriptor()
		if descriptor.ID == "" || descriptor.Product == "" || descriptor.Deployment == "" || seen[descriptor.ID] {
			t.Fatalf("invalid descriptor: %+v", descriptor)
		}
		seen[descriptor.ID] = true
	}
	inventory := fixturePanelInventory{
		files:       map[string]bool{"/usr/local/s-ui/sui": true},
		directories: map[string]bool{"/opt/hiddify-manager": true},
	}
	var detected []string
	for _, adapter := range adapters {
		if adapter.Detect(inventory) {
			detected = append(detected, adapter.Descriptor().ID)
		}
	}
	sort.Strings(detected)
	want := []string{"hiddify/managed-v1", "s-ui/native-v1"}
	if len(detected) != len(want) || detected[0] != want[0] || detected[1] != want[1] {
		t.Fatalf("detected=%v want=%v", detected, want)
	}
}

func TestPanelSnapshotCollectionUsesInjectedInventory(t *testing.T) {
	collectorCalls := 0
	adapter := nativePanelAdapter{
		descriptor: panelAdapterDescriptor{ID: "fixture/v1", Product: "Fixture", Binary: "/fixture/panel", Deployment: "native"},
		collect: func(panelAdapterInput) panelSnapshot {
			collectorCalls++
			return panelSnapshot{}
		},
	}
	inventory := fixturePanelInventory{files: map[string]bool{"/fixture/panel": true}}
	snapshots := collectPanelSnapshotsFromInventory(newScenarioCommander(nil, nil), false, time.Unix(1, 0), inventory, []panelAdapter{adapter}, nil)
	if collectorCalls != 1 || len(snapshots) != 1 || snapshots[0].Product != "Fixture" || snapshots[0].Adapter != "fixture/v1" {
		t.Fatalf("calls=%d snapshots=%+v", collectorCalls, snapshots)
	}
}

func TestPanelSnapshotCollectionPropagatesAuditCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	seenCanceled := false
	adapter := nativePanelAdapter{
		descriptor: panelAdapterDescriptor{ID: "fixture/v1", Product: "Fixture", Binary: "/fixture/panel", Deployment: "native"},
		collect: func(input panelAdapterInput) panelSnapshot {
			seenCanceled = input.Context != nil && input.Context.Err() == context.Canceled
			return panelSnapshot{}
		},
	}
	inventory := fixturePanelInventory{files: map[string]bool{"/fixture/panel": true}}
	collectPanelSnapshotsFromInventoryContext(ctx, newScenarioCommander(nil, nil), false, time.Unix(1, 0), inventory, []panelAdapter{adapter}, nil)
	if !seenCanceled {
		t.Fatal("panel adapter did not receive the audit cancellation context")
	}
}

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
			inspection, err := inspectPanelSchemaFixture(path, test.product)
			if err != nil {
				t.Fatal(err)
			}
			if inspection.Version != test.wantVersion || len(inspection.Fingerprint) != 16 || len(inspection.Capabilities) == 0 {
				t.Fatalf("inspection=%+v", inspection)
			}
		})
	}
}

func TestPanelSchemaRegistryHasCompleteUniqueVersions(t *testing.T) {
	versions := map[string]bool{}
	for _, descriptor := range panelSchemaRegistry {
		if descriptor.Version == "" || versions[descriptor.Version] {
			t.Fatalf("empty or duplicate schema version %q", descriptor.Version)
		}
		versions[descriptor.Version] = true
		if len(descriptor.Products) == 0 || len(descriptor.Required) == 0 || len(descriptor.Capabilities) == 0 {
			t.Fatalf("incomplete schema descriptor %+v", descriptor)
		}
		for _, product := range descriptor.Products {
			if product == "" || product != strings.ToLower(strings.TrimSpace(product)) {
				t.Fatalf("schema %s has a non-canonical product %q", descriptor.Version, product)
			}
		}
	}
}

func TestInspectPanelSchemaSupportsSUI153SchemaFixture(t *testing.T) {
	schema, err := os.ReadFile("testdata/panels/s-ui-1.5.3-schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectPanelSchemaFixture(path, "S-UI")
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Version != "s-ui-db-v1" || len(inspection.Fingerprint) != 16 || len(inspection.Capabilities) == 0 {
		t.Fatalf("inspection=%+v", inspection)
	}
}

func TestInspectPanelSchemaKeepsUnknownLayoutUnsupported(t *testing.T) {
	path, db := newSQLiteFixture(t)
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT, value TEXT); CREATE TABLE future_inbounds (port INTEGER);`); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectPanelSchemaFixture(path, "3x-ui")
	if err == nil || inspection.Version != "" || len(inspection.Fingerprint) != 16 {
		t.Fatalf("inspection=%+v err=%v, want unsupported schema", inspection, err)
	}
}

func inspectPanelSchemaFixture(path, product string) (panelSchemaInspection, error) {
	session, err := openSQLiteSession(path)
	if err != nil {
		return panelSchemaInspection{}, err
	}
	defer session.Close()
	return inspectPanelSchemaWithQuery(session.Query, product)
}
