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
