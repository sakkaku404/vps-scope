package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEnvWhitelistDoesNotReturnSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	data := "UVICORN_HOST=127.0.0.1\nUVICORN_PORT='8000'\nSUDO_PASSWORD=secret\nSQLALCHEMY_DATABASE_URL=sqlite:///secret.db\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readEnvWhitelist(path, map[string]bool{"UVICORN_HOST": true, "UVICORN_PORT": true})
	if err != nil {
		t.Fatal(err)
	}
	if got["UVICORN_HOST"] != "127.0.0.1" || got["UVICORN_PORT"] != "8000" || len(got) != 2 {
		t.Fatalf("unexpected allowlisted env: %#v", got)
	}
}

func TestReadKeyValueWhitelist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.cfg")
	if err := os.WriteFile(path, []byte("RUN_PORT=9000\nSECRET=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readKeyValueWhitelist(path, map[string]bool{"RUN_PORT": true})
	if err != nil || got["RUN_PORT"] != "9000" || len(got) != 1 {
		t.Fatalf("got=%#v err=%v", got, err)
	}
}

func TestApplyManagedProxyConfigExtractsOnlySemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.json")
	data := `{"inbounds":[{"listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"secret-uuid"}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"privateKey":"secret-key","target":"example.com:443","shortIds":["deadbeef"]}}}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s := panelSnapshot{Product: "Marzban"}
	applyManagedProxyConfig(&s, path, "Xray")
	if len(s.Inbounds) != 1 {
		t.Fatalf("inbounds=%#v error=%s", s.Inbounds, s.DatabaseError)
	}
	inbound := s.Inbounds[0]
	if inbound.Port != "443" || inbound.Protocol != "vless" || !inbound.RealityKeySet || inbound.RealityTargets != 1 || inbound.RealityIDs != 1 {
		t.Fatalf("inbound=%#v", inbound)
	}
}

func TestSingBoxMieruPortBindings(t *testing.T) {
	data := []byte(`{"inbounds":[{"type":"mieru","listen":"::","portBindings":[{"port":16659,"protocol":"TCP"},{"port":46348,"protocol":"UDP"}],"users":[{"name":"withheld","password":"secret"}]}]}`)
	s := parseSingBoxSummary("fixture.json", data)
	if len(s.Inbounds) != 2 || s.Inbounds[0].Port != "16659" || s.Inbounds[1].Port != "46348" || !s.UsesUDP {
		t.Fatalf("summary=%#v", s)
	}
}

func TestManagedPanelProcessOwnership(t *testing.T) {
	for _, test := range []struct{ product, process string }{
		{"Hiddify", `users:(("hiddify-core",pid=1))`},
		{"Hiddify", `users:(("xray",pid=2))`},
		{"Marzban", `users:(("xray",pid=3))`},
		{"3x-ui", `users:(("x-ui",pid=4))`},
		{"Outline", `users:(("outline-ss-serv",pid=5))`},
	} {
		if !panelOwnsProcess(test.product, test.process) {
			t.Errorf("%s should own %s", test.product, test.process)
		}
	}
	if panelOwnsProcess("Marzban", `users:(("nginx",pid=5))`) {
		t.Fatal("Marzban should not claim an unrelated nginx process")
	}
}

func TestOutlineAdapterWhitelistsEnvironmentAndState(t *testing.T) {
	values := outlineEnvValues([]string{
		"SB_API_PORT=39443",
		"SB_STATE_DIR=/opt/outline/persisted-state",
		"SB_API_PREFIX=must-not-leak",
		"SB_PRIVATE_KEY_FILE=/secret/key",
	})
	if len(values) != 2 || values["SB_API_PORT"] != "39443" || values["SB_STATE_DIR"] != "/opt/outline/persisted-state" {
		t.Fatalf("allowlisted values=%#v", values)
	}
	port, ok := parseOutlineState([]byte(`{"hostname":"203.0.113.10","portForNewAccessKeys":39444,"secret":"must-not-leak"}`))
	if !ok || port != "39444" {
		t.Fatalf("port=%q ok=%t", port, ok)
	}
}
