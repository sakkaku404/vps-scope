package app

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestInteractiveProfilePromptUsesConfiguredWriter(t *testing.T) {
	var out bytes.Buffer
	_ = Run(nil, strings.NewReader("1\n1\n1\n"), &out, &out, BuildInfo{Version: "test"})
	if strings.Contains(out.String(), "&{") {
		t.Fatalf("interactive output contains a formatted writer pointer: %q", out.String())
	}
	if !strings.Contains(out.String(), "选择 [1]: ") {
		t.Fatalf("interactive output is missing the profile prompt: %q", out.String())
	}
}

func TestParseDurationDays(t *testing.T) {
	got, err := parseDuration("7d")
	if err != nil || got != 7*24*time.Hour {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestChecksBilingual(t *testing.T) {
	for _, lang := range []string{"zh-CN", "en"} {
		var out bytes.Buffer
		if err := Run([]string{"checks", "--lang", lang}, bytes.NewBuffer(nil), &out, &out, BuildInfo{Version: "test"}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out.Bytes(), []byte("SSH-001")) {
			t.Fatalf("%s output missing SSH-001", lang)
		}
	}
}

func TestParseExpectedPublic(t *testing.T) {
	got, err := parseExpectedPublic("22/tcp, 443/tcp,8443/udp")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"22/tcp", "443/tcp", "8443/udp"} {
		if !got[key] {
			t.Fatalf("missing %s", key)
		}
	}
	if _, err := parseExpectedPublic("tcp/22"); err == nil {
		t.Fatal("invalid format accepted")
	}
}
