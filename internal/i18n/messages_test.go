package i18n

import (
	"strings"
	"testing"
)

func TestStableMessagesHaveCompleteFourLanguageCatalogs(t *testing.T) {
	for id, source := range Messages {
		if strings.TrimSpace(string(id)) == "" || strings.TrimSpace(source.ZH) == "" || strings.TrimSpace(source.EN) == "" {
			t.Errorf("message %q has an incomplete source definition", id)
			continue
		}
		for _, locale := range []string{"ru-RU", "fa-IR"} {
			translated := Message(locale, id)
			if strings.TrimSpace(translated) == "" || translated == source.EN {
				t.Errorf("message %q lacks a %s translation", id, locale)
			}
		}
	}
}

func TestUnknownStableMessageDoesNotSilentlyBecomeEmpty(t *testing.T) {
	const unknown MessageID = "test.unknown"
	if got := Message("en", unknown); got != string(unknown) {
		t.Fatalf("Message(%q)=%q want stable identifier", unknown, got)
	}
}
