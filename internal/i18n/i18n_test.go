package i18n

import (
	"strings"
	"testing"
)

func TestLocaleSupportsFourLanguages(t *testing.T) {
	for _, key := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(key, "")
	}
	for input, want := range map[string]string{
		"zh-CN": "zh-CN", "en": "en", "ru": "ru-RU", "ru_RU": "ru-RU",
		"fa": "fa-IR", "fa_IR": "fa-IR", "farsi": "fa-IR",
	} {
		if got := Locale(input); got != want {
			t.Errorf("Locale(%q)=%q want %q", input, got, want)
		}
	}
}

func TestLocaleAutoDetectsRussianAndPersian(t *testing.T) {
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	for value, want := range map[string]string{"ru_RU.UTF-8": "ru-RU", "fa_IR.UTF-8": "fa-IR"} {
		t.Setenv("LANG", value)
		if got := Locale("auto"); got != want {
			t.Errorf("LANG=%q locale=%q want %q", value, got, want)
		}
	}
}

func TestExtraCatalogsAreComplete(t *testing.T) {
	for _, locale := range []string{"ru-RU", "fa-IR"} {
		if len(ExtraCategories[locale]) != len(Categories) {
			t.Errorf("%s categories=%d want %d", locale, len(ExtraCategories[locale]), len(Categories))
		}
		if len(ExtraRules[locale]) != len(Rules) {
			t.Errorf("%s rules=%d want %d", locale, len(ExtraRules[locale]), len(Rules))
		}
		for id := range Rules {
			item := ExtraRules[locale][id]
			if strings.TrimSpace(item.Title) == "" || strings.TrimSpace(item.Why) == "" || strings.TrimSpace(item.Recommendation) == "" {
				t.Errorf("%s %s has an incomplete translation", locale, id)
			}
		}
		if UI(locale, "代理 VPS 结论", "Proxy VPS assessment") == "Proxy VPS assessment" {
			t.Errorf("%s UI fell back to English", locale)
		}
	}
}

func TestUITranslationsPreserveFormatAndStatusTokens(t *testing.T) {
	for locale, catalog := range ExtraUI {
		for source, translated := range catalog {
			for _, placeholder := range []string{"%d", "%s", "%t"} {
				if strings.Count(source, placeholder) != strings.Count(translated, placeholder) {
					t.Errorf("%s placeholder %s mismatch for %q -> %q", locale, placeholder, source, translated)
				}
			}
			for _, token := range []string{"PASS", "RISK", "INFO", "UNKNOWN"} {
				if strings.Contains(source, token) && !strings.Contains(translated, token) {
					t.Errorf("%s lost token %s in %q -> %q", locale, token, source, translated)
				}
			}
		}
	}
}

func TestPersianIsRTL(t *testing.T) {
	if !RTL("fa-IR") || RTL("ru-RU") || RTL("en") || RTL("zh-CN") {
		t.Fatal("unexpected RTL locale classification")
	}
}
