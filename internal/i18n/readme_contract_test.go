package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLocalizedReadmesKeepTheUserContract(t *testing.T) {
	t.Parallel()
	files := []string{
		"../../README.md",
		"../../docs/README.en.md",
		"../../docs/README.ru.md",
		"../../docs/README.fa.md",
	}
	required := []string{
		"releases/latest/download/run.sh",
		"S-UI 56709/tcp",
		"report.json",
		"manifest.json",
		"vps-scope-reports/latest",
		"SFTP",
		"scp <SSH_HOST>",
		"--profile proxy",
		"`auto`",
		"`general`",
		"`proxy`",
		"`web`",
		"`docker`",
		"`mixed`",
		"`custom`",
		"--expect-public",
		"--native-self-test",
		"`PASS`",
		"`RISK`",
		"`INFO`",
		"`UNKNOWN`",
		"vernu/vps-audit",
	}

	for _, name := range files {
		name := name
		t.Run(filepath.Base(name), func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, token := range required {
				if !strings.Contains(text, token) {
					t.Errorf("missing required README contract token %q", token)
				}
			}
			if strings.Count(text, "```")%2 != 0 {
				t.Error("contains an unclosed fenced code block")
			}
			checkLocalMarkdownLinks(t, name, text)
		})
	}
}

func TestRussianAndPersianReadmesRejectKnownLiteralMistranslations(t *testing.T) {
	t.Parallel()
	for name, rejected := range map[string][]string{
		"../../docs/README.ru.md": {
			"физическом осмотре VPS",
			"плоскостью управления",
			"обратной генерации",
			"криминалистической экспертизы",
			"VPS Scope Что проверить",
		},
		"../../docs/README.fa.md": {
			"هواپیمای مدیریتی",
			"پورتال عامل",
			"خرابی\u200cهای پزشکی قانونی",
			"بوت چینی/انگلیسی",
			"دامنه و محدودیت\u200cها را پشتیبانی کنید",
		},
	} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, phrase := range rejected {
			if strings.Contains(string(data), phrase) {
				t.Errorf("%s contains rejected literal mistranslation %q", name, phrase)
			}
		}
	}
}

var markdownLinkPattern = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)

func checkLocalMarkdownLinks(t *testing.T, document, text string) {
	t.Helper()
	base := filepath.Dir(document)
	for _, match := range markdownLinkPattern.FindAllStringSubmatch(text, -1) {
		target := match[1]
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
			strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:") {
			continue
		}
		if before, _, ok := strings.Cut(target, "#"); ok {
			target = before
		}
		if target == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(base, filepath.FromSlash(target))); err != nil {
			t.Errorf("broken local Markdown link %q: %v", match[1], err)
		}
	}
}
