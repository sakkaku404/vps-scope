package i18n

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func TestLocalizedReadmesDoNotLeakChineseInstructions(t *testing.T) {
	for _, path := range []string{"../../docs/README.ru.md", "../../docs/README.fa.md"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for lineNumber, line := range strings.Split(string(data), "\n") {
			// The language switcher intentionally labels the Chinese document in
			// Chinese. No other Han text belongs in Russian or Persian guidance.
			if strings.Contains(line, "../README.md") {
				continue
			}
			for _, r := range line {
				if unicode.Is(unicode.Han, r) {
					t.Fatalf("%s:%d contains untranslated Chinese text: %q", path, lineNumber+1, line)
				}
			}
		}
	}
}

// TestEveryLiteralUIMessageIsTranslated closes a subtle localization failure
// mode: choose() intentionally falls back to English, so changing one English
// source sentence could otherwise make only that line silently regress in the
// Russian and Persian reports. Parsing the two renderer/CLI packages makes the
// committed catalogs a checked source contract rather than a best-effort map.
func TestEveryLiteralUIMessageIsTranslated(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate i18n test source")
	}
	internal := filepath.Dir(filepath.Dir(current))
	used := map[string]string{}
	dynamicCalls := 0
	for _, packageName := range []string{"app", "report"} {
		dir := filepath.Join(internal, packageName)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) != 3 {
					return true
				}
				name, ok := call.Fun.(*ast.Ident)
				if !ok || name.Name != "choose" {
					return true
				}
				literal, ok := call.Args[2].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					dynamicCalls++
					return true
				}
				english, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Errorf("%s has invalid English UI literal: %v", path, err)
					return true
				}
				used[english] = path
				return true
			})
		}
	}
	// Seven proxy-overview helpers select from fixed bilingual label tables;
	// the HTML template adapter contributes one forwarding call. Keep this
	// exceptional surface fixed so new UI text cannot bypass catalog coverage.
	if dynamicCalls != 8 {
		t.Errorf("dynamic choose() calls=%d want 8; migrate new UI text to literal catalog-backed messages", dynamicCalls)
	}
	for english, path := range used {
		for _, locale := range []string{"ru-RU", "fa-IR"} {
			if strings.TrimSpace(ExtraUI[locale][english]) == "" {
				t.Errorf("%s lacks %s translation for %q", path, locale, english)
			}
		}
	}
}

func TestExtraUICatalogsHaveTheSameKeys(t *testing.T) {
	for english := range ExtraUI["ru-RU"] {
		if strings.TrimSpace(ExtraUI["fa-IR"][english]) == "" {
			t.Errorf("fa-IR lacks UI key %q", english)
		}
	}
	for english := range ExtraUI["fa-IR"] {
		if strings.TrimSpace(ExtraUI["ru-RU"][english]) == "" {
			t.Errorf("ru-RU lacks UI key %q", english)
		}
	}
}
