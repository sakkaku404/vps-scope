package report

import "testing"

func FuzzSafeBundleFileName(f *testing.F) {
	for _, seed := range []string{"report.json", "report.zh-CN.html", "../report.json", "/etc/passwd", "report.json/extra"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if safeBundleFileName("1.0", name) && (name == "" || name[0] == '/' || name == "." || name == "..") {
			t.Fatalf("unsafe bundle file name accepted: %q", name)
		}
	})
}
