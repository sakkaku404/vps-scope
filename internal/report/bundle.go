package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/sakkaku404/vps-scope/internal/i18n"
	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/safejson"
)

type Manifest struct {
	SchemaVersion string         `json:"schema_version"`
	CreatedAt     time.Time      `json:"created_at"`
	Files         []ManifestFile `json:"files"`
}

type ManifestFile struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

const maxManifestBytes = 1 << 20
const maxBundleFileBytes = 64 << 20
const maxBundleDirectoryEntries = 17 // manifest plus the maximum 16 declared files

var bundleFileNameRE = regexp.MustCompile(`^report\.([A-Za-z0-9-]+)\.(txt|md|html)$`)

func Bundle(dir string, r model.Report, opts Options) (Manifest, error) {
	locale := opts.Locale
	if !i18n.Supported(locale) {
		return Manifest{}, fmt.Errorf("unsupported report bundle locale %q", locale)
	}
	files := map[string]func(io.Writer) error{
		"report.json": func(w io.Writer) error { return JSON(w, r) },
		"report." + locale + ".txt": func(w io.Writer) error {
			local := opts
			local.Verbose = true
			local.Color = false
			return Text(w, r, local)
		},
		"report." + locale + ".md":   func(w io.Writer) error { return Markdown(w, r, opts) },
		"report." + locale + ".html": func(w io.Writer) error { return HTML(w, r, opts) },
	}
	return writeBundleFiles(dir, "1.0", files)
}

func writeBundleFiles(dir, schema string, files map[string]func(io.Writer) error) (manifest Manifest, err error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return Manifest{}, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Manifest{}, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(dir)
		}
	}()
	manifest = Manifest{SchemaVersion: schema, CreatedAt: time.Now().UTC()}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := atomicWriteLimited(path, maxBundleFileBytes, files[name]); err != nil {
			return Manifest{}, err
		}
		size, digest, err := fileDigest(path, maxBundleFileBytes)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Files = append(manifest.Files, ManifestFile{Name: name, Size: int(size), SHA256: digest})
	}
	if err := atomicWriteLimited(filepath.Join(dir, "manifest.json"), maxManifestBytes, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}); err != nil {
		return Manifest{}, err
	}
	complete = true
	return manifest, nil
}

func VerifyBundle(dir string) (Manifest, []string, error) {
	data, err := readFileLimited(filepath.Join(dir, "manifest.json"), maxManifestBytes)
	if err != nil {
		return Manifest{}, nil, err
	}
	var manifest Manifest
	if err := safejson.RejectDuplicateMembers(bytes.NewReader(data)); err != nil {
		return Manifest{}, nil, fmt.Errorf("manifest JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, nil, fmt.Errorf("manifest contains more than one JSON value")
		}
		return Manifest{}, nil, fmt.Errorf("manifest trailing data: %w", err)
	}
	if len(manifest.Files) > 16 {
		return Manifest{}, nil, fmt.Errorf("manifest declares too many files")
	}
	if manifest.SchemaVersion != "1.0" && manifest.SchemaVersion != SupportSchema {
		return Manifest{}, nil, fmt.Errorf("unsupported manifest schema %q", manifest.SchemaVersion)
	}
	failures := manifestCompletenessFailures(manifest)
	seen := map[string]bool{}
	for _, item := range manifest.Files {
		if !safeBundleFileName(manifest.SchemaVersion, item.Name) {
			failures = append(failures, item.Name+": invalid manifest file name")
			continue
		}
		if seen[item.Name] {
			failures = append(failures, item.Name+": duplicate manifest file name")
			continue
		}
		seen[item.Name] = true
		if item.Size < 0 || item.Size > maxBundleFileBytes {
			failures = append(failures, item.Name+": declared size exceeds safety limit")
			continue
		}
		size, digest, err := fileDigest(filepath.Join(dir, item.Name), int64(item.Size))
		if err != nil {
			failures = append(failures, item.Name+": "+err.Error())
			continue
		}
		if size != int64(item.Size) || digest != item.SHA256 {
			failures = append(failures, item.Name+": size or SHA-256 mismatch")
		}
	}
	entries, tooManyEntries, err := readDirectoryEntriesLimited(dir, maxBundleDirectoryEntries)
	if err != nil {
		return Manifest{}, nil, err
	}
	if tooManyEntries {
		failures = append(failures, fmt.Sprintf("bundle directory exceeds the %d entry safety limit", maxBundleDirectoryEntries))
		return manifest, failures, nil
	}
	declared := map[string]bool{"manifest.json": true}
	for _, item := range manifest.Files {
		declared[item.Name] = true
	}
	for _, entry := range entries {
		if !declared[entry.Name()] {
			failures = append(failures, entry.Name()+": file is not declared in manifest")
		}
	}
	return manifest, failures, nil
}

func readDirectoryEntriesLimited(dir string, maxEntries int) ([]os.DirEntry, bool, error) {
	if maxEntries < 0 {
		return nil, false, fmt.Errorf("invalid directory entry limit")
	}
	// #nosec G304 -- dir is the explicitly requested bundle directory; only a
	// bounded directory listing is performed.
	f, err := os.Open(dir)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, fmt.Errorf("bundle path is not a directory")
	}
	entries, err := f.ReadDir(maxEntries + 1)
	if err != nil && err != io.EOF {
		return nil, false, err
	}
	return entries, len(entries) > maxEntries, nil
}

func manifestCompletenessFailures(manifest Manifest) []string {
	if manifest.SchemaVersion == SupportSchema {
		required := map[string]bool{"report.redacted.json": false, "compatibility.json": false, "README.txt": false}
		for _, item := range manifest.Files {
			if _, ok := required[item.Name]; ok {
				required[item.Name] = true
			}
		}
		var failures []string
		for _, name := range []string{"README.txt", "compatibility.json", "report.redacted.json"} {
			if !required[name] {
				failures = append(failures, name+": required support-bundle file is missing from manifest")
			}
		}
		if len(manifest.Files) != 3 {
			failures = append(failures, fmt.Sprintf("manifest declares %d files; a support bundle requires exactly 3", len(manifest.Files)))
		}
		return failures
	}

	var failures []string
	hasJSON := false
	locales := map[string]map[string]bool{}
	for _, item := range manifest.Files {
		if item.Name == "report.json" {
			hasJSON = true
			continue
		}
		match := bundleFileNameRE.FindStringSubmatch(item.Name)
		if len(match) != 3 {
			continue
		}
		if locales[match[1]] == nil {
			locales[match[1]] = map[string]bool{}
		}
		locales[match[1]][match[2]] = true
	}
	if !hasJSON {
		failures = append(failures, "report.json: required report file is missing from manifest")
	}
	completeLocales := 0
	for _, extensions := range locales {
		if extensions["txt"] && extensions["md"] && extensions["html"] {
			completeLocales++
		}
	}
	if completeLocales == 0 {
		failures = append(failures, "localized report set is incomplete; expected matching txt, md, and html files")
	} else if completeLocales > 1 {
		failures = append(failures, "manifest contains more than one complete report locale")
	}
	if len(manifest.Files) != 4 {
		failures = append(failures, fmt.Sprintf("manifest declares %d files; a report bundle requires exactly 4", len(manifest.Files)))
	}
	return failures
}

func safeBundleFileName(schema, name string) bool {
	if schema == SupportSchema {
		return name == "report.redacted.json" || name == "compatibility.json" || name == "README.txt"
	}
	if name == "report.json" {
		return true
	}
	return filepath.Base(name) == name && bundleFileNameRE.MatchString(name)
}

func atomicWriteLimited(path string, maxBytes int64, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vps-scope-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := write(&limitedWriter{Writer: tmp, limit: maxBytes, remaining: maxBytes}); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type limitedWriter struct {
	io.Writer
	limit     int64
	remaining int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("report exceeds %d byte bundle safety limit", w.limit)
	}
	n, err := w.Writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func fileDigest(path string, maxBytes int64) (int64, string, error) {
	f, size, err := openRegularLimited(path, maxBytes)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, maxBytes+1))
	if err != nil {
		return 0, "", err
	}
	if n > maxBytes {
		return 0, "", fmt.Errorf("file exceeds %d byte safety limit", maxBytes)
	}
	if n != size {
		return 0, "", fmt.Errorf("file size changed during verification")
	}
	return n, hex.EncodeToString(hash.Sum(nil)), nil
}

func readFileLimited(path string, maxBytes int64) ([]byte, error) {
	f, size, err := openRegularLimited(path, maxBytes)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("manifest exceeds %d bytes", maxBytes)
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("manifest size changed during verification")
	}
	return data, nil
}

// openRegularLimited verifies the path both before and after opening it. The
// SameFile check prevents a symlink or inode swap between Lstat and Open from
// turning bundle verification into an unintended file reader.
func openRegularLimited(path string, maxBytes int64) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, 0, fmt.Errorf("not a regular file")
	}
	if before.Size() < 0 || before.Size() > maxBytes {
		return nil, 0, fmt.Errorf("file exceeds %d byte safety limit", maxBytes)
	}
	// #nosec G304 -- manifest-controlled names are allowlisted before this
	// call; Lstat, size, regular-file and SameFile checks prevent path swaps.
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		_ = f.Close()
		return nil, 0, fmt.Errorf("file changed during verification")
	}
	return f, after.Size(), nil
}
