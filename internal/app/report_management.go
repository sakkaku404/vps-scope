package app

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/report"
	"github.com/sakkaku404/vps-scope/internal/safefs"
)

func (e environment) writeReport(format, output string, r model.Report, opts report.Options, alsoTerminal ...bool) error {
	if format == "bundle" {
		if len(alsoTerminal) > 0 && alsoTerminal[0] {
			if err := report.Text(e.out, r, opts); err != nil {
				return err
			}
		}
		useDefault := output == ""
		if output == "" {
			var err error
			output, err = defaultBundleDir(r)
			if err != nil {
				return err
			}
		}
		manifest, err := report.Bundle(output, r, opts)
		if err != nil {
			return err
		}
		output, err = filepath.Abs(output)
		if err != nil {
			return err
		}
		if useDefault {
			if err := updateLatest(filepath.Dir(filepath.Dir(output)), output); err != nil {
				return fmt.Errorf("update latest report link: %w", err)
			}
		}
		convenientDir := output
		if useDefault {
			convenientDir = filepath.Join(filepath.Dir(filepath.Dir(output)), "latest")
		}
		e.printBundleHelp(output, convenientDir, opts.Locale, len(manifest.Files))
		return nil
	}
	var write func(io.Writer) error
	switch format {
	case "terminal", "text":
		write = func(w io.Writer) error { return report.Text(w, r, opts) }
	case "json":
		write = func(w io.Writer) error { return report.JSON(w, r) }
	case "markdown", "md":
		write = func(w io.Writer) error { return report.Markdown(w, r, opts) }
	case "html":
		write = func(w io.Writer) error { return report.HTML(w, r, opts) }
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
	if output == "" {
		return write(e.out)
	}
	if err := atomicWriteNew(output, 64<<20, write); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "%s: %s\n", choose(opts.Locale, "报告", "Report"), output)
	return nil
}

func atomicWriteNew(path string, maxBytes int64, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vps-scope-output-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	w := &boundedWriter{Writer: tmp, limit: maxBytes, remaining: maxBytes}
	if err := write(w); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Publishing via a hard link is atomic and never replaces an existing
	// destination. The temporary inode lives in the same directory/filesystem.
	return os.Link(tmpName, path)
}

type boundedWriter struct {
	io.Writer
	limit     int64
	remaining int64
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, fmt.Errorf("report exceeds %d byte output safety limit", w.limit)
	}
	n, err := w.Writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}

func defaultBundleDir(r model.Report) (string, error) {
	root, err := reportRoot()
	if err != nil {
		return "", err
	}
	// Nanoseconds prevent two audits of the same host in one second from
	// selecting the same bundle directory and overwriting evidence.
	return filepath.Join(root, safeName(r.Host.Hostname), r.StartedAt.Format("20060102T150405.000000000Z")), nil
}

func reportRoot() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("VPS_SCOPE_REPORT_DIR")); configured != "" {
		return filepath.Abs(configured)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, "vps-scope-reports"), nil
}

func updateLatest(root, bundle string) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	target, err := filepath.Rel(root, bundle)
	if err != nil {
		return err
	}
	tmp := filepath.Join(root, fmt.Sprintf(".latest-%d", time.Now().UnixNano()))
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	defer os.Remove(tmp)
	latest := filepath.Join(root, "latest")
	if err := os.Rename(tmp, latest); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	// Windows does not replace an existing symlink with Rename. Audits run on
	// Linux, where the branch above is atomic; this fallback keeps local Windows
	// report tests and offline report management usable.
	if err := os.Remove(latest); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmp, latest)
}

func (e environment) printBundleHelp(dir, convenientDir, locale string, reportFiles int) {
	ext := map[string]string{
		"html":     choose(locale, "用浏览器查看", "Open in a browser"),
		"text":     choose(locale, "在终端查看", "Read in a terminal"),
		"markdown": choose(locale, "Markdown 格式", "Markdown format"),
		"json":     choose(locale, "用于对比和重新生成", "Comparison and re-rendering"),
		"manifest": choose(locale, "文件完整性校验", "Integrity verification"),
	}
	localeName := locale
	fileSummary := fmt.Sprintf(choose(locale, "本次只执行了 1 次审计，生成 %d 种报告格式和 1 份校验清单，共 %d 个文件。", "One audit produced %d report formats and one integrity manifest: %d files total."), reportFiles, reportFiles+1)
	htmlName := "report." + localeName + ".html"
	htmlPath := filepath.Join(convenientDir, htmlName)
	fmt.Fprintf(e.out, "\n%s\n%s\n", choose(locale, "完整报告已经保存", "Full report saved"), fileSummary)
	fmt.Fprintf(e.out, "\n%s:\n  %s\n", choose(locale, "推荐查看", "Recommended report"), htmlPath)
	if runtime.GOOS == "windows" {
		fmt.Fprintf(e.out, "\n%s:\n  %s\n", choose(locale, "HTML 已保存在这台电脑，可点击下面的本地链接或双击文件查看", "The HTML report is on this computer; open the local link or double-click the file"), localFileURL(htmlPath))
	} else {
		e.printRemoteDownloadHelp(convenientDir, htmlName, locale)
	}
	fmt.Fprintf(e.out, "\n%s:\n  %s\n\n%s:\n", choose(locale, "报告历史目录", "Saved history directory"), dir, choose(locale, "本次报告包含", "Files in this bundle"))
	fmt.Fprintf(e.out, "  [1] %s   %s\n", htmlName, choose(locale, "推荐：下载后用浏览器打开", "Recommended: download and open in a browser"))
	fmt.Fprintf(e.out, "  [2] %s    %s\n", "report."+localeName+".txt", ext["text"])
	fmt.Fprintf(e.out, "  [3] %s     %s\n", "report."+localeName+".md", ext["markdown"])
	fmt.Fprintf(e.out, "  [4] %s         %s\n", "report.json", ext["json"])
	fmt.Fprintf(e.out, "  [5] %s       %s\n", "manifest.json", ext["manifest"])
	fmt.Fprintf(e.out, "\n%s\n", choose(locale, "以下命令仅适用于已经安装 VPS Scope 的服务器；一行临时运行不会保留程序本身。", "The following commands require an installed copy of VPS Scope; the one-line temporary runner does not keep the program."))
	fmt.Fprintf(e.out, "\n%s:\n  sudo vps-scope report show\n", choose(locale, "再次在终端查看最近报告", "Show the latest report in the terminal"))
	fmt.Fprintf(e.out, "\n%s:\n  sudo vps-scope verify %s\n", choose(locale, "需要时校验完整性", "Verify integrity when needed"), shellQuote(convenientDir))
}

func (e environment) printRemoteDownloadHelp(dir, htmlName, locale string) {
	htmlPath := path.Join(filepath.ToSlash(dir), htmlName)
	fmt.Fprintf(e.out, "\n%s:\n", choose(locale, "下载到自己的电脑", "Download to your computer"))
	fmt.Fprintf(e.out, "  %s:\n    %s\n", choose(locale, "最简单：在 SSH 软件中打开 SFTP，进入下面的目录并下载 HTML 文件", "Easiest: open SFTP in your SSH client, enter this directory, and download the HTML file"), dir)
	fmt.Fprintf(e.out, "    %s\n", htmlName)
	fmt.Fprintf(e.out, "\n  %s:\n    scp <SSH_HOST>:%s .\n", choose(locale, "也可以在自己的电脑运行命令", "Or run this command on your own computer"), shellQuote(htmlPath))
	fmt.Fprintf(e.out, "  %s\n", choose(locale, "<SSH_HOST> 是你平时使用的 IP、域名或 SSH 别名；端口、私钥或 ssh-agent 设置也要与平时登录时相同。", "<SSH_HOST> is the IP address, domain, or SSH alias you normally use; reuse the same port, identity file, or ssh-agent settings as your SSH login."))
}

func localFileURL(path string) string {
	path = filepath.ToSlash(path)
	if len(path) >= 2 && path[1] == ':' {
		path = "/" + path
	}
	return (&url.URL{Scheme: "file", Path: path}).String()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func (e environment) report(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: vps-scope report list|show|path")
	}
	root, err := reportRoot()
	if err != nil {
		return err
	}
	latest := filepath.Join(root, "latest")
	switch args[0] {
	case "path":
		path, err := filepath.EvalSymlinks(latest)
		if err != nil {
			return fmt.Errorf("no saved report found: %w", err)
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return err
		}
		fmt.Fprintln(e.out, path)
		return nil
	case "show":
		entries, err := safefs.ReadDirectoryBounded(latest, maxLatestReportEntries)
		if err != nil {
			return fmt.Errorf("read latest report bundle: %w", err)
		}
		var matches []string
		for _, entry := range entries {
			matched, matchErr := filepath.Match("report.*.txt", entry.Name())
			if matchErr != nil {
				return matchErr
			}
			if matched && !entry.IsDir() {
				matches = append(matches, filepath.Join(latest, entry.Name()))
			}
		}
		if len(matches) == 0 {
			return errors.New("no saved terminal report found; run an audit with a full report bundle first")
		}
		sort.Strings(matches)
		file, err := openLimitedLocalFile(matches[0], maxLocalJSONSize)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(e.out, file)
		return err
	case "list":
		var bundles []string
		hosts, err := safefs.ReadDirectoryBounded(root, maxReportHostEntries)
		if err != nil {
			return fmt.Errorf("no saved reports found: %w", err)
		}
		entriesExamined := len(hosts)
		for _, host := range hosts {
			if !host.IsDir() || host.Name() == "latest" {
				continue
			}
			remaining := maxReportListEntries - entriesExamined
			if remaining <= 0 {
				return fmt.Errorf("saved report inventory exceeds %d-entry safety limit", maxReportListEntries)
			}
			runs, readErr := safefs.ReadDirectoryBounded(filepath.Join(root, host.Name()), remaining)
			if readErr != nil {
				return fmt.Errorf("read saved reports for %q: %w", host.Name(), readErr)
			}
			entriesExamined += len(runs)
			for _, run := range runs {
				path := filepath.Join(root, host.Name(), run.Name())
				if run.IsDir() && regularPath(filepath.Join(path, "manifest.json")) {
					bundles = append(bundles, path)
				}
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(bundles)))
		if len(bundles) == 0 {
			return errors.New("no saved reports found")
		}
		for _, bundle := range bundles {
			fmt.Fprintln(e.out, bundle)
		}
		return nil
	default:
		return errors.New("usage: vps-scope report list|show|path")
	}
}

func openLimitedLocalFile(path string, maxBytes int64) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maxBytes {
		return nil, fmt.Errorf("local report %q is not a regular file within the %d byte limit", path, maxBytes)
	}
	// #nosec G304 -- path is a report selected by the user or bounded report
	// inventory and is validated before and after opening.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		_ = f.Close()
		return nil, fmt.Errorf("local report %q changed while being opened", path)
	}
	return f, nil
}

func regularPath(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
