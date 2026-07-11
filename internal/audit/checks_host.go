package audit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func checkWorkloads(ctx *Context) []model.Finding {
	f := model.Finding{ID: "WORK-001", Category: "workloads", Status: model.Info,
		Facts: map[string]string{"requested": ctx.Profile.Requested, "detected": ctx.Profile.Detected, "effective": ctx.Profile.Effective}}
	for _, reason := range ctx.Profile.Reasons {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "process and command detection", Key: "reason", Value: reason})
	}
	if ctx.Commander.Exists("ps") {
		r := ctx.Commander.Run(8*time.Second, "ps", "-eo", "pid=,user=,comm=,args=")
		for _, line := range lines(r.Stdout) {
			if workloadProcesses.MatchString(line) && len(f.Evidence) < 40 {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ps", Value: truncate(line, 350)})
			}
		}
	}
	return []model.Finding{f, checkSUIManagement(ctx)}
}

func checkSUIManagement(ctx *Context) model.Finding {
	binary := "/usr/local/s-ui/sui"
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		return notApplicable("WORK-002", "workloads", "binary discovery", "S-UI not installed at the supported path")
	}
	settings := ctx.Commander.Run(10*time.Second, binary, "setting", "-show")
	if settings.Err != nil {
		return unknown("WORK-002", "workloads", "sui setting -show", commandError(settings))
	}
	portRE := regexp.MustCompile(`(?mi)^\s*Panel port:\s*([0-9]+)\s*$`)
	match := portRE.FindStringSubmatch(settings.Stdout)
	if len(match) < 2 {
		return unknown("WORK-002", "workloads", "sui setting -show", "panel port was not present in command output")
	}
	port := match[1]
	f := model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Info, Facts: map[string]string{"panel_port": port}}
	version := ctx.Commander.Run(8*time.Second, binary, "-v")
	for _, line := range lines(version.Stdout) {
		if containsAny(line, "S-UI Panel", "Sing-Box") {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "sui -v", Value: line})
		}
	}
	listenerScope := "not-listening"
	if ctx.Commander.Exists("ss") {
		ss := ctx.Commander.Run(12*time.Second, "ss", "-H", "-lntup")
		for _, listener := range parseListeners(ss.Stdout) {
			if listener.Port == port && strings.HasPrefix(listener.Protocol, "tcp") {
				listenerScope = listener.Scope
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "panel_listener", Value: fmt.Sprintf("%s:%s scope=%s process=%s", listener.Address, port, listener.Scope, truncate(listener.Process, 160))})
			}
		}
	}
	allowAnywhere := false
	if ctx.Commander.Exists("ufw") {
		ufw := ctx.Commander.Run(12*time.Second, "ufw", "status", "verbose")
		for _, line := range lines(ufw.Stdout) {
			if strings.HasPrefix(strings.TrimSpace(line), port+"/tcp") && strings.Contains(line, "ALLOW IN") && strings.Contains(line, "Anywhere") {
				allowAnywhere = true
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ufw status verbose", Key: "panel_rule", Value: line})
			}
		}
	}
	f.Facts["listener_scope"] = listenerScope
	f.Facts["allow_anywhere"] = strconv.FormatBool(allowAnywhere)
	if (listenerScope == "public" || listenerScope == "public-wildcard") && allowAnywhere {
		f.Status, f.Severity = model.Risk, model.High
	} else if listenerScope == "loopback" {
		f.Status = model.Pass
	}
	return f
}

func checkFilesystem(ctx *Context) []model.Finding {
	f := model.Finding{ID: "FS-001", Category: "filesystem", Status: model.Pass, Facts: map[string]string{}}
	type target struct {
		path      string
		forbidden fs.FileMode
		secret    bool
	}
	targets := []target{
		{"/etc/passwd", 0o022, false}, {"/etc/shadow", 0o027, true}, {"/etc/sudoers", 0o022, true},
		{"/etc/ssh/sshd_config", 0o022, false}, {"/etc/sing-box/config.json", 0o077, true},
		{"/etc/hysteria/config.yaml", 0o077, true}, {"/etc/hysteria/config.yml", 0o077, true},
		{"/etc/x-ui/x-ui.db", 0o077, true}, {"/etc/s-ui/s-ui.db", 0o077, true}, {"/usr/local/s-ui/db/s-ui.db", 0o077, true},
	}
	problems := 0
	checked := 0
	for _, t := range targets {
		info, err := os.Stat(t.path)
		if err != nil {
			continue
		}
		checked++
		if tooOpen(info, t.forbidden) {
			problems++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "insecure_mode", Value: fmt.Sprintf("%s mode=%s", t.path, modeString(info))})
		}
	}
	for _, path := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		checked++
		if info.Mode().Perm()&0o002 != 0 && info.Mode()&os.ModeSticky == 0 {
			problems++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "missing_sticky_bit", Value: path + " mode=" + modeString(info)})
		}
	}
	f.Facts["checked_paths"] = strconv.Itoa(checked)
	f.Facts["permission_problems"] = strconv.Itoa(problems)
	if problems > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	return []model.Finding{f}
}

func checkPersistence(ctx *Context) []model.Finding {
	f := model.Finding{ID: "PERSIST-001", Category: "persistence", Status: model.Pass, Facts: map[string]string{}}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(/tmp/|/var/tmp/|/dev/shm/)`),
		regexp.MustCompile(`(?i)(curl|wget).{0,160}(\||;|&&).{0,40}(sh|bash)`),
		regexp.MustCompile(`(?i)base64\s+(-d|--decode).{0,120}(\||;).{0,40}(sh|bash)`),
	}
	paths := []string{"/etc/rc.local", "/etc/ld.so.preload", "/etc/crontab"}
	paths = append(paths, existingFiles("/etc/cron.d/*", "/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*/*.service")...)
	indicators := 0
	scanned := 0
	for _, path := range paths {
		data, err := readSmall(path, 4<<20)
		if err != nil {
			continue
		}
		scanned++
		for i, line := range lines(data) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, pattern := range patterns {
				if pattern.MatchString(trimmed) {
					indicators++
					f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: fmt.Sprintf("line_%d", i+1), Value: truncate(trimmed, 350)})
					break
				}
			}
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink == 0 && tooOpen(info, 0o022) {
			indicators++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "writable_startup_file", Value: path + " mode=" + modeString(info)})
		}
	}
	f.Facts["files_scanned"] = strconv.Itoa(scanned)
	f.Facts["indicators"] = strconv.Itoa(indicators)
	if indicators > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	return []model.Finding{f}
}

func checkReliability(ctx *Context) []model.Finding {
	f := model.Finding{ID: "REL-001", Category: "reliability", Status: model.Pass, Facts: map[string]string{}}
	oom, cores := 0, 0
	if ctx.Commander.Exists("journalctl") {
		r := ctx.Commander.Run(25*time.Second, "journalctl", "-k", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat")
		if r.Err == nil {
			re := regexp.MustCompile(`(?i)(out of memory|oom-kill|killed process \d+)`)
			for _, line := range lines(r.Stdout) {
				if re.MatchString(line) {
					oom++
					if len(f.Evidence) < 25 {
						f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl -k", Key: "oom", Value: truncate(line, 350)})
					}
				}
			}
		} else {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl -k", Key: "unavailable", Value: commandError(r)})
		}
	}
	if ctx.Commander.Exists("coredumpctl") {
		r := ctx.Commander.Run(20*time.Second, "coredumpctl", "list", "--since", sinceArg(ctx.LogSince), "--no-pager", "--no-legend")
		if r.Err == nil || r.Stdout != "" {
			coreLines := lines(r.Stdout)
			cores = len(coreLines)
			for i, line := range coreLines {
				if i >= 20 {
					break
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: "coredumpctl", Key: "core", Value: truncate(line, 350)})
			}
		}
	}
	storage := "auto"
	for _, path := range []string{"/etc/systemd/journald.conf"} {
		if data, err := readSmall(path, 2<<20); err == nil {
			for _, line := range lines(data) {
				if strings.HasPrefix(strings.TrimSpace(line), "Storage=") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
					_, storage, _ = strings.Cut(line, "=")
				}
			}
		}
	}
	persistent := false
	if info, err := os.Stat("/var/log/journal"); err == nil && info.IsDir() {
		persistent = true
	}
	diskFreePercent := diskFreePercent("/")
	f.Facts["oom_events"] = strconv.Itoa(oom)
	f.Facts["core_dumps"] = strconv.Itoa(cores)
	f.Facts["journal_storage"] = strings.TrimSpace(storage)
	f.Facts["journal_persistent_directory"] = strconv.FormatBool(persistent)
	f.Facts["root_disk_free_percent"] = strconv.Itoa(diskFreePercent)
	if oom > 0 || cores > 0 || (diskFreePercent >= 0 && diskFreePercent < 10) {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	f.Evidence = append(f.Evidence,
		model.Evidence{Source: "summary", Key: "oom_events", Value: strconv.Itoa(oom)},
		model.Evidence{Source: "summary", Key: "core_dumps", Value: strconv.Itoa(cores)},
		model.Evidence{Source: "/var/log/journal", Key: "persistent", Value: strconv.FormatBool(persistent)},
		model.Evidence{Source: "statfs /", Key: "free_percent", Value: strconv.Itoa(diskFreePercent)},
	)
	return []model.Finding{f}
}

// Keep deterministic order when future file scans add map-backed evidence.
func sortEvidence(values []model.Evidence) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Source == values[j].Source {
			return values[i].Value < values[j].Value
		}
		return values[i].Source < values[j].Source
	})
}

var _ = filepath.Separator
