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
	return []model.Finding{f, checkPanelManagement(ctx)}
}

type panelInstall struct {
	product string
	binary  string
	args    []string
}

func checkPanelManagement(ctx *Context) model.Finding {
	panels := discoverPanels(ctx)
	if len(panels) == 0 {
		return notApplicable("WORK-002", "workloads", "binary discovery", "no supported S-UI, 3x-ui, or x-ui installation found")
	}
	f := model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Pass, Facts: map[string]string{"panel_count": strconv.Itoa(len(panels))}}

	var listeners []Listener
	ssAvailable := ctx.Commander.Exists("ss")
	if ssAvailable {
		result := ctx.Commander.Run(12*time.Second, "ss", "-H", "-lntup")
		if result.Err == nil {
			listeners = parseListeners(result.Stdout)
		} else {
			ssAvailable = false
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss -H -lntup", Key: "error", Value: commandError(result)})
		}
	}
	ufw := readPanelUFW(ctx)
	products := make([]string, 0, len(panels))
	unknowns, inactive := 0, 0
	for _, panel := range panels {
		products = append(products, panel.product)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "panel discovery", Key: "product", Value: panel.product + " binary=" + panel.binary})
		settings := ctx.Commander.Run(10*time.Second, panel.binary, panel.args...)
		if settings.Err != nil && panel.product != "S-UI" {
			settings = ctx.Commander.Run(10*time.Second, panel.binary, "setting", "-show")
		}
		port, ok := parsePanelPort(panel.product, settings.Stdout)
		if settings.Err != nil || !ok {
			unknowns++
			f.Evidence = append(f.Evidence, model.Evidence{Source: panel.product + " settings", Key: "panel_port", Value: "unavailable"})
			continue
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: panel.product + " settings", Key: "panel_port", Value: port + "/tcp"})
		if !ssAvailable {
			unknowns++
			continue
		}
		scope, found := panelListenerScope(listeners, port, &f)
		if !found {
			inactive++
			continue
		}
		if scope != "public" && scope != "public-wildcard" {
			continue
		}
		disposition := panelFirewallDisposition(ufw, port, &f)
		switch disposition {
		case "allow-anywhere", "inactive":
			f.Status, f.Severity = model.Risk, model.High
		case "restricted", "blocked-by-default":
			// Public binding is constrained by the host firewall.
		default:
			unknowns++
		}
	}
	sort.Strings(products)
	f.Facts["products"] = strings.Join(products, ",")
	f.Facts["ports_unavailable"] = strconv.Itoa(unknowns)
	f.Facts["panels_not_listening"] = strconv.Itoa(inactive)
	if f.Status != model.Risk {
		if unknowns > 0 {
			f.Status, f.Unavailable = model.Unknown, true
			f.Error = "management-panel exposure could not be determined from the available port, listener, and firewall evidence"
		} else if inactive == len(panels) {
			f.Status = model.Info
		}
	}
	return f
}

func discoverPanels(ctx *Context) []panelInstall {
	var panels []panelInstall
	if regularFile("/usr/local/s-ui/sui") {
		panels = append(panels, panelInstall{product: "S-UI", binary: "/usr/local/s-ui/sui", args: []string{"setting", "-show"}})
	}
	if regularFile("/usr/local/x-ui/x-ui") {
		product := "x-ui"
		if script, err := os.ReadFile("/usr/local/x-ui/x-ui.sh"); err == nil && containsAny(string(script), "MHSanaei/3x-ui", "3X-UI", "3x-ui") {
			product = "3x-ui"
		}
		version := ctx.Commander.Run(8*time.Second, "/usr/local/x-ui/x-ui", "-v")
		if containsAny(version.Stdout+"\n"+version.Stderr, "3x-ui", "3X-UI") {
			product = "3x-ui"
		}
		panels = append(panels, panelInstall{product: product, binary: "/usr/local/x-ui/x-ui", args: []string{"setting", "-show", "true"}})
	}
	return panels
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parsePanelPort(product, output string) (string, bool) {
	pattern := `(?mi)^\s*(?:port|webPort)\s*:\s*([0-9]{1,5})\s*$`
	if product == "S-UI" {
		pattern = `(?mi)^\s*Panel port\s*:\s*([0-9]{1,5})\s*$`
	}
	match := regexp.MustCompile(pattern).FindStringSubmatch(output)
	if len(match) != 2 {
		return "", false
	}
	port, err := strconv.Atoi(match[1])
	return match[1], err == nil && port > 0 && port <= 65535
}

func panelListenerScope(listeners []Listener, port string, f *model.Finding) (string, bool) {
	scope := ""
	rank := map[string]int{"loopback": 1, "private": 2, "public": 3, "public-wildcard": 4}
	for _, listener := range listeners {
		if listener.Port != port || !strings.HasPrefix(listener.Protocol, "tcp") {
			continue
		}
		if rank[listener.Scope] > rank[scope] {
			scope = listener.Scope
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ss", Key: "panel_listener", Value: fmt.Sprintf("%s:%s scope=%s process=%s", listener.Address, port, listener.Scope, truncate(listener.Process, 160))})
	}
	return scope, scope != ""
}

type panelUFW struct {
	available, active, defaultDeny bool
	lines                          []string
}

func readPanelUFW(ctx *Context) panelUFW {
	if !ctx.Commander.Exists("ufw") {
		return panelUFW{}
	}
	r := ctx.Commander.Run(12*time.Second, "ufw", "status", "verbose")
	if r.Err != nil {
		return panelUFW{}
	}
	return panelUFW{available: true, active: regexp.MustCompile(`(?mi)^Status:\s+active\s*$`).MatchString(r.Stdout), defaultDeny: regexp.MustCompile(`(?mi)^Default:\s+deny \(incoming\)`).MatchString(r.Stdout), lines: lines(r.Stdout)}
}

func panelFirewallDisposition(ufw panelUFW, port string, f *model.Finding) string {
	if !ufw.available {
		return "unknown"
	}
	if !ufw.active {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ufw status verbose", Key: "panel_firewall", Value: "inactive"})
		return "inactive"
	}
	anywhere, restricted := false, false
	for _, line := range ufw.lines {
		idx := strings.Index(line, "ALLOW IN")
		if idx < 0 {
			continue
		}
		target := strings.TrimSpace(line[:idx])
		if target != port && target != port+"/tcp" && target != port+"/tcp (v6)" {
			continue
		}
		from := strings.TrimSpace(line[idx+len("ALLOW IN"):])
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ufw status verbose", Key: "panel_rule", Value: line})
		if strings.HasPrefix(from, "Anywhere") {
			anywhere = true
		} else {
			restricted = true
		}
	}
	if anywhere {
		return "allow-anywhere"
	}
	if restricted {
		return "restricted"
	}
	if ufw.defaultDeny {
		return "blocked-by-default"
	}
	return "unknown"
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
