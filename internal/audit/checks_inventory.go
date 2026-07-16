package audit

import (
	"bufio"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func checkResourceOverview(ctx *Context) model.Finding {
	f := model.Finding{ID: "SYS-003", Category: "system", Status: model.Info, Facts: map[string]string{}}
	f.Facts["cpu_logical_cores"] = strconv.Itoa(runtime.NumCPU())
	f.Evidence = append(f.Evidence, model.Evidence{Source: "runtime", Key: "logical_cpu_cores", Value: strconv.Itoa(runtime.NumCPU())})

	if data, err := readSmall("/proc/cpuinfo", 4<<20); err == nil {
		if modelName := parseCPUModel(data); modelName != "" {
			f.Facts["cpu_model"] = modelName
			f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/cpuinfo", Key: "model", Value: modelName})
		}
	}
	if usedPercent, ok := sampleCPUUsage(200 * time.Millisecond); ok {
		f.Facts["cpu_used_percent"] = strconv.Itoa(usedPercent)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/stat", Key: "cpu_used_sample", Value: fmt.Sprintf("%d%% over 200ms", usedPercent)})
	}
	if data, err := readSmall("/proc/meminfo", 1<<20); err == nil {
		memory := parseMemInfo(data)
		total, available := memory["MemTotal"], memory["MemAvailable"]
		if total > 0 {
			usedPercent := (total - available) * 100 / total
			f.Facts["memory_total_bytes"] = strconv.FormatInt(total, 10)
			f.Facts["memory_available_bytes"] = strconv.FormatInt(available, 10)
			f.Facts["memory_used_percent"] = strconv.FormatInt(usedPercent, 10)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/meminfo", Key: "memory", Value: fmt.Sprintf("total=%s available=%s used=%d%%", humanBytes(total), humanBytes(available), usedPercent)})
		}
		if swap := memory["SwapTotal"]; swap > 0 {
			free := memory["SwapFree"]
			f.Facts["swap_total_bytes"] = strconv.FormatInt(swap, 10)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/meminfo", Key: "swap", Value: fmt.Sprintf("total=%s used=%s", humanBytes(swap), humanBytes(swap-free))})
		}
	}
	if data, err := readSmall("/proc/uptime", 4<<10); err == nil {
		fields := strings.Fields(data)
		if len(fields) > 0 {
			if seconds, err := strconv.ParseFloat(fields[0], 64); err == nil {
				f.Facts["uptime_seconds"] = strconv.FormatInt(int64(seconds), 10)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/uptime", Key: "uptime", Value: formatUptime(int64(seconds))})
			}
		}
	}
	if data, err := readSmall("/proc/loadavg", 4<<10); err == nil {
		fields := strings.Fields(data)
		if len(fields) >= 3 {
			value := strings.Join(fields[:3], " ")
			f.Facts["load_average_1_5_15"] = value
			f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/loadavg", Key: "load_1m_5m_15m", Value: value})
		}
	}
	if ctx.Commander.Exists("df") {
		r := ctx.Commander.Run(8*time.Second, "df", "-B1", "--output=size,used,avail,pcent", "/")
		if r.Err == nil {
			if disk, ok := parseDF(r.Stdout); ok {
				f.Facts["root_disk_total_bytes"] = strconv.FormatInt(disk.total, 10)
				f.Facts["root_disk_available_bytes"] = strconv.FormatInt(disk.available, 10)
				f.Facts["root_disk_used_percent"] = strconv.Itoa(disk.usedPercent)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "df -B1 /", Key: "root_disk", Value: fmt.Sprintf("total=%s available=%s used=%d%%", humanBytes(disk.total), humanBytes(disk.available), disk.usedPercent)})
			}
		}
	}
	return f
}

func parseCPUModel(input string) string {
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && (strings.TrimSpace(key) == "model name" || strings.TrimSpace(key) == "Model") {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

type cpuTicks struct{ total, idle uint64 }

func parseCPUStat(input string) (cpuTicks, bool) {
	for _, line := range lines(input) {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "cpu" {
			continue
		}
		var values []uint64
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return cpuTicks{}, false
			}
			values = append(values, value)
		}
		var total uint64
		for _, value := range values {
			total += value
		}
		idle := values[3]
		if len(values) > 4 {
			idle += values[4]
		}
		return cpuTicks{total: total, idle: idle}, true
	}
	return cpuTicks{}, false
}

func sampleCPUUsage(interval time.Duration) (int, bool) {
	firstData, err := readSmall("/proc/stat", 8<<20)
	if err != nil {
		return 0, false
	}
	first, ok := parseCPUStat(firstData)
	if !ok {
		return 0, false
	}
	time.Sleep(interval)
	secondData, err := readSmall("/proc/stat", 8<<20)
	if err != nil {
		return 0, false
	}
	second, ok := parseCPUStat(secondData)
	if !ok || second.total <= first.total || second.idle < first.idle {
		return 0, false
	}
	totalDelta, idleDelta := second.total-first.total, second.idle-first.idle
	return int((totalDelta - idleDelta) * 100 / totalDelta), true
}

func parseMemInfo(input string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range lines(input) {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			n *= 1024
		}
		out[strings.TrimSpace(key)] = n
	}
	return out
}

type diskUsage struct {
	total, available int64
	usedPercent      int
}

func parseDF(input string) (diskUsage, bool) {
	rows := lines(input)
	if len(rows) < 2 {
		return diskUsage{}, false
	}
	fields := strings.Fields(rows[len(rows)-1])
	if len(fields) != 4 {
		return diskUsage{}, false
	}
	total, errTotal := strconv.ParseInt(fields[0], 10, 64)
	available, errAvailable := strconv.ParseInt(fields[2], 10, 64)
	percent, errPercent := strconv.Atoi(strings.TrimSuffix(fields[3], "%"))
	return diskUsage{total: total, available: available, usedPercent: percent}, errTotal == nil && errAvailable == nil && errPercent == nil
}

func humanBytes(value int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v := float64(value)
	unit := 0
	for v >= 1024 && unit < len(units)-1 {
		v /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f%s", v, units[unit])
}

func formatUptime(seconds int64) string {
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
}

func checkPasswordPolicy(ctx *Context, entries []passwdEntry) model.Finding {
	f := model.Finding{ID: "ACC-003", Category: "accounts", Status: model.Info, Facts: map[string]string{}}
	if !ctx.Commander.Exists("sshd") {
		return notApplicable("ACC-003", "accounts", "sshd", "SSH server not installed; local password policy remains inventory only")
	}
	settings, err := ctx.Facts.SSHDSettings()
	if err != nil {
		return unknown("ACC-003", "accounts", "sshd -T", err.Error())
	}
	passwordEnabled := strings.ToLower(settings["passwordauthentication"]) != "no"
	f.Facts["ssh_password_path_enabled"] = strconv.FormatBool(passwordEnabled)
	f.Facts["ssh_keyboard_interactive_enabled"] = strconv.FormatBool(strings.ToLower(settings["kbdinteractiveauthentication"]) != "no")
	f.Evidence = append(f.Evidence,
		model.Evidence{Source: "sshd -T", Key: "passwordauthentication", Value: settings["passwordauthentication"]},
		model.Evidence{Source: "sshd -T", Key: "kbdinteractiveauthentication", Value: settings["kbdinteractiveauthentication"]},
	)

	loginUsers := map[string]bool{}
	for _, entry := range entries {
		if loginShell(entry.Shell) {
			loginUsers[entry.Name] = true
		}
	}
	passwordUsers := []string{}
	shadowReadable := false
	if data, err := readSmall("/etc/shadow", 4<<20); err == nil {
		shadowReadable = true
		passwordUsers = parseShadowPasswordUsers(data, loginUsers)
	}
	f.Facts["shadow_readable"] = strconv.FormatBool(shadowReadable)
	f.Facts["login_accounts_with_password_hash"] = strconv.Itoa(len(passwordUsers))
	for _, name := range passwordUsers {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "/etc/shadow", Key: "password_bearing_login_account", Value: name})
	}

	policyConfigured := false
	if data, err := readSmall("/etc/pam.d/common-password", 2<<20); err == nil {
		policyConfigured = hasPasswordQualityPolicy(data)
	}
	f.Facts["pam_password_quality_enforced"] = strconv.FormatBool(policyConfigured)
	f.Evidence = append(f.Evidence, model.Evidence{Source: "/etc/pam.d/common-password", Key: "quality_module_active", Value: strconv.FormatBool(policyConfigured)})
	if !passwordEnabled {
		return f
	}
	if !shadowReadable {
		return unknown("ACC-003", "accounts", "/etc/shadow", "SSH password authentication is enabled but password-bearing login accounts could not be determined")
	}
	if len(passwordUsers) == 0 {
		f.Status = model.Pass
		return f
	}
	if policyConfigured {
		f.Status = model.Pass
	} else {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	return f
}

func parseSpaceSettings(output string) map[string]string {
	out := map[string]string{}
	for _, line := range lines(output) {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			out[strings.ToLower(key)] = strings.TrimSpace(value)
		}
	}
	return out
}

func parseShadowPasswordUsers(input string, loginUsers map[string]bool) []string {
	var users []string
	for _, line := range lines(input) {
		parts := strings.Split(line, ":")
		if len(parts) < 2 || !loginUsers[parts[0]] {
			continue
		}
		value := parts[1]
		if value != "" && !strings.HasPrefix(value, "!") && !strings.HasPrefix(value, "*") {
			users = append(users, parts[0])
		}
	}
	sort.Strings(users)
	return users
}

func hasPasswordQualityPolicy(input string) bool {
	for _, line := range lines(input) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if containsAny(strings.ToLower(line), "pam_pwquality.so", "pam_passwdqc.so") {
			return true
		}
	}
	return false
}

func checkActiveConnections(ctx *Context) model.Finding {
	connections, err := ctx.Facts.EstablishedConnections()
	if err != nil {
		return unknown("NET-003", "network", "ss established", err.Error())
	}
	f := model.Finding{ID: "NET-003", Category: "network", Status: model.Info, Facts: map[string]string{}}
	counts := map[string]int{}
	for i, connection := range connections {
		counts[connection.scope]++
		if i < 80 {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "ss established", Key: "connection", Value: fmt.Sprintf("%s local=%s peer=%s peer_scope=%s process=%s", connection.protocol, connection.local, connection.peer, connection.scope, truncate(connection.process, 160))})
		}
	}
	f.Facts["total"] = strconv.Itoa(len(connections))
	for scope, count := range counts {
		f.Facts["peer_"+scope] = strconv.Itoa(count)
	}
	return f
}
