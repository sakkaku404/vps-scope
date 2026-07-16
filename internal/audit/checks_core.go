package audit

import (
	"errors"
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

func checkSystem(ctx *Context) []model.Finding {
	priv := model.Finding{ID: "SYS-001", Category: "system", Status: model.Pass,
		Facts:    map[string]string{"is_root": strconv.FormatBool(ctx.Host.IsRoot)},
		Evidence: []model.Evidence{{Source: "geteuid", Key: "euid", Value: strconv.Itoa(os.Geteuid())}}}
	if !ctx.Host.IsRoot {
		priv.Status = model.Info
		priv.Evidence = append(priv.Evidence, model.Evidence{Source: "coverage", Value: "some privileged evidence may be unavailable"})
	}
	timeFinding := model.Finding{ID: "SYS-002", Category: "system"}
	if !ctx.Commander.Exists("timedatectl") {
		timeFinding = unknown("SYS-002", "system", "timedatectl", "command not found")
	} else {
		r := ctx.Commander.Run(8*time.Second, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
		if r.Err != nil {
			timeFinding = unknown("SYS-002", "system", "timedatectl", commandError(r))
		} else if strings.EqualFold(r.Stdout, "yes") {
			timeFinding.Status = model.Pass
		} else {
			timeFinding.Status, timeFinding.Severity = model.Risk, model.Low
		}
		timeFinding.Evidence = []model.Evidence{{Source: "timedatectl", Key: "NTPSynchronized", Value: r.Stdout}}
	}
	return []model.Finding{priv, timeFinding, checkResourceOverview(ctx), checkNetworkKernelContext(ctx)}
}

func checkNetworkKernelContext(ctx *Context) model.Finding {
	f := model.Finding{ID: "SYS-004", Category: "system", Status: model.Info, Facts: map[string]string{}}
	paths := map[string]string{
		"tcp_congestion_control": "/proc/sys/net/ipv4/tcp_congestion_control",
		"default_qdisc":          "/proc/sys/net/core/default_qdisc",
		"tcp_available_controls": "/proc/sys/net/ipv4/tcp_available_congestion_control",
	}
	for key, path := range paths {
		if value, err := readSmall(path, 4096); err == nil {
			value = strings.TrimSpace(value)
			f.Facts[key] = value
			f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: key, Value: value})
		}
	}
	if len(f.Evidence) == 0 {
		return unknown("SYS-004", "system", "/proc/sys/net", "network kernel state was not readable")
	}
	return f
}

func checkAccounts(ctx *Context) []model.Finding {
	entries, err := readPasswd()
	if err != nil {
		return []model.Finding{unknown("ACC-001", "accounts", "/etc/passwd", err.Error()), unknown("ACC-002", "accounts", "/etc/passwd", err.Error()), unknown("ACC-003", "accounts", "/etc/passwd", err.Error())}
	}
	var uid0, login []string
	for _, e := range entries {
		if e.UID == 0 {
			uid0 = append(uid0, e.Name)
		}
		if loginShell(e.Shell) {
			login = append(login, fmt.Sprintf("%s uid=%d shell=%s home=%s", e.Name, e.UID, e.Shell, e.Home))
		}
	}
	sort.Strings(uid0)
	sort.Strings(login)
	uidFinding := model.Finding{ID: "ACC-001", Category: "accounts", Status: model.Pass,
		Facts: map[string]string{"uid0_count": strconv.Itoa(len(uid0))}}
	if len(uid0) != 1 || uid0[0] != "root" {
		uidFinding.Status, uidFinding.Severity = model.Risk, model.Critical
	}
	for _, name := range uid0 {
		uidFinding.Evidence = append(uidFinding.Evidence, model.Evidence{Source: "/etc/passwd", Key: "uid0_user", Value: name})
	}
	loginFinding := model.Finding{ID: "ACC-002", Category: "accounts", Status: model.Info,
		Facts: map[string]string{"login_shell_count": strconv.Itoa(len(login))}}
	for i, value := range login {
		if i >= 30 {
			break
		}
		loginFinding.Evidence = append(loginFinding.Evidence, model.Evidence{Source: "/etc/passwd", Value: value})
	}
	return []model.Finding{uidFinding, loginFinding, checkPasswordPolicy(ctx, entries)}
}

func checkSSH(ctx *Context) []model.Finding {
	if !ctx.Commander.Exists("sshd") {
		return []model.Finding{
			notApplicable("SSH-001", "ssh", "command", "sshd not installed"),
			notApplicable("SSH-002", "ssh", "command", "sshd not installed"),
			notApplicable("SSH-003", "ssh", "command", "sshd not installed"),
			notApplicable("SSH-004", "ssh", "command", "sshd not installed"),
			notApplicable("SSH-005", "ssh", "command", "sshd not installed"),
		}
	}
	effective, err := ctx.Facts.SSHDSettings()
	if err != nil {
		return []model.Finding{unknown("SSH-001", "ssh", "sshd -T", err.Error()), unknown("SSH-002", "ssh", "sshd -T", err.Error()), unknown("SSH-003", "ssh", "sshd -T", err.Error()), checkSSHPermissions(), checkSSHKeyInventory(ctx)}
	}
	password := strings.ToLower(effective["passwordauthentication"])
	keyboard := strings.ToLower(effective["kbdinteractiveauthentication"])
	fPassword := model.Finding{ID: "SSH-001", Category: "ssh", Status: model.Pass,
		Evidence: []model.Evidence{{Source: "sshd -T", Key: "passwordauthentication", Value: password}, {Source: "sshd -T", Key: "kbdinteractiveauthentication", Value: keyboard}}}
	if password != "no" || keyboard != "no" {
		fPassword.Status, fPassword.Severity = model.Risk, model.High
	}
	root := strings.ToLower(effective["permitrootlogin"])
	fRoot := model.Finding{ID: "SSH-002", Category: "ssh", Status: model.Pass,
		Evidence: []model.Evidence{{Source: "sshd -T", Key: "permitrootlogin", Value: root}}}
	if root == "yes" {
		fRoot.Status, fRoot.Severity = model.Risk, model.High
	} else if root == "without-password" || root == "prohibit-password" {
		fRoot.Status = model.Info
	}
	pubkey := strings.ToLower(effective["pubkeyauthentication"])
	fPub := model.Finding{ID: "SSH-003", Category: "ssh", Status: model.Pass,
		Evidence: []model.Evidence{{Source: "sshd -T", Key: "pubkeyauthentication", Value: pubkey}}}
	if pubkey != "yes" {
		fPub.Status, fPub.Severity = model.Risk, model.High
	}
	return []model.Finding{fPassword, fRoot, fPub, checkSSHPermissions(), checkSSHKeyInventory(ctx)}
}

func checkSSHPermissions() model.Finding {
	entries, err := readPasswd()
	if err != nil {
		return unknown("SSH-004", "ssh", "/etc/passwd", err.Error())
	}
	f := model.Finding{ID: "SSH-004", Category: "ssh", Status: model.Pass, Facts: map[string]string{}}
	var problems []string
	keyCount := 0
	for _, e := range entries {
		if !loginShell(e.Shell) || e.Home == "" {
			continue
		}
		sshDir := filepath.Join(e.Home, ".ssh")
		if info, err := os.Stat(sshDir); err == nil {
			if tooOpen(info, 0o022) {
				problems = append(problems, fmt.Sprintf("%s mode=%s", sshDir, modeString(info)))
			}
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			path := filepath.Join(sshDir, name)
			if info, err := os.Stat(path); err == nil {
				keyCount++
				if tooOpen(info, 0o022) {
					problems = append(problems, fmt.Sprintf("%s mode=%s", path, modeString(info)))
				}
				if data, err := readSmall(path, 2<<20); err == nil {
					for _, line := range lines(data) {
						if strings.HasPrefix(strings.TrimSpace(line), "#") {
							continue
						}
						if options := authorizedKeyOptionNames(line); len(options) > 0 {
							f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: "authorized_key_options", Value: strings.Join(options, ",")})
						}
					}
				}
			}
		}
	}
	hostKeyPaths, discoveryErr := discoverExistingFiles(64, "/etc/ssh/ssh_host_*_key")
	for _, path := range hostKeyPaths {
		if info, err := os.Stat(path); err != nil {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, err))
		} else if tooOpen(info, fs.FileMode(0o037)) {
			problems = append(problems, fmt.Sprintf("%s mode=%s", path, modeString(info)))
		}
	}
	if len(problems) > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	for _, value := range problems {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "stat", Key: "insecure_mode", Value: value})
	}
	f.Facts["authorized_keys_files"] = strconv.Itoa(keyCount)
	f.Facts["permission_problems"] = strconv.Itoa(len(problems))
	return withIncompleteEvidence(f, "SSH host-key discovery", discoveryErr)
}

func checkSSHKeyInventory(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("ssh-keygen") {
		return unknown("SSH-005", "ssh", "ssh-keygen", "command not found")
	}
	entries, err := readPasswd()
	if err != nil {
		return unknown("SSH-005", "ssh", "/etc/passwd", err.Error())
	}
	f := model.Finding{ID: "SSH-005", Category: "ssh", Status: model.Pass, Facts: map[string]string{}}
	keys, weak, files, parseFailures := 0, 0, 0, 0
	fingerprints := map[string]int{}
	for _, entry := range entries {
		if !loginShell(entry.Shell) || entry.Home == "" {
			continue
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			path := filepath.Join(entry.Home, ".ssh", name)
			if !regularFile(path) {
				continue
			}
			files++
			data, readErr := readSmall(path, 2<<20)
			if readErr != nil {
				parseFailures++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "authorized_keys", Key: "unreadable", Value: path})
				continue
			}
			entryCount := authorizedKeyEntryCount(data)
			if entryCount == 0 {
				continue
			}
			r := ctx.Commander.Run(8*time.Second, "ssh-keygen", "-l", "-E", "sha256", "-f", path)
			if r.Err != nil && r.Stdout == "" {
				parseFailures++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ssh-keygen", Key: "unreadable_authorized_keys", Value: path})
				continue
			}
			parsedForFile := 0
			for _, line := range lines(r.Stdout) {
				item, ok := parseSSHKeygenFingerprint(line)
				if !ok {
					parseFailures++
					continue
				}
				keys++
				parsedForFile++
				fingerprints[item.fingerprint]++
				value := fmt.Sprintf("user=%s bits=%d fingerprint=%s type=%s", entry.Name, item.bits, item.fingerprint, item.algorithm)
				f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: "authorized_key", Value: value})
				if item.algorithm == "DSA" || (item.algorithm == "RSA" && item.bits < 2048) {
					weak++
					f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: "weak_authorized_key", Value: value})
				}
			}
			if r.Err != nil || parsedForFile < entryCount {
				parseFailures++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ssh-keygen", Key: "partially_unparsed_authorized_keys", Value: path})
			}
		}
	}
	duplicates := 0
	for _, count := range fingerprints {
		if count > 1 {
			duplicates += count - 1
		}
	}
	f.Facts["authorized_keys_files"] = strconv.Itoa(files)
	f.Facts["authorized_keys"] = strconv.Itoa(keys)
	f.Facts["weak_keys"] = strconv.Itoa(weak)
	f.Facts["duplicate_fingerprints"] = strconv.Itoa(duplicates)
	f.Facts["parse_failures"] = strconv.Itoa(parseFailures)
	if weak > 0 {
		f.Status, f.Severity = model.Risk, model.High
	} else if parseFailures > 0 {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "one or more authorized_keys files could not be fully fingerprinted"
	} else if files == 0 {
		f.Status = model.Info
	}
	return f
}

func authorizedKeyTextHasEntries(value string) bool {
	return authorizedKeyEntryCount(value) > 0
}

func authorizedKeyEntryCount(value string) int {
	count := 0
	for _, line := range lines(value) {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}

type sshKeyFingerprint struct {
	bits        int
	fingerprint string
	algorithm   string
}

func parseSSHKeygenFingerprint(line string) (sshKeyFingerprint, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return sshKeyFingerprint{}, false
	}
	bits, err := strconv.Atoi(fields[0])
	if err != nil || !strings.HasPrefix(fields[1], "SHA256:") {
		return sshKeyFingerprint{}, false
	}
	algorithm := strings.Trim(fields[len(fields)-1], "()")
	if algorithm == "" {
		return sshKeyFingerprint{}, false
	}
	return sshKeyFingerprint{bits: bits, fingerprint: fields[1], algorithm: strings.ToUpper(algorithm)}, true
}

func authorizedKeyOptionNames(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	index := -1
	for _, marker := range []string{" ssh-ed25519 ", " ssh-rsa ", " ssh-dss ", " ecdsa-sha2-", " sk-ssh-ed25519@", " sk-ecdsa-sha2-"} {
		if found := strings.Index(" "+line, marker); found >= 0 && (index < 0 || found < index) {
			index = found
		}
	}
	if index <= 0 {
		return nil
	}
	prefix := strings.TrimSpace((" " + line)[:index])
	if prefix == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, option := range splitAuthorizedKeyOptions(prefix) {
		name, _, _ := strings.Cut(strings.TrimSpace(option), "=")
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func splitAuthorizedKeyOptions(value string) []string {
	var out []string
	var current strings.Builder
	quoted, escaped := false, false
	for _, char := range value {
		if escaped {
			current.WriteRune(char)
			escaped = false
			continue
		}
		if char == '\\' && quoted {
			current.WriteRune(char)
			escaped = true
			continue
		}
		if char == '"' {
			quoted = !quoted
			current.WriteRune(char)
			continue
		}
		if char == ',' && !quoted {
			out = append(out, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(char)
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out
}

func checkPrivileges(ctx *Context) []model.Finding {
	sudo := model.Finding{ID: "PRIV-001", Category: "privileges", Status: model.Pass}
	dropIns, discoveryErr := discoverExistingFiles(256, "/etc/sudoers.d/*")
	paths := append([]string{"/etc/sudoers"}, dropIns...)
	discovered := make(map[string]bool, len(dropIns))
	for _, path := range dropIns {
		discovered[path] = true
	}
	readable := 0
	for _, path := range paths {
		data, err := readSmall(path, 2<<20)
		if err != nil {
			if discovered[path] || !errors.Is(err, fs.ErrNotExist) {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, err))
			}
			continue
		}
		readable++
		for i, line := range lines(data) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(strings.ToUpper(trimmed), "NOPASSWD:") {
				// A rule whose subject is root grants no privilege root does not
				// already have. Keep it out of risk findings.
				subject := strings.Fields(trimmed)
				if len(subject) > 0 && subject[0] == "root" {
					continue
				}
				sudo.Status, sudo.Severity = model.Risk, model.Medium
				// Sudo command arguments can contain deployment tokens. Retain the
				// privilege boundary, never the command text or its arguments.
				sudo.Evidence = append(sudo.Evidence, model.Evidence{Source: path, Key: fmt.Sprintf("line_%d", i+1), Value: sudoNOPASSWDEvidence(trimmed)})
			}
		}
	}
	if readable == 0 {
		sudo = unknown("PRIV-001", "privileges", "/etc/sudoers{,.d}", "no sudoers files were readable")
	}
	sudo = withIncompleteEvidence(sudo, "sudoers discovery", discoveryErr)

	if !ctx.Deep {
		return []model.Finding{sudo, notApplicable("PRIV-002", "privileges", "audit mode", "standard audit skips recursive SUID/SGID and capability discovery; run with --deep")}
	}
	privileged := model.Finding{ID: "PRIV-002", Category: "privileges", Status: model.Info, Facts: map[string]string{}}
	if !ctx.Commander.Exists("find") {
		privileged = unknown("PRIV-002", "privileges", "find", "command not found")
	} else {
		// /bin, /sbin and /usr/local are normally links or descendants of /usr.
		// Scanning them again can multiply runtime on small VPS disks.
		r := ctx.Commander.Run(18*time.Second, "find", "/usr", "/opt", "-xdev", "-type", "f", "-perm", "/6000", "-print")
		if r.Err != nil && r.Stdout == "" {
			privileged = unknown("PRIV-002", "privileges", "find", commandError(r))
		} else {
			items := lines(r.Stdout)
			privileged.Facts["suid_sgid_count"] = strconv.Itoa(len(items))
			for i, item := range items {
				if i >= 30 {
					break
				}
				privileged.Evidence = append(privileged.Evidence, model.Evidence{Source: "find -perm /6000", Value: item})
			}
			for _, item := range items {
				if (strings.HasPrefix(item, "/opt/") || strings.HasPrefix(item, "/usr/local/")) && !packageOwns(ctx.Commander, item) {
					privileged.Status, privileged.Severity = model.Risk, model.Medium
					privileged.Evidence = append(privileged.Evidence, model.Evidence{Source: "dpkg-query -S", Key: "unowned_privileged_file", Value: item})
				}
			}
		}
	}
	if ctx.Commander.Exists("getcap") {
		r := ctx.Commander.Run(18*time.Second, "getcap", "-r", "/usr", "/opt")
		caps := lines(r.Stdout)
		if privileged.Facts == nil {
			privileged.Facts = map[string]string{}
		}
		privileged.Facts["file_capability_count"] = strconv.Itoa(len(caps))
		for i, item := range caps {
			if i >= 30 {
				break
			}
			privileged.Evidence = append(privileged.Evidence, model.Evidence{Source: "getcap -r", Value: item})
			path := strings.Fields(item)
			if len(path) > 0 && containsAny(item, "cap_sys_admin", "cap_setuid", "cap_dac_override") && !packageOwns(ctx.Commander, path[0]) {
				privileged.Status, privileged.Severity = model.Risk, model.High
				privileged.Evidence = append(privileged.Evidence, model.Evidence{Source: "dpkg-query -S", Key: "unowned_dangerous_capability", Value: item})
			}
		}
	}
	return []model.Finding{sudo, privileged}
}

func sudoNOPASSWDEvidence(line string) string {
	fields := strings.Fields(line)
	subject := "unknown"
	if len(fields) > 0 {
		subject = fields[0]
	}
	runAs := "default"
	if match := regexp.MustCompile(`\(([^)]{1,80})\)`).FindStringSubmatch(line); len(match) == 2 {
		runAs = strings.TrimSpace(match[1])
	}
	return fmt.Sprintf("subject=%s runas=%s tag=NOPASSWD command_details=withheld", subject, runAs)
}

func packageOwns(cmd Commander, path string) bool {
	if !cmd.Exists("dpkg-query") {
		return false
	}
	r := cmd.Run(5*time.Second, "dpkg-query", "-S", path)
	return r.Err == nil && strings.Contains(r.Stdout, ":")
}
