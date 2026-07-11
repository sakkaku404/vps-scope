package audit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
	return []model.Finding{priv, timeFinding, checkResourceOverview(ctx)}
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
		}
	}
	r := ctx.Commander.Run(12*time.Second, "sshd", "-T")
	if r.Err != nil {
		errText := commandError(r)
		return []model.Finding{unknown("SSH-001", "ssh", "sshd -T", errText), unknown("SSH-002", "ssh", "sshd -T", errText), unknown("SSH-003", "ssh", "sshd -T", errText), checkSSHPermissions()}
	}
	effective := map[string]string{}
	for _, line := range lines(r.Stdout) {
		key, value, ok := strings.Cut(line, " ")
		if ok {
			effective[strings.ToLower(key)] = strings.TrimSpace(value)
		}
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
	return []model.Finding{fPassword, fRoot, fPub, checkSSHPermissions()}
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
						if containsAny(line, "command=", "environment=", "from=") {
							f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: "restricted_key_option", Value: truncate(line, 180)})
						}
					}
				}
			}
		}
	}
	for _, path := range existingFiles("/etc/ssh/ssh_host_*_key") {
		if info, err := os.Stat(path); err == nil && tooOpen(info, fs.FileMode(0o037)) {
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
	return f
}

func checkPrivileges(ctx *Context) []model.Finding {
	sudo := model.Finding{ID: "PRIV-001", Category: "privileges", Status: model.Pass}
	paths := append([]string{"/etc/sudoers"}, existingFiles("/etc/sudoers.d/*")...)
	readable := 0
	for _, path := range paths {
		data, err := readSmall(path, 2<<20)
		if err != nil {
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
				sudo.Evidence = append(sudo.Evidence, model.Evidence{Source: path, Key: fmt.Sprintf("line_%d", i+1), Value: truncate(trimmed, 300)})
			}
		}
	}
	if readable == 0 {
		sudo = unknown("PRIV-001", "privileges", "/etc/sudoers{,.d}", "no sudoers files were readable")
	}

	privileged := model.Finding{ID: "PRIV-002", Category: "privileges", Status: model.Info, Facts: map[string]string{}}
	if !ctx.Commander.Exists("find") {
		privileged = unknown("PRIV-002", "privileges", "find", "command not found")
	} else {
		r := ctx.Commander.Run(35*time.Second, "find", "/usr", "/bin", "/sbin", "/opt", "/usr/local", "-xdev", "-type", "f", "-perm", "/6000", "-print")
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
		r := ctx.Commander.Run(30*time.Second, "getcap", "-r", "/usr", "/bin", "/sbin", "/opt", "/usr/local")
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

func packageOwns(cmd Commander, path string) bool {
	if !cmd.Exists("dpkg-query") {
		return false
	}
	r := cmd.Run(5*time.Second, "dpkg-query", "-S", path)
	return r.Err == nil && strings.Contains(r.Stdout, ":")
}
