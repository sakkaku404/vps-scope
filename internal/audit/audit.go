package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

const SchemaVersion = "1.0"

var CategoryOrder = []string{
	"system", "accounts", "ssh", "privileges", "network", "firewall", "auth", "updates",
	"packages", "processes", "docker", "tls", "workloads", "filesystem", "persistence", "reliability",
}

type Build struct {
	Version string
	Commit  string
}

type ProgressFunc func(index, total int, category string)

type Options struct {
	Locale         string
	Profile        string
	ExpectedPublic map[string]bool
	LogSince       time.Duration
	Commander      Commander
	Build          Build
	Progress       ProgressFunc
	Now            func() time.Time
}

type Context struct {
	Options
	Host    model.Host
	Profile model.Profile
}

type CheckFunc func(*Context) []model.Finding

var checks = map[string]CheckFunc{
	"system": checkSystem, "accounts": checkAccounts, "ssh": checkSSH, "privileges": checkPrivileges,
	"network": checkNetwork, "firewall": checkFirewall, "auth": checkAuth, "updates": checkUpdates,
	"packages": checkPackages, "processes": checkProcesses, "docker": checkDocker, "tls": checkTLS,
	"workloads": checkWorkloads, "filesystem": checkFilesystem, "persistence": checkPersistence,
	"reliability": checkReliability,
}

func Run(opts Options) (model.Report, error) {
	if runtime.GOOS != "linux" {
		return model.Report{}, fmt.Errorf("audit is supported only on Ubuntu/Debian Linux; current OS is %s", runtime.GOOS)
	}
	if opts.Commander == nil {
		opts.Commander = OSCommander{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LogSince <= 0 {
		opts.LogSince = 7 * 24 * time.Hour
	}
	if opts.Profile == "" {
		opts.Profile = "auto"
	}
	started := opts.Now().UTC()
	host, err := collectHost(opts.Commander)
	if err != nil {
		return model.Report{}, err
	}
	if host.OS != "ubuntu" && host.OS != "debian" {
		return model.Report{}, fmt.Errorf("unsupported distribution %q; v1 supports Ubuntu and Debian only", host.OS)
	}
	profile := detectProfile(opts.Commander, opts.Profile)
	ctx := &Context{Options: opts, Host: host, Profile: profile}
	findings := make([]model.Finding, 0, 64)
	for i, category := range CategoryOrder {
		if opts.Progress != nil {
			opts.Progress(i+1, len(CategoryOrder), category)
		}
		fn := checks[category]
		if fn == nil {
			continue
		}
		findings = append(findings, safeCheck(fn, ctx, category)...)
	}
	report := model.Report{
		SchemaVersion: SchemaVersion,
		ToolVersion:   opts.Build.Version,
		ToolCommit:    opts.Build.Commit,
		Locale:        opts.Locale,
		StartedAt:     started,
		FinishedAt:    opts.Now().UTC(),
		LogSince:      opts.LogSince.String(),
		Host:          host,
		Profile:       profile,
		Findings:      findings,
		Metadata: map[string]string{
			"mutation_policy": "never-modify-system",
			"network_checks":  "disabled-by-default",
		},
	}
	report.Recount()
	return report, nil
}

func safeCheck(fn CheckFunc, ctx *Context, category string) (out []model.Finding) {
	defer func() {
		if v := recover(); v != nil {
			out = []model.Finding{{
				ID:       strings.ToUpper(category[:min(3, len(category))]) + "-INTERNAL",
				Category: category, Status: model.Unknown, Unavailable: true,
				Error: fmt.Sprintf("check panicked: %v", v),
			}}
		}
	}()
	return fn(ctx)
}

func collectHost(cmd Commander) (model.Host, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return model.Host{}, fmt.Errorf("read /etc/os-release: %w", err)
	}
	values := parseKeyValues(string(data))
	hostname, _ := os.Hostname()
	kernel := cmd.Run(5*time.Second, "uname", "-r").Stdout
	arch := cmd.Run(5*time.Second, "uname", "-m").Stdout
	virt := ""
	if cmd.Exists("systemd-detect-virt") {
		virt = cmd.Run(5*time.Second, "systemd-detect-virt").Stdout
	}
	machineID, _ := os.ReadFile("/etc/machine-id")
	sum := sha256.Sum256([]byte(strings.TrimSpace(string(machineID)) + "\x00" + hostname))
	return model.Host{
		StableID: hex.EncodeToString(sum[:8]), Hostname: hostname,
		OS: strings.ToLower(values["ID"]), OSVersion: values["VERSION_ID"],
		Kernel: kernel, Architecture: arch, Virtualization: virt, IsRoot: os.Geteuid() == 0,
	}, nil
}

func detectProfile(cmd Commander, requested string) model.Profile {
	result := cmd.Run(8*time.Second, "ps", "-eo", "comm=")
	processes := strings.ToLower(result.Stdout)
	hasProxy := containsAny(processes, "sing-box", "x-ui", "s-ui", "\nsui\n", "hysteria")
	hasWeb := containsAny(processes, "nginx", "caddy", "apache2")
	hasDocker := containsAny(processes, "dockerd", "containerd") || cmd.Exists("docker")
	reasons := []string{}
	if hasProxy {
		reasons = append(reasons, "proxy-workload")
	}
	if hasWeb {
		reasons = append(reasons, "web-workload")
	}
	if hasDocker {
		reasons = append(reasons, "docker-workload")
	}
	detected := "general"
	count := 0
	for _, b := range []bool{hasProxy, hasWeb, hasDocker} {
		if b {
			count++
		}
	}
	if count > 1 {
		detected = "mixed"
	} else if hasProxy {
		detected = "proxy"
	} else if hasWeb {
		detected = "web"
	} else if hasDocker {
		detected = "docker"
	}
	effective := requested
	if requested == "" || requested == "auto" {
		effective = detected
	}
	return model.Profile{Requested: requested, Detected: detected, Effective: effective, Reasons: reasons}
}

func parseKeyValues(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			out[key] = strings.Trim(strings.TrimSpace(value), `"'`)
		}
	}
	return out
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(s, value) {
			return true
		}
	}
	return false
}

func commandError(r CommandResult) string {
	if r.Err == nil {
		return ""
	}
	if r.Stderr != "" {
		return truncate(r.Stderr, 500)
	}
	return r.Err.Error()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func unknown(id, category, source, errText string) model.Finding {
	return model.Finding{ID: id, Category: category, Status: model.Unknown, Unavailable: true, Error: errText,
		Evidence: []model.Evidence{{Source: source, Value: errText}}}
}

func notApplicable(id, category, source, value string) model.Finding {
	return model.Finding{ID: id, Category: category, Status: model.Info, NotApplicable: true,
		Evidence: []model.Evidence{{Source: source, Value: value}}}
}

var errNoEvidence = errors.New("no usable evidence")
