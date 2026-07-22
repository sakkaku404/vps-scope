package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
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
	Locale          string
	Profile         string
	ExpectedPublic  map[string]bool
	LogSince        time.Duration
	Deep            bool
	ExternalDomains []string
	ExpectCDN       bool
	ExternalProber  ExternalProber
	Policy          *Policy
	Commander       Commander
	Build           Build
	Progress        ProgressFunc
	Now             func() time.Time
}

type Context struct {
	Options
	Host                  model.Host
	Profile               model.Profile
	ProfileDiscoveryError error
	Facts                 *FactStore
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
	if opts.Locale == "" {
		opts.Locale = "en"
	}
	if opts.Build.Version == "" {
		opts.Build.Version = "dev"
	}
	started := opts.Now().UTC()
	host, err := collectHost(opts.Commander)
	if err != nil {
		return model.Report{}, err
	}
	if host.OS != "ubuntu" && host.OS != "debian" {
		return model.Report{}, fmt.Errorf("unsupported distribution %q; v1 supports Ubuntu and Debian only", host.OS)
	}
	facts := NewFactStore(opts.Commander)
	profile, profileErr := detectProfile(opts.Commander, facts, opts.Profile)
	ctx := &Context{Options: opts, Host: host, Profile: profile, ProfileDiscoveryError: profileErr, Facts: facts}
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
	assignReasonCodes(findings)
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
		Endpoints:     reportEndpoints(ctx),
		Metadata: map[string]string{
			"mutation_policy": "never-modify-system",
			"network_checks":  map[bool]string{true: "explicitly-enabled", false: "disabled-by-default"}[len(opts.ExternalDomains) > 0],
			"audit_depth":     map[bool]string{true: "deep", false: "standard"}[opts.Deep],
			"policy_schema":   map[bool]string{true: PolicySchemaVersion, false: "none"}[opts.Policy != nil],
		},
	}
	report.Recount()
	if failures := ValidateReport(report, opts.Build.Version); len(failures) > 0 {
		return model.Report{}, fmt.Errorf("internal report contract validation failed: %s", strings.Join(failures, "; "))
	}
	return report, nil
}

func reportEndpoints(ctx *Context) []model.Endpoint {
	listeners, err := ctx.Facts.Listeners()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	endpoints := make([]model.Endpoint, 0, len(listeners))
	for _, listener := range listeners {
		port, err := strconv.Atoi(listener.Port)
		if err != nil {
			continue
		}
		protocol := strings.TrimSuffix(strings.TrimSuffix(listener.Protocol, "4"), "6")
		family := "ipv4"
		if strings.Contains(listener.Address, ":") || strings.HasSuffix(listener.Protocol, "6") {
			family = "ipv6"
		}
		key := fmt.Sprintf("%s/%d/%s/%s", protocol, port, family, listener.Scope)
		if seen[key] {
			continue
		}
		seen[key] = true
		endpoint := model.Endpoint{Protocol: protocol, Port: port, Family: family, Scope: listener.Scope, Process: truncate(listener.Process, 120)}
		if expected, ok := ctx.Policy.Endpoint(port, protocol, family); ok {
			endpoint.Role = expected.Role
			endpoint.ExpectedExposure = expected.Exposure
		}
		endpoints = append(endpoints, endpoint)
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Port != endpoints[j].Port {
			return endpoints[i].Port < endpoints[j].Port
		}
		if endpoints[i].Protocol != endpoints[j].Protocol {
			return endpoints[i].Protocol < endpoints[j].Protocol
		}
		return endpoints[i].Family < endpoints[j].Family
	})
	return endpoints
}

func safeCheck(fn CheckFunc, ctx *Context, category string) (out []model.Finding) {
	defer func() {
		if recover() != nil {
			out = unavailableCategoryFindings(category)
		}
	}()
	return fn(ctx)
}

func unavailableCategoryFindings(category string) []model.Finding {
	const message = "internal check failure recovered; details withheld"
	out := make([]model.Finding, 0, 4)
	for _, id := range StableCheckIDs {
		if reportCategoryForID(id) != category {
			continue
		}
		out = append(out, model.Finding{
			ID: id, Category: category, Status: model.Unknown, Unavailable: true, Error: message,
			Evidence: []model.Evidence{{Source: "internal", Key: "failure", Value: message}},
		})
	}
	return out
}

func collectHost(cmd Commander) (model.Host, error) {
	data, err := readSmall("/etc/os-release", 64<<10)
	if err != nil {
		return model.Host{}, fmt.Errorf("read /etc/os-release: %w", err)
	}
	values := parseKeyValues(data)
	hostname, err := os.Hostname()
	if err != nil {
		return model.Host{}, fmt.Errorf("read hostname: %w", err)
	}
	if strings.TrimSpace(hostname) == "" {
		return model.Host{}, fmt.Errorf("read hostname: empty value")
	}
	kernelResult := cmd.Run(5*time.Second, "uname", "-r")
	if kernelResult.Err != nil || kernelResult.Truncated || strings.TrimSpace(kernelResult.Stdout) == "" {
		return model.Host{}, fmt.Errorf("read kernel release: %s", commandError(kernelResult))
	}
	archResult := cmd.Run(5*time.Second, "uname", "-m")
	if archResult.Err != nil || archResult.Truncated || strings.TrimSpace(archResult.Stdout) == "" {
		return model.Host{}, fmt.Errorf("read architecture: %s", commandError(archResult))
	}
	kernel, arch := kernelResult.Stdout, archResult.Stdout
	virt := ""
	if cmd.Exists("systemd-detect-virt") {
		virt = cmd.Run(5*time.Second, "systemd-detect-virt").Stdout
	}
	machineID, machineIDErr := readSmall("/etc/machine-id", 4<<10)
	if machineIDErr != nil {
		return model.Host{}, fmt.Errorf("read machine identity: %w", machineIDErr)
	}
	if strings.TrimSpace(machineID) == "" {
		return model.Host{}, fmt.Errorf("read machine identity: empty value")
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(machineID) + "\x00" + hostname))
	return model.Host{
		StableID: hex.EncodeToString(sum[:8]), Hostname: hostname,
		OS: strings.ToLower(values["ID"]), OSVersion: values["VERSION_ID"],
		Kernel: kernel, Architecture: arch, Virtualization: virt, IsRoot: os.Geteuid() == 0,
	}, nil
}

func detectProfile(cmd Commander, facts *FactStore, requested string) (model.Profile, error) {
	processList, processErr := facts.Processes()
	var processText strings.Builder
	for _, process := range processList {
		processText.WriteString(processLine(process))
		processText.WriteByte('\n')
	}
	processes := strings.ToLower(processText.String())
	hasProxy := containsAny(processes,
		"sing-box", "xray", "x-ui", "s-ui", "\nsui\n", "hysteria", "tuic",
		"trojan", "ss-server", "sslocal", "marzban", "hiddify", "outline-ss-server", "wg-quick",
		"openvpn",
	)
	if !hasProxy {
		for _, path := range []string{
			"/etc/sing-box", "/usr/local/etc/sing-box", "/etc/xray", "/usr/local/etc/xray",
			"/etc/hysteria", "/usr/local/x-ui", "/usr/local/s-ui", "/opt/marzban", "/opt/hiddify-manager",
		} {
			if info, err := os.Stat(path); err == nil && info.IsDir() {
				hasProxy = true
				break
			}
		}
	}
	hasWeb := containsAny(processes, "nginx", "caddy", "haproxy", "apache2")
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
	return model.Profile{Requested: requested, Detected: detected, Effective: effective, Reasons: reasons}, processErr
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
	if r.Truncated {
		return "command output exceeded the capture limit"
	}
	if r.Err == nil {
		return ""
	}
	if r.Stderr != "" {
		return sanitizeCommandDiagnostic(r.Stderr)
	}
	return sanitizeCommandDiagnostic(r.Err.Error())
}

// Native validators and log commands can echo configuration values. Keep
// short diagnostic context, but remove obvious credentials before it reaches a
// report bundle that users may share.
func sanitizeCommandDiagnostic(value string) string {
	value = truncate(value, 500)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(password|passwd|token|secret|uuid|private[_ -]?key|authorization)\b\s*([:=]|\s)\s*[^\s,;]+`),
		regexp.MustCompile(`https?://[^\s]+`),
	}
	for _, pattern := range patterns {
		value = pattern.ReplaceAllString(value, "[redacted]")
	}
	return value
}

func nativeCommandError(r CommandResult) string {
	if r.Truncated {
		return "native self-test output exceeded the capture limit; output withheld"
	}
	if r.Err == nil {
		return ""
	}
	return fmt.Sprintf("native self-test exited with code %d; stderr withheld for privacy", r.Code)
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

// withIncompleteEvidence prevents an incomplete collector result from becoming
// a PASS/INFO conclusion. A risk already proven by independent evidence remains
// a risk, but the report records that the inventory was incomplete.
func withIncompleteEvidence(f model.Finding, source string, err error) model.Finding {
	if err == nil {
		return f
	}
	message := "evidence discovery incomplete: " + truncate(err.Error(), 300)
	if f.Facts == nil {
		f.Facts = map[string]string{}
	}
	f.Facts["evidence_discovery_incomplete"] = "true"
	f.Evidence = append(f.Evidence, model.Evidence{Source: source, Key: "unavailable", Value: message})
	if f.Error == "" {
		f.Error = message
	}
	if f.Status != model.Risk {
		f.Status = model.Unknown
		f.Severity = ""
		f.Unavailable = true
		f.NotApplicable = false
	}
	return f
}
