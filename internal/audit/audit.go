package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sakkaku404/vps-scope/internal/contract"
	"github.com/sakkaku404/vps-scope/internal/model"
)

const SchemaVersion = "1.0"

var errAuditDeadline = errors.New("vps-scope audit deadline reached")

type Build struct {
	Version string
	Commit  string
}

type ProgressFunc func(index, total int, category string)

type Options struct {
	Context         context.Context
	Locale          string
	Profile         string
	ExpectedPublic  map[string]bool
	LogSince        time.Duration
	Deep            bool
	NativeSelfTest  bool
	AuditTimeout    time.Duration
	ExternalDomains []string
	ExpectCDN       bool
	ExternalProber  ExternalProber
	Policy          *Policy
	Commander       Commander
	Build           Build
	Progress        ProgressFunc
	Now             func() time.Time
	fileSource      fileEvidenceSource
	hostname        func() (string, error)
	effectiveUID    func() int
	timeoutContext  func(context.Context, time.Duration, error) (context.Context, context.CancelFunc)
}

// MaxLogSince bounds journal and event-history collection. A longer window is
// not only expensive on small VPS hosts; day-suffixed CLI values can otherwise
// overflow time.Duration before they reach the collectors.
const MaxLogSince = 366 * 24 * time.Hour

type Context struct {
	Options
	Host                    model.Host
	Profile                 model.Profile
	ProfileDiscoveryError   error
	Facts                   *FactStore
	Deployment              *model.Deployment
	DeploymentBudgetRejects int
	EvidenceTime            time.Time
	EffectiveUID            int
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
	return runForPlatform(opts, runtime.GOOS)
}

func runForPlatform(opts Options, platform string) (model.Report, error) {
	if platform != "linux" {
		return model.Report{}, fmt.Errorf("audit is supported only on Ubuntu/Debian Linux; current OS is %s", platform)
	}
	if opts.Commander == nil {
		opts.Commander = OSCommander{}
	}
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if err := opts.Context.Err(); err != nil {
		return model.Report{}, fmt.Errorf("audit canceled: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.hostname == nil {
		opts.hostname = os.Hostname
	}
	if opts.effectiveUID == nil {
		opts.effectiveUID = os.Geteuid
	}
	if opts.timeoutContext == nil {
		opts.timeoutContext = context.WithTimeoutCause
	}
	if opts.LogSince <= 0 {
		opts.LogSince = 7 * 24 * time.Hour
	}
	if opts.LogSince > MaxLogSince {
		return model.Report{}, fmt.Errorf("log lookback must not exceed %s", MaxLogSince)
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
	if opts.AuditTimeout == 0 {
		opts.AuditTimeout = 5 * time.Minute
	}
	if opts.AuditTimeout < 30*time.Second || opts.AuditTimeout > 30*time.Minute {
		return model.Report{}, fmt.Errorf("audit timeout must be between 30s and 30m")
	}
	auditContext, cancelAudit := opts.timeoutContext(opts.Context, opts.AuditTimeout, errAuditDeadline)
	defer cancelAudit()
	opts.Context = auditContext
	collectorCommands := newSnapshotCommander(newDeadlineCommander(opts.Commander, opts.AuditTimeout, opts.Context))
	opts.Commander = collectorCommands
	started := opts.Now().UTC()
	facts := newFactStoreAtContext(opts.Context, opts.Commander, opts.NativeSelfTest, started, opts.fileSource)
	effectiveUID := opts.effectiveUID()
	host, err := collectHost(opts.Commander, facts, opts.hostname, effectiveUID)
	if err != nil {
		return model.Report{}, err
	}
	if host.OS != "ubuntu" && host.OS != "debian" {
		return model.Report{}, fmt.Errorf("unsupported distribution %q; v1 supports Ubuntu and Debian only", host.OS)
	}
	profile, profileErr := detectProfile(opts.Commander, facts, opts.Profile)
	ctx := &Context{Options: opts, Host: host, Profile: profile, ProfileDiscoveryError: profileErr, Facts: facts, EvidenceTime: started, EffectiveUID: effectiveUID}
	findings := make([]model.Finding, 0, 64)
	contractRepairs := 0
	collectionTimedOut := false
	for i, category := range CategoryOrder {
		if err := opts.Context.Err(); err != nil {
			if !errors.Is(context.Cause(opts.Context), errAuditDeadline) {
				return model.Report{}, fmt.Errorf("audit canceled: %w", err)
			}
			collectionTimedOut = true
			for _, remainingCategory := range CategoryOrder[i:] {
				findings = append(findings, auditDeadlineFindings(remainingCategory)...)
			}
			break
		}
		if opts.Progress != nil {
			opts.Progress(i+1, len(CategoryOrder), category)
		}
		fn := checks[category]
		if fn == nil {
			continue
		}
		categoryFindings, repairs := reconcileCategoryFindings(category, safeCheck(fn, ctx, category))
		contractRepairs += repairs
		findings = append(findings, normalizeFindings(categoryFindings)...)
	}
	if err := opts.Context.Err(); err != nil {
		if !errors.Is(context.Cause(opts.Context), errAuditDeadline) {
			return model.Report{}, fmt.Errorf("audit canceled: %w", err)
		}
		collectionTimedOut = true
	}
	assignReasonCodes(findings)
	normalizeDeployment(ctx.Deployment)
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
		Deployment:    ctx.Deployment,
		Metadata: map[string]string{
			"mutation_policy":      "never-modify-system",
			"network_checks":       map[bool]string{true: "explicitly-enabled", false: "disabled-by-default"}[len(opts.ExternalDomains) > 0],
			"audit_depth":          map[bool]string{true: "deep", false: "standard"}[opts.Deep],
			"native_self_test":     map[bool]string{true: "enabled-executes-local-workload-code", false: "disabled-by-default"}[opts.NativeSelfTest],
			"audit_timeout":        opts.AuditTimeout.String(),
			"collection_timed_out": strconv.FormatBool(collectionTimedOut),
			"policy_schema":        map[bool]string{true: PolicySchemaVersion, false: "none"}[opts.Policy != nil],
		},
	}
	commandStats := collectorCommands.Stats()
	report.Metadata["collector_command_requests"] = strconv.Itoa(commandStats.CommandCalls)
	report.Metadata["collector_command_cache_hits"] = strconv.Itoa(commandStats.CommandHits)
	report.Metadata["collector_lookup_requests"] = strconv.Itoa(commandStats.ExistsCalls)
	report.Metadata["collector_lookup_cache_hits"] = strconv.Itoa(commandStats.ExistsHits)
	report.Metadata["collector_command_retained_bytes"] = strconv.Itoa(commandStats.RetainedBytes)
	report.Metadata["collector_command_budget_rejections"] = strconv.Itoa(commandStats.BudgetRejects)
	fileStats := facts.FileStats()
	report.Metadata["collector_file_read_requests"] = strconv.Itoa(fileStats.ReadRequests)
	report.Metadata["collector_file_read_cache_hits"] = strconv.Itoa(fileStats.ReadHits)
	report.Metadata["collector_file_link_requests"] = strconv.Itoa(fileStats.LinkRequests)
	report.Metadata["collector_file_link_cache_hits"] = strconv.Itoa(fileStats.LinkHits)
	report.Metadata["collector_file_stat_requests"] = strconv.Itoa(fileStats.StatRequests + fileStats.LstatRequests)
	report.Metadata["collector_file_stat_cache_hits"] = strconv.Itoa(fileStats.StatHits + fileStats.LstatHits)
	report.Metadata["collector_directory_requests"] = strconv.Itoa(fileStats.DirRequests)
	report.Metadata["collector_directory_cache_hits"] = strconv.Itoa(fileStats.DirHits)
	report.Metadata["collector_file_retained_bytes"] = strconv.Itoa(fileStats.RetainedBytes)
	report.Metadata["collector_directory_retained_entries"] = strconv.Itoa(fileStats.RetainedDirectoryEntries)
	report.Metadata["collector_file_budget_rejections"] = strconv.Itoa(fileStats.BudgetRejects)
	report.Metadata["collector_contract_repairs"] = strconv.Itoa(contractRepairs)
	report.Metadata["collector_topology_budget_rejections"] = strconv.Itoa(ctx.DeploymentBudgetRejects)
	report.Recount()
	if failures := ValidateReport(report, opts.Build.Version); len(failures) > 0 {
		return model.Report{}, fmt.Errorf("internal report contract validation failed: %s", strings.Join(failures, "; "))
	}
	return report, nil
}

func auditDeadlineFindings(category string) []model.Finding {
	message := "audit deadline reached before this check could run"
	findings := make([]model.Finding, 0, 8)
	for _, id := range StableCheckIDs {
		if reportCategoryForID(id) != category {
			continue
		}
		findings = append(findings, model.Finding{
			ID: id, Category: category, Status: model.Unknown, Unavailable: true, Error: message,
			Evidence: []model.Evidence{{Source: "audit deadline", Key: "unavailable", Value: message}},
		})
	}
	return findings
}

func (ctx *Context) evidenceTime() time.Time {
	if !ctx.EvidenceTime.IsZero() {
		return ctx.EvidenceTime.UTC()
	}
	if ctx.Now != nil {
		return ctx.Now().UTC()
	}
	return time.Now().UTC()
}

func (ctx *Context) auditContext() context.Context {
	if ctx.Options.Context != nil {
		return ctx.Options.Context
	}
	return context.Background()
}

func reconcileCategoryFindings(category string, findings []model.Finding) ([]model.Finding, int) {
	expected := make([]string, 0, 8)
	for _, id := range StableCheckIDs {
		if reportCategoryForID(id) == category {
			expected = append(expected, id)
		}
	}
	byID := make(map[string][]model.Finding, len(findings))
	repairs := 0
	for _, finding := range findings {
		if reportCategoryForID(finding.ID) != category || finding.Category != category {
			repairs++
			continue
		}
		byID[finding.ID] = append(byID[finding.ID], finding)
	}
	out := make([]model.Finding, 0, len(expected))
	for _, id := range expected {
		matches := byID[id]
		if len(matches) == 1 {
			out = append(out, matches[0])
			continue
		}
		repairs++
		problem := "missing"
		if len(matches) > 1 {
			problem = "duplicate"
		}
		message := "internal check contract repair: " + problem + " result; details withheld"
		out = append(out, model.Finding{
			ID: id, Category: category, Status: model.Unknown, Unavailable: true, Error: message,
			Evidence: []model.Evidence{{Source: "internal", Key: "contract_repair", Value: message}},
		})
	}
	return out, repairs
}

func normalizeDeployment(deployment *model.Deployment) {
	if deployment == nil {
		return
	}
	for index := range deployment.Components {
		component := &deployment.Components[index]
		component.Product = limitText(component.Product, 256)
		component.Source = limitText(component.Source, 1024)
		component.Deployment = limitText(component.Deployment, 256)
		component.Confidence = limitText(component.Confidence, 64)
		component.Kind = limitText(component.Kind, 64)
	}
	for index := range deployment.Endpoints {
		endpoint := &deployment.Endpoints[index]
		endpoint.Product = limitText(endpoint.Product, 256)
		endpoint.Protocol = limitText(endpoint.Protocol, 256)
		endpoint.Address = limitText(endpoint.Address, 512)
		endpoint.Process = limitText(endpoint.Process, 256)
		endpoint.Security = limitText(endpoint.Security, 512)
		endpoint.Firewall = limitText(endpoint.Firewall, 512)
		endpoint.Judgment = limitText(endpoint.Judgment, 512)
		endpoint.Source = limitText(endpoint.Source, 1024)
		endpoint.TLS = limitText(endpoint.TLS, 64)
		endpoint.PathPosture = limitText(endpoint.PathPosture, 64)
	}
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
		if endpoints[i].Family != endpoints[j].Family {
			return endpoints[i].Family < endpoints[j].Family
		}
		if endpoints[i].Scope != endpoints[j].Scope {
			return endpoints[i].Scope < endpoints[j].Scope
		}
		return endpoints[i].Process < endpoints[j].Process
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

func collectHost(cmd Commander, facts *FactStore, hostname func() (string, error), effectiveUID int) (model.Host, error) {
	data, err := facts.ReadSmall("/etc/os-release", 64<<10)
	if err != nil {
		return model.Host{}, fmt.Errorf("read /etc/os-release: %w", err)
	}
	values := parseKeyValues(data)
	hostnameValue, err := hostname()
	if err != nil {
		return model.Host{}, fmt.Errorf("read hostname: %w", err)
	}
	if strings.TrimSpace(hostnameValue) == "" {
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
	machineID, machineIDErr := facts.ReadSmall("/etc/machine-id", 4<<10)
	if machineIDErr != nil {
		return model.Host{}, fmt.Errorf("read machine identity: %w", machineIDErr)
	}
	if strings.TrimSpace(machineID) == "" {
		return model.Host{}, fmt.Errorf("read machine identity: empty value")
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(machineID) + "\x00" + hostnameValue))
	return model.Host{
		StableID: hex.EncodeToString(sum[:8]), Hostname: limitText(hostnameValue, 1024),
		OS: strings.ToLower(values["ID"]), OSVersion: limitText(values["VERSION_ID"], 1024),
		Kernel: limitText(kernel, 1024), Architecture: limitText(arch, 1024), Virtualization: limitText(virt, 1024), IsRoot: effectiveUID == 0,
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
			if info, err := facts.Stat(path); err == nil && info.IsDir() {
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
	s = sanitizeReportText(s)
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) <= n {
		return s
	}
	return truncateUTF8(s, n) + "..."
}

const (
	maxFindingEvidenceEntries = contract.MaxFindingEvidenceEntries
	maxFindingFactEntries     = contract.MaxFindingFactEntries
	maxEvidenceSourceBytes    = contract.MaxEvidenceSourceBytes
	maxEvidenceKeyBytes       = contract.MaxEvidenceKeyBytes
	maxEvidenceValueBytes     = contract.MaxEvidenceValueBytes
	maxFindingErrorBytes      = contract.MaxFindingErrorBytes
	maxFindingFactKeyBytes    = contract.MaxFindingFactKeyBytes
	maxFindingFactValueBytes  = contract.MaxFindingFactValueBytes
)

// normalizeFindings applies the same deterministic resource budget to every
// collector. A noisy journal, package inventory, or hostile local database
// must not make the final report unbounded or fail the entire audit after all
// other checks have completed.
func normalizeFindings(findings []model.Finding) []model.Finding {
	for index := range findings {
		finding := &findings[index]
		finding.Error = limitText(finding.Error, maxFindingErrorBytes)
		for evidenceIndex := range finding.Evidence {
			evidence := &finding.Evidence[evidenceIndex]
			evidence.Source = limitText(evidence.Source, maxEvidenceSourceBytes)
			evidence.Key = limitText(evidence.Key, maxEvidenceKeyBytes)
			evidence.Value = limitText(evidence.Value, maxEvidenceValueBytes)
		}
		if len(finding.Evidence) > maxFindingEvidenceEntries {
			omitted := len(finding.Evidence) - (maxFindingEvidenceEntries - 1)
			finding.Evidence = append(finding.Evidence[:maxFindingEvidenceEntries-1], model.Evidence{
				Source: "internal evidence budget", Key: "entries_omitted",
				Value: strconv.Itoa(omitted) + " additional evidence entries omitted",
			})
			if finding.Facts == nil {
				finding.Facts = map[string]string{}
			}
			finding.Facts["evidence_entries_omitted"] = strconv.Itoa(omitted)
		}
		finding.Facts = normalizeFindingFacts(finding.Facts)
	}
	return findings
}

func normalizeFindingFacts(facts map[string]string) map[string]string {
	if facts == nil {
		return nil
	}
	keys := make([]string, 0, len(facts))
	for key := range facts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	omitted := 0
	if len(keys) > maxFindingFactEntries {
		omitted = len(keys) - (maxFindingFactEntries - 1)
		keys = keys[:maxFindingFactEntries-1]
	}
	normalized := make(map[string]string, len(keys)+1)
	for _, key := range keys {
		normalized[limitText(key, maxFindingFactKeyBytes)] = limitText(facts[key], maxFindingFactValueBytes)
	}
	if omitted > 0 {
		normalized["fact_entries_omitted"] = strconv.Itoa(omitted)
	}
	return normalized
}

func limitText(value string, limit int) string {
	value = sanitizeReportText(value)
	if len(value) <= limit {
		return value
	}
	return truncateUTF8(value, limit-3) + "..."
}

// sanitizeReportText removes terminal control sequences and bidirectional
// override/isolate characters from locally collected text. Reports are often
// opened directly in a privileged terminal, so evidence must be inert data,
// not a way for a hostile filename, process argument, or log line to alter the
// display.
func sanitizeReportText(value string) string {
	return strings.Map(func(r rune) rune {
		if isUnsafeReportRune(r) {
			return ' '
		}
		return r
	}, value)
}

func isUnsafeReportRune(r rune) bool {
	return unicode.IsControl(r) || isBidiControl(r) || r == '\u2028' || r == '\u2029'
}

func isBidiControl(r rune) bool {
	return r == '\u061c' || r == '\u200e' || r == '\u200f' ||
		(r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

func truncateUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
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
