package audit

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func checkPackages(ctx *Context) []model.Finding {
	return []model.Finding{checkAPTRepositories(), checkDPKGVerify(ctx)}
}

func checkAPTRepositories() model.Finding {
	paths := append([]string{"/etc/apt/sources.list"}, existingFiles("/etc/apt/sources.list.d/*.list", "/etc/apt/sources.list.d/*.sources")...)
	f := model.Finding{ID: "PKG-001", Category: "packages", Status: model.Pass, Facts: map[string]string{}}
	thirdParty, unsafe := 0, 0
	for _, path := range paths {
		data, err := readSmall(path, 4<<20)
		if err != nil {
			continue
		}
		for i, line := range lines(data) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}
			lower := strings.ToLower(trimmed)
			if !containsAny(lower, "http://", "https://", "uris:") {
				continue
			}
			isOfficial := containsAny(lower, "ubuntu.com", "debian.org")
			if !isOfficial {
				thirdParty++
				f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: fmt.Sprintf("line_%d", i+1), Value: sanitizeAPTSourceLine(trimmed)})
			}
			if containsAny(lower, "trusted=yes", "allow-insecure=yes", "allow-unauthenticated") {
				unsafe++
			}
		}
	}
	f.Facts["third_party_entries"] = strconv.Itoa(thirdParty)
	f.Facts["unsafe_trust_entries"] = strconv.Itoa(unsafe)
	if unsafe > 0 {
		f.Status, f.Severity = model.Risk, model.High
	} else if thirdParty > 0 {
		f.Status = model.Info
	}
	return f
}

var aptURLPattern = regexp.MustCompile(`(?i)https?://[^\s"']+`)

func sanitizeAPTSourceLine(line string) string {
	var origins []string
	seen := map[string]bool{}
	for _, raw := range aptURLPattern.FindAllString(line, -1) {
		raw = strings.TrimRight(raw, ",;)]}")
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
			continue
		}
		host := parsed.Hostname()
		if port := parsed.Port(); port != "" {
			host = host + ":" + port
		}
		origin := strings.ToLower(parsed.Scheme) + "://" + host
		if !seen[origin] {
			seen[origin] = true
			origins = append(origins, origin)
		}
	}
	sort.Strings(origins)
	if len(origins) == 0 {
		origins = []string{"<unparsed-third-party-source>"}
	}
	lower := strings.ToLower(line)
	return fmt.Sprintf("origin=%s signed-by=%t unsafe-trust=%t; path, query, and credentials withheld", strings.Join(origins, ","), strings.Contains(lower, "signed-by"), containsAny(lower, "trusted=yes", "allow-insecure=yes", "allow-unauthenticated"))
}

func checkDPKGVerify(ctx *Context) model.Finding {
	if !ctx.Commander.Exists("dpkg") {
		return unknown("PKG-002", "packages", "dpkg", "command not found")
	}
	r := ctx.Commander.Run(60*time.Second, "dpkg", "--verify")
	// dpkg may return non-zero when it found differences, so stdout is still evidence.
	if r.Err != nil && r.Stdout == "" {
		return unknown("PKG-002", "packages", "dpkg --verify", commandError(r))
	}
	parsed := parseDPKGVerify(r.Stdout)
	f := model.Finding{ID: "PKG-002", Category: "packages", Status: model.Pass, Facts: map[string]string{
		"differences_total": strconv.Itoa(parsed.total), "config_changes": strconv.Itoa(parsed.config),
		"excluded_nonessential_missing": strconv.Itoa(parsed.excludedMissing), "runtime_files_missing": strconv.Itoa(parsed.runtimeMissing),
		"non_config_content_changes": strconv.Itoa(parsed.contentChanged),
	}}
	if parsed.runtimeMissing > 0 || parsed.contentChanged > 0 {
		f.Status, f.Severity = model.Risk, model.High
	} else if parsed.total > 0 {
		f.Status = model.Info
	}
	f.Evidence = append(f.Evidence,
		model.Evidence{Source: "dpkg --verify", Key: "config_changes", Value: strconv.Itoa(parsed.config)},
		model.Evidence{Source: "dpkg --verify", Key: "excluded_nonessential_missing", Value: strconv.Itoa(parsed.excludedMissing)},
		model.Evidence{Source: "dpkg --verify", Key: "runtime_files_missing", Value: strconv.Itoa(parsed.runtimeMissing)},
		model.Evidence{Source: "dpkg --verify", Key: "non_config_content_changes", Value: strconv.Itoa(parsed.contentChanged)},
	)
	for i, line := range parsed.relevant {
		if i >= 50 {
			break
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "dpkg --verify", Value: line})
	}
	return f
}

type dpkgVerifyResult struct {
	total, config, excludedMissing, runtimeMissing, contentChanged int
	relevant                                                       []string
}

func parseDPKGVerify(output string) dpkgVerifyResult {
	var result dpkgVerifyResult
	for _, line := range lines(output) {
		result.total++
		fields := strings.Fields(line)
		path := ""
		if len(fields) > 0 {
			path = fields[len(fields)-1]
		}
		if strings.Contains(line, " c ") {
			result.config++
			result.relevant = append(result.relevant, line)
			continue
		}
		if strings.HasPrefix(line, "missing") {
			if strings.HasPrefix(path, "/usr/share/doc/") || strings.HasPrefix(path, "/usr/share/man/") || strings.HasPrefix(path, "/usr/share/locale/") {
				result.excludedMissing++
			} else {
				result.runtimeMissing++
				result.relevant = append(result.relevant, line)
			}
			continue
		}
		result.contentChanged++
		result.relevant = append(result.relevant, line)
	}
	return result
}

func checkProcesses(ctx *Context) []model.Finding {
	failed := model.Finding{ID: "PROC-001", Category: "processes", Status: model.Pass, Facts: map[string]string{}}
	if !ctx.Commander.Exists("systemctl") {
		failed = unknown("PROC-001", "processes", "systemctl", "command not found")
	} else {
		r := ctx.Commander.Run(15*time.Second, "systemctl", "--failed", "--no-legend", "--plain")
		if r.Err != nil && r.Stdout == "" {
			failed = unknown("PROC-001", "processes", "systemctl --failed", commandError(r))
		} else {
			units := lines(r.Stdout)
			failed.Facts["failed_units"] = strconv.Itoa(len(units))
			if len(units) > 0 {
				failed.Status, failed.Severity = model.Risk, model.Low
			}
			for i, unit := range units {
				if i >= 30 {
					break
				}
				failed.Evidence = append(failed.Evidence, model.Evidence{Source: "systemctl --failed", Value: unit})
			}
		}
	}
	deleted := checkDeletedExecutables()
	return []model.Finding{failed, deleted}
}

func checkDeletedExecutables() model.Finding {
	f := model.Finding{ID: "PROC-002", Category: "processes", Status: model.Pass, Facts: map[string]string{}}
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return unknown("PROC-002", "processes", "/proc", err.Error())
	}
	var deleted []string
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		path := filepath.Join("/proc", entry.Name(), "exe")
		target, err := os.Readlink(path)
		if err == nil && strings.HasSuffix(target, " (deleted)") {
			deleted = append(deleted, "pid="+entry.Name()+" exe="+target)
		}
	}
	sort.Strings(deleted)
	f.Facts["deleted_executables"] = strconv.Itoa(len(deleted))
	if len(deleted) > 0 {
		// Deleted executables commonly remain after package upgrades. They are
		// evidence to investigate or restart, not proof of compromise.
		f.Status = model.Info
	}
	for i, item := range deleted {
		if i >= 30 {
			break
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/*/exe", Value: item})
	}
	return f
}

type dockerInspect struct {
	Name   string `json:"Name"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		IpcMode     string   `json:"IpcMode"`
		Binds       []string `json:"Binds"`
		CapAdd      []string `json:"CapAdd"`
		SecurityOpt []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

func checkDocker(ctx *Context) []model.Finding {
	if !ctx.Commander.Exists("docker") {
		return []model.Finding{notApplicable("DOCKER-001", "docker", "command", "docker not installed")}
	}
	ps := ctx.Commander.Run(15*time.Second, "docker", "ps", "-q")
	if ps.Err != nil {
		return []model.Finding{unknown("DOCKER-001", "docker", "docker ps", commandError(ps))}
	}
	ids := lines(ps.Stdout)
	if len(ids) == 0 {
		return []model.Finding{{ID: "DOCKER-001", Category: "docker", Status: model.Info, Evidence: []model.Evidence{{Source: "docker ps", Value: "no running containers"}}}}
	}
	args := append([]string{"inspect"}, ids...)
	inspect := ctx.Commander.Run(30*time.Second, "docker", args...)
	if inspect.Err != nil {
		return []model.Finding{unknown("DOCKER-001", "docker", "docker inspect", commandError(inspect))}
	}
	var containers []dockerInspect
	if err := json.Unmarshal([]byte(inspect.Stdout), &containers); err != nil {
		return []model.Finding{unknown("DOCKER-001", "docker", "docker inspect JSON", err.Error())}
	}
	f := model.Finding{ID: "DOCKER-001", Category: "docker", Status: model.Pass, Facts: map[string]string{"running_containers": strconv.Itoa(len(containers))}}
	problems := 0
	for _, c := range containers {
		name := strings.TrimPrefix(c.Name, "/")
		if c.HostConfig.Privileged {
			problems++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "privileged", Value: name})
		}
		if c.HostConfig.NetworkMode == "host" {
			problems++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "host_network", Value: name})
		}
		if c.HostConfig.PidMode == "host" || c.HostConfig.IpcMode == "host" {
			problems++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "host_namespace", Value: name})
		}
		for _, bind := range c.HostConfig.Binds {
			if strings.Contains(bind, "/var/run/docker.sock") || strings.HasPrefix(bind, "/:/") {
				problems++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "sensitive_bind", Value: name + " " + bind})
			}
		}
		for containerPort, bindings := range c.NetworkSettings.Ports {
			for _, b := range bindings {
				scope := classifyAddress(b.HostIP)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "published_port", Value: fmt.Sprintf("%s %s:%s->%s scope=%s", name, b.HostIP, b.HostPort, containerPort, scope)})
			}
		}
	}
	f.Facts["isolation_problems"] = strconv.Itoa(problems)
	if problems > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	return []model.Finding{f}
}

func checkTLS(ctx *Context) []model.Finding {
	findings := []model.Finding{checkFileTLS(ctx)}
	if embedded, ok := embeddedSUITLS(ctx); ok {
		findings = append(findings, embedded)
	} else {
		findings = append(findings, notApplicable("TLS-002", "tls", "S-UI TLS database", "no embedded S-UI TLS material detected"))
	}
	return findings
}

func checkFileTLS(ctx *Context) model.Finding {
	paths := discoverCertificatePaths(ctx)
	if len(paths) == 0 {
		return notApplicable("TLS-001", "tls", "certificate discovery", "no file-backed server certificate found in supported locations")
	}
	f := model.Finding{ID: "TLS-001", Category: "tls", Status: model.Pass, Facts: map[string]string{"certificates": strconv.Itoa(len(paths))}}
	now := ctx.Now()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			f.Status = model.Unknown
			f.Unavailable = true
			f.Evidence = append(f.Evidence, model.Evidence{Source: path, Value: err.Error()})
			continue
		}
		block, _ := pem.Decode(data)
		if block == nil {
			f.Status = model.Unknown
			f.Evidence = append(f.Evidence, model.Evidence{Source: path, Value: "no PEM certificate block"})
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			f.Status = model.Unknown
			f.Evidence = append(f.Evidence, model.Evidence{Source: path, Value: err.Error()})
			continue
		}
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		value := fmt.Sprintf("subject=%s not_after=%s days_remaining=%d", cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339), days)
		f.Evidence = append(f.Evidence, model.Evidence{Source: path, Value: value})
		if days < 0 {
			f.Status, f.Severity = model.Risk, model.Critical
		} else if days <= 30 && f.Severity != model.Critical {
			f.Status, f.Severity = model.Risk, model.High
		}
	}
	if ctx.Commander.Exists("systemctl") {
		for _, timer := range []string{"certbot.timer", "acme.timer"} {
			r := ctx.Commander.Run(6*time.Second, "systemctl", "is-enabled", timer)
			if strings.TrimSpace(r.Stdout) == "enabled" {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-enabled", Key: timer, Value: "enabled"})
			}
		}
	}
	return f
}

func embeddedSUITLS(ctx *Context) (model.Finding, bool) {
	db := "/usr/local/s-ui/db/s-ui.db"
	if _, err := os.Stat(db); err != nil {
		return model.Finding{}, false
	}
	if !ctx.Commander.Exists("sqlite3") {
		return unknown("TLS-002", "tls", "S-UI TLS database", "S-UI database exists but sqlite3 is unavailable; embedded TLS material was not extracted"), true
	}
	r := ctx.Commander.Run(8*time.Second, "sqlite3", "-readonly", db, "SELECT count(*) FROM tls WHERE server IS NOT NULL AND length(server)>0;")
	if r.Err != nil {
		return unknown("TLS-002", "tls", "S-UI TLS database", commandError(r)), true
	}
	count, err := strconv.Atoi(strings.TrimSpace(r.Stdout))
	if err != nil {
		return unknown("TLS-002", "tls", "S-UI TLS database", "could not parse embedded TLS record count"), true
	}
	if count == 0 {
		return model.Finding{}, false
	}
	f := unknown("TLS-002", "tls", "S-UI TLS database", "certificate validity is unknown because TLS material is embedded; private-key-bearing blobs are intentionally never exported")
	f.Evidence = []model.Evidence{{Source: db, Key: "embedded_tls_records", Value: strconv.Itoa(count)}, {Source: "privacy policy", Value: "TLS BLOB contents not extracted"}}
	return f, true
}

func discoverCertificatePaths(ctx *Context) []string {
	seen := map[string]bool{}
	add := func(path string) {
		path = strings.Trim(strings.TrimSpace(path), `"'`)
		if path == "" || strings.Contains(path, "$s") || !filepath.IsAbs(path) {
			return
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			seen[path] = true
		}
	}
	for _, path := range existingFiles("/etc/letsencrypt/live/*/fullchain.pem") {
		add(path)
	}
	if ctx.Commander.Exists("nginx") {
		r := ctx.Commander.Run(15*time.Second, "nginx", "-T")
		re := regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^;]+);`)
		for _, match := range re.FindAllStringSubmatch(r.Stdout+r.Stderr, -1) {
			if len(match) > 1 {
				add(match[1])
			}
		}
	}
	for _, config := range []string{"/etc/hysteria/config.yaml", "/etc/hysteria/config.yml", "/etc/sing-box/config.json"} {
		data, err := readSmall(config, 8<<20)
		if err != nil {
			continue
		}
		re := regexp.MustCompile(`(?m)(?:"certificate(?:_path)?"\s*:\s*"([^"]+)"|^\s*(?:cert|certificate)\s*:\s*([^#\s]+))`)
		for _, match := range re.FindAllStringSubmatch(data, -1) {
			for _, value := range match[1:] {
				add(value)
			}
		}
	}
	var paths []string
	for path := range seen {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

var workloadProcesses = regexp.MustCompile(`(?i)\b(sing-box|xray|x-ui|s-ui|sui|hysteria|tuic|trojan|ss-server|sslocal|marzban|hiddify|outline-ss-server|wg-quick|nginx|caddy|apache2|dockerd|containerd)\b`)
