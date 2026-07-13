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
	verify := notApplicable("PKG-002", "packages", "audit mode", "standard audit skips full dpkg file verification; run with --deep")
	if ctx.Deep {
		verify = checkDPKGVerify(ctx)
	}
	return []model.Finding{checkAPTRepositories(), verify}
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
	if r.Truncated || (r.Err != nil && r.Stdout == "") {
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
	securityRelevant, severity := classifyDeletedExecutables(deleted)
	f.Facts["security_relevant_deleted_executables"] = strconv.Itoa(securityRelevant)
	if securityRelevant > 0 {
		f.Status, f.Severity = model.Risk, severity
	}
	for i, item := range deleted {
		if i >= 30 {
			break
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/*/exe", Value: item})
	}
	return f
}

func classifyDeletedExecutables(items []string) (int, model.Severity) {
	count, severity := 0, model.Medium
	for _, item := range items {
		lower := strings.ToLower(item)
		if proxyProcessPattern.MatchString(lower) || containsAny(lower, "/tmp/", "/var/tmp/", "/dev/shm/") {
			count++
		}
		if containsAny(lower, "/tmp/", "/var/tmp/", "/dev/shm/") {
			severity = model.High
		}
	}
	return count, severity
}

type dockerInspect struct {
	Name   string `json:"Name"`
	Config struct {
		User   string            `json:"User"`
		Image  string            `json:"Image"`
		Env    []string          `json:"Env"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		Binds          []string `json:"Binds"`
		CapAdd         []string `json:"CapAdd"`
		SecurityOpt    []string `json:"SecurityOpt"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

func decodeDockerInspect(input string, out *[]dockerInspect) error {
	if err := json.Unmarshal([]byte(input), out); err != nil {
		return fmt.Errorf("docker inspect JSON: %w", err)
	}
	return nil
}

func checkDocker(ctx *Context) []model.Finding {
	if !ctx.Commander.Exists("docker") {
		return []model.Finding{notApplicable("DOCKER-001", "docker", "command", "docker not installed")}
	}
	containers, err := ctx.Facts.DockerContainers()
	if err != nil {
		return []model.Finding{unknown("DOCKER-001", "docker", "docker inspect", err.Error())}
	}
	if len(containers) == 0 {
		return []model.Finding{{ID: "DOCKER-001", Category: "docker", Status: model.Info, Evidence: []model.Evidence{{Source: "docker ps", Value: "no running containers"}}}}
	}
	f := model.Finding{ID: "DOCKER-001", Category: "docker", Status: model.Pass, Facts: map[string]string{"running_containers": strconv.Itoa(len(containers))}}
	problemKeys := map[string]bool{}
	recordProblem := func(key string) { problemKeys[key] = true }
	composeProjects, composeServices := map[string]bool{}, 0
	for _, c := range containers {
		name := strings.TrimPrefix(c.Name, "/")
		project, service := c.Config.Labels["com.docker.compose.project"], c.Config.Labels["com.docker.compose.service"]
		if project != "" || service != "" {
			composeProjects[project] = true
			composeServices++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect labels", Key: "compose_service", Value: fmt.Sprintf("project=%s service=%s container=%s image=%s network_mode=%s", valueOr(project, "unknown"), valueOr(service, "unknown"), name, c.Config.Image, c.HostConfig.NetworkMode)})
		}
		user := c.Config.User
		if user == "" {
			user = "root(default)"
		}
		networks := make([]string, 0, len(c.NetworkSettings.Networks))
		for network := range c.NetworkSettings.Networks {
			networks = append(networks, network)
		}
		sort.Strings(networks)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "container_context", Value: fmt.Sprintf("name=%s image=%s user=%s restart=%s readonly_rootfs=%t networks=%s", name, c.Config.Image, user, valueOr(c.HostConfig.RestartPolicy.Name, "none"), c.HostConfig.ReadonlyRootfs, strings.Join(networks, ","))})
		if c.HostConfig.Privileged {
			recordProblem(name + ":privileged")
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "privileged", Value: name})
		}
		if c.HostConfig.NetworkMode == "host" {
			image := strings.ToLower(c.Config.Image)
			if strings.Contains(image, "gozargah/marzban") || strings.Contains(image, "quay.io/outline/shadowbox") {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "expected_host_network", Value: name + " image=" + c.Config.Image + " official deployment model; effective listeners are audited separately"})
			} else {
				recordProblem(name + ":host-network")
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "host_network", Value: name})
			}
		}
		if c.HostConfig.PidMode == "host" || c.HostConfig.IpcMode == "host" {
			recordProblem(name + ":host-namespace")
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "host_namespace", Value: name})
		}
		for _, bind := range c.HostConfig.Binds {
			if strings.Contains(bind, "/var/run/docker.sock") || strings.HasPrefix(bind, "/:/") {
				recordProblem(name + ":sensitive-mount")
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "sensitive_bind", Value: name + " " + bind})
			}
		}
		for _, mount := range c.Mounts {
			if mount.Source == "/var/run/docker.sock" || mount.Destination == "/var/run/docker.sock" || (mount.Source == "/" && mount.RW) {
				recordProblem(name + ":sensitive-mount")
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect mounts", Key: "sensitive_mount", Value: fmt.Sprintf("%s type=%s source=%s destination=%s rw=%t", name, mount.Type, mount.Source, mount.Destination, mount.RW)})
			}
		}
		for _, capability := range c.HostConfig.CapAdd {
			if containsAny(strings.ToUpper(capability), "SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH", "ALL") {
				recordProblem(name + ":dangerous-capability:" + strings.ToUpper(capability))
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "dangerous_capability", Value: name + " capability=" + capability})
			}
		}
		for containerPort, bindings := range c.NetworkSettings.Ports {
			for _, b := range bindings {
				scope := classifyAddress(b.HostIP)
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: "published_port", Value: fmt.Sprintf("%s %s:%s->%s scope=%s", name, b.HostIP, b.HostPort, containerPort, scope)})
			}
		}
	}
	f.Facts["compose_projects"] = strconv.Itoa(len(composeProjects))
	f.Facts["compose_services"] = strconv.Itoa(composeServices)
	f.Facts["isolation_problems"] = strconv.Itoa(len(problemKeys))
	if len(problemKeys) > 0 {
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
	paths, discoveryTruncated := discoverCertificatePaths(ctx)
	if len(paths) == 0 {
		if discoveryTruncated {
			return unknown("TLS-001", "tls", "certificate discovery", "nginx configuration output exceeded the capture limit")
		}
		return notApplicable("TLS-001", "tls", "certificate discovery", "no file-backed server certificate found in supported locations")
	}
	f := model.Finding{ID: "TLS-001", Category: "tls", Status: model.Pass, Facts: map[string]string{"certificates": strconv.Itoa(len(paths))}}
	now := ctx.Now()
	if discoveryTruncated {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "nginx configuration output exceeded the capture limit; certificate discovery may be incomplete"
		f.Evidence = append(f.Evidence, model.Evidence{Source: "nginx -T", Key: "unavailable", Value: f.Error})
	}
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
	renewalEvidence, renewalFailures := 0, 0
	if ctx.Commander.Exists("systemctl") {
		for _, timer := range []string{"certbot.timer", "acme.timer"} {
			r := ctx.Commander.Run(6*time.Second, "systemctl", "is-enabled", timer)
			if strings.TrimSpace(r.Stdout) == "enabled" {
				renewalEvidence++
				f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl is-enabled", Key: timer, Value: "enabled"})
			}
		}
		for _, service := range []string{"certbot.service", "acme.service", "acme-renew.service"} {
			r := ctx.Commander.Run(6*time.Second, "systemctl", "show", service, "--property=LoadState,Result,ExecMainStatus,ActiveEnterTimestamp")
			values := parseKeyValues(r.Stdout)
			if values["LoadState"] != "loaded" {
				continue
			}
			renewalEvidence++
			result := values["Result"]
			f.Evidence = append(f.Evidence, model.Evidence{Source: "systemctl show", Key: service, Value: fmt.Sprintf("result=%s exit_status=%s last_active=%s", result, values["ExecMainStatus"], values["ActiveEnterTimestamp"])})
			if result != "" && result != "success" {
				renewalFailures++
			}
		}
	}
	for _, path := range existingFiles("/etc/cron.d/*", "/etc/cron.daily/*") {
		data, err := readSmall(path, 1<<20)
		if err == nil && regexp.MustCompile(`(?i)\b(certbot|acme\.sh|lego)\b`).MatchString(data) {
			renewalEvidence++
			f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: "renewal_schedule", Value: "detected"})
		}
	}
	f.Facts["renewal_evidence"] = strconv.Itoa(renewalEvidence)
	f.Facts["renewal_failures"] = strconv.Itoa(renewalFailures)
	if renewalFailures > 0 && f.Severity != model.Critical && f.Severity != model.High {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	usesLetsEncrypt := false
	for _, path := range paths {
		usesLetsEncrypt = usesLetsEncrypt || strings.HasPrefix(path, "/etc/letsencrypt/")
	}
	if usesLetsEncrypt && renewalEvidence == 0 && f.Status != model.Risk {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "certificate renewal scheduling or recent execution could not be established"
	}
	return f
}

func embeddedSUITLS(ctx *Context) (model.Finding, bool) {
	db := "/usr/local/s-ui/db/s-ui.db"
	if _, err := os.Stat(db); err != nil {
		return model.Finding{}, false
	}
	rows, err := querySQLite(db, "SELECT count(*) FROM tls WHERE server IS NOT NULL AND length(server)>0;")
	if err != nil || len(rows) != 1 || len(rows[0]) != 1 {
		if err == nil {
			err = fmt.Errorf("could not read embedded TLS record count")
		}
		return unknown("TLS-002", "tls", "S-UI TLS database", err.Error()), true
	}
	count, err := strconv.Atoi(rows[0][0])
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

func discoverCertificatePaths(ctx *Context) ([]string, bool) {
	seen := map[string]bool{}
	discoveryTruncated := false
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
	for _, panel := range ctx.Facts.Panels() {
		for _, endpoint := range panel.Endpoints {
			add(endpoint.CertFile)
		}
		for _, path := range panel.CertificateFiles {
			add(path)
		}
	}
	if ctx.Commander.Exists("nginx") {
		r := ctx.Commander.Run(15*time.Second, "nginx", "-T")
		discoveryTruncated = r.Truncated
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
	return paths, discoveryTruncated
}

var workloadProcesses = regexp.MustCompile(`(?i)\b(sing-box|xray|x-ui|s-ui|sui|hysteria|tuic|trojan|ss-server|sslocal|marzban|hiddify|outline-ss-server|wg-quick|openvpn|nginx|caddy|haproxy|apache2|dockerd|containerd)\b`)
