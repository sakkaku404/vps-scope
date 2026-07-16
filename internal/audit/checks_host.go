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
	"github.com/sakkaku404/vps-scope/internal/safefs"
)

func checkWorkloads(ctx *Context) []model.Finding {
	f := model.Finding{ID: "WORK-001", Category: "workloads", Status: model.Info,
		Facts: map[string]string{"requested": ctx.Profile.Requested, "detected": ctx.Profile.Detected, "effective": ctx.Profile.Effective}}
	for _, reason := range ctx.Profile.Reasons {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "process and command detection", Key: "reason", Value: reason})
	}
	if processes, err := ctx.Facts.Processes(); err == nil {
		for _, process := range processes {
			line := processLine(process)
			if workloadProcessLine(line) && len(f.Evidence) < 40 {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "ps", Value: sanitizeProcessEvidence(line)})
			}
		}
	}
	findings := []model.Finding{f, checkPanelManagement(ctx)}
	return append(findings, proxyChecks(ctx)...)
}

func checkPanelManagement(ctx *Context) model.Finding {
	panels, panelDiscoveryErr := ctx.Facts.Panels()
	containerPanels, containerDiscoveryErr := discoverContainerPanels(ctx)
	if panelDiscoveryErr == nil {
		panelDiscoveryErr = containerDiscoveryErr
	}
	if len(panels) == 0 && len(containerPanels) == 0 {
		return withIncompleteEvidence(notApplicable("WORK-002", "workloads", "binary and container discovery", "no supported S-UI, 3x-ui, x-ui, Hiddify, Marzban, or Outline panel found"), "panel and container discovery", panelDiscoveryErr)
	}
	nativeProducts := map[string]bool{}
	for _, panel := range panels {
		nativeProducts[strings.ToLower(panel.Product)] = true
	}
	filteredContainers := containerPanels[:0]
	for _, panel := range containerPanels {
		if !nativeProducts[strings.ToLower(panel.product)] {
			filteredContainers = append(filteredContainers, panel)
		}
	}
	containerPanels = filteredContainers
	f := model.Finding{ID: "WORK-002", Category: "workloads", Status: model.Pass, Facts: map[string]string{"panel_count": strconv.Itoa(len(panels) + len(containerPanels))}}

	listeners, listenerErr := ctx.Facts.Listeners()
	ssAvailable := listenerErr == nil
	if listenerErr != nil {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ss -H -lntup", Key: "error", Value: listenerErr.Error()})
	}
	ufw := readPanelUFW(ctx)
	products := make([]string, 0, len(panels))
	unknowns, inactive := 0, 0
	publicUnrestricted, publicPlaintext, publicDefaultPath, pathUnknown, publicReverseProxy := 0, 0, 0, 0, 0
	for _, panel := range panels {
		products = append(products, panel.Product)
		f.Evidence = append(f.Evidence, model.Evidence{Source: "panel discovery", Key: "product", Value: fmt.Sprintf("product=%s version=%s adapter=%s schema=%s schema_supported=%t schema_fingerprint=%s capabilities=%s binary=%s", panel.Product, panel.Version, panel.Adapter, panel.SchemaVersion, panel.SchemaSupported, panel.SchemaFingerprint, strings.Join(panel.SchemaCapabilities, ","), panel.Binary)})
		if panel.RuntimeCommandError != "" {
			unknowns++
			f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Binary, Key: "runtime_command", Value: panel.RuntimeCommandError})
		}
		if panel.DefaultCredentialKnown {
			f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Product + " settings", Key: "default_credential", Value: strconv.FormatBool(panel.DefaultCredential)})
			if panel.DefaultCredential {
				f.Status, f.Severity = model.Risk, model.Critical
			}
		}
		endpoint, ok := managementEndpoint(panel)
		if !ok || endpoint.Port == "" {
			unknowns++
			f.Evidence = append(f.Evidence, model.Evidence{Source: panel.Product + " settings", Key: "panel_port", Value: "unavailable"})
			continue
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source, Key: "management_endpoint", Value: fmt.Sprintf("product=%s listen=%s port=%s/tcp tls=%s path_default=%s", panel.Product, endpoint.Listen, endpoint.Port, knownBool(endpoint.TLS, endpoint.TLSKnown), knownBool(endpoint.PathIsDefault, endpoint.PathKnown))})
		if !endpoint.PathKnown {
			pathUnknown++
		}
		if !ssAvailable {
			unknowns++
			continue
		}
		scope, found := panelListenerScope(listeners, endpoint.Port, &f)
		if !found {
			inactive++
			continue
		}
		if scope != "public" && scope != "public-wildcard" {
			continue
		}
		family := "any"
		for _, listener := range listeners {
			if listener.Port == endpoint.Port && strings.HasPrefix(listener.Protocol, "tcp") && listener.Scope == scope {
				family = listenerAddressFamily(listener.Address)
				break
			}
		}
		disposition := panelFirewallDispositionFamily(ufw, endpoint.Port, family, &f)
		judgment := "public-management-restricted-by-host-firewall"
		switch disposition {
		case "allow-anywhere", "inactive":
			publicUnrestricted++
			f.Status, f.Severity = model.Risk, model.High
			judgment = "public-management-exposed"
		case "restricted", "blocked-by-default":
			// Public binding is constrained by the host firewall.
		default:
			unknowns++
			judgment = "public-management-firewall-unknown"
		}
		if endpoint.PathKnown && endpoint.PathIsDefault {
			publicDefaultPath++
			judgment += "+root-or-default-path"
		}
		if endpoint.TLSKnown && !endpoint.TLS {
			publicPlaintext++
			judgment += "+plaintext-panel"
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: endpoint.Source + " + ss + host firewall", Key: "management_posture", Value: fmt.Sprintf("product=%s port=%s/tcp scope=%s firewall=%s tls=%s path_default=%s judgment=%s", panel.Product, endpoint.Port, scope, disposition, knownBool(endpoint.TLS, endpoint.TLSKnown), knownBool(endpoint.PathIsDefault, endpoint.PathKnown), judgment)})
	}
	// A loopback-bound panel can still be Internet-facing through Nginx,
	// Caddy, or HAProxy. Treat that as management exposure here as well as in
	// the detailed reverse-proxy relationship check.
	reverseProxyRoutes, reverseProxyErr := discoverReverseProxyRoutes()
	for _, route := range reverseProxyRoutes {
		frontend := matchingListener(listeners, route.FrontendPort, route.FrontendTransport)
		if frontend == nil || (frontend.Scope != "public" && frontend.Scope != "public-wildcard") {
			continue
		}
		if classifyAddress(route.BackendAddress) == "unknown" || matchingBackendListener(listeners, route.BackendAddress, route.BackendPort, "tcp") == nil {
			continue
		}
		disposition := firewallDispositionFamily(ufw, route.FrontendPort, "tcp", listenerAddressFamily(frontend.Address))
		if disposition != "allow-anywhere" && disposition != "inactive" {
			continue
		}
		for _, panel := range panels {
			endpoint, ok := managementEndpoint(panel)
			if !ok || endpoint.Port != route.BackendPort {
				continue
			}
			publicReverseProxy++
			raiseRisk(&f, model.High)
			judgment := "public-reverse-proxy-management-exposed"
			if route.Access == "path-gated" {
				judgment = "public-path-gated-reverse-proxy-management-exposed"
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: route.Source + " + ss + host firewall", Key: "management_posture", Value: fmt.Sprintf("product=%s port=%s/tcp scope=%s firewall=%s tls=unknown path_default=%s judgment=%s", panel.Product, route.FrontendPort, frontend.Scope, disposition, knownBool(endpoint.PathIsDefault, endpoint.PathKnown), judgment)})
		}
	}
	for _, panel := range containerPanels {
		products = append(products, panel.product)
		unknowns++
		f.Evidence = append(f.Evidence, model.Evidence{Source: "docker ps", Key: "container_panel", Value: fmt.Sprintf("product=%s name=%s image=%s", panel.product, panel.name, panel.image)})
		if len(panel.ports) == 0 {
			detail := "no directly published ports; management access may use a reverse-proxy network"
			if panel.hostNetwork {
				detail = "host network; management port requires a product adapter or listener correlation"
			}
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: panel.name, Value: detail})
		} else {
			for _, line := range panel.ports {
				f.Evidence = append(f.Evidence, model.Evidence{Source: "docker inspect", Key: panel.name, Value: truncate(line, 180)})
			}
		}
	}
	sort.Strings(products)
	f.Facts["products"] = strings.Join(products, ",")
	f.Facts["ports_unavailable"] = strconv.Itoa(unknowns)
	f.Facts["panels_not_listening"] = strconv.Itoa(inactive)
	f.Facts["public_unrestricted_management"] = strconv.Itoa(publicUnrestricted)
	f.Facts["public_plaintext_management"] = strconv.Itoa(publicPlaintext)
	f.Facts["public_default_path_management"] = strconv.Itoa(publicDefaultPath)
	f.Facts["management_path_unknown"] = strconv.Itoa(pathUnknown)
	f.Facts["public_reverse_proxy_management"] = strconv.Itoa(publicReverseProxy)
	if f.Status != model.Risk {
		if unknowns > 0 {
			f.Status, f.Unavailable = model.Unknown, true
			f.Error = "management-panel exposure could not be determined from the available port, listener, and firewall evidence"
		} else if inactive == len(panels) && len(containerPanels) == 0 {
			f.Status = model.Info
		}
	}
	f = withIncompleteEvidence(f, "panel and container discovery", panelDiscoveryErr)
	return withIncompleteEvidence(f, "reverse-proxy configuration discovery", reverseProxyErr)
}

func managementEndpoint(panel panelSnapshot) (panelEndpoint, bool) {
	for _, endpoint := range panel.Endpoints {
		if endpoint.Role == "management" {
			return endpoint, true
		}
	}
	return panelEndpoint{}, false
}

func knownBool(value, known bool) string {
	if !known {
		return "unknown"
	}
	return strconv.FormatBool(value)
}

type containerPanelInstall struct {
	product     string
	name        string
	image       string
	ports       []string
	hostNetwork bool
}

func discoverContainerPanels(ctx *Context) ([]containerPanelInstall, error) {
	if !ctx.Commander.Exists("docker") {
		return nil, nil
	}
	containers, err := ctx.Facts.DockerContainers()
	if err != nil {
		return nil, fmt.Errorf("Docker container panel discovery: %w", err)
	}
	var out []containerPanelInstall
	for _, container := range containers {
		name := strings.TrimPrefix(container.Name, "/")
		product, ok := panelProductFromContainer(name + " " + container.Config.Image)
		if !ok {
			continue
		}
		var ports []string
		for containerPort, bindings := range container.NetworkSettings.Ports {
			for _, binding := range bindings {
				ports = append(ports, fmt.Sprintf("%s -> %s:%s", containerPort, binding.HostIP, binding.HostPort))
			}
		}
		sort.Strings(ports)
		out = append(out, containerPanelInstall{product: product, name: name, image: container.Config.Image, ports: ports, hostNetwork: container.HostConfig.NetworkMode == "host"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func panelProductFromContainer(value string) (string, bool) {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "marzban"):
		return "Marzban", true
	case strings.Contains(lower, "hiddify"):
		return "Hiddify", true
	case strings.Contains(lower, "outline"):
		return "Outline", true
	case containsAny(lower, "3x-ui", "x-ui"):
		return "containerized x-ui/3x-ui", true
	case containsAny(lower, "s-ui", "/sui"):
		return "containerized S-UI", true
	default:
		return "", false
	}
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
	defaultDenyByFamily            map[string]bool
	lines                          []string
	backend                        string
	rules                          []firewallRule
	collectionErr                  error
}

func readPanelUFW(ctx *Context) panelUFW {
	if ctx.Facts != nil {
		return ctx.Facts.UFW()
	}
	return collectHostFirewall(ctx.Commander)
}

func parsePanelUFW(output string) panelUFW {
	defaultDeny := regexp.MustCompile(`(?mi)^Default:\s+deny \(incoming\)`).MatchString(output)
	f := panelUFW{available: true, active: regexp.MustCompile(`(?mi)^Status:\s+active\s*$`).MatchString(output), defaultDeny: defaultDeny, defaultDenyByFamily: map[string]bool{"any": defaultDeny}, lines: lines(output), backend: "ufw"}
	f.rules = parseUFWRules(f.lines)
	return f
}

func panelFirewallDisposition(ufw panelUFW, port string, f *model.Finding) string {
	return panelFirewallDispositionFamily(ufw, port, "any", f)
}

func panelFirewallDispositionFamily(ufw panelUFW, port, family string, f *model.Finding) string {
	disposition := firewallDispositionFamily(ufw, port, "tcp", family)
	if disposition == "allow-restricted" {
		disposition = "restricted"
	}
	f.Evidence = append(f.Evidence, model.Evidence{Source: firewallEvidenceSource(ufw), Key: "panel_firewall", Value: disposition})
	return disposition
}

func checkFilesystem(ctx *Context) []model.Finding {
	f := model.Finding{ID: "FS-001", Category: "filesystem", Status: model.Pass, Facts: map[string]string{}}
	type target struct {
		path      string
		forbidden fs.FileMode
	}
	targets := []target{
		{"/etc/passwd", 0o022}, {"/etc/shadow", 0o027}, {"/etc/sudoers", 0o022},
		{"/etc/ssh/sshd_config", 0o022},
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

func checkTemporaryExecutables() model.Finding {
	f := model.Finding{ID: "PERSIST-002", Category: "persistence", Status: model.Pass, Facts: map[string]string{}}
	entries, err := safefs.ReadDirectoryBounded("/proc", procDirectoryEntryLimit)
	if err != nil {
		return unknown("PERSIST-002", "persistence", "/proc", err.Error())
	}
	seen := map[string]bool{}
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		target, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil || !(strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/var/tmp/") || strings.HasPrefix(target, "/dev/shm/")) {
			continue
		}
		cleanTarget := strings.TrimSuffix(target, " (deleted)")
		resolvedTarget, _ := filepath.EvalSymlinks(cleanTarget)
		if self != "" && (cleanTarget == self || resolvedTarget == self) {
			continue
		}
		key := entry.Name() + "\x00" + target
		if !seen[key] {
			seen[key] = true
			f.Evidence = append(f.Evidence, model.Evidence{Source: "/proc/*/exe", Key: "temporary_executable", Value: "pid=" + entry.Name() + " path=" + target})
		}
	}
	f.Facts["temporary_executables"] = strconv.Itoa(len(seen))
	if len(seen) > 0 {
		f.Status, f.Severity = model.Risk, model.High
	}
	return f
}

func checkPersistence(ctx *Context) []model.Finding {
	f := model.Finding{ID: "PERSIST-001", Category: "persistence", Status: model.Pass, Facts: map[string]string{}}
	patterns := []struct {
		name string
		re   *regexp.Regexp
	}{
		{"temporary-execution-path", regexp.MustCompile(`(?i)(/tmp/|/var/tmp/|/dev/shm/)`)},
		{"remote-download-piped-to-shell", regexp.MustCompile(`(?i)(curl|wget).{0,160}(\||;|&&).{0,40}(sh|bash)`)},
		{"base64-decoded-shell", regexp.MustCompile(`(?i)base64\s+(-d|--decode).{0,120}(\||;).{0,40}(sh|bash)`)},
	}
	paths := []string{"/etc/rc.local", "/etc/ld.so.preload", "/etc/crontab"}
	discovered, discoveryErr := discoverExistingFiles(2048, "/etc/cron.d/*", "/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*/*.service")
	paths = append(paths, discovered...)
	discoveredSet := make(map[string]bool, len(discovered))
	for _, path := range discovered {
		discoveredSet[path] = true
	}
	indicators := 0
	scanned := 0
	for _, path := range paths {
		data, err := readSmall(path, 4<<20)
		if err != nil {
			if persistenceReadFailureIncomplete(path, err, discoveredSet[path]) {
				discoveryErr = errors.Join(discoveryErr, fmt.Errorf("%s: %w", path, err))
			}
			continue
		}
		scanned++
		for i, line := range lines(data) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, pattern := range patterns {
				if pattern.re.MatchString(trimmed) {
					indicators++
					f.Evidence = append(f.Evidence, model.Evidence{Source: path, Key: fmt.Sprintf("line_%d", i+1), Value: "indicator=" + pattern.name + "; command content withheld by privacy policy"})
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
	f = withIncompleteEvidence(f, "startup-file discovery", discoveryErr)
	return []model.Finding{f, checkTemporaryExecutables()}
}

func persistenceReadFailureIncomplete(path string, readErr error, discovered bool) bool {
	if readErr == nil {
		return false
	}
	if !discovered {
		return !errors.Is(readErr, fs.ErrNotExist)
	}
	// systemd glob results legitimately include masked units that resolve to
	// /dev/null and stale wants/ aliases. Neither is an executable persistence
	// file, so do not turn a disabled unit into unavailable evidence.
	info, statErr := os.Stat(path)
	return !errors.Is(statErr, fs.ErrNotExist) && (statErr != nil || info.Mode().IsRegular())
}

func checkLogAndInodePressure(ctx *Context) model.Finding {
	f := model.Finding{ID: "REL-002", Category: "reliability", Status: model.Info, Facts: map[string]string{}}
	if ctx.Commander.Exists("df") {
		r := ctx.Commander.Run(8*time.Second, "df", "-Pi", "/")
		if r.Err == nil {
			rows := lines(r.Stdout)
			if len(rows) > 1 {
				fields := strings.Fields(rows[len(rows)-1])
				if len(fields) >= 5 {
					f.Facts["root_inode_used_percent"] = strings.TrimSuffix(fields[4], "%")
					f.Evidence = append(f.Evidence, model.Evidence{Source: "df -Pi /", Key: "inode_use", Value: fields[4]})
				}
			}
		}
	}
	if ctx.Commander.Exists("journalctl") {
		r := ctx.Commander.Run(10*time.Second, "journalctl", "--disk-usage", "--no-pager")
		if r.Err == nil {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl --disk-usage", Key: "journal_size", Value: truncate(strings.TrimSpace(r.Stdout), 180)})
		}
	}
	if ctx.Commander.Exists("docker") {
		r := ctx.Commander.Run(15*time.Second, "docker", "system", "df", "--format", "{{json .}}")
		if r.Err == nil {
			f.Evidence = append(f.Evidence, model.Evidence{Source: "docker system df", Key: "docker_storage_rows", Value: strconv.Itoa(len(lines(r.Stdout)))})
		}
	}
	if len(f.Evidence) == 0 {
		return unknown("REL-002", "reliability", "df, journalctl, docker", "storage pressure evidence was unavailable")
	}
	return f
}

func checkReliability(ctx *Context) []model.Finding {
	f := model.Finding{ID: "REL-001", Category: "reliability", Status: model.Pass, Facts: map[string]string{}}
	oom, cores := 0, 0
	if ctx.Commander.Exists("journalctl") {
		r := ctx.Commander.Run(25*time.Second, "journalctl", "-k", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat")
		if r.Truncated {
			f.Status, f.Unavailable, f.Error = model.Unknown, true, commandError(r)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl -k", Key: "unavailable", Value: commandError(r)})
		} else if r.Err == nil {
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
		if r.Truncated {
			f.Status, f.Unavailable, f.Error = model.Unknown, true, commandError(r)
			f.Evidence = append(f.Evidence, model.Evidence{Source: "coredumpctl", Key: "unavailable", Value: commandError(r)})
		} else if r.Err == nil || r.Stdout != "" {
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
	return []model.Finding{f, checkLogAndInodePressure(ctx)}
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
