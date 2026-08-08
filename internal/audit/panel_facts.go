package audit

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type panelEndpoint struct {
	Role          string
	Listen        string
	Port          string
	TLS           bool
	TLSKnown      bool
	Source        string
	CertFile      string
	PathIsDefault bool
	PathKnown     bool
}

type panelInboundFact struct {
	Enabled        bool
	Listen         string
	Port           string
	Protocol       string
	Network        string
	Security       string
	ClientCount    int
	Expired        bool
	QuotaExhausted bool
	RealityKeySet  bool
	RealityTargets int
	RealityIDs     int
}

type panelSnapshot struct {
	Product                  string
	Version                  string
	Adapter                  string
	SchemaVersion            string
	SchemaFingerprint        string
	SchemaCapabilities       []string
	SchemaSupported          bool
	Binary                   string
	Database                 string
	Endpoints                []panelEndpoint
	Inbounds                 []panelInboundFact
	DatabaseAvailable        bool
	DatabaseError            string
	DiscoveryError           string
	RuntimeCommandError      string
	ManagementMetadataError  string
	CertificateMetadataError string
	ClientInventoryError     string
	DefaultCredential        bool
	DefaultCredentialKnown   bool
	EnabledClients           int
	DisabledClients          int
	ClientInventoryKnown     bool
	CertificateFiles         []string
	SensitiveFiles           []string
}

func collectPanelSnapshotsFromInventory(cmd Commander, nativeSelfTest bool, auditTime time.Time, inventory panelInventory, adapters []panelAdapter, files *fileEvidenceSnapshot) []panelSnapshot {
	return collectPanelSnapshotsFromInventoryContext(context.Background(), cmd, nativeSelfTest, auditTime, inventory, adapters, files)
}

func collectPanelSnapshotsFromInventoryContext(ctx context.Context, cmd Commander, nativeSelfTest bool, auditTime time.Time, inventory panelInventory, adapters []panelAdapter, files *fileEvidenceSnapshot) []panelSnapshot {
	var out []panelSnapshot
	if files == nil {
		files = newFileEvidenceSnapshot(osFileEvidenceSource{})
	}
	input := panelAdapterInput{Context: ctx, Commander: cmd, NativeSelfTest: nativeSelfTest, AuditTime: auditTime, Files: files}
	for _, adapter := range adapters {
		if adapter.Detect(inventory) {
			descriptor := adapter.Descriptor()
			snapshot := adapter.Collect(input)
			snapshot.Adapter = descriptor.ID
			if snapshot.Product == "" {
				snapshot.Product = descriptor.Product
			}
			out = append(out, snapshot)
		}
	}
	return out
}

func collectSUIFacts(cmd Commander, nativeSelfTest bool) panelSnapshot {
	return collectSUIFactsAt(cmd, nativeSelfTest, time.Now().UTC())
}

func collectSUIFactsAt(cmd Commander, nativeSelfTest bool, _ time.Time) panelSnapshot {
	return collectSUIFactsAtSource(cmd, nativeSelfTest, time.Time{}, newFileEvidenceSnapshot(osFileEvidenceSource{}))
}

func collectSUIFactsAtSource(cmd Commander, nativeSelfTest bool, _ time.Time, files *fileEvidenceSnapshot) panelSnapshot {
	return collectSUIFactsAtSourceContext(context.Background(), cmd, nativeSelfTest, time.Time{}, files)
}

func collectSUIFactsAtSourceContext(ctx context.Context, cmd Commander, nativeSelfTest bool, _ time.Time, files *fileEvidenceSnapshot) panelSnapshot {
	s := panelSnapshot{Product: "S-UI", Binary: "/usr/local/s-ui/sui", Database: "/usr/local/s-ui/db/s-ui.db"}
	if nativeSelfTest {
		binary, trustErr := trustedExecutable(cmd, s.Binary)
		if trustErr != nil {
			s.RuntimeCommandError = "panel command skipped: " + truncate(trustErr.Error(), 240)
		} else {
			version := cmd.Run(8*time.Second, binary, "-v")
			s.Version = firstVersion(version.Stdout + "\n" + version.Stderr)
			settings := cmd.Run(8*time.Second, binary, "setting", "-show")
			if settings.Err != nil || settings.Truncated {
				s.RuntimeCommandError = "sui setting -show: " + commandError(settings)
			} else {
				if port, ok := parseNamedPort(settings.Stdout, "Panel port"); ok {
					path, pathKnown := parseNamedTextKnown(settings.Stdout, "Panel path")
					s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: "*", Port: port, Source: "sui setting -show", PathKnown: pathKnown, PathIsDefault: panelPathIsDefault(path)})
				}
				if port, ok := parseNamedPort(settings.Stdout, "Sub port"); ok {
					path, pathKnown := parseNamedTextKnown(settings.Stdout, "Sub path")
					s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "subscription", Listen: "*", Port: port, Source: "sui setting -show", PathKnown: pathKnown, PathIsDefault: subscriptionPathIsDefault(path)})
				}
			}
		}
	}
	if info, err := files.Stat(s.Database); err != nil || !info.Mode().IsRegular() {
		s.DatabaseError = "S-UI database missing"
		return s
	}
	session, err := openSQLiteSessionForAudit(ctx, s.Database)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	defer session.Close()
	inspection, err := inspectPanelSchemaWithQuery(session.Query, "S-UI")
	s.SchemaFingerprint = inspection.Fingerprint
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.SchemaVersion = inspection.Version
	s.SchemaCapabilities = inspection.Capabilities
	s.SchemaSupported = true
	settingRows, err := session.Query(`SELECT key, value FROM settings WHERE key IN ('webListen','webPort','webBasePath','webCertFile','webKeyFile','subListen','subPort','subPath','subCertFile','subKeyFile');`)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.DatabaseAvailable = true
	applyPanelSettings(&s, settingRows, "S-UI database")
	applySUIDefaults(&s, settingRows)
	inboundRows, err := session.Query(`SELECT 1, COALESCE(json_extract(i.options,'$.listen'),''), COALESCE(json_extract(i.options,'$.listen_port'),''), i.type, '', CASE WHEN json_extract(t.server,'$.reality.enabled')=1 THEN 'reality' WHEN i.tls_id IS NULL OR i.tls_id=0 THEN '' ELSE 'tls' END, 0, 0, 0, CASE WHEN length(COALESCE(json_extract(t.server,'$.reality.private_key'),''))>0 THEN 1 ELSE 0 END, CASE WHEN length(COALESCE(json_extract(t.server,'$.reality.handshake.server'),''))>0 OR COALESCE(json_extract(t.server,'$.reality.handshake.server_port'),0)>0 THEN 1 ELSE 0 END, COALESCE(json_array_length(json_extract(t.server,'$.reality.short_id')),0)+CASE WHEN length(COALESCE(json_extract(t.server,'$.server_name'),''))>0 THEN 1 ELSE 0 END FROM inbounds i LEFT JOIN tls t ON t.id=i.tls_id;`)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.Inbounds, err = parsePanelInboundRows(inboundRows)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	certRows, err := session.Query(`SELECT DISTINCT COALESCE(json_extract(server,'$.certificate_path'),'') FROM tls WHERE length(COALESCE(json_extract(server,'$.certificate_path'),''))>0;`)
	if err == nil {
		s.CertificateFiles = firstColumn(certRows)
	} else {
		s.CertificateMetadataError = err.Error()
	}
	clientRows, err := session.Query(`SELECT COALESCE(sum(CASE WHEN enable=1 THEN 1 ELSE 0 END),0), COALESCE(sum(CASE WHEN enable=1 THEN 0 ELSE 1 END),0) FROM clients;`)
	if err == nil && len(clientRows) == 1 && len(clientRows[0]) == 2 {
		enabled, enabledErr := nonNegativeInt(clientRows[0][0])
		disabled, disabledErr := nonNegativeInt(clientRows[0][1])
		if enabledErr == nil && disabledErr == nil {
			s.EnabledClients, s.DisabledClients, s.ClientInventoryKnown = enabled, disabled, true
		} else {
			s.ClientInventoryError = "client inventory query returned malformed counts"
		}
	} else if err != nil {
		s.ClientInventoryError = err.Error()
	} else {
		s.ClientInventoryError = "client inventory query returned an unexpected shape"
	}
	return s
}

func collectXUIFacts(cmd Commander, nativeSelfTest bool) panelSnapshot {
	return collectXUIFactsAt(cmd, nativeSelfTest, time.Now().UTC())
}

func collectXUIFactsAt(cmd Commander, nativeSelfTest bool, auditTime time.Time) panelSnapshot {
	return collectXUIFactsAtSource(cmd, nativeSelfTest, auditTime, newFileEvidenceSnapshot(osFileEvidenceSource{}))
}

func collectXUIFactsAtSource(cmd Commander, nativeSelfTest bool, auditTime time.Time, files *fileEvidenceSnapshot) panelSnapshot {
	return collectXUIFactsAtSourceContext(context.Background(), cmd, nativeSelfTest, auditTime, files)
}

func collectXUIFactsAtSourceContext(ctx context.Context, cmd Commander, nativeSelfTest bool, auditTime time.Time, files *fileEvidenceSnapshot) panelSnapshot {
	s := panelSnapshot{Product: "x-ui", Binary: "/usr/local/x-ui/x-ui", Database: "/etc/x-ui/x-ui.db"}
	var binary string
	trustErr := error(nil)
	if nativeSelfTest {
		binary, trustErr = trustedExecutable(cmd, s.Binary)
		if trustErr != nil {
			s.RuntimeCommandError = "panel command skipped: " + truncate(trustErr.Error(), 240)
		} else {
			version := cmd.Run(8*time.Second, binary, "-v")
			s.Version = firstVersion(version.Stdout + "\n" + version.Stderr)
			if containsAny(version.Stdout+"\n"+version.Stderr, "3x-ui", "3X-UI") {
				s.Product = "3x-ui"
			}
		}
	}
	if script, err := files.ReadSmall("/usr/local/x-ui/x-ui.sh", 1<<20); err == nil && containsAny(script, "MHSanaei/3x-ui", "3X-UI", "3x-ui") {
		s.Product = "3x-ui"
	}
	if nativeSelfTest && trustErr == nil {
		settings := cmd.Run(8*time.Second, binary, "setting", "-show", "true")
		if settings.Err != nil {
			settings = cmd.Run(8*time.Second, binary, "setting", "-show")
		}
		if settings.Err != nil || settings.Truncated {
			s.RuntimeCommandError = "x-ui setting -show: " + commandError(settings)
		} else {
			if port, ok := parsePanelPort(s.Product, settings.Stdout); ok {
				path, pathKnown := parseNamedTextKnown(settings.Stdout, "webBasePath")
				s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: "*", Port: port, Source: "x-ui setting -show", PathKnown: pathKnown, PathIsDefault: panelPathIsDefault(path)})
			}
			if match := regexp.MustCompile(`(?mi)^\s*hasDefaultCredential\s*:\s*(true|false)\s*$`).FindStringSubmatch(settings.Stdout); len(match) == 2 {
				s.DefaultCredentialKnown = true
				s.DefaultCredential = strings.EqualFold(match[1], "true")
			}
			for i := range s.Endpoints {
				if s.Endpoints[i].Role == "management" {
					s.Endpoints[i].TLSKnown = true
					s.Endpoints[i].TLS = !regexp.MustCompile(`(?mi)panel is not secure with SSL`).MatchString(settings.Stdout)
				}
			}
		}
		listen := cmd.Run(6*time.Second, binary, "setting", "-getListen")
		if listen.Err != nil || listen.Truncated {
			message := "x-ui setting -getListen: " + commandError(listen)
			if s.RuntimeCommandError == "" {
				s.RuntimeCommandError = message
			} else {
				s.RuntimeCommandError += "; " + message
			}
		} else if value := parseListenValue(listen.Stdout); value != "" {
			setPanelEndpointListen(&s, "management", value)
		}
	}
	if info, err := files.Stat(s.Database); err != nil || !info.Mode().IsRegular() {
		s.DatabaseError = "x-ui database missing"
		return s
	}
	session, err := openSQLiteSessionForAudit(ctx, s.Database)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	defer session.Close()
	inspection, err := inspectPanelSchemaWithQuery(session.Query, s.Product)
	s.SchemaFingerprint = inspection.Fingerprint
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.SchemaVersion = inspection.Version
	s.SchemaCapabilities = inspection.Capabilities
	s.SchemaSupported = true
	s.DatabaseAvailable = true
	if s.Product == "3x-ui" {
		apply3XUIDefaults(&s)
	}
	settingRows, err := session.Query(`SELECT key, value FROM settings WHERE key IN ('webListen','webPort','webBasePath','webCertFile','webCertKey','subEnable','subListen','subPort','subPath','subCertFile','subKeyFile');`)
	if err == nil {
		applyPanelSettings(&s, settingRows, "x-ui database")
	} else {
		s.ManagementMetadataError = err.Error()
	}
	nowMillis := auditTime.UnixMilli()
	query := fmt.Sprintf(`SELECT enable, COALESCE(listen,''), port, protocol, CASE WHEN protocol='shadowsocks' THEN COALESCE(json_extract(settings,'$.network'),'') ELSE COALESCE(json_extract(stream_settings,'$.network'),'') END, COALESCE(json_extract(stream_settings,'$.security'),''), COALESCE(json_array_length(json_extract(settings,'$.clients')),0), CASE WHEN expiry_time>0 AND expiry_time<%d THEN 1 ELSE 0 END, CASE WHEN total>0 AND up+down>=total THEN 1 ELSE 0 END, CASE WHEN length(COALESCE(json_extract(stream_settings,'$.realitySettings.privateKey'),''))>0 THEN 1 ELSE 0 END, CASE WHEN length(COALESCE(json_extract(stream_settings,'$.realitySettings.target'),json_extract(stream_settings,'$.realitySettings.dest'),''))>0 THEN 1 ELSE 0 END, COALESCE(json_array_length(json_extract(stream_settings,'$.realitySettings.serverNames')),0)+COALESCE(json_array_length(json_extract(stream_settings,'$.realitySettings.shortIds')),0) FROM inbounds;`, nowMillis)
	inboundRows, err := session.Query(query)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.Inbounds, err = parsePanelInboundRows(inboundRows)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	certRows, err := session.Query(`SELECT DISTINCT COALESCE(json_extract(stream_settings,'$.tlsSettings.certificates[0].certificateFile'),'') FROM inbounds WHERE length(COALESCE(json_extract(stream_settings,'$.tlsSettings.certificates[0].certificateFile'),''))>0;`)
	if err == nil {
		s.CertificateFiles = firstColumn(certRows)
	} else {
		s.CertificateMetadataError = err.Error()
	}
	clientRows, err := session.Query(`SELECT COALESCE(sum(CASE WHEN enable=1 THEN 1 ELSE 0 END),0), COALESCE(sum(CASE WHEN enable=1 THEN 0 ELSE 1 END),0) FROM clients;`)
	if err == nil && len(clientRows) == 1 && len(clientRows[0]) == 2 {
		enabled, enabledErr := nonNegativeInt(clientRows[0][0])
		disabled, disabledErr := nonNegativeInt(clientRows[0][1])
		if enabledErr == nil && disabledErr == nil {
			s.EnabledClients, s.DisabledClients, s.ClientInventoryKnown = enabled, disabled, true
		} else {
			s.ClientInventoryError = "client inventory query returned malformed counts"
		}
	} else if err != nil {
		s.ClientInventoryError = err.Error()
	} else {
		s.ClientInventoryError = "client inventory query returned an unexpected shape"
	}
	return s
}

func apply3XUIDefaults(snapshot *panelSnapshot) {
	// 3x-ui stores only overrides in the settings table. A fresh database
	// therefore has no subPort/subPath rows even though the built-in
	// subscription server is enabled and listening. Seed the documented
	// defaults, then let persisted settings override or disable them.
	upsertPanelEndpoint(snapshot, panelEndpoint{
		Role: "subscription", Listen: "*", Port: "2096",
		TLS: false, TLSKnown: true, Source: "3x-ui built-in defaults",
		PathKnown: true, PathIsDefault: true,
	})
}

func applySUIDefaults(snapshot *panelSnapshot, rows [][]string) {
	// S-UI 1.5.x persists webBasePath only when it differs from the built-in
	// root path. A configured webPort with no webBasePath row therefore means
	// "/", not "unknown". Keep the inference local to a schema-supported S-UI
	// database; persisted values applied above always take precedence.
	hasWebPort, hasWebBasePath := false, false
	for _, row := range rows {
		if len(row) != 2 {
			continue
		}
		switch row[0] {
		case "webPort":
			hasWebPort = strings.TrimSpace(row[1]) != ""
		case "webBasePath":
			hasWebBasePath = true
		}
	}
	if !hasWebPort || hasWebBasePath {
		return
	}
	endpoint, ok := panelEndpointByRole(*snapshot, "management")
	if !ok {
		return
	}
	endpoint.PathKnown = true
	endpoint.PathIsDefault = true
	endpoint.Source = "S-UI database + built-in default"
	upsertPanelEndpoint(snapshot, endpoint)
}

func parsePanelInboundRows(rows [][]string) ([]panelInboundFact, error) {
	var out []panelInboundFact
	for index, row := range rows {
		if len(row) != 12 {
			return nil, fmt.Errorf("panel inbound row %d returned %d columns; expected 12", index+1, len(row))
		}
		if row[0] != "0" && row[0] != "1" {
			return nil, fmt.Errorf("panel inbound row %d returned an invalid enabled state", index+1)
		}
		if !validPort(row[2]) {
			return nil, fmt.Errorf("panel inbound row %d returned an invalid port", index+1)
		}
		clientCount, err := nonNegativeInt(row[6])
		if err != nil {
			return nil, fmt.Errorf("panel inbound row %d returned an invalid client count", index+1)
		}
		for _, column := range []int{7, 8, 9} {
			if row[column] != "0" && row[column] != "1" {
				return nil, fmt.Errorf("panel inbound row %d returned an invalid boolean value", index+1)
			}
		}
		realityTargets, targetErr := nonNegativeInt(row[10])
		realityIDs, idErr := nonNegativeInt(row[11])
		if targetErr != nil || idErr != nil {
			return nil, fmt.Errorf("panel inbound row %d returned invalid Reality metadata counts", index+1)
		}
		out = append(out, panelInboundFact{
			Enabled: row[0] == "1", Listen: normalizeListen(row[1]), Port: row[2],
			Protocol: row[3], Network: row[4], Security: row[5], ClientCount: clientCount,
			Expired: row[7] == "1", QuotaExhausted: row[8] == "1",
			RealityKeySet: row[9] == "1", RealityTargets: realityTargets, RealityIDs: realityIDs,
		})
	}
	return out, nil
}

func nonNegativeInt(value string) (int, error) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid non-negative integer")
	}
	return n, nil
}

func firstColumn(rows [][]string) []string {
	var out []string
	for _, row := range rows {
		if len(row) > 0 && row[0] != "" {
			out = append(out, row[0])
		}
	}
	return out
}

func applyPanelSettings(snapshot *panelSnapshot, rows [][]string, source string) {
	values := map[string]string{}
	for _, row := range rows {
		if len(row) == 2 {
			values[row[0]] = row[1]
		}
	}
	for _, role := range []struct{ name, prefix string }{{"management", "web"}, {"subscription", "sub"}} {
		if role.name == "subscription" && settingIsFalse(values["subEnable"]) {
			removePanelEndpoint(snapshot, role.name)
			continue
		}
		old, hasOld := panelEndpointByRole(*snapshot, role.name)
		port, portSet := values[role.prefix+"Port"]
		if !portSet && hasOld {
			port = old.Port
		}
		if port == "" {
			continue
		}
		updated := old
		updated.Role, updated.Port = role.name, port
		changed := portSet
		if listen, ok := values[role.prefix+"Listen"]; ok {
			updated.Listen = normalizeListen(listen)
			changed = true
		} else if !hasOld {
			updated.Listen = "::"
		}
		certFile, certSet := values[role.prefix+"CertFile"]
		keyFile, keySet := values[role.prefix+"KeyFile"]
		certKey, certKeySet := values[role.prefix+"CertKey"]
		if certSet || keySet || certKeySet {
			updated.CertFile = certFile
			updated.TLSKnown = true
			updated.TLS = certFile != "" && (keyFile != "" || certKey != "")
			changed = true
		} else if !hasOld && portSet {
			// Preserve the previous database semantics: a configured panel
			// endpoint without certificate settings is known plaintext.
			updated.TLSKnown = true
			updated.TLS = false
		}
		if path, ok := values[map[string]string{"web": "webBasePath", "sub": "subPath"}[role.prefix]]; ok {
			updated.PathKnown = true
			changed = true
			if role.name == "management" {
				updated.PathIsDefault = panelPathIsDefault(path)
			} else {
				updated.PathIsDefault = subscriptionPathIsDefault(path)
			}
		}
		if changed || !hasOld {
			updated.Source = source
		}
		upsertPanelEndpoint(snapshot, updated)
	}
}

func settingIsFalse(value string) bool {
	value = strings.TrimSpace(value)
	return strings.EqualFold(value, "false") || value == "0"
}

func panelEndpointByRole(snapshot panelSnapshot, role string) (panelEndpoint, bool) {
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.Role == role {
			return endpoint, true
		}
	}
	return panelEndpoint{}, false
}

func removePanelEndpoint(snapshot *panelSnapshot, role string) {
	endpoints := snapshot.Endpoints[:0]
	for _, endpoint := range snapshot.Endpoints {
		if endpoint.Role != role {
			endpoints = append(endpoints, endpoint)
		}
	}
	snapshot.Endpoints = endpoints
}

func upsertPanelEndpoint(snapshot *panelSnapshot, endpoint panelEndpoint) {
	for i := range snapshot.Endpoints {
		if snapshot.Endpoints[i].Role == endpoint.Role {
			snapshot.Endpoints[i] = endpoint
			return
		}
	}
	snapshot.Endpoints = append(snapshot.Endpoints, endpoint)
}

func setPanelEndpointListen(snapshot *panelSnapshot, role, listen string) {
	for i := range snapshot.Endpoints {
		if snapshot.Endpoints[i].Role == role {
			snapshot.Endpoints[i].Listen = normalizeListen(listen)
		}
	}
}

func parseNamedPort(output, name string) (string, bool) {
	match := regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(name) + `\s*:\s*([0-9]{1,5})\s*$`).FindStringSubmatch(output)
	if len(match) != 2 {
		return "", false
	}
	port, err := strconv.Atoi(match[1])
	return match[1], err == nil && port > 0 && port <= 65535
}

func parseNamedTextKnown(output, name string) (string, bool) {
	match := regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(name) + `\s*:\s*(.*?)\s*$`).FindStringSubmatch(output)
	if len(match) != 2 {
		return "", false
	}
	return strings.TrimSpace(match[1]), true
}

func panelPathIsDefault(path string) bool {
	path = strings.TrimSpace(path)
	return path == "" || path == "/" || strings.EqualFold(path, "/panel/") || strings.EqualFold(path, "/xui/")
}

func subscriptionPathIsDefault(path string) bool {
	path = strings.TrimSpace(path)
	return path == "" || path == "/" || strings.EqualFold(path, "/sub/")
}

func parseListenValue(output string) string {
	for _, line := range lines(output) {
		if _, value, ok := strings.Cut(line, ":"); ok {
			value = strings.TrimSpace(value)
			if value != "" {
				return value
			}
		}
	}
	return strings.TrimSpace(output)
}

func firstVersion(output string) string {
	match := regexp.MustCompile(`(?i)\bv?([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b`).FindStringSubmatch(output)
	if len(match) == 2 {
		return match[1]
	}
	return "unknown"
}
