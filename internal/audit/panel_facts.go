package audit

import (
	"fmt"
	"os"
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
	Product                string
	Version                string
	Adapter                string
	SchemaVersion          string
	Binary                 string
	Database               string
	Endpoints              []panelEndpoint
	Inbounds               []panelInboundFact
	DatabaseAvailable      bool
	DatabaseError          string
	DefaultCredential      bool
	DefaultCredentialKnown bool
	EnabledClients         int
	DisabledClients        int
	CertificateFiles       []string
	SensitiveFiles         []string
}

func collectPanelSnapshots(cmd Commander) []panelSnapshot {
	var out []panelSnapshot
	for _, adapter := range panelAdapters() {
		if adapter.Detect() {
			snapshot := adapter.Collect(cmd)
			snapshot.Adapter = adapter.ID()
			out = append(out, snapshot)
		}
	}
	return out
}

func collectSUIFacts(cmd Commander) panelSnapshot {
	s := panelSnapshot{Product: "S-UI", Binary: "/usr/local/s-ui/sui", Database: "/usr/local/s-ui/db/s-ui.db"}
	version := cmd.Run(8*time.Second, s.Binary, "-v")
	s.Version = firstVersion(version.Stdout + "\n" + version.Stderr)
	settings := cmd.Run(8*time.Second, s.Binary, "setting", "-show")
	if port, ok := parseNamedPort(settings.Stdout, "Panel port"); ok {
		path := parseNamedText(settings.Stdout, "Panel path")
		s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: "::", Port: port, Source: "sui setting -show", PathKnown: path != "", PathIsDefault: panelPathIsDefault(path)})
	}
	if port, ok := parseNamedPort(settings.Stdout, "Sub port"); ok {
		path := parseNamedText(settings.Stdout, "Sub path")
		s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "subscription", Listen: "::", Port: port, Source: "sui setting -show", PathKnown: path != "", PathIsDefault: subscriptionPathIsDefault(path)})
	}
	if !regularFile(s.Database) {
		s.DatabaseError = "S-UI database missing"
		return s
	}
	schema, err := detectPanelSchema(cmd, s.Database, "S-UI")
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.SchemaVersion = schema
	settingRows, err := sqliteTSV(cmd, s.Database, `SELECT key, value FROM settings WHERE key IN ('webListen','webPort','webCertFile','webKeyFile','subListen','subPort','subCertFile','subKeyFile');`)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.DatabaseAvailable = true
	applyPanelSettings(&s, settingRows, "S-UI database")
	inboundRows, err := sqliteTSV(cmd, s.Database, `SELECT 1, COALESCE(json_extract(i.options,'$.listen'),''), COALESCE(json_extract(i.options,'$.listen_port'),''), i.type, '', CASE WHEN json_extract(t.server,'$.reality.enabled')=1 THEN 'reality' WHEN i.tls_id IS NULL OR i.tls_id=0 THEN '' ELSE 'tls' END, 0, 0, 0, CASE WHEN length(COALESCE(json_extract(t.server,'$.reality.private_key'),''))>0 THEN 1 ELSE 0 END, CASE WHEN length(COALESCE(json_extract(t.server,'$.reality.handshake.server'),''))>0 OR COALESCE(json_extract(t.server,'$.reality.handshake.server_port'),0)>0 THEN 1 ELSE 0 END, COALESCE(json_array_length(json_extract(t.server,'$.reality.short_id')),0)+CASE WHEN length(COALESCE(json_extract(t.server,'$.server_name'),''))>0 THEN 1 ELSE 0 END FROM inbounds i LEFT JOIN tls t ON t.id=i.tls_id;`)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.Inbounds = parsePanelInboundRows(inboundRows)
	certRows, err := sqliteTSV(cmd, s.Database, `SELECT DISTINCT COALESCE(json_extract(server,'$.certificate_path'),'') FROM tls WHERE length(COALESCE(json_extract(server,'$.certificate_path'),''))>0;`)
	if err == nil {
		s.CertificateFiles = firstColumn(certRows)
	}
	clientRows, err := sqliteTSV(cmd, s.Database, `SELECT COALESCE(sum(CASE WHEN enable=1 THEN 1 ELSE 0 END),0), COALESCE(sum(CASE WHEN enable=1 THEN 0 ELSE 1 END),0) FROM clients;`)
	if err == nil && len(clientRows) == 1 && len(clientRows[0]) == 2 {
		s.EnabledClients, _ = strconv.Atoi(clientRows[0][0])
		s.DisabledClients, _ = strconv.Atoi(clientRows[0][1])
	}
	return s
}

func collectXUIFacts(cmd Commander) panelSnapshot {
	s := panelSnapshot{Product: "x-ui", Binary: "/usr/local/x-ui/x-ui", Database: "/etc/x-ui/x-ui.db"}
	version := cmd.Run(8*time.Second, s.Binary, "-v")
	s.Version = firstVersion(version.Stdout + "\n" + version.Stderr)
	if containsAny(version.Stdout+"\n"+version.Stderr, "3x-ui", "3X-UI") {
		s.Product = "3x-ui"
	}
	if script, err := os.ReadFile("/usr/local/x-ui/x-ui.sh"); err == nil && containsAny(string(script), "MHSanaei/3x-ui", "3X-UI", "3x-ui") {
		s.Product = "3x-ui"
	}
	settings := cmd.Run(8*time.Second, s.Binary, "setting", "-show", "true")
	if settings.Err != nil {
		settings = cmd.Run(8*time.Second, s.Binary, "setting", "-show")
	}
	if port, ok := parsePanelPort(s.Product, settings.Stdout); ok {
		path := parseNamedText(settings.Stdout, "webBasePath")
		s.Endpoints = append(s.Endpoints, panelEndpoint{Role: "management", Listen: "::", Port: port, Source: "x-ui setting -show", PathKnown: path != "", PathIsDefault: panelPathIsDefault(path)})
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
	listen := cmd.Run(6*time.Second, s.Binary, "setting", "-getListen")
	if value := parseListenValue(listen.Stdout); value != "" {
		setPanelEndpointListen(&s, "management", value)
	}
	if !regularFile(s.Database) {
		s.DatabaseError = "x-ui database missing"
		return s
	}
	schema, err := detectPanelSchema(cmd, s.Database, s.Product)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.SchemaVersion = schema
	s.DatabaseAvailable = true
	settingRows, err := sqliteTSV(cmd, s.Database, `SELECT key, value FROM settings WHERE key IN ('webListen','webPort','webCertFile','webCertKey','subEnable','subListen','subPort','subCertFile','subKeyFile');`)
	if err == nil {
		applyPanelSettings(&s, settingRows, "x-ui database")
	}
	nowMillis := time.Now().UnixMilli()
	query := fmt.Sprintf(`SELECT enable, COALESCE(listen,''), port, protocol, CASE WHEN protocol='shadowsocks' THEN COALESCE(json_extract(settings,'$.network'),'') ELSE COALESCE(json_extract(stream_settings,'$.network'),'') END, COALESCE(json_extract(stream_settings,'$.security'),''), COALESCE(json_array_length(json_extract(settings,'$.clients')),0), CASE WHEN expiry_time>0 AND expiry_time<%d THEN 1 ELSE 0 END, CASE WHEN total>0 AND up+down>=total THEN 1 ELSE 0 END, CASE WHEN length(COALESCE(json_extract(stream_settings,'$.realitySettings.privateKey'),''))>0 THEN 1 ELSE 0 END, CASE WHEN length(COALESCE(json_extract(stream_settings,'$.realitySettings.target'),json_extract(stream_settings,'$.realitySettings.dest'),''))>0 THEN 1 ELSE 0 END, COALESCE(json_array_length(json_extract(stream_settings,'$.realitySettings.serverNames')),0)+COALESCE(json_array_length(json_extract(stream_settings,'$.realitySettings.shortIds')),0) FROM inbounds;`, nowMillis)
	inboundRows, err := sqliteTSV(cmd, s.Database, query)
	if err != nil {
		s.DatabaseError = err.Error()
		return s
	}
	s.Inbounds = parsePanelInboundRows(inboundRows)
	certRows, err := sqliteTSV(cmd, s.Database, `SELECT DISTINCT COALESCE(json_extract(stream_settings,'$.tlsSettings.certificates[0].certificateFile'),'') FROM inbounds WHERE length(COALESCE(json_extract(stream_settings,'$.tlsSettings.certificates[0].certificateFile'),''))>0;`)
	if err == nil {
		s.CertificateFiles = firstColumn(certRows)
	}
	clientRows, err := sqliteTSV(cmd, s.Database, `SELECT COALESCE(sum(CASE WHEN enable=1 THEN 1 ELSE 0 END),0), COALESCE(sum(CASE WHEN enable=1 THEN 0 ELSE 1 END),0) FROM clients;`)
	if err == nil && len(clientRows) == 1 && len(clientRows[0]) == 2 {
		s.EnabledClients, _ = strconv.Atoi(clientRows[0][0])
		s.DisabledClients, _ = strconv.Atoi(clientRows[0][1])
	}
	return s
}

func sqliteTSV(cmd Commander, database, query string) ([][]string, error) {
	rows, embeddedErr := querySQLite(database, query)
	if embeddedErr == nil {
		return rows, nil
	}
	// Keep the system command as a compatibility fallback for unusual SQLite
	// files or platforms, while normal Linux builds remain dependency-free.
	if !cmd.Exists("sqlite3") {
		return nil, fmt.Errorf("embedded SQLite reader: %v; sqlite3 fallback unavailable", embeddedErr)
	}
	r := cmd.Run(10*time.Second, "sqlite3", "-readonly", "-separator", "\t", database, query)
	if r.Err != nil {
		return nil, fmt.Errorf("sqlite metadata query: %s", commandError(r))
	}
	var fallbackRows [][]string
	for _, line := range lines(r.Stdout) {
		fallbackRows = append(fallbackRows, strings.Split(line, "\t"))
	}
	return fallbackRows, nil
}

func parsePanelInboundRows(rows [][]string) []panelInboundFact {
	var out []panelInboundFact
	for _, row := range rows {
		if len(row) != 12 {
			continue
		}
		clientCount, _ := strconv.Atoi(row[6])
		out = append(out, panelInboundFact{
			Enabled: row[0] == "1", Listen: normalizeListen(row[1]), Port: row[2],
			Protocol: row[3], Network: row[4], Security: row[5], ClientCount: clientCount,
			Expired: row[7] == "1", QuotaExhausted: row[8] == "1",
			RealityKeySet: row[9] == "1", RealityTargets: atoi(row[10]), RealityIDs: atoi(row[11]),
		})
	}
	return out
}

func atoi(value string) int {
	n, _ := strconv.Atoi(value)
	return n
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
		port := values[role.prefix+"Port"]
		if port == "" {
			continue
		}
		listen := normalizeListen(values[role.prefix+"Listen"])
		tlsKnown := true
		certFile := values[role.prefix+"CertFile"]
		tls := certFile != "" && (values[role.prefix+"KeyFile"] != "" || values[role.prefix+"CertKey"] != "")
		updated := panelEndpoint{Role: role.name, Listen: listen, Port: port, TLS: tls, TLSKnown: tlsKnown, Source: source, CertFile: certFile}
		for _, old := range snapshot.Endpoints {
			if old.Role == role.name {
				updated.PathKnown, updated.PathIsDefault = old.PathKnown, old.PathIsDefault
			}
		}
		upsertPanelEndpoint(snapshot, updated)
	}
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

func parseNamedText(output, name string) string {
	match := regexp.MustCompile(`(?mi)^\s*` + regexp.QuoteMeta(name) + `\s*:\s*(\S+)\s*$`).FindStringSubmatch(output)
	if len(match) == 2 {
		return strings.TrimSpace(match[1])
	}
	return ""
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
