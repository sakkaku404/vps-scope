package redact

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type Redactor struct {
	values  map[string]string
	counts  map[string]int
	literal map[string]string
}

var (
	ipv4RE                 = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6RE                 = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
	domainRE               = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	emailRE                = regexp.MustCompile("(?i)\\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\\.[a-z]{2,63}\\b")
	fingerprintRE          = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)
	uuidRE                 = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	homeUserRE             = regexp.MustCompile(`/home/([a-z_][a-z0-9_-]*)`)
	userFieldRE            = regexp.MustCompile(`(?i)\b(user(?:name)?=)([a-z_][a-z0-9_-]*)`)
	credentialAssignmentRE = regexp.MustCompile(`(?i)(\b(?:password|passwd|token|access[_-]?token|secret|api[_-]?key|apikey|private[_-]?key|authorization)\b["']?\s*[:=]\s*)(?:"([^"\r\n]*)"|'([^'\r\n]*)'|([^\s,;}\]"'\\]+))`)
	escapedCredentialRE    = regexp.MustCompile(`(?i)(\b(?:password|passwd|token|access[_-]?token|secret|api[_-]?key|apikey|private[_-]?key|authorization)\b(?:\\)+["']\s*[:=]\s*(?:\\)+["'])([^\r\n]*?)((?:\\)+["'])`)
	authorizationSchemeRE  = regexp.MustCompile(`(?i)(\bauthorization\b["']?\s*[:=]\s*)(Bearer|Basic)\s+([^\s,;"']+)`)
	bearerRE               = regexp.MustCompile(`(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]+)`)
	urlUserinfoRE          = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([^/@\s]+)(@)`)
	sensitiveQueryRE       = regexp.MustCompile(`(?i)([?&](?:password|passwd|token|access[_-]?token|secret|api[_-]?key|apikey|private[_-]?key|authorization|auth|signature|sig)=)([^&#\s"'\\,}\]]+)`)
	subscriptionPathRE     = regexp.MustCompile(`(?i)(/(?:sub|subscribe|subscription)/)([^/?#\s"'\\,}\]]+)`)
	privateKeyBlockRE      = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	privateKeyHeaderRE     = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----`)
	redactionPlaceholderRE = regexp.MustCompile(`(?i)^(?:CREDENTIAL|TOKEN|SECRET|PRIVATE_KEY|SUBSCRIPTION|REDACTED)(?:_\d+)?$`)
	stableHostPseudonymRE  = regexp.MustCompile(`^HOST_ID_[0-9a-f]{32}$`)
	legacyStableHostRE     = regexp.MustCompile(`^HOST_ID_[0-9]+$`)
)

func New() *Redactor {
	return &Redactor{values: map[string]string{}, counts: map[string]int{}, literal: map[string]string{}}
}

func (r *Redactor) Report(in model.Report) model.Report {
	out := in
	alreadyRedacted := in.Metadata["redacted"] == "true"
	out.Host.Hostname = r.sensitiveToken("HOST", in.Host.Hostname)
	if alreadyRedacted && (stableHostPseudonymRE.MatchString(in.Host.StableID) || legacyStableHostRE.MatchString(in.Host.StableID)) {
		out.Host.StableID = in.Host.StableID
	} else {
		out.Host.StableID = r.stableHostToken(in.Host.StableID)
	}
	out.Profile.Reasons = make([]string, len(in.Profile.Reasons))
	for i, reason := range in.Profile.Reasons {
		out.Profile.Reasons[i] = r.text(reason)
	}
	out.Endpoints = make([]model.Endpoint, len(in.Endpoints))
	for i, endpoint := range in.Endpoints {
		out.Endpoints[i] = endpoint
		out.Endpoints[i].Process = r.text(endpoint.Process)
	}
	out.Deployment = r.deployment(in.Deployment, in.Host.StableID, !alreadyRedacted)
	out.Findings = make([]model.Finding, len(in.Findings))
	for i, finding := range in.Findings {
		out.Findings[i] = finding
		out.Findings[i].Error = r.text(finding.Error)
		if finding.Facts != nil {
			out.Findings[i].Facts = make(map[string]string, len(finding.Facts))
			for key, value := range finding.Facts {
				out.Findings[i].Facts[r.text(key)] = r.fieldValue(key, value)
			}
		}
		out.Findings[i].Evidence = make([]model.Evidence, len(finding.Evidence))
		for j, evidence := range finding.Evidence {
			out.Findings[i].Evidence[j] = evidence
			out.Findings[i].Evidence[j].Source = r.text(evidence.Source)
			out.Findings[i].Evidence[j].Key = r.text(evidence.Key)
			out.Findings[i].Evidence[j].Value = r.fieldValue(evidence.Key, evidence.Value)
			if finding.ID == "ACC-002" {
				parts := strings.SplitN(out.Findings[i].Evidence[j].Value, " ", 2)
				if len(parts) > 0 && regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(parts[0]) {
					parts[0] = r.token("USER", parts[0])
					out.Findings[i].Evidence[j].Value = strings.Join(parts, " ")
				}
			}
			if accountEvidenceKey(finding.ID, evidence.Key) {
				out.Findings[i].Evidence[j].Value = r.token("USER", strings.TrimSpace(evidence.Value))
			}
		}
	}
	if out.Metadata == nil {
		out.Metadata = map[string]string{}
	} else {
		out.Metadata = make(map[string]string, len(in.Metadata)+1)
		for key, value := range in.Metadata {
			out.Metadata[r.text(key)] = r.fieldValue(key, value)
		}
	}
	out.Metadata["redacted"] = "true"
	return out
}

// stableHostToken preserves equality across independently redacted reports
// without exposing the host's original stable identifier. Diff and baseline
// safety depend on two different hosts never collapsing to HOST_ID_1 merely
// because each report was redacted in a fresh process.
func (r *Redactor) stableHostToken(value string) string {
	if value == "" {
		return ""
	}
	key := "HOST_ID\x00" + value
	if token, ok := r.values[key]; ok {
		return token
	}
	sum := sha256.Sum256([]byte("vps-scope/redacted-host-id/v1\x00" + value))
	token := "HOST_ID_" + hex.EncodeToString(sum[:16])
	r.values[key] = token
	if len(value) >= 3 {
		r.literal[value] = token
	}
	return token
}

func (r *Redactor) deployment(in *model.Deployment, stableID string, remapIDs bool) *model.Deployment {
	if in == nil {
		return nil
	}
	out := &model.Deployment{Coverage: in.Coverage}
	nodeIDs := make(map[string]string, len(in.Components)+len(in.Endpoints))
	out.Components = make([]model.Component, len(in.Components))
	for i, component := range in.Components {
		out.Components[i] = component
		if remapIDs {
			out.Components[i].ID = redactedTopologyID("component", component.ID, stableID)
		}
		nodeIDs[component.ID] = out.Components[i].ID
		out.Components[i].Product = r.text(component.Product)
		out.Components[i].Source = r.text(component.Source)
		out.Components[i].Deployment = r.text(component.Deployment)
	}
	out.Endpoints = make([]model.ServiceEndpoint, len(in.Endpoints))
	for i, endpoint := range in.Endpoints {
		out.Endpoints[i] = endpoint
		if remapIDs {
			out.Endpoints[i].ID = redactedTopologyID("endpoint", endpoint.ID, stableID)
			out.Endpoints[i].ComponentID = nodeIDs[endpoint.ComponentID]
		}
		nodeIDs[endpoint.ID] = out.Endpoints[i].ID
		out.Endpoints[i].Product = r.text(endpoint.Product)
		out.Endpoints[i].Protocol = r.text(endpoint.Protocol)
		out.Endpoints[i].Address = r.text(endpoint.Address)
		out.Endpoints[i].Process = r.text(endpoint.Process)
		out.Endpoints[i].Security = r.text(endpoint.Security)
		out.Endpoints[i].Firewall = r.text(endpoint.Firewall)
		out.Endpoints[i].Judgment = r.text(endpoint.Judgment)
		out.Endpoints[i].Source = r.text(endpoint.Source)
		if endpoint.ConnectionCount != nil {
			count := *endpoint.ConnectionCount
			out.Endpoints[i].ConnectionCount = &count
		}
	}
	out.Links = make([]model.TopologyLink, len(in.Links))
	for i, link := range in.Links {
		out.Links[i] = link
		if remapIDs {
			out.Links[i].From = nodeIDs[link.From]
			out.Links[i].To = nodeIDs[link.To]
		}
	}
	return out
}

// redactedTopologyID uses the unshared host identity as a key, so relationship
// IDs remain stable for one host without exposing a plain hash that can be
// brute-forced over the IPv4 address space and known endpoint fields.
func redactedTopologyID(kind, original, stableID string) string {
	mac := hmac.New(sha256.New, []byte("vps-scope/redacted-topology/v1\x00"+stableID))
	_, _ = mac.Write([]byte(kind + "\x00" + original))
	return kind + ":" + hex.EncodeToString(mac.Sum(nil)[:8])
}

func accountEvidenceKey(id, key string) bool {
	if id == "ACC-001" && key == "uid0_user" {
		return true
	}
	return id == "ACC-003" && key == "password_bearing_login_account"
}

func (r *Redactor) text(value string) string {
	value = r.replaceKnownLiterals(value)
	value = privateKeyBlockRE.ReplaceAllStringFunc(value, func(candidate string) string {
		return r.token("PRIVATE_KEY", candidate)
	})
	value = authorizationSchemeRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := authorizationSchemeRE.FindStringSubmatch(candidate)
		if len(match) != 4 || safeCredentialValue(match[3]) {
			return candidate
		}
		return match[1] + match[2] + " " + r.credentialToken(match[3])
	})
	value = bearerRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := bearerRE.FindStringSubmatch(candidate)
		if len(match) != 3 || safeCredentialValue(match[2]) {
			return candidate
		}
		return match[1] + r.credentialToken(match[2])
	})
	value = urlUserinfoRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := urlUserinfoRE.FindStringSubmatch(candidate)
		if len(match) != 4 || redactionPlaceholderRE.MatchString(match[2]) {
			return candidate
		}
		return match[1] + r.credentialToken(match[2]) + match[3]
	})
	value = sensitiveQueryRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := sensitiveQueryRE.FindStringSubmatch(candidate)
		if len(match) != 3 || safeCredentialValue(match[2]) {
			return candidate
		}
		return match[1] + r.credentialToken(match[2])
	})
	value = escapedCredentialRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := escapedCredentialRE.FindStringSubmatch(candidate)
		if len(match) != 4 || safeCredentialValue(match[2]) {
			return candidate
		}
		return match[1] + r.credentialToken(match[2]) + match[3]
	})
	value = credentialAssignmentRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := credentialAssignmentRE.FindStringSubmatch(candidate)
		if len(match) != 5 {
			return candidate
		}
		raw, quote := assignmentValue(match)
		if safeCredentialValue(raw) {
			return candidate
		}
		return match[1] + quote + r.credentialToken(raw) + quote
	})
	value = subscriptionPathRE.ReplaceAllStringFunc(value, func(candidate string) string {
		match := subscriptionPathRE.FindStringSubmatch(candidate)
		if len(match) != 3 || !looksHighEntropyPathSegment(match[2]) {
			return candidate
		}
		token := r.token("SUBSCRIPTION", match[2])
		r.literal[match[2]] = token
		return match[1] + token
	})

	value = r.replaceKnownLiterals(value)
	value = ipv4RE.ReplaceAllStringFunc(value, func(candidate string) string {
		ip := net.ParseIP(candidate)
		if ip == nil || preserveNetworkSemanticAddress(ip) {
			return candidate
		}
		return r.token("IP", candidate)
	})
	value = ipv6RE.ReplaceAllStringFunc(value, func(candidate string) string {
		ip := net.ParseIP(candidate)
		if ip == nil || preserveNetworkSemanticAddress(ip) {
			return candidate
		}
		return r.token("IP", candidate)
	})
	value = emailRE.ReplaceAllStringFunc(value, func(candidate string) string {
		return r.token("EMAIL", strings.ToLower(candidate))
	})
	value = domainRE.ReplaceAllStringFunc(value, func(candidate string) string {
		lower := strings.ToLower(candidate)
		if containsSafeDomain(lower) {
			return candidate
		}
		return r.token("DOMAIN", lower)
	})
	value = fingerprintRE.ReplaceAllStringFunc(value, func(candidate string) string { return r.token("SSH_KEY", candidate) })
	value = uuidRE.ReplaceAllStringFunc(value, func(candidate string) string { return r.token("UUID", strings.ToLower(candidate)) })
	value = homeUserRE.ReplaceAllStringFunc(value, func(candidate string) string {
		user := strings.TrimPrefix(candidate, "/home/")
		return "/home/" + r.token("USER", user)
	})
	value = userFieldRE.ReplaceAllStringFunc(value, func(candidate string) string {
		parts := strings.SplitN(candidate, "=", 2)
		return parts[0] + "=" + r.token("USER", parts[1])
	})
	return value
}

// Loopback and unspecified addresses describe exposure semantics rather than
// host identity. Preserving them keeps a support report useful: 127.0.0.1 is
// local-only while 0.0.0.0 and :: are wildcard listeners. None identifies the
// audited VPS on the public Internet.
func preserveNetworkSemanticAddress(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified()
}

func (r *Redactor) replaceKnownLiterals(value string) string {
	literals := make([]string, 0, len(r.literal))
	for sensitive := range r.literal {
		literals = append(literals, sensitive)
	}
	sort.Slice(literals, func(i, j int) bool { return len(literals[i]) > len(literals[j]) })
	for _, sensitive := range literals {
		value = strings.ReplaceAll(value, sensitive, r.literal[sensitive])
	}
	return value
}

func (r *Redactor) fieldValue(key, value string) string {
	if sensitiveFieldName(key) && !safeCredentialValue(value) {
		return r.credentialToken(strings.TrimSpace(value))
	}
	return r.text(value)
}

func (r *Redactor) credentialToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || safeCredentialValue(value) {
		return value
	}
	token := r.token("CREDENTIAL", value)
	if shouldRememberCredential(value) {
		r.literal[value] = token
	}
	return token
}

func sensitiveFieldName(value string) bool {
	value = strings.ToLower(strings.Trim(strings.TrimSpace(value), `"'`))
	value = strings.ReplaceAll(value, "-", "_")
	switch value {
	case "password", "passwd", "token", "access_token", "secret", "api_key", "apikey", "private_key", "authorization":
		return true
	default:
		return false
	}
}

func assignmentValue(match []string) (value, quote string) {
	switch {
	case match[2] != "":
		return match[2], `"`
	case match[3] != "":
		return match[3], `'`
	default:
		return match[4], ""
	}
}

func safeCredentialValue(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	if value == "" || redactionPlaceholderRE.MatchString(value) {
		return true
	}
	switch strings.ToLower(value) {
	case "absent", "basic", "bearer", "configured", "disabled", "enabled", "false", "missing", "none", "not-configured", "not_configured", "not-set", "null", "present", "redacted", "required", "true", "unknown", "yes", "no", "authentication", "scheme", "header", "token":
		return true
	default:
		return false
	}
}

func shouldRememberCredential(value string) bool {
	if len(value) < 8 || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	return looksHighEntropyPathSegment(value)
}

func looksHighEntropyPathSegment(value string) bool {
	if len(value) < 16 || redactionPlaceholderRE.MatchString(value) {
		return false
	}
	unique := map[rune]bool{}
	var lower, upper, digit int
	encodingSymbol := false
	for _, char := range value {
		unique[char] = true
		switch {
		case char >= 'a' && char <= 'z':
			lower++
		case char >= 'A' && char <= 'Z':
			upper++
		case char >= '0' && char <= '9':
			digit++
		default:
			if strings.ContainsRune("_+=/%", char) {
				encodingSymbol = true
			}
		}
	}
	if len(unique) < 8 {
		return false
	}
	return digit > 0 && lower+upper > 0 || lower > 0 && upper > 0 || encodingSymbol && (digit > 0 || lower > 0 && upper > 0)
}

// ValidateNoResidualCredentials performs a conservative final inspection of
// an already-redacted JSON document. It reports only the pattern class, never
// the matched value, so an error cannot leak the suspected credential.
func ValidateNoResidualCredentials(value string) error {
	if privateKeyHeaderRE.MatchString(value) {
		return fmt.Errorf("possible private-key material remains")
	}
	for _, match := range authorizationSchemeRE.FindAllStringSubmatch(value, -1) {
		if len(match) == 4 && !safeCredentialValue(match[3]) {
			return fmt.Errorf("possible Authorization credential remains")
		}
	}
	for _, match := range bearerRE.FindAllStringSubmatch(value, -1) {
		if len(match) == 3 && !safeCredentialValue(match[2]) {
			return fmt.Errorf("possible Bearer credential remains")
		}
	}
	for _, match := range urlUserinfoRE.FindAllStringSubmatch(value, -1) {
		if len(match) == 4 && !redactionPlaceholderRE.MatchString(match[2]) {
			return fmt.Errorf("possible URL userinfo remains")
		}
	}
	for _, match := range sensitiveQueryRE.FindAllStringSubmatch(value, -1) {
		if len(match) == 3 && !safeCredentialValue(match[2]) {
			return fmt.Errorf("possible sensitive query parameter remains")
		}
	}
	for _, match := range escapedCredentialRE.FindAllStringSubmatch(value, -1) {
		if len(match) == 4 && !safeCredentialValue(match[2]) {
			return fmt.Errorf("possible escaped credential assignment remains")
		}
	}
	for _, match := range credentialAssignmentRE.FindAllStringSubmatch(value, -1) {
		if len(match) != 5 {
			continue
		}
		raw, _ := assignmentValue(match)
		if !safeCredentialValue(raw) {
			return fmt.Errorf("possible credential assignment remains")
		}
	}
	for _, match := range subscriptionPathRE.FindAllStringSubmatch(value, -1) {
		if len(match) == 3 && looksHighEntropyPathSegment(match[2]) {
			return fmt.Errorf("possible subscription credential path remains")
		}
	}
	return nil
}

func (r *Redactor) sensitiveToken(kind, value string) string {
	token := r.token(kind, value)
	// Very short hostnames are too ambiguous to replace safely in free text:
	// replacing a host named "1" would corrupt every count, timestamp and IP.
	// The structured host field is still always tokenized.
	if len(value) >= 3 {
		r.literal[value] = token
	}
	return token
}

func containsSafeDomain(value string) bool {
	for _, suffix := range []string{"ubuntu.com", "debian.org", "docker.com", "github.com", "go.dev"} {
		if value == suffix || strings.HasSuffix(value, "."+suffix) {
			return true
		}
	}
	return false
}

func (r *Redactor) token(kind, value string) string {
	if value == "" {
		return ""
	}
	key := kind + "\x00" + value
	if token, ok := r.values[key]; ok {
		return token
	}
	r.counts[kind]++
	token := fmt.Sprintf("%s_%d", kind, r.counts[kind])
	r.values[key] = token
	return token
}
