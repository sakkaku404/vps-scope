package redact

import (
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
	ipv4RE        = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6RE        = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b`)
	domainRE      = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	emailRE       = regexp.MustCompile("(?i)\\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\\.[a-z]{2,63}\\b")
	fingerprintRE = regexp.MustCompile(`SHA256:[A-Za-z0-9+/=]+`)
	uuidRE        = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	homeUserRE    = regexp.MustCompile(`/home/([a-z_][a-z0-9_-]*)`)
	userFieldRE   = regexp.MustCompile(`(?i)\b(user(?:name)?=)([a-z_][a-z0-9_-]*)`)
)

func New() *Redactor {
	return &Redactor{values: map[string]string{}, counts: map[string]int{}, literal: map[string]string{}}
}

func (r *Redactor) Report(in model.Report) model.Report {
	out := in
	out.Host.Hostname = r.sensitiveToken("HOST", in.Host.Hostname)
	out.Host.StableID = r.sensitiveToken("HOST_ID", in.Host.StableID)
	out.Profile.Reasons = make([]string, len(in.Profile.Reasons))
	for i, reason := range in.Profile.Reasons {
		out.Profile.Reasons[i] = r.text(reason)
	}
	out.Findings = make([]model.Finding, len(in.Findings))
	for i, finding := range in.Findings {
		out.Findings[i] = finding
		out.Findings[i].Error = r.text(finding.Error)
		if finding.Facts != nil {
			out.Findings[i].Facts = make(map[string]string, len(finding.Facts))
			for key, value := range finding.Facts {
				out.Findings[i].Facts[r.text(key)] = r.text(value)
			}
		}
		out.Findings[i].Evidence = make([]model.Evidence, len(finding.Evidence))
		for j, evidence := range finding.Evidence {
			out.Findings[i].Evidence[j] = evidence
			out.Findings[i].Evidence[j].Source = r.text(evidence.Source)
			out.Findings[i].Evidence[j].Key = r.text(evidence.Key)
			out.Findings[i].Evidence[j].Value = r.text(evidence.Value)
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
			out.Metadata[r.text(key)] = r.text(value)
		}
	}
	out.Metadata["redacted"] = "true"
	return out
}

func accountEvidenceKey(id, key string) bool {
	if id == "ACC-001" && key == "uid0_user" {
		return true
	}
	return id == "ACC-003" && key == "password_bearing_login_account"
}

func (r *Redactor) text(value string) string {
	literals := make([]string, 0, len(r.literal))
	for sensitive := range r.literal {
		literals = append(literals, sensitive)
	}
	sort.Slice(literals, func(i, j int) bool { return len(literals[i]) > len(literals[j]) })
	for _, sensitive := range literals {
		replacement := r.literal[sensitive]
		value = strings.ReplaceAll(value, sensitive, replacement)
	}
	value = ipv4RE.ReplaceAllStringFunc(value, func(candidate string) string {
		ip := net.ParseIP(candidate)
		if ip == nil || ip.IsLoopback() {
			return candidate
		}
		return r.token("IP", candidate)
	})
	value = ipv6RE.ReplaceAllStringFunc(value, func(candidate string) string {
		ip := net.ParseIP(candidate)
		if ip == nil || ip.IsLoopback() {
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
