package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/sakkaku404/vps-scope/internal/safejson"
)

const PolicySchemaVersion = "1.0"

// Policy describes operator intent without containing credentials or changing
// the audited host. It is deliberately narrower than a proxy configuration:
// only endpoint exposure and egress expectations belong here.
type Policy struct {
	SchemaVersion string           `json:"schema_version"`
	Endpoints     []EndpointPolicy `json:"endpoints,omitempty"`
	Egress        EgressPolicy     `json:"egress,omitempty"`
}

type EndpointPolicy struct {
	Port                  int      `json:"port"`
	Protocol              string   `json:"protocol"`
	Role                  string   `json:"role"`
	Workload              string   `json:"workload,omitempty"`
	Transport             string   `json:"transport,omitempty"`
	Exposure              string   `json:"exposure"`
	Families              []string `json:"families,omitempty"`
	AllowedSources        []string `json:"allowed_sources,omitempty"`
	RequireTLS            *bool    `json:"require_tls,omitempty"`
	RequireNonDefaultPath *bool    `json:"require_non_default_path,omitempty"`
}

type EgressPolicy struct {
	IPv4Interfaces  []string `json:"ipv4_interfaces,omitempty"`
	IPv6Interfaces  []string `json:"ipv6_interfaces,omitempty"`
	RequireSamePath bool     `json:"require_same_path,omitempty"`
	DNSMode         string   `json:"dns_mode,omitempty"`
}

func LoadPolicy(path string) (*Policy, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > 1<<20 {
		return nil, fmt.Errorf("read policy: input must be a regular non-symlink file no larger than 1 MiB")
	}
	// #nosec G304 -- path is the explicit CLI input and is constrained by a
	// regular-file, non-symlink, size and SameFile pre/post-open check.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
		return nil, fmt.Errorf("read policy: input changed while being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, fmt.Errorf("read policy: input exceeds the 1 MiB limit")
	}
	if err := safejson.RejectDuplicateMembers(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &policy, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return fmt.Errorf("multiple JSON values are not allowed")
	}
	return err
}

func (p *Policy) Validate() error {
	if p == nil {
		return nil
	}
	if p.SchemaVersion != PolicySchemaVersion {
		return fmt.Errorf("unsupported policy schema_version %q; expected %s", p.SchemaVersion, PolicySchemaVersion)
	}
	if len(p.Endpoints) > 256 {
		return fmt.Errorf("policy has %d endpoints; limit is 256", len(p.Endpoints))
	}
	seen := map[string]bool{}
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		e.Protocol = strings.ToLower(strings.TrimSpace(e.Protocol))
		e.Role = strings.ToLower(strings.TrimSpace(e.Role))
		e.Workload = strings.TrimSpace(e.Workload)
		e.Transport = strings.ToLower(strings.TrimSpace(e.Transport))
		e.Exposure = strings.ToLower(strings.TrimSpace(e.Exposure))
		if e.Port < 1 || e.Port > 65535 {
			return fmt.Errorf("policy endpoint %d has invalid port %d", i+1, e.Port)
		}
		if e.Protocol != "tcp" && e.Protocol != "udp" {
			return fmt.Errorf("policy endpoint %d protocol must be tcp or udp", i+1)
		}
		if len(e.Workload) > 64 || len(e.Transport) > 64 {
			return fmt.Errorf("policy endpoint %d workload or transport label exceeds 64 characters", i+1)
		}
		switch e.Role {
		case "proxy-ingress", "management", "subscription", "control-api", "web", "ssh", "other":
		default:
			return fmt.Errorf("policy endpoint %d has unsupported role %q", i+1, e.Role)
		}
		switch e.Exposure {
		case "public", "restricted", "private", "loopback", "blocked":
		default:
			return fmt.Errorf("policy endpoint %d has unsupported exposure %q", i+1, e.Exposure)
		}
		families := map[string]bool{}
		for _, family := range e.Families {
			family = strings.ToLower(strings.TrimSpace(family))
			if family != "ipv4" && family != "ipv6" {
				return fmt.Errorf("policy endpoint %d has invalid address family %q", i+1, family)
			}
			families[family] = true
		}
		e.Families = sortedKeys(families)
		if len(e.AllowedSources) > 256 {
			return fmt.Errorf("policy endpoint %d has more than 256 allowed sources", i+1)
		}
		sources := map[string]bool{}
		for _, source := range e.AllowedSources {
			source = strings.TrimSpace(source)
			if len(source) == 0 || len(source) > 64 {
				return fmt.Errorf("policy endpoint %d has invalid allowed source length", i+1)
			}
			if ip := net.ParseIP(source); ip == nil {
				if _, _, err := net.ParseCIDR(source); err != nil {
					return fmt.Errorf("policy endpoint %d has invalid allowed source %q", i+1, source)
				}
			}
			if sources[source] {
				return fmt.Errorf("policy endpoint %d has duplicate allowed source %q", i+1, source)
			}
			sources[source] = true
		}
		e.AllowedSources = sortedKeys(sources)
		if len(e.AllowedSources) > 0 && e.Exposure != "restricted" {
			return fmt.Errorf("policy endpoint %d allowed_sources requires restricted exposure", i+1)
		}
		key := fmt.Sprintf("%d/%s/%s", e.Port, e.Protocol, e.Role)
		if seen[key] {
			return fmt.Errorf("duplicate policy endpoint %s", key)
		}
		seen[key] = true
	}
	if len(p.Egress.IPv4Interfaces) > 64 || len(p.Egress.IPv6Interfaces) > 64 {
		return fmt.Errorf("policy egress interface list exceeds 64 entries")
	}
	for _, group := range []struct {
		family string
		items  []string
	}{{"ipv4", p.Egress.IPv4Interfaces}, {"ipv6", p.Egress.IPv6Interfaces}} {
		seenInterfaces := map[string]bool{}
		for _, item := range group.items {
			if !validNetworkInterfaceName(item) {
				return fmt.Errorf("policy egress interface %q is invalid", item)
			}
			if seenInterfaces[item] {
				return fmt.Errorf("policy egress %s interface %q is duplicated", group.family, item)
			}
			seenInterfaces[item] = true
		}
	}
	p.Egress.IPv4Interfaces = uniqueStrings(p.Egress.IPv4Interfaces)
	p.Egress.IPv6Interfaces = uniqueStrings(p.Egress.IPv6Interfaces)
	p.Egress.DNSMode = strings.ToLower(strings.TrimSpace(p.Egress.DNSMode))
	switch p.Egress.DNSMode {
	case "", "system", "private-only", "loopback-only":
	default:
		return fmt.Errorf("policy egress dns_mode %q is invalid", p.Egress.DNSMode)
	}
	return nil
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func (p *Policy) ExpectedPublicListeners() map[string]bool {
	out := map[string]bool{}
	if p == nil {
		return out
	}
	for _, endpoint := range p.Endpoints {
		if endpoint.Exposure == "public" || endpoint.Exposure == "restricted" {
			out[fmt.Sprintf("%d/%s", endpoint.Port, endpoint.Protocol)] = true
		}
	}
	return out
}

func (p *Policy) Endpoint(port int, protocol, family string) (EndpointPolicy, bool) {
	if p == nil {
		return EndpointPolicy{}, false
	}
	protocol = strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(protocol, "4"), "6"))
	for _, endpoint := range p.Endpoints {
		if endpoint.Port != port || endpoint.Protocol != protocol {
			continue
		}
		if len(endpoint.Families) == 0 {
			return endpoint, true
		}
		for _, expectedFamily := range endpoint.Families {
			if expectedFamily == family {
				return endpoint, true
			}
		}
	}
	return EndpointPolicy{}, false
}

func (p *Policy) Empty() bool {
	return p == nil || (len(p.Endpoints) == 0 && p.Egress.Empty())
}

func (p EgressPolicy) Empty() bool {
	return len(p.IPv4Interfaces) == 0 && len(p.IPv6Interfaces) == 0 && !p.RequireSamePath && p.DNSMode == ""
}

// WritePolicyTemplate writes a credential-free starting point. It never
// overwrites an existing file.
func WritePolicyTemplate(path string) error {
	policy := Policy{SchemaVersion: PolicySchemaVersion, Endpoints: []EndpointPolicy{
		{Port: 22, Protocol: "tcp", Role: "ssh", Exposure: "restricted", AllowedSources: []string{"192.0.2.0/24"}},
		{Port: 443, Protocol: "tcp", Role: "proxy-ingress", Workload: "sing-box", Transport: "reality", Exposure: "public", Families: []string{"ipv4", "ipv6"}},
	}}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	// #nosec G304 -- path is the explicit output selected by the operator;
	// O_EXCL prevents replacement and the file is created private.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}
