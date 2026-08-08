package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
	"github.com/sakkaku404/vps-scope/internal/safejson"
)

func classifyDialError(err error) string {
	if errors.Is(err, io.EOF) {
		return "connection closed during observation"
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}
	text := strings.ToLower(err.Error())
	for _, label := range []string{"connection refused", "network is unreachable", "no route to host"} {
		if strings.Contains(text, label) {
			return label
		}
	}
	return "connection failed"
}

func validateProbePlan(plan probePlan) error {
	nonce, nonceErr := hex.DecodeString(plan.Nonce)
	if plan.SchemaVersion != probeSchemaVersion || plan.ReportStableID == "" || len(plan.ReportStableID) > 256 || len(nonce) != 16 || nonceErr != nil || plan.CreatedAt.IsZero() || !validProbeTarget(plan.Target) {
		return errors.New("probe plan is incomplete or uses an unsupported schema")
	}
	if len(plan.Endpoints) == 0 || len(plan.Endpoints) > 128 {
		return errors.New("probe plan must contain between 1 and 128 endpoints")
	}
	if len(plan.ResolvedIPs) > 16 {
		return errors.New("probe plan contains too many resolved target addresses")
	}
	for _, value := range plan.ResolvedIPs {
		if net.ParseIP(value) == nil {
			return errors.New("probe plan contains an invalid resolved target address")
		}
	}
	for _, endpoint := range plan.Endpoints {
		if (endpoint.Protocol != "tcp" && endpoint.Protocol != "udp") || endpoint.Port < 1 || endpoint.Port > 65535 || (endpoint.Family != "ipv4" && endpoint.Family != "ipv6") || (endpoint.Scope != "public" && endpoint.Scope != "public-wildcard") || len(endpoint.Process) > 256 || !validProbeRole(endpoint.Role) || !validProbeExposure(endpoint.ExpectedExposure) {
			return errors.New("probe plan contains an invalid endpoint")
		}
	}
	return nil
}

func validateProbeObservation(observation probeObservation, report model.Report) error {
	if observation.SchemaVersion != probeSchemaVersion || len(observation.PlanSHA256) != sha256.Size*2 || observation.ObservedAt.IsZero() || len(observation.Observer) > 128 || strings.ContainsAny(observation.Observer, "\r\n\x00") {
		return errors.New("probe observation is incomplete or uses an unsupported schema")
	}
	if err := validateProbePlan(observation.Plan); err != nil {
		return err
	}
	planDigest, err := canonicalProbePlanSHA256(observation.Plan)
	if err != nil {
		return err
	}
	if !strings.EqualFold(observation.PlanSHA256, planDigest) {
		return errors.New("probe observation plan hash does not match its embedded plan")
	}
	if observation.Plan.ReportStableID != report.Host.StableID {
		return errors.New("probe observation belongs to a different report host")
	}
	if len(observation.Results) != len(observation.Plan.Endpoints) {
		return errors.New("probe observation result count does not match its plan")
	}
	for index, result := range observation.Results {
		endpoint := observation.Plan.Endpoints[index]
		if result.Protocol != endpoint.Protocol || result.Port != endpoint.Port || result.Family != endpoint.Family || result.Role != endpoint.Role || result.ExpectedExposure != endpoint.ExpectedExposure {
			return errors.New("probe observation endpoint order does not match its plan")
		}
		if result.State != "reachable" && result.State != "not-reachable" && result.State != "indeterminate" {
			return errors.New("probe observation contains an invalid result state")
		}
		if len(result.Detail) > 256 || result.LatencyMillis < 0 || result.LatencyMillis > 600_000 {
			return errors.New("probe observation contains invalid result metadata")
		}
	}
	return nil
}

func canonicalProbePlanSHA256(plan probePlan) (string, error) {
	canonicalPlan, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode embedded probe plan: %w", err)
	}
	canonicalPlan = append(canonicalPlan, '\n')
	digest := sha256.Sum256(canonicalPlan)
	return hex.EncodeToString(digest[:]), nil
}

func validProbeRole(role string) bool {
	switch role {
	case "", "proxy-ingress", "management", "subscription", "control-api", "web", "ssh", "other":
		return true
	default:
		return false
	}
}

func validProbeExposure(exposure string) bool {
	switch exposure {
	case "", "public", "restricted", "private", "loopback", "blocked":
		return true
	default:
		return false
	}
}

func applyProbeObservation(report *model.Report, observation probeObservation) {
	finding := model.Finding{ID: "NET-004", Category: "network", Status: model.Info, ReasonCode: "net.004.external-observation-inventory", Facts: map[string]string{}}
	reachable, unreachable, indeterminate, expectedIndeterminate, risks := 0, 0, 0, 0, 0
	for _, result := range observation.Results {
		switch result.State {
		case "reachable":
			reachable++
			if result.Role == "management" || result.Role == "control-api" || result.ExpectedExposure == "blocked" || result.ExpectedExposure == "private" || result.ExpectedExposure == "loopback" {
				risks++
			}
		case "not-reachable":
			unreachable++
			if result.ExpectedExposure == "public" {
				risks++
			}
		case "indeterminate":
			indeterminate++
			if result.ExpectedExposure != "" || result.Role != "" {
				expectedIndeterminate++
			}
		}
		finding.Evidence = append(finding.Evidence, model.Evidence{Source: "operator-supplied external observation", Key: result.State, Value: fmt.Sprintf("%s/%d family=%s role=%s expected=%s detail=%s", result.Protocol, result.Port, result.Family, result.Role, result.ExpectedExposure, result.Detail)})
	}
	finding.Facts["reachable"] = fmt.Sprint(reachable)
	finding.Facts["not_reachable"] = fmt.Sprint(unreachable)
	finding.Facts["indeterminate"] = fmt.Sprint(indeterminate)
	finding.Facts["expected_indeterminate"] = fmt.Sprint(expectedIndeterminate)
	finding.Facts["observer"] = observation.Observer
	finding.Facts["observed_at"] = observation.ObservedAt.UTC().Format(time.RFC3339)
	finding.Facts["plan_sha256"] = observation.PlanSHA256
	if risks > 0 {
		finding.Status, finding.Severity, finding.ReasonCode = model.Risk, model.High, "net.004.external-observation-mismatch"
	} else if expectedIndeterminate > 0 {
		finding.Status, finding.ReasonCode = model.Unknown, "net.004.external-observation-incomplete"
	} else if hasExplicitProbeExpectation(observation.Results) {
		finding.Status, finding.ReasonCode = model.Pass, "net.004.external-observation-matched"
	}
	replaced := false
	for index := range report.Findings {
		if report.Findings[index].ID == "NET-004" {
			report.Findings[index] = finding
			replaced = true
			break
		}
	}
	if !replaced {
		report.Findings = append(report.Findings, finding)
	}
	if report.Metadata == nil {
		report.Metadata = map[string]string{}
	}
	report.Metadata["external_observation"] = observation.ObservedAt.UTC().Format(time.RFC3339)
	report.Recount()
}

func probeableEndpoint(endpoint model.Endpoint) bool {
	if endpoint.Scope != "public" && endpoint.Scope != "public-wildcard" {
		return false
	}
	process := strings.ToLower(endpoint.Process)
	if endpoint.Protocol == "udp" && (endpoint.Port == 68 || endpoint.Port == 546) && strings.Contains(process, "dhcp") {
		return false
	}
	return true
}

func hasExplicitProbeExpectation(results []probeResult) bool {
	for _, result := range results {
		if result.ExpectedExposure != "" || result.Role != "" {
			return true
		}
	}
	return false
}

func parseProbeRoleEndpoints(value string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		parts := strings.Split(item, "/")
		if len(parts) != 2 || (parts[1] != "tcp" && parts[1] != "udp") {
			return nil, fmt.Errorf("invalid management endpoint %q", item)
		}
		port := 0
		if _, err := fmt.Sscan(parts[0], &port); err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid management endpoint %q", item)
		}
		out[fmt.Sprintf("%d/%s", port, parts[1])] = "management"
	}
	return out, nil
}

func validProbeTarget(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, "/:[] ") {
		return net.ParseIP(value) != nil
	}
	return net.ParseIP(value) != nil || probeHostnamePattern.MatchString(value)
}

func resolveProbeTarget(target string, allowPrivate bool) ([]string, error) {
	target = strings.TrimSpace(target)
	var addresses []net.IP
	if parsed := net.ParseIP(target); parsed != nil {
		addresses = []net.IP{parsed}
	} else {
		resolved, err := net.LookupIP(target)
		if err != nil {
			return nil, fmt.Errorf("resolve probe target: %w", err)
		}
		addresses = resolved
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if !allowPrivate && !safePublicProbeIP(address) {
			continue
		}
		canonical := address.String()
		if !seen[canonical] {
			seen[canonical] = true
			out = append(out, canonical)
		}
	}
	if len(out) == 0 {
		if allowPrivate {
			return nil, errors.New("probe target did not resolve to an IP address")
		}
		return nil, errors.New("probe target resolves only to loopback, private, link-local, multicast, or otherwise non-public addresses; use --allow-private-target only for a target you control")
	}
	if len(out) > 16 {
		out = out[:16]
	}
	sort.Strings(out)
	return out, nil
}

func validateResolvedProbeIPs(values []string, allowPrivate bool) error {
	if len(values) == 0 || len(values) > 16 {
		return errors.New("probe plan must contain between 1 and 16 resolved target addresses")
	}
	for _, value := range values {
		address := net.ParseIP(value)
		if address == nil {
			return errors.New("probe plan contains an invalid resolved target address")
		}
		if !allowPrivate && !safePublicProbeIP(address) {
			return errors.New("probe plan contains a non-public target address; use --allow-private-target only for a target you control")
		}
	}
	return nil
}

func safePublicProbeIP(address net.IP) bool {
	return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsUnspecified() && !address.IsMulticast()
}

func probeIPForFamily(values []string, family string) string {
	for _, value := range values {
		address := net.ParseIP(value)
		if address == nil {
			continue
		}
		if family == "ipv4" && address.To4() != nil {
			return address.String()
		}
		if family == "ipv6" && address.To4() == nil {
			return address.String()
		}
	}
	return ""
}

func readLimitedJSONBytes(path string) ([]byte, error) {
	file, err := openLimitedJSON(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxLocalJSONSize+1))
}

func decodeStrictJSON(data []byte, destination any) error {
	if err := safejson.RejectDuplicateMembers(bytes.NewReader(data)); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func writeJSONNew(path string, value any) error {
	return atomicWriteNew(path, maxLocalJSONSize, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		return encoder.Encode(value)
	})
}
