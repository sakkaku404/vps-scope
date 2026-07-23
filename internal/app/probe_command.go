package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

const probeSchemaVersion = "1.0"

var probeHostnamePattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)

type probePlan struct {
	SchemaVersion  string           `json:"schema_version"`
	ReportStableID string           `json:"report_stable_id"`
	Target         string           `json:"target"`
	CreatedAt      time.Time        `json:"created_at"`
	Nonce          string           `json:"nonce"`
	Endpoints      []model.Endpoint `json:"endpoints"`
}

type probeResult struct {
	Protocol         string `json:"protocol"`
	Port             int    `json:"port"`
	Family           string `json:"family"`
	Role             string `json:"role,omitempty"`
	ExpectedExposure string `json:"expected_exposure,omitempty"`
	State            string `json:"state"`
	Detail           string `json:"detail,omitempty"`
	LatencyMillis    int64  `json:"latency_ms,omitempty"`
}

type probeObservation struct {
	SchemaVersion string        `json:"schema_version"`
	PlanSHA256    string        `json:"plan_sha256"`
	Plan          probePlan     `json:"plan"`
	ObservedAt    time.Time     `json:"observed_at"`
	Observer      string        `json:"observer,omitempty"`
	Results       []probeResult `json:"results"`
}

func (e environment) probe(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vps-scope probe plan|run|import")
	}
	switch args[0] {
	case "plan":
		return e.probePlan(args[1:])
	case "run":
		return e.probeRun(args[1:])
	case "import":
		return e.probeImport(args[1:])
	default:
		return fmt.Errorf("unknown probe operation %q", args[0])
	}
}

func (e environment) probePlan(args []string) error {
	fs := e.newFlagSet("probe plan")
	target := fs.String("target", "", "public IP address or hostname to observe")
	output := fs.String("output", "", "new probe plan JSON path")
	management := fs.String("management", "", "comma-separated management endpoints such as 2095/tcp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *output == "" || !validProbeTarget(*target) {
		return errors.New("usage: vps-scope probe plan --target HOST --output PLAN.json [--management PORT/tcp,...] REPORT.json")
	}
	report, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	roles, err := parseProbeRoleEndpoints(*management)
	if err != nil {
		return err
	}
	endpoints := make([]model.Endpoint, 0, len(report.Endpoints))
	for _, endpoint := range report.Endpoints {
		if !probeableEndpoint(endpoint) {
			continue
		}
		if role := roles[fmt.Sprintf("%d/%s", endpoint.Port, endpoint.Protocol)]; role != "" {
			endpoint.Role = role
		}
		if targetIP := net.ParseIP(*target); targetIP != nil {
			if targetIP.To4() != nil && endpoint.Family != "ipv4" {
				continue
			}
			if targetIP.To4() == nil && endpoint.Family != "ipv6" {
				continue
			}
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 {
		return errors.New("report contains no public endpoints compatible with the target; run a current audit first")
	}
	if len(endpoints) > 128 {
		return fmt.Errorf("probe plan has %d endpoints; limit is 128", len(endpoints))
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("create probe nonce: %w", err)
	}
	plan := probePlan{SchemaVersion: probeSchemaVersion, ReportStableID: report.Host.StableID, Target: *target, CreatedAt: time.Now().UTC(), Nonce: hex.EncodeToString(nonce), Endpoints: endpoints}
	if err := writeJSONNew(*output, plan); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "Probe plan: %s (%d endpoints)\n", *output, len(endpoints))
	return nil
}

func (e environment) probeRun(args []string) error {
	fs := e.newFlagSet("probe run")
	output := fs.String("output", "", "new observation JSON path")
	timeout := fs.Duration("timeout", 3*time.Second, "per-endpoint TCP timeout")
	observer := fs.String("observer", "", "optional non-secret observer label")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *output == "" {
		return errors.New("usage: vps-scope probe run --output OBSERVATION.json [--timeout 3s] PLAN.json")
	}
	if *timeout < 500*time.Millisecond || *timeout > 10*time.Second {
		return errors.New("probe timeout must be between 500ms and 10s")
	}
	planBytes, err := readLimitedJSONBytes(fs.Arg(0))
	if err != nil {
		return err
	}
	var plan probePlan
	if err := decodeStrictJSON(planBytes, &plan); err != nil {
		return fmt.Errorf("read probe plan: %w", err)
	}
	if err := validateProbePlan(plan); err != nil {
		return err
	}
	results := runProbePlan(plan, *timeout)
	digest := sha256.Sum256(planBytes)
	observation := probeObservation{SchemaVersion: probeSchemaVersion, PlanSHA256: hex.EncodeToString(digest[:]), Plan: plan, ObservedAt: time.Now().UTC(), Observer: strings.TrimSpace(*observer), Results: results}
	if err := writeJSONNew(*output, observation); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "Observation: %s (%d results)\n", *output, len(results))
	return nil
}

func (e environment) probeImport(args []string) error {
	fs := e.newFlagSet("probe import")
	output := fs.String("output", "", "new enriched report JSON path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *output == "" {
		return errors.New("usage: vps-scope probe import --output ENRICHED.json REPORT.json OBSERVATION.json")
	}
	report, err := readReport(fs.Arg(0))
	if err != nil {
		return err
	}
	observationBytes, err := readLimitedJSONBytes(fs.Arg(1))
	if err != nil {
		return err
	}
	var observation probeObservation
	if err := decodeStrictJSON(observationBytes, &observation); err != nil {
		return fmt.Errorf("read probe observation: %w", err)
	}
	if err := validateProbeObservation(observation, report); err != nil {
		return err
	}
	applyProbeObservation(&report, observation)
	if err := writeJSONNew(*output, report); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "Enriched report: %s\n", *output)
	return nil
}

func runProbePlan(plan probePlan, timeout time.Duration) []probeResult {
	results := make([]probeResult, len(plan.Endpoints))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := 8
	if len(plan.Endpoints) < workers {
		workers = len(plan.Endpoints)
	}
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				endpoint := plan.Endpoints[index]
				result := probeResult{Protocol: endpoint.Protocol, Port: endpoint.Port, Family: endpoint.Family, Role: endpoint.Role, ExpectedExposure: endpoint.ExpectedExposure}
				if endpoint.Protocol == "udp" {
					result.State = "indeterminate"
					result.Detail = "UDP was not sent arbitrary probe data; use a protocol-aware client test"
					results[index] = result
					continue
				}
				started := time.Now()
				network := "tcp4"
				if endpoint.Family == "ipv6" {
					network = "tcp6"
				}
				connection, err := (&net.Dialer{Timeout: timeout}).Dial(network, net.JoinHostPort(plan.Target, fmt.Sprint(endpoint.Port)))
				result.LatencyMillis = time.Since(started).Milliseconds()
				if err != nil {
					result.State = "not-reachable"
					result.Detail = classifyDialError(err)
				} else {
					result.State = "reachable"
					_ = connection.Close()
				}
				results[index] = result
			}
		}()
	}
	for index := range plan.Endpoints {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	return results
}

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
	canonicalPlan, err := json.MarshalIndent(observation.Plan, "", "  ")
	if err != nil {
		return fmt.Errorf("encode embedded probe plan: %w", err)
	}
	canonicalPlan = append(canonicalPlan, '\n')
	planDigest := sha256.Sum256(canonicalPlan)
	if !strings.EqualFold(observation.PlanSHA256, hex.EncodeToString(planDigest[:])) {
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
	for index := range report.Findings {
		if report.Findings[index].ID == "NET-004" {
			report.Findings[index] = finding
			break
		}
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

func readLimitedJSONBytes(path string) ([]byte, error) {
	file, err := openLimitedJSON(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxLocalJSONSize+1))
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
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
