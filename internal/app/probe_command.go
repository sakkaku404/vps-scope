package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sakkaku404/vps-scope/internal/audit"
	"github.com/sakkaku404/vps-scope/internal/model"
)

const probeSchemaVersion = "1.0"

var probeHostnamePattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$`)

type probePlan struct {
	SchemaVersion  string           `json:"schema_version"`
	ReportStableID string           `json:"report_stable_id"`
	Target         string           `json:"target"`
	ResolvedIPs    []string         `json:"resolved_ips,omitempty"`
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
	allowPrivate := fs.Bool("allow-private-target", false, "allow loopback, private, or link-local observation targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *output == "" || !validProbeTarget(*target) {
		return errors.New("usage: vps-scope probe plan --target HOST --output PLAN.json [--management PORT/tcp,...] [--allow-private-target] REPORT.json")
	}
	resolvedIPs, err := resolveProbeTarget(*target, *allowPrivate)
	if err != nil {
		return err
	}
	report, err := e.readReport(fs.Arg(0))
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
	plan := probePlan{SchemaVersion: probeSchemaVersion, ReportStableID: report.Host.StableID, Target: *target, ResolvedIPs: resolvedIPs, CreatedAt: time.Now().UTC(), Nonce: hex.EncodeToString(nonce), Endpoints: endpoints}
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
	allowPrivate := fs.Bool("allow-private-target", false, "allow loopback, private, or link-local observation targets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 || *output == "" {
		return errors.New("usage: vps-scope probe run --output OBSERVATION.json [--timeout 3s] [--allow-private-target] PLAN.json")
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
	resolvedIPs := plan.ResolvedIPs
	if len(resolvedIPs) == 0 {
		// Compatibility with plans created before resolved targets were embedded.
		resolvedIPs, err = resolveProbeTarget(plan.Target, *allowPrivate)
		if err != nil {
			return err
		}
	} else if err := validateResolvedProbeIPs(resolvedIPs, *allowPrivate); err != nil {
		return err
	}
	// Record the exact addresses used by this execution, including plans from
	// older versions that did not pin DNS results. The observation must be
	// self-contained and must never imply that a later resolver answer was the
	// address actually probed.
	plan.ResolvedIPs = append([]string(nil), resolvedIPs...)
	results := runProbePlan(plan, resolvedIPs, *timeout)
	planDigest, err := canonicalProbePlanSHA256(plan)
	if err != nil {
		return err
	}
	observation := probeObservation{SchemaVersion: probeSchemaVersion, PlanSHA256: planDigest, Plan: plan, ObservedAt: time.Now().UTC(), Observer: strings.TrimSpace(*observer), Results: results}
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
	report, err := e.readReport(fs.Arg(0))
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
	if failures := audit.ValidateReport(report, e.build.Version); len(failures) > 0 {
		return fmt.Errorf("probe observation produced an invalid report: %s", strings.Join(failures, "; "))
	}
	if err := writeJSONNew(*output, report); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "Enriched report: %s\n", *output)
	return nil
}

func runProbePlan(plan probePlan, resolvedIPs []string, timeout time.Duration) []probeResult {
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
				target := probeIPForFamily(resolvedIPs, endpoint.Family)
				if target == "" {
					result.State = "not-reachable"
					result.Detail = "target has no address for endpoint family"
					results[index] = result
					continue
				}
				started := time.Now()
				network := "tcp4"
				if endpoint.Family == "ipv6" {
					network = "tcp6"
				}
				connection, err := (&net.Dialer{Timeout: timeout}).Dial(network, net.JoinHostPort(target, fmt.Sprint(endpoint.Port)))
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
