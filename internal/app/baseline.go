package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type baselineDocument struct {
	SchemaVersion string         `json:"schema_version"`
	Host          string         `json:"host"`
	StableID      string         `json:"stable_id,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	Items         []baselineItem `json:"items"`
}

type baselineItem struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

const (
	maxBaselineItems      = 4096
	maxBaselineValueBytes = 4096
)

func (e environment) baseline(args []string) error {
	if len(args) != 3 || (args[0] != "create" && args[0] != "check") {
		return errors.New("usage: vps-scope baseline create REPORT.json BASELINE.json | baseline check BASELINE.json REPORT.json")
	}
	if args[0] == "create" {
		r, err := e.readReport(args[1])
		if err != nil {
			return err
		}
		if err := validateComparableHostIdentity(r); err != nil {
			return err
		}
		doc := makeBaseline(r)
		if err := atomicWriteNew(args[2], maxLocalJSONSize, func(w io.Writer) error {
			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			return encoder.Encode(doc)
		}); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "Baseline created: %s (%d stable items)\n", args[2], len(doc.Items))
		return nil
	}
	doc, err := readBaseline(args[1])
	if err != nil {
		return err
	}
	r, err := e.readReport(args[2])
	if err != nil {
		return err
	}
	if err := validateComparableHostIdentity(r); err != nil {
		return err
	}
	current := makeBaseline(r)
	if doc.StableID != "" && current.StableID != "" && doc.StableID != current.StableID {
		return fmt.Errorf("baseline stable_id %q does not match report stable_id %q", doc.StableID, current.StableID)
	}
	if doc.StableID == "" {
		fmt.Fprintln(e.out, "WARNING legacy baseline has no stable_id; host identity is verified by hostname only")
	}
	if (doc.StableID == "" || current.StableID == "") && doc.Host != "" && current.Host != "" && doc.Host != current.Host {
		return fmt.Errorf("baseline host %q does not match report host %q", doc.Host, current.Host)
	}
	added, removed := compareBaseline(doc.Items, current.Items)
	for _, item := range added {
		fmt.Fprintf(e.out, "ADDED    %-18s %s\n", item.Kind, item.Value)
	}
	for _, item := range removed {
		fmt.Fprintf(e.out, "REMOVED  %-18s %s\n", item.Kind, item.Value)
	}
	if len(added)+len(removed) > 0 {
		return fmt.Errorf("baseline drift: %d added, %d removed", len(added), len(removed))
	}
	fmt.Fprintf(e.out, "PASS baseline matches (%d stable items)\n", len(current.Items))
	return nil
}

func makeBaseline(r model.Report) baselineDocument {
	doc := baselineDocument{SchemaVersion: "vps-scope-baseline/v2", Host: r.Host.Hostname, StableID: r.Host.StableID, CreatedAt: time.Now().UTC()}
	seen := map[string]bool{}
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		key := kind + "\x00" + value
		if value != "" && !seen[key] {
			seen[key] = true
			doc.Items = append(doc.Items, baselineItem{Kind: kind, Value: value})
		}
	}
	if len(r.Endpoints) > 0 {
		for _, endpoint := range r.Endpoints {
			if endpoint.Scope != "public" && endpoint.Scope != "public-wildcard" {
				continue
			}
			process := normalizeListenerIdentity(endpoint.Process)
			add("public_listener", fmt.Sprintf("%s/%d family=%s scope=%s process=%s", endpoint.Protocol, endpoint.Port, endpoint.Family, endpoint.Scope, process))
		}
	}
	if r.Deployment != nil {
		for _, component := range r.Deployment.Components {
			switch {
			case component.Kind == "container":
				add("container", fmt.Sprintf("product=%s deployment=%s", component.Product, component.Deployment))
			case component.Kind == "proxy-core" && component.Runtime:
				add("proxy_service", fmt.Sprintf("product=%s deployment=%s", component.Product, component.Deployment))
			}
		}
		for _, endpoint := range r.Deployment.Endpoints {
			value := structuredBaselineEndpoint(endpoint)
			switch endpoint.Role {
			case "management", "subscription":
				add("panel_endpoint", value)
			case "proxy-ingress", "control-api":
				add("proxy_endpoint", value)
			case "container-publish":
				add("container_port", value)
			}
		}
	}
	for _, finding := range r.Findings {
		for _, evidence := range finding.Evidence {
			switch {
			case len(r.Endpoints) == 0 && finding.ID == "NET-001" && containsPublicScope(evidence.Value):
				add("public_listener", normalizeListenerIdentity(evidence.Value))
			case evidence.Key == "authorized_key":
				add("ssh_key", evidence.Value)
			case evidence.Key == "allow_rule":
				add("firewall_rule", evidence.Value)
			case r.Deployment == nil && (evidence.Key == "proxy_container" || evidence.Key == "container_panel"):
				add("container", evidence.Value)
			case r.Deployment == nil && evidence.Key == "published_port":
				add("container_port", evidence.Value)
			case r.Deployment == nil && evidence.Key == "management_endpoint":
				add("panel_endpoint", evidence.Value)
			case r.Deployment == nil && (evidence.Key == "proxy_ingress" || evidence.Key == "control_endpoint"):
				add("proxy_endpoint", evidence.Value)
			case r.Deployment == nil && finding.ID == "WORK-007" && evidence.Source == "systemctl show":
				add("proxy_service", evidence.Key)
			}
		}
	}
	sort.Slice(doc.Items, func(i, j int) bool {
		if doc.Items[i].Kind == doc.Items[j].Kind {
			return doc.Items[i].Value < doc.Items[j].Value
		}
		return doc.Items[i].Kind < doc.Items[j].Kind
	})
	return doc
}

func structuredBaselineEndpoint(endpoint model.ServiceEndpoint) string {
	return fmt.Sprintf("product=%s role=%s protocol=%s port=%d/%s address=%s family=%s scope=%s",
		endpoint.Product, endpoint.Role, endpoint.Protocol, endpoint.Port, endpoint.Transport,
		endpoint.Address, endpoint.Family, endpoint.Scope)
}

var listenerVolatileRE = regexp.MustCompile(`(?i)(?:,?pid=\d+|,?fd=\d+|,?ino=\d+)`)

func normalizeListenerIdentity(value string) string {
	value = listenerVolatileRE.ReplaceAllString(value, "")
	value = regexp.MustCompile(`\s+`).ReplaceAllString(value, " ")
	return strings.TrimSpace(value)
}

func containsPublicScope(value string) bool {
	return strings.Contains(value, "scope=public ") || strings.Contains(value, "scope=public-wildcard") || strings.HasSuffix(value, "scope=public")
}

func readBaseline(path string) (baselineDocument, error) {
	file, err := openLimitedJSON(path)
	if err != nil {
		return baselineDocument{}, err
	}
	defer file.Close()
	var doc baselineDocument
	if err := decodeSingleJSONWithOptions(file, &doc, true); err != nil {
		return doc, err
	}
	if doc.SchemaVersion != "vps-scope-baseline/v1" && doc.SchemaVersion != "vps-scope-baseline/v2" {
		return doc, fmt.Errorf("unsupported baseline schema %q", doc.SchemaVersion)
	}
	if strings.TrimSpace(doc.Host) == "" || len(doc.Host) > 1024 || !safeBaselineText(doc.Host) {
		return doc, errors.New("baseline host is empty, oversized, or unsafe")
	}
	if doc.SchemaVersion == "vps-scope-baseline/v2" && strings.TrimSpace(doc.StableID) == "" {
		return doc, errors.New("baseline v2 stable_id is empty")
	}
	if len(doc.StableID) > 1024 || !safeBaselineText(doc.StableID) || doc.CreatedAt.IsZero() {
		return doc, errors.New("baseline identity or creation time is invalid")
	}
	if len(doc.Items) > maxBaselineItems {
		return doc, fmt.Errorf("baseline contains %d items; limit is %d", len(doc.Items), maxBaselineItems)
	}
	allowedKinds := map[string]bool{
		"public_listener": true, "ssh_key": true, "firewall_rule": true,
		"container": true, "container_port": true, "panel_endpoint": true,
		"proxy_endpoint": true, "proxy_service": true,
	}
	seen := make(map[string]bool, len(doc.Items))
	for index, item := range doc.Items {
		if !allowedKinds[item.Kind] || strings.TrimSpace(item.Value) == "" || len(item.Value) > maxBaselineValueBytes || !safeBaselineText(item.Value) {
			return doc, fmt.Errorf("baseline item %d is invalid", index+1)
		}
		key := item.Kind + "\x00" + item.Value
		if seen[key] {
			return doc, fmt.Errorf("baseline item %d duplicates an earlier item", index+1)
		}
		seen[key] = true
	}
	return doc, nil
}

func safeBaselineText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r <= 0x9f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return false
		}
	}
	return true
}

func compareBaseline(old, current []baselineItem) (added, removed []baselineItem) {
	oldSet, currentSet := map[string]baselineItem{}, map[string]baselineItem{}
	for _, item := range old {
		oldSet[item.Kind+"\x00"+item.Value] = item
	}
	for _, item := range current {
		currentSet[item.Kind+"\x00"+item.Value] = item
	}
	for key, item := range currentSet {
		if _, ok := oldSet[key]; !ok {
			added = append(added, item)
		}
	}
	for key, item := range oldSet {
		if _, ok := currentSet[key]; !ok {
			removed = append(removed, item)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Kind+added[i].Value < added[j].Kind+added[j].Value })
	sort.Slice(removed, func(i, j int) bool { return removed[i].Kind+removed[i].Value < removed[j].Kind+removed[j].Value })
	return added, removed
}
