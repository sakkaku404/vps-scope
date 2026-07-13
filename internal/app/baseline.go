package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type baselineDocument struct {
	SchemaVersion string         `json:"schema_version"`
	Host          string         `json:"host"`
	CreatedAt     time.Time      `json:"created_at"`
	Items         []baselineItem `json:"items"`
}

type baselineItem struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (e environment) baseline(args []string) error {
	if len(args) != 3 || (args[0] != "create" && args[0] != "check") {
		return errors.New("usage: vps-scope baseline create REPORT.json BASELINE.json | baseline check BASELINE.json REPORT.json")
	}
	if args[0] == "create" {
		r, err := readReport(args[1])
		if err != nil {
			return err
		}
		doc := makeBaseline(r)
		file, err := os.OpenFile(args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(doc); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "Baseline created: %s (%d stable items)\n", args[2], len(doc.Items))
		return nil
	}
	doc, err := readBaseline(args[1])
	if err != nil {
		return err
	}
	r, err := readReport(args[2])
	if err != nil {
		return err
	}
	current := makeBaseline(r)
	if doc.Host != "" && current.Host != "" && doc.Host != current.Host {
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
	doc := baselineDocument{SchemaVersion: "vps-scope-baseline/v1", Host: r.Host.Hostname, CreatedAt: time.Now().UTC()}
	seen := map[string]bool{}
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		key := kind + "\x00" + value
		if value != "" && !seen[key] {
			seen[key] = true
			doc.Items = append(doc.Items, baselineItem{Kind: kind, Value: value})
		}
	}
	for _, finding := range r.Findings {
		for _, evidence := range finding.Evidence {
			switch {
			case finding.ID == "NET-001" && containsPublicScope(evidence.Value):
				add("public_listener", evidence.Value)
			case evidence.Key == "authorized_key":
				add("ssh_key", evidence.Value)
			case evidence.Key == "allow_rule":
				add("firewall_rule", evidence.Value)
			case evidence.Key == "proxy_container" || evidence.Key == "container_panel":
				add("container", evidence.Value)
			case evidence.Key == "published_port":
				add("container_port", evidence.Value)
			case evidence.Key == "management_endpoint":
				add("panel_endpoint", evidence.Value)
			case evidence.Key == "proxy_ingress" || evidence.Key == "control_endpoint":
				add("proxy_endpoint", evidence.Value)
			case finding.ID == "WORK-007" && evidence.Source == "systemctl show":
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

func containsPublicScope(value string) bool {
	return strings.Contains(value, "scope=public ") || strings.Contains(value, "scope=public-wildcard") || strings.HasSuffix(value, "scope=public")
}

func readBaseline(path string) (baselineDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return baselineDocument{}, err
	}
	defer file.Close()
	var doc baselineDocument
	if err := json.NewDecoder(file).Decode(&doc); err != nil {
		return doc, err
	}
	if doc.SchemaVersion != "vps-scope-baseline/v1" {
		return doc, fmt.Errorf("unsupported baseline schema %q", doc.SchemaVersion)
	}
	return doc, nil
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
