package app

import (
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestBaselineStableInventoryAndDrift(t *testing.T) {
	r := model.Report{Host: model.Host{Hostname: "fixture", StableID: "machine-1"}, Findings: []model.Finding{
		{ID: "NET-001", Evidence: []model.Evidence{{Source: "ss", Value: `tcp 0.0.0.0:443 scope=public-wildcard process=users:(("sing-box",pid=123,fd=7))`}, {Source: "ss", Value: "tcp 127.0.0.1:53 scope=loopback"}}},
		{ID: "SSH-004", Evidence: []model.Evidence{{Key: "authorized_key", Value: "root SHA256:fixture ED25519"}}},
		{ID: "FW-002", Evidence: []model.Evidence{{Key: "allow_rule", Value: "443/tcp ALLOW IN Anywhere"}}},
	}}
	base := makeBaseline(r)
	if base.SchemaVersion != "vps-scope-baseline/v2" || base.StableID != "machine-1" {
		t.Fatalf("unexpected baseline identity: %#v", base)
	}
	if len(base.Items) != 3 {
		t.Fatalf("items=%d", len(base.Items))
	}
	added, removed := compareBaseline(base.Items, makeBaseline(r).Items)
	if len(added)+len(removed) != 0 {
		t.Fatal("identical report drifted")
	}
	r.Findings[0].Evidence[0].Value = `tcp 0.0.0.0:443 scope=public-wildcard process=users:(("sing-box",pid=456,fd=9))`
	added, removed = compareBaseline(base.Items, makeBaseline(r).Items)
	if len(added)+len(removed) != 0 {
		t.Fatal("PID/fd-only listener change caused drift")
	}
	r.Findings[0].Evidence[0].Value = "tcp 0.0.0.0:8443 scope=public-wildcard process=sing-box"
	added, removed = compareBaseline(base.Items, makeBaseline(r).Items)
	if len(added) != 1 || len(removed) != 1 {
		t.Fatalf("added=%d removed=%d", len(added), len(removed))
	}
}
