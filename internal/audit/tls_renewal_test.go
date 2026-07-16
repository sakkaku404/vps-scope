package audit

import (
	"fmt"
	"testing"
)

func TestRenewalJournalSignals(t *testing.T) {
	success, failure := renewalJournalSignals("Certificate not due for renewal\nrenewal failed: timeout\nSuccessfully renewed certificate")
	if success != 2 || failure != 1 {
		t.Fatalf("signals = success %d failure %d", success, failure)
	}
}

func TestRenewalJournalSummaryUsesLastObservedOutcome(t *testing.T) {
	success, failure, last := renewalJournalSummary("Successfully renewed certificate\nrenewal failed: timeout")
	if success != 1 || failure != 1 || last != "failure" {
		t.Fatalf("summary = success %d failure %d last %q", success, failure, last)
	}
}

func TestRenewalCommandMethod(t *testing.T) {
	for input, want := range map[string]string{
		"0 2 * * * root certbot renew":       "certbot",
		"/root/.acme.sh/acme.sh --cron":      "acme.sh",
		"lego --domains example.invalid run": "lego",
		"echo certificate":                   "",
	} {
		if got := renewalCommandMethod(input); got != want {
			t.Errorf("renewalCommandMethod(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestCaddyServiceHealthIsNotRenewalSuccess(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "show", "caddy.service", "--property=LoadState,ActiveState,Result,ExecMainStatus,ActiveEnterTimestamp,ExecReload"):                                                            {Stdout: "LoadState=loaded\nActiveState=active\nResult=success\nExecMainStatus=0\n"},
		scenarioCommandKey("journalctl", "--since", "30 days ago", "-u", "certbot.service", "-u", "acme.service", "-u", "acme-renew.service", "-u", "lego.service", "-u", "caddy.service", "--no-pager", "-o", "cat"): {},
	}
	f := collectTLSRenewalFactsWithDiscovery(scenarioContext(newScenarioCommander([]string{"systemctl", "journalctl"}, results)), noRenewalFiles)
	if f.SuccessSignals != 0 || f.FailureSignals != 0 {
		t.Fatalf("Caddy service health became renewal evidence: %#v", f)
	}
}

func TestValueOrUnknown(t *testing.T) {
	if valueOrUnknown("  ") != "unknown" || valueOrUnknown(" active ") != "active" {
		t.Fatal("unexpected normalization")
	}
}

func TestCollectTLSRenewalFactsSeparatesScheduleSuccessAndReload(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "is-enabled", "certbot.timer"):                                                                                                                                                {Stdout: "enabled\n"},
		scenarioCommandKey("systemctl", "show", "certbot.timer", "--property=LastTriggerUSec,NextElapseUSecRealtime"):                                                                                                 {Stdout: "LastTriggerUSec=Mon 2026-07-13\nNextElapseUSecRealtime=Tue 2026-07-14\n"},
		scenarioCommandKey("systemctl", "show", "certbot.service", "--property=LoadState,ActiveState,Result,ExecMainStatus,ActiveEnterTimestamp,ExecReload"):                                                          {Stdout: "LoadState=loaded\nActiveState=inactive\nResult=success\nExecMainStatus=0\nExecReload={ path=/bin/systemctl ; argv[]=systemctl reload nginx ; }\n"},
		scenarioCommandKey("journalctl", "--since", "30 days ago", "-u", "certbot.service", "-u", "acme.service", "-u", "acme-renew.service", "-u", "lego.service", "-u", "caddy.service", "--no-pager", "-o", "cat"): {Stdout: "Successfully renewed certificate\n"},
	}
	f := collectTLSRenewalFactsWithDiscovery(scenarioContext(newScenarioCommander([]string{"systemctl", "journalctl"}, results)), noRenewalFiles)
	if f.Schedules != 1 || f.SuccessSignals != 2 || f.FailureSignals != 0 || f.ReloadHooks != 1 {
		t.Fatalf("unexpected renewal facts: %#v", f)
	}
	if len(f.Methods) != 1 || f.Methods[0] != "certbot" {
		t.Fatalf("unexpected methods: %#v", f.Methods)
	}
}

func TestCollectTLSRenewalFactsRejectsPartialEnabledTimer(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "is-enabled", "certbot.timer"): {Stdout: "enabled\n", Err: fmt.Errorf("transport interrupted")},
	}
	f := collectTLSRenewalFactsWithDiscovery(scenarioContext(newScenarioCommander([]string{"systemctl"}, results)), noRenewalFiles)
	if f.Schedules != 0 || f.DiscoveryError == nil {
		t.Fatalf("partial timer result became schedule evidence: %#v", f)
	}
}

func TestCollectTLSRenewalFactsRejectsPartialLoadedService(t *testing.T) {
	results := map[string]CommandResult{
		scenarioCommandKey("systemctl", "show", "certbot.service", "--property=LoadState,ActiveState,Result,ExecMainStatus,ActiveEnterTimestamp,ExecReload"): {Stdout: "LoadState=loaded\nResult=success\nExecMainStatus=0\n", Err: fmt.Errorf("transport interrupted")},
	}
	f := collectTLSRenewalFactsWithDiscovery(scenarioContext(newScenarioCommander([]string{"systemctl"}, results)), noRenewalFiles)
	if f.SuccessSignals != 0 || f.DiscoveryError == nil {
		t.Fatalf("partial service result became success evidence: %#v", f)
	}
}

func noRenewalFiles(int, ...string) ([]string, error) { return nil, nil }
