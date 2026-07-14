package audit

import "testing"

func TestRenewalJournalSignals(t *testing.T) {
	success, failure := renewalJournalSignals("Certificate not due for renewal\nrenewal failed: timeout\nSuccessfully renewed certificate")
	if success != 2 || failure != 1 {
		t.Fatalf("signals = success %d failure %d", success, failure)
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
	f := collectTLSRenewalFacts(scenarioContext(newScenarioCommander([]string{"systemctl", "journalctl"}, results)))
	if f.Schedules != 1 || f.SuccessSignals != 2 || f.FailureSignals != 0 || f.ReloadHooks != 1 {
		t.Fatalf("unexpected renewal facts: %#v", f)
	}
	if len(f.Methods) != 1 || f.Methods[0] != "certbot" {
		t.Fatalf("unexpected methods: %#v", f.Methods)
	}
}
