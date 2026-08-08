package audit

import (
	"errors"
	"testing"

	"github.com/sakkaku404/vps-scope/internal/model"
)

func TestAuthEvaluatorsDoNotRequireLiveCollectors(t *testing.T) {
	activity := newFailedLoginActivity()
	activity.add("Failed password for invalid user admin from 203.0.113.7 port 1234 ssh2")
	failed := evaluateFailedLogins(failedLoginSnapshot{Activity: activity, Source: "fixture"})
	if failed.Status != model.Info || failed.Facts["unique_sources"] != "1" {
		t.Fatalf("failed login finding=%+v", failed)
	}

	sudo := evaluateSudoAudit(sudoAuditSnapshot{Available: true, Result: CommandResult{Stdout: "one\ntwo\n"}})
	if sudo.Status != model.Pass || sudo.Facts["sudo_journal_lines"] != "2" {
		t.Fatalf("sudo finding=%+v", sudo)
	}

	intrusion := evaluateIntrusionPrevention(intrusionPreventionSnapshot{
		Fail2ban: intrusionServiceSnapshot{Installed: true, ActiveKnown: true, Active: true, ActiveValue: "active", ProtectionKnown: true, Protected: true, Detail: "Jail list: sshd"},
	})
	if intrusion.Status != model.Pass || intrusion.Facts["fail2ban_sshd_jail"] != "true" {
		t.Fatalf("intrusion finding=%+v", intrusion)
	}
}

func TestUpdateEvaluatorsDistinguishSecurityAndEvidenceFailure(t *testing.T) {
	security := evaluatePendingUpdates(updateAuditSnapshot{APTAvailable: true, APTUpgrade: CommandResult{Stdout: "Inst openssl [1] (2 Debian-Security)\n"}})
	if security.Status != model.Risk || security.Severity != model.High || security.Facts["pending_security"] != "1" {
		t.Fatalf("security update finding=%+v", security)
	}

	unknownTimer := evaluateUnattended(updateAuditSnapshot{
		DPKGQueryAvailable: true,
		UnattendedPackage:  CommandResult{Stdout: "install ok installed"},
		SystemctlAvailable: true,
		UpgradeTimer:       CommandResult{Err: errors.New("fixture failure")},
	})
	if unknownTimer.Status != model.Unknown || !unknownTimer.Unavailable {
		t.Fatalf("unattended finding=%+v", unknownTimer)
	}
}

func TestReliabilityEvaluatorsUseFrozenSnapshot(t *testing.T) {
	snapshot := reliabilitySnapshot{
		DFAvailable:          true,
		Inodes:               CommandResult{Stdout: "Filesystem Inodes IUsed IFree IUse% Mounted\n/dev/vda1 10 1 9 10% /\n"},
		JournalAvailable:     true,
		JournalDiskUsage:     CommandResult{Stdout: "Archived and active journals take up 8.0M."},
		KernelJournal:        CommandResult{Stdout: "kernel: Out of memory: Killed process 123"},
		CoredumpctlAvailable: true,
		CoreDumps:            CommandResult{},
		JournalStorage:       "persistent",
		JournalPersistent:    true,
		DiskFreePercent:      70,
	}
	reliability := evaluateReliability(snapshot)
	if reliability.Status != model.Risk || reliability.Facts["oom_events"] != "1" {
		t.Fatalf("reliability finding=%+v", reliability)
	}
	pressure := evaluateLogAndInodePressure(snapshot)
	if pressure.Status != model.Info || pressure.Facts["root_inode_used_percent"] != "10" {
		t.Fatalf("pressure finding=%+v", pressure)
	}
}
