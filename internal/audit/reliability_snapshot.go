package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

// reliabilitySnapshot is the immutable evidence boundary for REL-001 and
// REL-002. Collection is deliberately sequential to keep load low on 512 MiB
// hosts; evaluation is pure and can be exercised without a live system.
type reliabilitySnapshot struct {
	DFAvailable          bool
	Inodes               CommandResult
	JournalAvailable     bool
	JournalDiskUsage     CommandResult
	KernelJournal        CommandResult
	DockerAvailable      bool
	DockerDiskUsage      CommandResult
	CoredumpctlAvailable bool
	CoreDumps            CommandResult
	JournalStorage       string
	JournalPersistent    bool
	DiskFreePercent      int
	FileErr              error
}

func collectReliabilitySnapshot(ctx *Context) reliabilitySnapshot {
	snapshot := reliabilitySnapshot{
		DFAvailable:          ctx.Commander.Exists("df"),
		JournalAvailable:     ctx.Commander.Exists("journalctl"),
		DockerAvailable:      ctx.Commander.Exists("docker"),
		CoredumpctlAvailable: ctx.Commander.Exists("coredumpctl"),
		JournalStorage:       "auto",
		DiskFreePercent:      diskFreePercent("/"),
	}
	if snapshot.DFAvailable {
		snapshot.Inodes = ctx.Commander.Run(8*time.Second, "df", "-Pi", "/")
	}
	if snapshot.JournalAvailable {
		snapshot.JournalDiskUsage = ctx.Commander.Run(10*time.Second, "journalctl", "--disk-usage", "--no-pager")
		snapshot.KernelJournal = ctx.Commander.Run(25*time.Second, "journalctl", "-k", "--since", sinceArg(ctx.LogSince), "--no-pager", "-o", "cat")
	}
	if snapshot.DockerAvailable {
		snapshot.DockerDiskUsage = ctx.Commander.Run(15*time.Second, "docker", "system", "df", "--format", "{{json .}}")
	}
	if snapshot.CoredumpctlAvailable {
		snapshot.CoreDumps = ctx.Commander.Run(20*time.Second, "coredumpctl", "list", "--since", sinceArg(ctx.LogSince), "--no-pager", "--no-legend")
	}
	if data, err := ctx.Facts.ReadSmall("/etc/systemd/journald.conf", 2<<20); err == nil {
		for _, line := range lines(data) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "Storage=") && !strings.HasPrefix(trimmed, "#") {
				_, snapshot.JournalStorage, _ = strings.Cut(line, "=")
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		snapshot.FileErr = errors.Join(snapshot.FileErr, fmt.Errorf("/etc/systemd/journald.conf: %w", err))
	}
	if info, err := ctx.Facts.Stat("/var/log/journal"); err == nil {
		snapshot.JournalPersistent = info.IsDir()
	} else if !errors.Is(err, fs.ErrNotExist) {
		snapshot.FileErr = errors.Join(snapshot.FileErr, fmt.Errorf("/var/log/journal: %w", err))
	}
	if snapshot.DiskFreePercent < 0 {
		snapshot.FileErr = errors.Join(snapshot.FileErr, errors.New("statfs /: disk free percentage unavailable"))
	}
	return snapshot
}

func evaluateLogAndInodePressure(snapshot reliabilitySnapshot) model.Finding {
	f := model.Finding{ID: "REL-002", Category: "reliability", Status: model.Info, Facts: map[string]string{}}
	if snapshot.DFAvailable && snapshot.Inodes.Err == nil {
		rows := lines(snapshot.Inodes.Stdout)
		if len(rows) > 1 {
			fields := strings.Fields(rows[len(rows)-1])
			if len(fields) >= 5 {
				f.Facts["root_inode_used_percent"] = strings.TrimSuffix(fields[4], "%")
				f.Evidence = append(f.Evidence, model.Evidence{Source: "df -Pi /", Key: "inode_use", Value: fields[4]})
			}
		}
	}
	if snapshot.JournalAvailable && snapshot.JournalDiskUsage.Err == nil {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl --disk-usage", Key: "journal_size", Value: truncate(strings.TrimSpace(snapshot.JournalDiskUsage.Stdout), 180)})
	}
	if snapshot.DockerAvailable && snapshot.DockerDiskUsage.Err == nil {
		f.Evidence = append(f.Evidence, model.Evidence{Source: "docker system df", Key: "docker_storage_rows", Value: strconv.Itoa(len(lines(snapshot.DockerDiskUsage.Stdout)))})
	}
	if len(f.Evidence) == 0 {
		return unknown("REL-002", "reliability", "df, journalctl, docker", "storage pressure evidence was unavailable")
	}
	return f
}

func evaluateReliability(snapshot reliabilitySnapshot) model.Finding {
	f := model.Finding{ID: "REL-001", Category: "reliability", Status: model.Pass, Facts: map[string]string{}}
	oom, cores := 0, 0
	discoveryErr := snapshot.FileErr
	if snapshot.JournalAvailable {
		result := snapshot.KernelJournal
		if result.Truncated || result.Err != nil {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("journalctl -k: %s", commandError(result)))
			f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl -k", Key: "unavailable", Value: commandError(result)})
		} else {
			re := regexp.MustCompile(`(?i)(out of memory|oom-kill|killed process \d+)`)
			for _, line := range lines(result.Stdout) {
				if re.MatchString(line) {
					oom++
					if len(f.Evidence) < 25 {
						f.Evidence = append(f.Evidence, model.Evidence{Source: "journalctl -k", Key: "oom", Value: truncate(line, 350)})
					}
				}
			}
		}
	} else {
		discoveryErr = errors.Join(discoveryErr, errors.New("journalctl -k: command not found"))
	}
	if snapshot.CoredumpctlAvailable {
		result := snapshot.CoreDumps
		if result.Truncated || result.Err != nil {
			discoveryErr = errors.Join(discoveryErr, fmt.Errorf("coredumpctl: %s", commandError(result)))
			f.Evidence = append(f.Evidence, model.Evidence{Source: "coredumpctl", Key: "unavailable", Value: commandError(result)})
		} else {
			coreLines := lines(result.Stdout)
			cores = len(coreLines)
			for index, line := range coreLines {
				if index >= 20 {
					break
				}
				f.Evidence = append(f.Evidence, model.Evidence{Source: "coredumpctl", Key: "core", Value: truncate(line, 350)})
			}
		}
	} else {
		discoveryErr = errors.Join(discoveryErr, errors.New("coredumpctl: command not found"))
	}
	f.Facts["oom_events"] = strconv.Itoa(oom)
	f.Facts["core_dumps"] = strconv.Itoa(cores)
	f.Facts["journal_storage"] = strings.TrimSpace(snapshot.JournalStorage)
	f.Facts["journal_persistent_directory"] = strconv.FormatBool(snapshot.JournalPersistent)
	f.Facts["root_disk_free_percent"] = strconv.Itoa(snapshot.DiskFreePercent)
	if oom > 0 || cores > 0 || snapshot.DiskFreePercent >= 0 && snapshot.DiskFreePercent < 10 {
		f.Status, f.Severity = model.Risk, model.Medium
	}
	f.Evidence = append(f.Evidence,
		model.Evidence{Source: "summary", Key: "oom_events", Value: strconv.Itoa(oom)},
		model.Evidence{Source: "summary", Key: "core_dumps", Value: strconv.Itoa(cores)},
		model.Evidence{Source: "/var/log/journal", Key: "persistent", Value: strconv.FormatBool(snapshot.JournalPersistent)},
		model.Evidence{Source: "statfs /", Key: "free_percent", Value: strconv.Itoa(snapshot.DiskFreePercent)},
	)
	return withIncompleteEvidence(f, "reliability log discovery", discoveryErr)
}
