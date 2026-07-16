package audit

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// A proxy VPS normally has only a small number of running containers. Keep
	// the inventory finite so a hostile or accidentally huge Docker daemon
	// cannot turn one audit into an unbounded argument list, output buffer, or
	// series of slow inspect calls. The collector is deliberately all-or-error:
	// callers never receive a clean-looking prefix of a larger inventory.
	maxDockerContainerInventory = 128
	dockerInspectBatchSize      = 32
)

// FactStore owns evidence that is expensive or privacy-sensitive to collect.
// Every collector runs at most once per audit; checks consume the same typed
// facts instead of invoking ps, ss, UFW, or Docker repeatedly.
type FactStore struct {
	cmd Commander

	listenersOnce sync.Once
	listeners     []Listener
	listenersErr  error

	processesOnce sync.Once
	processes     []ProcessInfo
	processesErr  error

	ufwOnce sync.Once
	ufw     panelUFW

	dockerOnce sync.Once
	docker     []dockerInspect
	dockerErr  error

	dockerFirewallOnce sync.Once
	dockerFirewall     dockerFirewallFacts

	panelsOnce sync.Once
	panels     []panelSnapshot
}

func (f *FactStore) Panels() []panelSnapshot {
	f.panelsOnce.Do(func() {
		f.panels = collectPanelSnapshots(f.cmd)
		if containers, err := f.DockerContainers(); err == nil {
			f.panels = append(f.panels, collectContainerPanelSnapshots(containers)...)
		}
	})
	return append([]panelSnapshot(nil), f.panels...)
}

type ProcessInfo struct {
	PID     string
	User    string
	Command string
	Args    string
}

func processLine(p ProcessInfo) string {
	return strings.TrimSpace(strings.Join([]string{p.PID, p.User, p.Command, p.Args}, " "))
}

func NewFactStore(cmd Commander) *FactStore { return &FactStore{cmd: cmd} }

func (f *FactStore) Listeners() ([]Listener, error) {
	f.listenersOnce.Do(func() {
		if !f.cmd.Exists("ss") {
			f.listenersErr = fmt.Errorf("ss command not found")
			return
		}
		r := f.cmd.Run(15*time.Second, "ss", "-H", "-lntup")
		if r.Err != nil && r.Stdout == "" {
			r = f.cmd.Run(15*time.Second, "ss", "-H", "-lntu")
		}
		if r.Truncated {
			f.listenersErr = fmt.Errorf("ss listener output exceeded the capture limit")
			return
		}
		if r.Err != nil {
			f.listenersErr = fmt.Errorf("ss -H -lntu[p]: %s", commandError(r))
			return
		}
		f.listeners = parseListeners(r.Stdout)
	})
	return append([]Listener(nil), f.listeners...), f.listenersErr
}

func (f *FactStore) Processes() ([]ProcessInfo, error) {
	f.processesOnce.Do(func() {
		if !f.cmd.Exists("ps") {
			f.processesErr = fmt.Errorf("ps command not found")
			return
		}
		r := f.cmd.Run(10*time.Second, "ps", "-eo", "pid=,user=,comm=,args=")
		if r.Truncated {
			f.processesErr = fmt.Errorf("ps output exceeded the capture limit")
			return
		}
		if r.Err != nil {
			f.processesErr = fmt.Errorf("ps: %s", commandError(r))
			return
		}
		for _, line := range lines(r.Stdout) {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			args := ""
			if len(fields) > 3 {
				args = strings.Join(fields[3:], " ")
			}
			f.processes = append(f.processes, ProcessInfo{PID: fields[0], User: fields[1], Command: fields[2], Args: args})
		}
	})
	return append([]ProcessInfo(nil), f.processes...), f.processesErr
}

func (f *FactStore) UFW() panelUFW {
	f.ufwOnce.Do(func() {
		f.ufw = collectHostFirewall(f.cmd)
	})
	return f.ufw
}

func (f *FactStore) DockerContainers() ([]dockerInspect, error) {
	f.dockerOnce.Do(func() {
		if !f.cmd.Exists("docker") {
			f.dockerErr = fmt.Errorf("docker command not found")
			return
		}
		ps := f.cmd.Run(15*time.Second, "docker", "ps", "-q")
		if ps.Err != nil || ps.Truncated {
			f.dockerErr = fmt.Errorf("docker ps: %s", commandError(ps))
			return
		}
		ids, err := dockerContainerIDs(ps.Stdout)
		if err != nil {
			f.dockerErr = err
			return
		}
		if len(ids) == 0 {
			return
		}
		inspected := make([]dockerInspect, 0, len(ids))
		for start := 0; start < len(ids); start += dockerInspectBatchSize {
			end := start + dockerInspectBatchSize
			if end > len(ids) {
				end = len(ids)
			}
			args := append([]string{"inspect"}, ids[start:end]...)
			inspect := f.cmd.Run(15*time.Second, "docker", args...)
			batch := start/dockerInspectBatchSize + 1
			total := (len(ids) + dockerInspectBatchSize - 1) / dockerInspectBatchSize
			if inspect.Truncated {
				f.dockerErr = fmt.Errorf("docker inspect batch %d/%d output exceeded the capture limit", batch, total)
				return
			}
			if inspect.Err != nil {
				f.dockerErr = fmt.Errorf("docker inspect batch %d/%d: %s", batch, total, commandError(inspect))
				return
			}
			var decoded []dockerInspect
			if err := decodeDockerInspect(inspect.Stdout, &decoded); err != nil {
				f.dockerErr = fmt.Errorf("docker inspect batch %d/%d: %w", batch, total, err)
				return
			}
			if len(decoded) != end-start {
				f.dockerErr = fmt.Errorf("docker inspect batch %d/%d returned %d containers for %d requested", batch, total, len(decoded), end-start)
				return
			}
			inspected = append(inspected, decoded...)
		}
		f.docker = inspected
	})
	return append([]dockerInspect(nil), f.docker...), f.dockerErr
}

func dockerContainerIDs(output string) ([]string, error) {
	ids := lines(output)
	if len(ids) > maxDockerContainerInventory {
		return nil, fmt.Errorf("docker ps returned %d running containers; safety limit is %d", len(ids), maxDockerContainerInventory)
	}
	for _, id := range ids {
		if len(id) == 0 || len(id) > 64 {
			return nil, fmt.Errorf("docker ps returned an invalid container ID")
		}
		for _, c := range id {
			if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
				return nil, fmt.Errorf("docker ps returned an invalid container ID")
			}
		}
	}
	return ids, nil
}

func (f *FactStore) DockerFirewall() dockerFirewallFacts {
	f.dockerFirewallOnce.Do(func() {
		f.dockerFirewall = collectDockerFirewall(f.cmd)
	})
	return f.dockerFirewall.clone()
}
