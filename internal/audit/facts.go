package audit

import (
	"fmt"
	"strings"
	"sync"
	"time"
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

	panelsOnce sync.Once
	panels     []panelSnapshot
}

func (f *FactStore) Panels() []panelSnapshot {
	f.panelsOnce.Do(func() { f.panels = collectPanelSnapshots(f.cmd) })
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
		if !f.cmd.Exists("ufw") {
			return
		}
		r := f.cmd.Run(12*time.Second, "ufw", "status", "verbose")
		if r.Err != nil || r.Truncated {
			return
		}
		f.ufw = parsePanelUFW(r.Stdout)
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
		ids := lines(ps.Stdout)
		if len(ids) == 0 {
			return
		}
		args := append([]string{"inspect"}, ids...)
		inspect := f.cmd.Run(30*time.Second, "docker", args...)
		if inspect.Truncated {
			f.dockerErr = fmt.Errorf("docker inspect output exceeded the capture limit")
			return
		}
		if inspect.Err != nil {
			f.dockerErr = fmt.Errorf("docker inspect: %s", commandError(inspect))
			return
		}
		if err := decodeDockerInspect(inspect.Stdout, &f.docker); err != nil {
			f.dockerErr = err
		}
	})
	return append([]dockerInspect(nil), f.docker...), f.dockerErr
}
