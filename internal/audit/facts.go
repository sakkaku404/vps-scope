package audit

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"sort"
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
// facts instead of invoking ps, ss, UFW, or Docker repeatedly. Listener and
// established-connection snapshots therefore remain internally consistent.
type FactStore struct {
	cmd            Commander
	nativeSelfTest bool
	auditTime      time.Time
	ctx            context.Context
	files          *fileEvidenceSnapshot

	listenersOnce sync.Once
	listeners     []Listener
	listenersErr  error

	connectionsOnce sync.Once
	connections     []activeConnection
	connectionsErr  error

	sshdOnce     sync.Once
	sshdSettings map[string]string
	sshdErr      error

	processesOnce sync.Once
	processes     []ProcessInfo
	processesErr  error

	hostFirewallOnce sync.Once
	hostFirewall     hostFirewallSnapshot
	firewallProgram  *firewallProgram

	dockerOnce sync.Once
	docker     []dockerInspect
	dockerErr  error

	dockerFirewallOnce sync.Once
	dockerFirewall     dockerFirewallFacts

	panelsOnce sync.Once
	panels     []panelSnapshot
	panelsErr  error

	reverseProxyOnce sync.Once
	reverseProxy     []reverseProxyRoute
	reverseProxyErr  error

	proxyUnitsOnce sync.Once
	proxyUnits     []string
	proxyUnitsErr  error

	wireGuardOnce       sync.Once
	wireGuardInterfaces []wireGuardInterface
	wireGuardInstalled  bool
	wireGuardErr        error
}

type wireGuardInterface struct {
	Name string
	Port string
}

// WireGuardInterfaces returns one interface/listen-port inventory shared by
// generic listener policy and the WireGuard workload check. Using one snapshot
// prevents an interface reload between `wg show all listen-port` and per-
// interface queries from producing contradictory conclusions.
func (f *FactStore) WireGuardInterfaces() ([]wireGuardInterface, bool, error) {
	f.wireGuardOnce.Do(func() {
		if !f.cmd.Exists("wg") {
			return
		}
		f.wireGuardInstalled = true
		r := f.cmd.Run(8*time.Second, "wg", "show", "all", "listen-port")
		if r.Err != nil || r.Truncated {
			f.wireGuardErr = fmt.Errorf("wg listen-port inventory: %s", commandError(r))
			return
		}
		seen := map[string]bool{}
		for _, line := range lines(r.Stdout) {
			fields := strings.Fields(line)
			if len(fields) != 2 || !validNetworkInterfaceName(fields[0]) || fields[1] != "0" && !validPort(fields[1]) || seen[fields[0]] {
				f.wireGuardInterfaces = nil
				f.wireGuardErr = fmt.Errorf("wg listen-port inventory returned malformed or duplicate interface metadata")
				return
			}
			seen[fields[0]] = true
			f.wireGuardInterfaces = append(f.wireGuardInterfaces, wireGuardInterface{Name: fields[0], Port: fields[1]})
		}
		sort.Slice(f.wireGuardInterfaces, func(i, j int) bool { return f.wireGuardInterfaces[i].Name < f.wireGuardInterfaces[j].Name })
	})
	return append([]wireGuardInterface(nil), f.wireGuardInterfaces...), f.wireGuardInstalled, f.wireGuardErr
}

// Panels returns native panel facts plus container-backed panel facts. Docker
// is optional: a host without Docker still has a complete native-panel
// inventory. If Docker is present but its inventory cannot be collected, the
// error is returned so a Docker-only panel is never mistaken for no panel.
func (f *FactStore) Panels() ([]panelSnapshot, error) {
	f.panelsOnce.Do(func() {
		f.panels = collectPanelSnapshotsFromInventoryContext(f.ctx, f.cmd, f.nativeSelfTest, f.auditTime, snapshotPanelInventory{files: f.files}, panelAdapters(), f.files)
		if !f.cmd.Exists("docker") {
			return
		}
		containers, err := f.DockerContainers()
		if err != nil {
			f.panelsErr = fmt.Errorf("docker-backed panel discovery: %w", err)
			return
		}
		f.panels = append(f.panels, collectContainerPanelSnapshotsFromFiles(containers, f.files)...)
	})
	return append([]panelSnapshot(nil), f.panels...), f.panelsErr
}

// ReverseProxyRoutes returns one configuration snapshot shared by management
// exposure and reverse-proxy relationship checks. Running nginx -T twice can
// otherwise correlate a panel with two different live configurations during a
// reload.
func (f *FactStore) ReverseProxyRoutes() ([]reverseProxyRoute, error) {
	f.reverseProxyOnce.Do(func() {
		f.reverseProxy, f.reverseProxyErr = discoverReverseProxyRoutesFromFiles(f.cmd, f.nativeSelfTest, f.files)
	})
	return append([]reverseProxyRoute(nil), f.reverseProxy...), f.reverseProxyErr
}

// ProxyServiceUnits is the single systemd inventory used by service isolation
// and log checks. The two conclusions must refer to the same set of units.
func (f *FactStore) ProxyServiceUnits() ([]string, error) {
	f.proxyUnitsOnce.Do(func() {
		f.proxyUnits, f.proxyUnitsErr = collectProxyServiceUnits(f.cmd)
	})
	return append([]string(nil), f.proxyUnits...), f.proxyUnitsErr
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

func NewFactStore(cmd Commander, nativeSelfTest bool) *FactStore {
	return NewFactStoreAt(cmd, nativeSelfTest, time.Now().UTC())

}

func NewFactStoreAt(cmd Commander, nativeSelfTest bool, auditTime time.Time) *FactStore {
	return newFactStoreAt(cmd, nativeSelfTest, auditTime, osFileEvidenceSource{})
}

func newFactStoreAt(cmd Commander, nativeSelfTest bool, auditTime time.Time, source fileEvidenceSource) *FactStore {
	return newFactStoreAtContext(context.Background(), cmd, nativeSelfTest, auditTime, source)

}

func newFactStoreAtContext(ctx context.Context, cmd Commander, nativeSelfTest bool, auditTime time.Time, source fileEvidenceSource) *FactStore {
	if ctx == nil {
		ctx = context.Background()
	}
	return &FactStore{ctx: ctx, cmd: cmd, nativeSelfTest: nativeSelfTest, auditTime: auditTime.UTC(), files: newFileEvidenceSnapshot(source), firewallProgram: newFirewallProgram(cmd)}
}

func (f *FactStore) ReadSmall(path string, limit int64) (string, error) {
	return f.files.ReadSmall(path, limit)
}

// ReadFreshSmall is reserved for an explicitly time-varying sample. It uses
// the same injected, bounded source as the sealed snapshot but deliberately
// bypasses the cache, so a second /proc/stat observation can measure a delta
// without silently reaching around test or collection boundaries.
func (f *FactStore) ReadFreshSmall(path string, limit int64) (string, error) {
	if limit < 0 {
		return "", fmt.Errorf("invalid fresh file read limit")
	}
	if limit > maxSnapshotFileReadBytes {
		limit = maxSnapshotFileReadBytes
	}
	return snapshotReadSmall(f.files.source, path, limit)
}

func (f *FactStore) Readlink(path string) (string, error) {
	return f.files.Readlink(path)
}

func (f *FactStore) ReadDirectory(path string, limit int) ([]fs.DirEntry, error) {
	return f.files.ReadDirectory(path, limit)
}

func (f *FactStore) Stat(path string) (fs.FileInfo, error) {
	return f.files.Stat(path)
}

func (f *FactStore) Lstat(path string) (fs.FileInfo, error) {
	return f.files.Lstat(path)
}

func (f *FactStore) FileStats() fileSnapshotStats { return f.files.Stats() }

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
		f.listeners, f.listenersErr = parseListeners(r.Stdout)
		if f.listenersErr != nil {
			f.listenersErr = fmt.Errorf("ss listener parse: %w", f.listenersErr)
		}
	})
	return append([]Listener(nil), f.listeners...), f.listenersErr
}

// EstablishedConnections is a point-in-time connection snapshot shared by
// NET-003 and proxy ingress summaries. Sharing it prevents a busy proxy from
// reporting general and per-ingress counts from different ss invocations.
func (f *FactStore) EstablishedConnections() ([]activeConnection, error) {
	f.connectionsOnce.Do(func() {
		if !f.cmd.Exists("ss") {
			f.connectionsErr = fmt.Errorf("ss command not found")
			return
		}
		r := f.cmd.Run(15*time.Second, "ss", "-H", "-ntup", "state", "established")
		if r.Err != nil && r.Stdout == "" {
			r = f.cmd.Run(15*time.Second, "ss", "-H", "-ntu", "state", "established")
		}
		if r.Truncated {
			f.connectionsErr = fmt.Errorf("ss established output exceeded the capture limit")
			return
		}
		if r.Err != nil {
			f.connectionsErr = fmt.Errorf("ss established: %s", commandError(r))
			return
		}
		f.connections, f.connectionsErr = parseEstablishedConnections(r.Stdout)
		if f.connectionsErr != nil {
			f.connectionsErr = fmt.Errorf("ss established parse: %w", f.connectionsErr)
		}
	})
	return append([]activeConnection(nil), f.connections...), f.connectionsErr
}

// SSHDSettings is the effective OpenSSH daemon configuration shared by SSH
// posture and password-policy context. Both findings must evaluate one
// sshd -T result rather than independently sampling a live daemon.
func (f *FactStore) SSHDSettings() (map[string]string, error) {
	f.sshdOnce.Do(func() {
		if !f.cmd.Exists("sshd") {
			f.sshdErr = fmt.Errorf("sshd command not found")
			return
		}
		r := f.cmd.Run(12*time.Second, "sshd", "-T")
		if r.Truncated {
			f.sshdErr = fmt.Errorf("sshd -T output exceeded the capture limit")
			return
		}
		if r.Err != nil {
			f.sshdErr = fmt.Errorf("sshd -T: %s", commandError(r))
			return
		}
		f.sshdSettings = parseSpaceSettings(r.Stdout)
		for _, required := range []string{"passwordauthentication", "kbdinteractiveauthentication", "permitrootlogin", "pubkeyauthentication"} {
			if strings.TrimSpace(f.sshdSettings[required]) == "" {
				f.sshdErr = fmt.Errorf("sshd -T omitted required setting %s", required)
				f.sshdSettings = nil
				return
			}
		}
	})
	return maps.Clone(f.sshdSettings), f.sshdErr
}

type activeConnection struct {
	protocol, local, peer, scope, process string
}

func parseEstablishedConnections(output string) ([]activeConnection, error) {
	var out []activeConnection
	for index, line := range lines(output) {
		fields := strings.Fields(line)
		if !strings.HasPrefix(strings.ToLower(fields[0]), "tcp") {
			continue
		}
		if len(fields) < 5 {
			return nil, fmt.Errorf("ss established row %d is malformed", index+1)
		}
		localIndex := 3
		if len(fields) >= 6 && (strings.EqualFold(fields[1], "ESTAB") || strings.EqualFold(fields[1], "ESTABLISHED")) {
			localIndex = 4
		}
		peerIndex := localIndex + 1
		if peerIndex >= len(fields) {
			return nil, fmt.Errorf("ss established row %d is missing a peer endpoint", index+1)
		}
		local, peer := fields[localIndex], fields[peerIndex]
		localAddress, localPort := splitHostPortLoose(local)
		peerAddress, peerPort := splitHostPortLoose(peer)
		if classifyAddress(localAddress) == "unknown" || classifyAddress(peerAddress) == "unknown" || !validPort(localPort) || !validPort(peerPort) {
			return nil, fmt.Errorf("ss established row %d has an invalid endpoint", index+1)
		}
		process := ""
		if len(fields) > peerIndex+1 {
			process = strings.Join(fields[peerIndex+1:], " ")
		}
		out = append(out, activeConnection{protocol: strings.ToLower(fields[0]), local: local, peer: peer, scope: classifyAddress(peerAddress), process: process})
	}
	return out, nil
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

func (f *FactStore) HostFirewall() hostFirewallSnapshot {
	f.hostFirewallOnce.Do(func() {
		f.hostFirewall = collectHostFirewallFromProgram(f.cmd, f.firewallProgram)
	})
	return f.hostFirewall
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
		f.dockerFirewall = collectDockerFirewallFromProgram(f.firewallProgram)
	})
	return f.dockerFirewall.clone()
}
