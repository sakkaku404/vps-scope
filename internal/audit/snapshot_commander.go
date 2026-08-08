package audit

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const maxCommandSnapshotRetainedBytes = 64 << 20

var errCommandSnapshotBudget = errors.New("audit command snapshot memory budget exceeded")

// snapshotCommander gives one audit a consistent view of command evidence.
// Collectors are read-only, so repeating an identical command during the same
// run should reuse the first result instead of observing a later host state.
// It also removes accidental duplicate work on small VPS instances.
type snapshotCommander struct {
	delegate Commander

	mu            sync.Mutex
	results       map[string]*commandSnapshotEntry
	exists        map[string]*existsSnapshotEntry
	trusted       map[string]*trustedSnapshotEntry
	commandCalls  int
	commandHits   int
	existsCalls   int
	existsHits    int
	trustedCalls  int
	trustedHits   int
	retainedBytes int
	budgetRejects int
}

type trustedExecutableResult struct {
	path string
	err  error
}

type commandSnapshotEntry struct {
	ready  chan struct{}
	result CommandResult
}

type existsSnapshotEntry struct {
	ready chan struct{}
	value bool
}

type trustedSnapshotEntry struct {
	ready  chan struct{}
	result trustedExecutableResult
}

type commandSnapshotStats struct {
	CommandCalls  int
	CommandHits   int
	ExistsCalls   int
	ExistsHits    int
	TrustedCalls  int
	TrustedHits   int
	RetainedBytes int
	BudgetRejects int
}

func newSnapshotCommander(delegate Commander) *snapshotCommander {
	return &snapshotCommander{
		delegate: delegate,
		results:  map[string]*commandSnapshotEntry{},
		exists:   map[string]*existsSnapshotEntry{},
		trusted:  map[string]*trustedSnapshotEntry{},
	}
}

func (c *snapshotCommander) Exists(name string) bool {
	c.mu.Lock()
	c.existsCalls++
	if entry, ok := c.exists[name]; ok {
		c.existsHits++
		c.mu.Unlock()
		<-entry.ready
		return entry.value
	}
	entry := &existsSnapshotEntry{ready: make(chan struct{})}
	c.exists[name] = entry
	c.mu.Unlock()

	entry.value = snapshotDelegateExists(c.delegate, name)
	c.mu.Lock()
	close(entry.ready)
	c.mu.Unlock()
	return entry.value
}

func (c *snapshotCommander) Run(timeout time.Duration, name string, args ...string) CommandResult {
	key := commandSnapshotKey(name, args)
	c.mu.Lock()
	c.commandCalls++
	if entry, ok := c.results[key]; ok {
		c.commandHits++
		c.mu.Unlock()
		<-entry.ready
		return entry.result
	}
	entry := &commandSnapshotEntry{ready: make(chan struct{})}
	c.results[key] = entry
	c.mu.Unlock()

	result := snapshotDelegateRun(c.delegate, timeout, name, args...)
	c.mu.Lock()
	resultBytes := len(result.Stdout) + len(result.Stderr)
	if resultBytes > maxCommandSnapshotRetainedBytes-c.retainedBytes {
		result = CommandResult{Code: result.Code, Err: errCommandSnapshotBudget, Truncated: true}
		c.budgetRejects++
	} else {
		c.retainedBytes += resultBytes
	}
	entry.result = result
	close(entry.ready)
	c.mu.Unlock()
	return result
}

func (c *snapshotCommander) TrustedExecutable(name string) (string, error) {
	c.mu.Lock()
	c.trustedCalls++
	if entry, ok := c.trusted[name]; ok {
		c.trustedHits++
		c.mu.Unlock()
		<-entry.ready
		return entry.result.path, entry.result.err
	}
	entry := &trustedSnapshotEntry{ready: make(chan struct{})}
	c.trusted[name] = entry
	c.mu.Unlock()

	path, err := snapshotDelegateTrustedExecutable(c.delegate, name)
	entry.result = trustedExecutableResult{path: path, err: err}
	c.mu.Lock()
	close(entry.ready)
	c.mu.Unlock()
	return path, err
}

func (c *snapshotCommander) Stats() commandSnapshotStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return commandSnapshotStats{
		CommandCalls:  c.commandCalls,
		CommandHits:   c.commandHits,
		ExistsCalls:   c.existsCalls,
		ExistsHits:    c.existsHits,
		TrustedCalls:  c.trustedCalls,
		TrustedHits:   c.trustedHits,
		RetainedBytes: c.retainedBytes,
		BudgetRejects: c.budgetRejects,
	}
}

func commandSnapshotKey(name string, args []string) string {
	return name + "\x00" + strings.Join(args, "\x00")
}

func snapshotDelegateRun(delegate Commander, timeout time.Duration, name string, args ...string) (result CommandResult) {
	defer func() {
		if recover() != nil {
			result = CommandResult{Code: -1, Err: fmt.Errorf("collector command failed internally")}
		}
	}()
	return delegate.Run(timeout, name, args...)
}

func snapshotDelegateExists(delegate Commander, name string) (exists bool) {
	defer func() {
		if recover() != nil {
			exists = false
		}
	}()
	return delegate.Exists(name)
}

func snapshotDelegateTrustedExecutable(delegate Commander, name string) (path string, err error) {
	defer func() {
		if recover() != nil {
			path, err = "", fmt.Errorf("trusted executable lookup failed internally")
		}
	}()
	return trustedExecutable(delegate, name)
}
