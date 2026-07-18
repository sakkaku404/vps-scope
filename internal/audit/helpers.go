package audit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type passwdEntry struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

func readPasswd() ([]passwdEntry, error) {
	f, err := openRegularReadOnly("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsePasswd(f)
}

func parsePasswd(reader io.Reader) ([]passwdEntry, error) {
	var entries []passwdEntry
	limited := &io.LimitedReader{R: reader, N: (4 << 20) + 1}
	scanner := bufio.NewScanner(limited)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 7 {
			return nil, fmt.Errorf("/etc/passwd line %d is malformed", lineNumber)
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("/etc/passwd line %d has an invalid UID or GID", lineNumber)
		}
		entries = append(entries, passwdEntry{Name: parts[0], UID: uid, GID: gid, Home: parts[5], Shell: parts[6]})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("/etc/passwd exceeds 4 MiB safety limit")
	}
	return entries, nil
}

func loginShell(shell string) bool {
	return shell != "" && !containsAny(shell, "nologin", "/false", "/sync", "/shutdown", "/halt")
}

func modeString(info fs.FileInfo) string { return fmt.Sprintf("%04o", info.Mode().Perm()) }

func tooOpen(info fs.FileInfo, forbidden fs.FileMode) bool { return info.Mode().Perm()&forbidden != 0 }

func readSmall(path string, limit int64) (string, error) {
	if limit < 0 {
		return "", fmt.Errorf("invalid read limit")
	}
	f, err := openRegularReadOnly(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	// Read from the descriptor we inspected. Re-opening by path here would
	// allow a concurrent replacement to bypass the size guard.
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("file larger than %d bytes", limit)
	}
	return string(data), nil
}

const (
	maxFileDiscoveryMatches = 4096
	fileDiscoveryEntryLimit = 16 << 10
	procDirectoryEntryLimit = 64 << 10
)

var errFileDiscoveryLimit = errors.New("file discovery safety limit exceeded")

// discoverExistingFiles expands a small, fixed set of local configuration
// patterns without filepath.Glob's unbounded directory allocation. Both the
// number of directory entries examined and the number of unique matches are
// bounded. Callers must propagate an error as incomplete evidence rather than
// silently treating the returned prefix as a complete inventory.
func discoverExistingFiles(maxMatches int, patterns ...string) ([]string, error) {
	return discoverExistingFilesWithBudget(maxMatches, fileDiscoveryEntryLimit, patterns...)
}

func discoverExistingFilesWithBudget(maxMatches, maxEntries int, patterns ...string) ([]string, error) {
	if maxMatches <= 0 || maxMatches > maxFileDiscoveryMatches || maxEntries <= 0 {
		return nil, fmt.Errorf("invalid file discovery budget")
	}
	state := fileDiscoveryState{
		maxMatches: maxMatches,
		maxEntries: maxEntries,
		seen:       make(map[string]bool, min(maxMatches, 64)),
	}
	for _, pattern := range patterns {
		if err := state.expand(pattern); err != nil {
			return nil, err
		}
	}
	sort.Strings(state.matches)
	return state.matches, nil
}

type fileDiscoveryState struct {
	maxMatches int
	maxEntries int
	entries    int
	matches    []string
	seen       map[string]bool
}

func (s *fileDiscoveryState) expand(pattern string) error {
	clean := filepath.Clean(pattern)
	if !filepath.IsAbs(clean) {
		return fmt.Errorf("file discovery pattern must be absolute")
	}
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	rest = strings.TrimLeft(rest, string(filepath.Separator))
	segments := strings.Split(rest, string(filepath.Separator))
	root := volume + string(filepath.Separator)
	if err := s.walk(root, segments, 0); err != nil {
		return fmt.Errorf("discover %q: %w", pattern, err)
	}
	return nil
}

func (s *fileDiscoveryState) walk(current string, segments []string, index int) error {
	if index == len(segments) {
		if _, err := os.Lstat(current); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if s.seen[current] {
			return nil
		}
		if len(s.matches) >= s.maxMatches {
			return fmt.Errorf("%w: more than %d matching paths", errFileDiscoveryLimit, s.maxMatches)
		}
		s.seen[current] = true
		s.matches = append(s.matches, current)
		return nil
	}

	segment := segments[index]
	if !strings.ContainsAny(segment, "*?[") {
		next := filepath.Join(current, segment)
		if index+1 < len(segments) {
			info, err := os.Stat(next)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if !info.IsDir() {
				return nil
			}
		}
		return s.walk(next, segments, index+1)
	}

	// #nosec G304 -- current is derived from fixed in-program glob patterns;
	// traversal and returned entries are bounded by fileDiscoveryState.
	dir, err := os.Open(current)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	defer dir.Close()
	for {
		remaining := s.maxEntries - s.entries
		if remaining <= 0 {
			extra, readErr := dir.ReadDir(1)
			if len(extra) > 0 {
				return fmt.Errorf("%w: more than %d directory entries", errFileDiscoveryLimit, s.maxEntries)
			}
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return readErr
			}
			return nil
		}
		batchSize := min(remaining, 256)
		entries, readErr := dir.ReadDir(batchSize)
		s.entries += len(entries)
		for _, entry := range entries {
			matched, matchErr := filepath.Match(segment, entry.Name())
			if matchErr != nil {
				return matchErr
			}
			if !matched {
				continue
			}
			next := filepath.Join(current, entry.Name())
			if index+1 < len(segments) {
				info, statErr := os.Stat(next)
				if statErr != nil {
					// A wildcard directory segment commonly also matches broken
					// file aliases (for example masked or removed systemd units).
					// They cannot contain the remaining segments, so skip them.
					if errors.Is(statErr, fs.ErrNotExist) {
						continue
					}
					return statErr
				}
				if !info.IsDir() {
					continue
				}
			}
			if err := s.walk(next, segments, index+1); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

func lines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

func sinceArg(d time.Duration) string {
	seconds := int64(d.Seconds())
	if seconds%86400 == 0 {
		return fmt.Sprintf("-%dd", seconds/86400)
	}
	if seconds%3600 == 0 {
		return fmt.Sprintf("-%dh", seconds/3600)
	}
	return fmt.Sprintf("-%ds", seconds)
}

type Listener struct {
	Protocol string
	Address  string
	Port     string
	Scope    string
	Process  string
}

func parseListeners(output string) ([]Listener, error) {
	var out []Listener
	for index, line := range lines(output) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return nil, fmt.Errorf("ss listener row %d is malformed", index+1)
		}
		protocol := strings.ToLower(fields[0])
		local := fields[4]
		if !strings.HasPrefix(protocol, "tcp") && !strings.HasPrefix(protocol, "udp") {
			return nil, fmt.Errorf("ss listener row %d has unsupported protocol %q", index+1, fields[0])
		}
		address, port := splitHostPortLoose(local)
		if !validPort(port) || classifyAddress(address) == "unknown" {
			return nil, fmt.Errorf("ss listener row %d has an invalid local endpoint", index+1)
		}
		process := ""
		if len(fields) > 6 {
			process = strings.Join(fields[6:], " ")
		}
		out = append(out, Listener{Protocol: protocol, Address: address, Port: port, Scope: classifyAddress(address), Process: process})
	}
	return out, nil
}

func splitHostPortLoose(value string) (string, string) {
	if strings.HasPrefix(value, "[") {
		if host, port, err := net.SplitHostPort(value); err == nil {
			return host, port
		}
	}
	idx := strings.LastIndex(value, ":")
	if idx < 0 {
		return value, ""
	}
	return strings.Trim(value[:idx], "[]"), value[idx+1:]
}

func classifyAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "*" || address == "0.0.0.0" || address == "::" || address == "" {
		return "public-wildcard"
	}
	address = strings.Trim(address, "[]")
	address = strings.ReplaceAll(address, "]", "")
	zoneLess, _, _ := strings.Cut(address, "%")
	ip := net.ParseIP(zoneLess)
	if ip == nil {
		return "unknown"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "private"
	}
	return "public"
}
