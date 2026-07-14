package audit

import (
	"bufio"
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
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []passwdEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			continue
		}
		entries = append(entries, passwdEntry{Name: parts[0], UID: uid, GID: gid, Home: parts[5], Shell: parts[6]})
	}
	return entries, scanner.Err()
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
	f, err := os.Open(path)
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

func existingFiles(patterns ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		for _, path := range matches {
			if !seen[path] {
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
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

func limitedEvidence(source string, values []string, limit int) []modelEvidence {
	if limit <= 0 {
		limit = 20
	}
	var out []modelEvidence
	for i, value := range values {
		if i >= limit {
			out = append(out, modelEvidence{Source: source, Value: fmt.Sprintf("... %d more", len(values)-limit)})
			break
		}
		out = append(out, modelEvidence{Source: source, Value: truncate(value, 500)})
	}
	return out
}

// modelEvidence is kept local so helpers do not expose report-model construction.
type modelEvidence struct{ Source, Key, Value string }

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

func parseListeners(output string) []Listener {
	var out []Listener
	for _, line := range lines(output) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		protocol := strings.ToLower(fields[0])
		local := fields[4]
		if !strings.HasPrefix(protocol, "tcp") && !strings.HasPrefix(protocol, "udp") {
			continue
		}
		address, port := splitHostPortLoose(local)
		process := ""
		if len(fields) > 6 {
			process = strings.Join(fields[6:], " ")
		}
		out = append(out, Listener{Protocol: protocol, Address: address, Port: port, Scope: classifyAddress(address), Process: process})
	}
	return out
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
