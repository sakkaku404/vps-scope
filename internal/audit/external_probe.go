package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sakkaku404/vps-scope/internal/model"
)

type externalObservation struct {
	Domain      string
	Addresses   []string
	TLSPresent  bool
	TLSNotAfter time.Time
	TLSError    string
}

type ExternalProber interface {
	Observe(context.Context, string) externalObservation
}

type networkExternalProber struct{}

func (networkExternalProber) Observe(ctx context.Context, domain string) externalObservation {
	observation := externalObservation{Domain: domain}
	addresses, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		observation.TLSError = "dns lookup failed: " + err.Error()
		return observation
	}
	observation.Addresses = uniqueStrings(addresses)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	connection, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12})
	if err != nil {
		observation.TLSError = "TLS probe failed: " + err.Error()
		return observation
	}
	defer connection.Close()
	observation.TLSPresent = true
	if certificates := connection.ConnectionState().PeerCertificates; len(certificates) > 0 {
		observation.TLSNotAfter = certificates[0].NotAfter.UTC()
	}
	return observation
}

func checkExternalExposure(ctx *Context) model.Finding {
	if len(ctx.ExternalDomains) == 0 {
		return notApplicable("WORK-014", "workloads", "external DNS and TLS", "external observation is disabled by default; enable it explicitly with --external-domain")
	}
	prober := ctx.ExternalProber
	if prober == nil {
		prober = networkExternalProber{}
	}
	localAddresses := localGlobalAddresses(ctx)
	f := model.Finding{ID: "WORK-014", Category: "workloads", Status: model.Info, Facts: map[string]string{"domains": strconv.Itoa(len(ctx.ExternalDomains)), "network_access": "explicitly-enabled"}}
	if ctx.ExpectCDN && len(localAddresses) == 0 {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "CDN origin comparison requires readable local global IPv4/IPv6 addresses"
		f.Evidence = append(f.Evidence, model.Evidence{Source: "ip -o addr show scope global", Key: "local_address_evidence", Value: "unavailable"})
	}
	directOrigins, dnsFailures, tlsFailures, expiring := 0, 0, 0, 0
	overallCtx, overallCancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer overallCancel()
	for index, domain := range ctx.ExternalDomains {
		if overallCtx.Err() != nil {
			remaining := len(ctx.ExternalDomains) - index
			dnsFailures += remaining
			f.Evidence = append(f.Evidence, model.Evidence{Source: "external DNS/TLS", Key: "observation_budget_exhausted", Value: fmt.Sprintf("%d domain observations skipped after the 45s total network budget", remaining)})
			break
		}
		probeCtx, cancel := context.WithTimeout(overallCtx, 10*time.Second)
		observation := prober.Observe(probeCtx, domain)
		cancel()
		if len(observation.Addresses) == 0 {
			dnsFailures++
			f.Evidence = append(f.Evidence, model.Evidence{Source: "external DNS/TLS", Key: "observation_failed", Value: fmt.Sprintf("domain=%s error=%s", domain, truncate(observation.TLSError, 180))})
			continue
		}
		matchesLocal := intersectsAddresses(observation.Addresses, localAddresses)
		judgment := "dns-addresses-do-not-match-local-interface"
		if matchesLocal {
			judgment = "dns-publishes-local-server-address"
			if ctx.ExpectCDN {
				directOrigins++
				f.Status, f.Severity = model.Risk, model.High
				judgment = "cdn-expected-but-origin-address-published"
			}
		}
		tlsState := "unavailable"
		if observation.TLSPresent {
			tlsState = "valid-handshake"
			if !observation.TLSNotAfter.IsZero() {
				days := int(observation.TLSNotAfter.Sub(ctx.Now()).Hours() / 24)
				tlsState += fmt.Sprintf(" expires_in_days=%d", days)
				if days < 14 {
					expiring++
					if f.Status != model.Risk {
						f.Status, f.Severity = model.Risk, model.Medium
					}
				}
			}
		} else if observation.TLSError != "" {
			tlsState = "failed:" + truncate(observation.TLSError, 120)
			tlsFailures++
		} else {
			tlsFailures++
		}
		f.Evidence = append(f.Evidence, model.Evidence{Source: "external DNS/TLS", Key: "domain_observation", Value: fmt.Sprintf("domain=%s addresses=%s tls=%s judgment=%s", domain, strings.Join(observation.Addresses, ","), tlsState, judgment)})
	}
	f.Facts["local_global_addresses"] = strconv.Itoa(len(localAddresses))
	f.Facts["direct_origin_matches"] = strconv.Itoa(directOrigins)
	f.Facts["probe_failures"] = strconv.Itoa(dnsFailures)
	f.Facts["tls_probe_failures"] = strconv.Itoa(tlsFailures)
	f.Facts["expiring_tls"] = strconv.Itoa(expiring)
	if (dnsFailures > 0 || tlsFailures > 0) && f.Status != model.Risk {
		f.Status, f.Unavailable = model.Unknown, true
		f.Error = "one or more explicitly requested external DNS or TLS observations failed"
	}
	return f
}

func localGlobalAddresses(ctx *Context) []string {
	if !ctx.Commander.Exists("ip") {
		return nil
	}
	r := ctx.Commander.Run(6*time.Second, "ip", "-o", "addr", "show", "scope", "global")
	if r.Err != nil || r.Truncated {
		return nil
	}
	var out []string
	for _, line := range lines(r.Stdout) {
		fields := strings.Fields(line)
		for index, field := range fields {
			if (field == "inet" || field == "inet6") && index+1 < len(fields) {
				address := strings.SplitN(fields[index+1], "/", 2)[0]
				if net.ParseIP(address) != nil {
					out = append(out, address)
				}
			}
		}
	}
	return uniqueStrings(out)
}

func intersectsAddresses(left, right []string) bool {
	seen := map[string]bool{}
	for _, value := range left {
		if ip := net.ParseIP(value); ip != nil {
			seen[ip.String()] = true
		}
	}
	for _, value := range right {
		if ip := net.ParseIP(value); ip != nil && seen[ip.String()] {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
