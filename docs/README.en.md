# VPS Scope

VPS Scope is a security and runtime auditor for Ubuntu and Debian VPS hosts used for self-hosted proxies, tunnels, and privacy networks. It understands sing-box, Xray, Reality, Hysteria2, proxy panels, reverse proxies, and Docker deployment relationships instead of treating every public port as the same kind of exposure.

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](../LICENSE)

[中文](../README.md) · [Proxy compatibility](PROXY-COMPATIBILITY.md) · [Compatibility matrix](COMPATIBILITY-MATRIX.md) · [Privacy](PRIVACY.md) · [Checks](CHECKS.md) · [Design notes](DESIGN.md) · [Testing](TESTING.md)

## Why VPS Scope exists

This project began with a hands-on review of [vernu/vps-audit](https://github.com/vernu/vps-audit). That script makes a VPS check approachable, but on real servers, reading configuration files directly, applying service or port-count thresholds, and treating failed collection as safe can produce false positives and missed findings.

VPS Scope is not a fork of that project; its code and detection implementation were developed independently. VPS Scope redesigns and implements its checks around effective system state and reviewable evidence: failed collection becomes `UNKNOWN`, listeners are separated into public, private, loopback, and container-published scopes, and findings are interpreted in the context of the server's role. The original comparison used commit [`e39115f`](https://github.com/vernu/vps-audit/tree/e39115f85414073ee5cf96bea5e3b1b811375a2a), whose script SHA-256 is `db1134574f3c8df30bc9ac10821d207dda13ae22b0905964e2c0bc7cc71192e6`.

Thanks to OpenAI Codex for writing most of the Go—it has currently written far more Go than the maintainer, who is still working on understanding it.

## What it looks at

The audit covers the parts of a small VPS that are easy to overlook: system resources, account and password context, effective SSH settings, listeners and active connections, firewall rules, Fail2ban/CrowdSec, login activity, pending updates, systemd services, Docker isolation, TLS certificates, file permissions, and common persistence locations.

Proxy hosts get additional context for:

- sing-box, Xray, Hysteria2, TUIC, Trojan, and Shadowsocks cores and ingress
- S-UI, 3x-ui/x-ui, Marzban, Hiddify, and Outline management/ingress relations
- direct and reverse-proxied panel exposure, including root/default paths and plaintext panel endpoints; a hidden URL path is not treated as access control
- native read-only configuration checks for sing-box and Xray
- publicly bound Clash API, V2Ray API, and similar control endpoints
- permissions on panel databases and proxy configuration
- systemd identity, capabilities, isolation, and file-descriptor limits
- UDP buffer and error-counter context for Hysteria2 and TUIC workloads
- config-to-listener relations across TCP/UDP transport, process ownership, exposure scope, merged UFW/effective nftables INPUT policy, and stale allows left without a live listener
- management/subscription ports reused by proxy ingress, disabled inbounds that remain live, and unexplained public listeners owned by a panel or core
- Reality semantic completeness without exporting private keys, SNI values, targets, or short IDs
- privacy-safe category counts for authentication, handshake, DNS, TLS, routing, panel login, API/subscription abuse, web probes, and fatal log signals
- per-ingress established TCP connection snapshots for comparison and baselines, without generic attack-count thresholds
- WireGuard interface, UDP listener, firewall, and recent-handshake counts without peer keys or endpoints
- Nginx, Caddy, and HAProxy chains from public frontends to panel or proxy backends, including public management routes and over-broad backend listeners
- Docker Compose project/service context, effective mounts, Docker socket access, privileged/host namespaces, added capabilities, and published paths across INPUT, FORWARD, and DOCKER-USER
- optional external DNS/TLS observation, disabled by default and enabled only when domains are explicitly supplied, with CDN-origin address comparison

Detecting a product is not the same as proving which port is its management plane. Container networking, reverse proxies, and unknown panel layouts remain `UNKNOWN` when the evidence cannot support a safe conclusion. See [proxy compatibility](PROXY-COMPATIBILITY.md) for the tested scope.

Results are based on the state the system is actually using where possible. For example, SSH settings come from `sshd -T`, not from grepping one configuration file. Network listeners are separated into public, private, loopback, IPv4, IPv6, and container-published endpoints.

VPS Scope uses four result states:

- `PASS` — the check ran and the expected condition was met
- `RISK` — the collected evidence needs attention
- `INFO` — useful context or inventory, but not a problem by itself
- `UNKNOWN` — the check could not reach a reliable conclusion

There is no security score, and the tool does not make changes or offer an automatic fix mode.

## Install

Run one audit without installing anything:

```bash
curl -fsSL https://sakkaku404.github.io/vps-scope/run.sh | sudo bash
```

That one command downloads the current release, verifies its SHA-256, runs the audit, and removes the temporary binary. There is no second command.

To install `vps-scope` for repeated use:

```bash
curl -fsSL https://raw.githubusercontent.com/sakkaku404/vps-scope/main/install.sh | sudo bash
```

Then run `sudo vps-scope`. The installer detects amd64 or arm64 automatically and verifies the release checksum before installing anything. When `cosign` is already available it also verifies the GitHub Actions keyless signature; set `VPS_SCOPE_REQUIRE_SIGNATURE=1` to make that signature mandatory. See [release artifact verification](SUPPLY-CHAIN.md) for the trust model and manual verification command.

If you prefer to inspect scripts before running them, download them first or use the manual steps below.

### Manual install

Download the binary for your architecture from [Releases](https://github.com/sakkaku404/vps-scope/releases). For example, on an amd64 server:

```bash
curl -LO https://github.com/sakkaku404/vps-scope/releases/latest/download/vps-scope_linux_amd64
curl -LO https://github.com/sakkaku404/vps-scope/releases/latest/download/SHA256SUMS
grep 'vps-scope_linux_amd64$' SHA256SUMS | sha256sum -c -
chmod +x vps-scope_linux_amd64
sudo ./vps-scope_linux_amd64
```

Use `vps-scope_linux_arm64` on an arm64 server.

## Build from source

VPS Scope has no third-party Go dependencies.

```bash
go build -trimpath -o vps-scope ./cmd/vps-scope
sudo ./vps-scope
```

Running it without arguments opens a short setup prompt with Chinese and English output. It can also run non-interactively:

```bash
sudo ./vps-scope audit --lang en --profile general
sudo ./vps-scope audit --lang en --profile proxy
sudo ./vps-scope audit --profile custom --expect-public 22/tcp,443/tcp
sudo ./vps-scope audit --profile proxy --external-domain panel.example.com --expect-cdn
```

The standard audit is suitable for routine use and avoids recursive filesystem scans. Use `sudo vps-scope audit --deep` to add SUID/SGID, file-capability, and installed-package integrity checks. Deep-only checks that were not run are shown as skipped, never as `PASS`.

Profiles give the audit some context about the server's job. Built-in choices include `general`, `web`, `proxy`, `docker`, and `mixed`. Custom public listeners can be declared as `PORT/tcp` or `PORT/udp`; this affects exposure checks, not the rest of the audit.

External DNS/TLS observation is disabled by default. `--external-domain` explicitly enables network access, while `--expect-cdn` declares that those domains should sit behind a CDN. The audit compares DNS results with local global addresses and observes TLS on port 443; historical DNS, cloud firewalls, and true off-host reachability still require a second vantage point.

## Reports

Interactive mode defaults to showing the result in the terminal and saving a full report bundle. Saved reports go to `~/vps-scope-reports/HOST/TIMESTAMP/`; `~/vps-scope-reports/latest` points to the newest one. Each run uses a distinct directory and refuses to overwrite an existing bundle. The completion message explains each file and prints a copy-paste download command.

Start with the action summary rather than the raw count: it separates confirmed high-priority risks, likely availability problems, routine maintenance, and evidence gaps. This is a reading aid only; it never changes a finding's `PASS` / `RISK` / `INFO` / `UNKNOWN` state. Terminal and Markdown reports show a small set of key evidence first, while the full evidence remains available in verbose output, JSON, and collapsible Markdown sections.

```bash
sudo vps-scope report show  # show the latest report again
sudo vps-scope report list  # list saved reports
sudo vps-scope report path  # print the latest report directory
```

Reports can also be written to an explicit location as JSON, plain text, Markdown, HTML, or a full bundle:

```bash
sudo ./vps-scope audit --format bundle --output ./reports/sgp
```

A bundle contains the canonical JSON report, human-readable formats, and a SHA-256 manifest. The HTML report is a self-contained offline page with status filters, search, and collapsible evidence; it loads no external scripts or fonts. Report files are created with restrictive permissions on Linux.

JSON reports can be rendered again without reconnecting to the server:

```bash
vps-scope render --lang zh-CN --format html --output report.zh-CN.html report.json
vps-scope render --lang en --format markdown --output report.en.md report.json
```

The `redact` command replaces hostnames, addresses, domains, usernames, and key fingerprints with stable placeholders before a report is shared:

```bash
vps-scope redact --format markdown --output public.md report.json
```

VPS Scope does not copy passwords, tokens, private keys, subscription paths, SSH key comments, or full process arguments into a report. It also refuses to export application blobs that may combine certificates with private keys. See the [privacy notes](PRIVACY.md) for the complete boundary.

## Comparing runs

Use `diff` to see what changed on one server, or `fleet` for a quick comparison across several machines:

```bash
vps-scope diff old.json new.json  # security regressions and improvements first
vps-scope diff --all old.json new.json  # also include same-status raw evidence changes
vps-scope fleet west.json sgp.json tw.json japan.json
```

For long-lived hosts, create a baseline and highlight added or removed public listeners, SSH keys, firewall rules, panel/proxy endpoints, containers, and proxy services. Baseline v2 binds to the host StableID and removes volatile listener PID/fd data; legacy v1 files remain readable with a weaker-identity warning:

```bash
vps-scope baseline create report.json baseline.json
vps-scope baseline check baseline.json report-new.json
```

Checks keep the same IDs in Chinese and English, so reports remain comparable regardless of display language.

## Other commands

```text
doctor      show which audit sources are available on this host
checks      list checks and their IDs
explain     explain a check and its recommendation
render      turn a JSON report into another language or format
redact      make a report safer to share
report      view and manage saved reports
verify      verify the files in a report bundle
version     show build information
```

## Support

VPS Scope currently supports Ubuntu and Debian on Linux `amd64` and `arm64`. Some checks use system tools such as `ss`, `journalctl`, `ufw`, `firewall-cmd`, `nft`, `iptables`, `fail2ban-client`, `cscli`, `dpkg`, `docker`, `coredumpctl`, or `sqlite3`. If one is unavailable, the affected result is reported as unavailable rather than silently treated as safe.

VPS Scope is useful for reviewing a server, but it cannot prove that a machine is clean or see cloud firewall rules from inside the guest. See [the design notes](DESIGN.md) for the current trust boundary and known limitations.

## Development

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/vps-scope
```

Contributions and reproducible Ubuntu/Debian fixtures are welcome. Please do not attach an unredacted server report to a public issue.

Use GitHub's private vulnerability reporting for security problems in VPS Scope itself. See [SECURITY.md](../SECURITY.md) for details.

## License

MIT
