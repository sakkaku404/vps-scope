# VPS Scope

> A security and runtime auditor for VPS hosts running self-hosted proxies, tunnels, and privacy networks.

VPS Scope runs on Ubuntu and Debian. It begins with a complete host review covering accounts and SSH, sudo, firewalls, intrusion protection, system updates, packages, systemd services, Docker, TLS certificates, logs, resource reliability, and suspicious persistence. Those results remain useful even when the server does not run a proxy.

On a proxy host, that Linux baseline is only the start. A public port may be an expected Reality, Hysteria2, or Shadowsocks ingress, or it may be a management panel, subscription endpoint, or internal API that should not be open to the entire internet.

VPS Scope therefore joins the host and workload evidence into one view: panel databases and proxy configuration describe what should exist; systemd, Docker, processes, and live listeners show what is actually running; host firewall and reverse-proxy evidence show how it may be reached. The report tries to answer a few practical questions:

- Are SSH, accounts, firewall policy, updates, and system services showing a confirmed risk?
- Are proxy ingresses actually listening and handled correctly by the firewall?
- Are S-UI, 3x-ui, or other management planes unintentionally public?
- Do configuration, panel state, processes, and listeners agree?
- Could TLS, logs, resource pressure, or a failed service interrupt the proxy?

It is not just product detection and it is not a port scan with a Linux checklist attached. Ordinary VPS hosts still receive the full host baseline; proxy hosts receive the additional relationships among ingress, management, subscriptions, control APIs, containers, and reverse proxies.

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/run.sh | sudo bash
```

The prompt supports Simplified Chinese, English, Russian, and Persian. Non-interactive runs can use `--lang zh-CN`, `--lang en`, `--lang ru-RU`, or `--lang fa-IR`.

By default, the terminal shows the conclusion and the VPS keeps a complete report bundle. VPS Scope has no repair mode and does not change SSH, firewall rules, services, accounts, or packages.

The default audit also does not execute binaries belonging to S-UI, 3x-ui, sing-box, Xray, Nginx, or other audited workloads. It reads configuration, databases, and system runtime state. Only an explicit `--native-self-test` runs those local programs after ownership and permission checks; this executes third-party code with the audit process's privileges, which means root when the audit uses `sudo`.

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](../LICENSE)

[简体中文](../README.md) · **English** · [Русский](README.ru.md) · [فارسی](README.fa.md)

[Proxy compatibility](PROXY-COMPATIBILITY.md) · [Compatibility matrix](COMPATIBILITY-MATRIX.md) · [Privacy](PRIVACY.md) · [Checks](CHECKS.md) · [Design notes](DESIGN.md) · [Testing](TESTING.md)

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
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/run.sh | sudo bash
```

The prompt supports Simplified Chinese, English, Russian, and Persian. For non-interactive use, pass `--lang zh-CN`, `--lang en`, `--lang ru-RU`, or `--lang fa-IR`.

That one command downloads the current release, verifies its SHA-256, runs the audit, and removes the temporary binary. There is no second command.

The runner and installer are themselves signed Release assets. Once started, they always verify the downloaded binary's checksum and, when `cosign` is available, its GitHub Actions keyless signature. Without `cosign`, an interactive terminal must type `continue` before falling back to checksum-only mode, while non-interactive use stops by default. Automation should set `VPS_SCOPE_ALLOW_UNSIGNED=1` only after accepting that trade-off; set `VPS_SCOPE_REQUIRE_SIGNATURE=1` to forbid an unsigned binary fallback.

To install `vps-scope` for repeated use:

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/install.sh | sudo bash
```

Then run `sudo vps-scope`. The installer detects amd64 or arm64 automatically. An explicitly selected version is bound to that exact tag identity during signature verification. Releases also include the project license and a third-party notice generated from the modules linked into the binary.

The one-line `curl | bash` command cannot authenticate its bootstrap script before execution. For a fully verified path, download a pinned script and its Sigstore bundle, verify the script, and then let it verify the binary. See [release artifact verification](SUPPLY-CHAIN.md) for the exact commands and trust boundary.

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

Building from source requires the Go toolchain. Go module dependencies are downloaded according to `go.mod` and `go.sum`; the released binary does not require those libraries to be installed separately on the VPS.

```bash
go build -trimpath -o vps-scope ./cmd/vps-scope
sudo ./vps-scope
```

Running it without arguments opens a short setup prompt with Chinese, English, Russian, and Persian output. It can also run non-interactively:

```bash
sudo ./vps-scope audit --lang en --profile general
sudo ./vps-scope audit --lang en --profile proxy
sudo ./vps-scope audit --lang ru-RU --profile proxy
sudo ./vps-scope audit --lang fa-IR --profile proxy
sudo ./vps-scope audit --profile custom --expect-public 22/tcp,443/tcp
sudo ./vps-scope audit --profile proxy --external-domain panel.example.com --expect-cdn
# Optional: execute trusted local workload binaries for their native self-tests
sudo ./vps-scope audit --native-self-test
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

`report.json` is the common audit record behind every renderer. It contains the 55 stable check IDs, statuses, severities, and reason codes, plus a typed deployment view of components, service endpoints, proxy/reverse-proxy links, and evidence coverage. HTML, Markdown, history comparison, and baselines consume that structure instead of parsing terminal prose. Older schema-1.0 reports remain readable, while `vps-scope verify` checks both integrity and the semantic contract of current reports.

JSON reports can be rendered again without reconnecting to the server:

```bash
vps-scope render --lang zh-CN --format html --output report.zh-CN.html report.json
vps-scope render --lang en --format markdown --output report.en.md report.json
```

Both a standalone report and a complete bundle can be verified. Bundle verification checks the declared file set, undeclared files, and SHA-256 values; current reports are also checked for the complete 55-ID contract, consistent statuses and severities, summary counts, and reason codes:

```bash
vps-scope verify report.json
vps-scope verify ./reports/sgp
```

Matching hashes prove that files match their manifest. Semantic verification additionally detects a report that was already incomplete or internally inconsistent when it was produced.

The `redact` command replaces hostnames, addresses, domains, usernames, and key fingerprints with stable placeholders before a report is shared:

```bash
vps-scope redact --format markdown --output public.md report.json
```

For a panel compatibility report, create the narrower support bundle:

```bash
vps-scope support report.json
```

It contains an already-redacted report, allowlisted OS and panel schema/capability metadata, a privacy notice, and a SHA-256 manifest. It does not read or package raw databases, configuration files, private keys, tokens, or UUIDs. Review every file before sharing.

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

Checks keep the same IDs in every language, so reports remain comparable regardless of display language.

## Declared policy and second-vantage observation

Automatic discovery can explain common panels and proxy ingress, but it cannot know your intended source restrictions, TLS/path requirements, or IPv4/IPv6 egress. A policy file records that intent without storing proxy credentials or changing the host:

```bash
vps-scope policy init policy.json
# edit the endpoint roles, exposure and egress expectations
vps-scope policy validate policy.json
sudo vps-scope audit --profile proxy --policy policy.json
```

With a policy, `WORK-015` and `WORK-016` compare endpoint exposure, allowed sources, TLS/path requirements, interfaces, and DNS against live evidence. Without one, ordinary discovery still runs, but inference is not presented as operator-approved policy.

To check what another network vantage can actually reach, create a credential-free plan on the audited host, run it on another controlled VPS, and import the result:

```bash
vps-scope probe plan --target 203.0.113.10 --output plan.json report.json
vps-scope probe run --output observation.json plan.json
vps-scope probe import --output report-observed.json report.json observation.json
```

TCP observations are compared with declared exposure. UDP remains explicitly indeterminate because sending an arbitrary datagram is not proof that a real Hysteria2, TUIC, WireGuard, or other protocol handshake succeeded.

`WORK-017` also compares detected 3x-ui, sing-box, and Xray versions with a bundled snapshot of official upstream security advisories. It performs no network request. A matched affected range is `RISK`; a missing version or stale database is `UNKNOWN`. No match means only that the bundled set contains no matching advisory, not that the product is vulnerability-free.

## Other commands

```text
doctor      show which audit sources are available on this host
checks      list checks and their IDs
explain     explain a check and its recommendation
render      turn a JSON report into another language or format
redact      make a report safer to share
support     create a privacy-safe compatibility support bundle
report      view and manage saved reports
verify      verify report semantics and report-bundle integrity
policy      create or validate explicit deployment intent
probe       plan, run, and import a second-vantage TCP observation
version     show build information
```

## Support

VPS Scope currently supports Ubuntu and Debian on Linux `amd64` and `arm64`. Some checks use system tools such as `ss`, `journalctl`, `ufw`, `firewall-cmd`, `nft`, `iptables`, `fail2ban-client`, `cscli`, `dpkg`, `docker`, or `coredumpctl`. If one is unavailable, the affected result is reported as unavailable rather than silently treated as safe. Panel databases are read by the embedded read-only SQLite implementation; the target does not need `sqlite3`.

VPS Scope is useful for reviewing a server, but it cannot prove that a machine is clean or see cloud firewall rules from inside the guest. See [the design notes](DESIGN.md) for the current trust boundary and known limitations.

The 1.x guarantees for report schemas, check IDs, reason codes, public commands, exit behavior, and older reports are documented in the [stability and compatibility policy](STABILITY.md). The complete policy/probe workflow is in [Deployment policy and external observation](POLICY-AND-PROBE.md). Human-readable layout may evolve; automation should consume canonical JSON.

### How release candidates are validated

Compilation is not the acceptance criterion. The current laboratory uses five independent VPS roles: Debian 13 with S-UI, Debian 12 with 3x-ui/Xray, Ubuntu 24.04 with Docker/Nginx, a near-stock Debian 13 host, and a constrained Debian 13 host with 512 MiB of memory. Every role runs a standard audit, deep audit, bundle verification, and redacted support bundle. The Docker role also exercises a 32-container inventory, DOCKER-USER/forwarding semantics, and a custom INPUT chain; the hosts then run a TCP/UDP reachability matrix.

The latest candidate completed two consecutive rounds with 55 findings per host and no drift in finding status, severity, reason code, components, or endpoint relationships. All 16 cross-host TCP/UDP probes passed and the laboratory left no tagged firewall rules or helper processes behind. Deep audits took about 25–51 seconds, including the 512 MiB host. These are controlled laboratory observations, not performance guarantees for every distribution, panel version, or cloud network. See [Testing](TESTING.md) and [Release readiness](READINESS.md) for the reproducible contract.

## Why VPS Scope exists

This project began with a hands-on review of [vernu/vps-audit](https://github.com/vernu/vps-audit). That script makes a VPS check approachable, but on real servers, reading configuration files directly, applying service or port-count thresholds, and treating failed collection as safe can produce false positives and missed findings.

VPS Scope is not a fork of that project; its code and detection implementation were developed independently. VPS Scope redesigns and implements its checks around effective system state and reviewable evidence: failed collection becomes `UNKNOWN`, listeners are separated into public, private, loopback, and container-published scopes, and findings are interpreted in the context of the server's role. The original comparison used commit [`e39115f`](https://github.com/vernu/vps-audit/tree/e39115f85414073ee5cf96bea5e3b1b811375a2a), whose script SHA-256 is `db1134574f3c8df30bc9ac10821d207dda13ae22b0905964e2c0bc7cc71192e6`.

Thanks to OpenAI Codex for writing most of the Go—it has currently written far more Go than the maintainer, who is still working on understanding it.

## Development

```bash
go test -count=1 ./...
go vet ./...
staticcheck ./...
gosec -quiet ./...
govulncheck ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/vps-scope
```

Contributions and reproducible Ubuntu/Debian fixtures are welcome. Please do not attach an unredacted server report to a public issue.

Use GitHub's private vulnerability reporting for security problems in VPS Scope itself. See [SECURITY.md](../SECURITY.md) for details.

## License

MIT
