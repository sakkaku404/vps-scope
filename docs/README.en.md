# VPS Scope

> A security and runtime auditor for VPS hosts running self-hosted proxies, tunnels, and privacy networks.

VPS Scope runs on Ubuntu and Debian. It begins with a broad host-security baseline covering accounts and SSH, sudo, firewalls, intrusion protection, system updates, packages, systemd services, Docker, TLS certificates, logs, resource reliability, and suspicious persistence. Those results remain useful even when the server does not run a proxy.

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

This command verifies the downloaded file's SHA-256 and then runs it. If `cosign` is not installed, it prints one short warning that the publisher signature was not verified; it no longer asks for `continue`.

The prompt supports Simplified Chinese, English, Russian, and Persian. Non-interactive runs can use `--lang zh-CN`, `--lang en`, `--lang ru-RU`, or `--lang fa-IR`.

To skip the prompts, put audit flags after `bash -s --`. Leading flags are automatically treated as `audit` arguments:

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/run.sh | sudo bash -s -- --lang en --profile proxy
```

By default, the result is shown only in the terminal and no report files are written. Choose output option 2 or 3 to save HTML, Markdown, and JSON reports. VPS Scope has no repair mode and does not change SSH, firewall rules, services, accounts, or packages.

The default audit also does not execute binaries belonging to S-UI, 3x-ui, sing-box, Xray, Nginx, or other audited workloads. It reads configuration, databases, and system runtime state. Only an explicit `--native-self-test` runs those local programs after ownership and permission checks; this executes third-party code with the audit process's privileges, which means root when the audit uses `sudo`.

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](../LICENSE)

[简体中文](../README.md) · **English** · [Русский](README.ru.md) · [فارسی](README.fa.md)

[Proxy compatibility](PROXY-COMPATIBILITY.md) · [Compatibility matrix](COMPATIBILITY-MATRIX.md) · [Privacy](PRIVACY.md) · [Checks](CHECKS.md) · [Design notes](DESIGN.md) · [Testing](TESTING.md)

## A real example

This excerpt comes from a test VPS running S-UI 1.5.3 and sing-box. Addresses and unrelated details have been removed:

```text
Proxy VPS assessment
────────────────────────────────────────────────────────────────────
Detected: S-UI, sing-box
Proxy ingress     PASS
  4 proxy ingresses confirmed; configuration, listeners, and firewall agree.
Management plane  RISK/HIGH
  S-UI 56709/tcp · public wildcard · firewall allows · TLS enabled
  non-default path · still reachable from the whole internet
Configuration     INFO
  Configuration was parsed statically; no panel or proxy binary was executed.

Proxy ingress:
  443/tcp    sing-box/vless (reality)       public · allowed · PASS
  443/udp    sing-box/hysteria2             public · allowed · PASS
  32003/tcp  sing-box/shadowsocks           public · allowed · PASS
  32003/udp  sing-box/shadowsocks           public · allowed · PASS
```

One panel and core process can own several public ports. A general VPS audit may describe all of them simply as open ports. VPS Scope relates the panel database, proxy configuration, live processes, listeners, and firewall so that expected proxy ingress is not confused with a management panel that should be restricted.

## Saving and opening a full report

The default run writes no report files. Choose output option 2 or 3, or use `--format bundle`, to save one audit in four formats plus an integrity manifest:

```text
report.en.html   recommended; download and open in a browser
report.en.txt    terminal text
report.en.md     complete Markdown report
report.json      canonical machine-readable data for comparison and baselines
manifest.json    SHA-256 manifest for the four report files
```

After saving, the program shows a stable `vps-scope-reports/latest/report.en.html` path first. For root this is normally `/root/vps-scope-reports/latest/report.en.html`; other users should use the absolute path printed by the program. The easiest download method is the SFTP browser in your SSH client. You can also run this on your own computer:

```bash
scp <SSH_HOST>:'/root/vps-scope-reports/latest/report.en.html' .
```

Replace `<SSH_HOST>` with the IP address, domain, or SSH alias you normally use, including the same port, identity file, or ssh-agent settings. The VPS cannot discover where your private key is stored. Report files remain after a one-line temporary run, but the downloaded program is removed when that run exits. Only installed copies can use `sudo vps-scope report show`, `report path`, `report list`, or `verify` later.

## What VPS Scope checks

### Proxy ingress and management planes

- distinguishes proxy ingress, management panels, subscription endpoints, and control APIs
- relates protocol configuration to TCP/UDP listeners, process ownership, and IPv4/IPv6 firewall evidence
- finds configured-but-missing listeners, blocked ingress, process mismatches, and disabled ingress that remains live
- identifies panels that listen publicly, stay on loopback, or are exposed through Nginx, Caddy, or HAProxy
- reports root/default paths and TLS posture without treating a hidden path as access control

### Configuration and runtime

- parses sing-box and Xray configuration statically by default; native self-tests are explicit opt-in
- compares S-UI and 3x-ui/x-ui databases, generated configuration, processes, and listeners
- checks the runtime relationships of Reality, Hysteria2, TUIC, Trojan, Shadowsocks, WireGuard, and OpenVPN
- counts authentication, handshake, DNS, TLS, routing, and panel-login signals without copying raw logs or user data
- checks certificate validity, renewal scheduling, recent renewal results, and reload closure

### Docker and the host baseline

- checks privileged mode, host networking, dangerous capabilities, Docker socket mounts, and published ports
- relates container publication to INPUT, FORWARD, and DOCKER-USER
- reviews SSH, accounts, sudo, Fail2ban/CrowdSec, updates, packages, and systemd services
- reviews OOM, core dumps, disk and inode pressure, journal persistence, and suspicious startup entries
- finds extra UID-0 accounts, unusual authorized keys, executables in temporary directories, and deleted executables that remain running

## Support levels

Recognition is not a promise that every release, fork, or deployment layout is fully understood.

### Most extensively validated

- S-UI
- 3x-ui / x-ui
- sing-box
- Xray-core

These components have been exercised together with real panel databases, configuration, listeners, firewall rules, and protocol ingress on disposable VPS hosts.

### Dedicated adapters or checks

- Hiddify, Marzban, and Outline
- WireGuard and OpenVPN
- Hysteria2, TUIC, Trojan, and Shadowsocks

### Deployment-relationship discovery

- Docker and Docker Compose
- Nginx, Caddy, and HAProxy

Exact versions and tested semantics are recorded in [Proxy compatibility](PROXY-COMPATIBILITY.md) and the [Compatibility matrix](COMPATIBILITY-MATRIX.md). Unknown database schemas, dynamic reverse-proxy targets, and incomplete evidence remain `UNKNOWN` rather than being reported as safe.

Before v1.1.0, five disposable VPS roles completed two consecutive standard/deep audit, bundle verification, support-bundle, and cross-host probe rounds. Every host produced all 55 findings without status, severity, reason-code, or endpoint-relation drift; the 512 MiB host also completed a deep audit. The hosts and temporary test state were removed afterwards. This is historical controlled evidence, not a guarantee for every platform. See [Testing](TESTING.md) and [Release readiness](READINESS.md).

## Understanding results

VPS Scope does not produce an unexplained security score. It uses four states:

- `PASS` — evidence supports the current conclusion; it is not a permanent safety guarantee
- `RISK` — a confirmed issue or a condition that needs review
- `INFO` — inventory or context that is not a problem by itself
- `UNKNOWN` — evidence was missing or collection failed; it is never treated as `PASS`

Start with the proxy assessment, priority actions, availability risks, and evidence gaps. The final 55-check index is a directory of results, not the whole report.

## Install

Run one audit without installing anything:

```bash
curl -fsSL https://github.com/sakkaku404/vps-scope/releases/latest/download/run.sh | sudo bash
```

The prompt supports Simplified Chinese, English, Russian, and Persian. For non-interactive use, pass `--lang zh-CN`, `--lang en`, `--lang ru-RU`, or `--lang fa-IR`.

That one command downloads the current release, verifies its SHA-256, runs the audit, and removes the temporary binary. If `cosign` is unavailable, it prints a short publisher-signature warning and continues without another prompt. There is no second command.

The runner and installer are themselves signed Release assets. Once started, they always verify the downloaded binary's checksum and, when `cosign` is available, its GitHub Actions keyless signature. Without `cosign`, the temporary runner warns and continues automatically; set `VPS_SCOPE_REQUIRE_SIGNATURE=1` to require signature verification and stop otherwise. The persistent installer still requires interactive approval, while automation must explicitly use `--allow-unsigned` or `VPS_SCOPE_ALLOW_UNSIGNED=1` to accept checksum-only installation.

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

### What the server profile changes

The profile does not remove any host-baseline checks and never changes the server. It only gives the evaluator context for deciding whether a public listener is expected for this host.

| Profile | Use it for | Effect on interpretation |
|---|---|---|
| `auto` | Recommended when unsure | Detects `general`, `proxy`, `web`, `docker`, or `mixed` from processes, systemd, Docker, and known configuration paths |
| `general` | An ordinary Linux VPS | Does not assume a proxy, web, or container ingress |
| `proxy` | sing-box, Xray, S-UI, 3x-ui, Hysteria2, and similar hosts | Treats evidence-backed proxy ingress as expected candidates while still auditing panels, subscriptions, and control APIs separately |
| `web` | Nginx, Caddy, HAProxy, Apache, and similar frontends | Adds web-frontend context to public listeners |
| `docker` | Hosts that primarily publish Docker services | Interprets exposure through container publication, FORWARD, and DOCKER-USER |
| `mixed` | Hosts combining proxy, web, and container roles | Combines the relevant contexts |
| `custom` | Operators who know the exact intended public ports | Requires `--expect-public PORT/tcp,PORT/udp` |

Choosing `proxy` never makes a public management panel safe. If the selected profile is wrong, the audit may ask for review of a legitimate listener, but it will not modify anything. Use `auto` when unsure; the report records both the selected and detected roles.

External DNS/TLS observation is disabled by default. `--external-domain` explicitly enables network access, while `--expect-cdn` declares that those domains should sit behind a CDN. The audit compares DNS results with local global addresses and observes TLS on port 443; historical DNS, cloud firewalls, and true off-host reachability still require a second vantage point.

## Report verification and sharing

Start with the action summary rather than the raw count: it separates confirmed high-priority risks, likely availability problems, routine maintenance, and evidence gaps. This is a reading aid only; it never changes a finding's `PASS` / `RISK` / `INFO` / `UNKNOWN` state.

Reports can also be written to an explicit location as JSON, plain text, Markdown, HTML, or a full bundle:

```bash
sudo ./vps-scope audit --format bundle --output ./reports/sgp
```

A bundle contains the canonical JSON report, human-readable formats, and a SHA-256 manifest. The HTML report is a self-contained offline page with status filters, search, and collapsible evidence; it loads no external scripts or fonts. Report files are created with restrictive permissions on Linux.

`report.json` is the common audit record behind every renderer. It contains the 55 stable check IDs, statuses, severities, and reason codes, plus a typed deployment view of components, service endpoints, proxy/reverse-proxy links, and evidence coverage. HTML, Markdown, history comparison, and baselines consume that structure instead of parsing terminal prose. Older schema-1.0 reports remain readable. `vps-scope verify report.json` checks the semantic contract; verifying a complete bundle also checks its declared file set and SHA-256 values against `manifest.json`.

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

Compilation is not the acceptance criterion. Before v1.1.0, five disposable VPS roles were used for release regression: Debian 13 with S-UI, Debian 12 with 3x-ui/Xray, Ubuntu 24.04 with Docker/Nginx, a near-stock Debian 13 host, and a constrained Debian 13 host with 512 MiB of memory. Every role ran a standard audit, deep audit, bundle verification, and redacted support bundle. The Docker role also exercised a 32-container inventory, DOCKER-USER/forwarding semantics, and a custom INPUT chain; the hosts then ran a TCP/UDP reachability matrix.

That candidate completed two consecutive rounds with 55 findings per host and no drift in finding status, severity, reason code, components, or endpoint relationships. All 16 cross-host TCP/UDP probes passed and the laboratory left no tagged firewall rules or helper processes behind. Deep audits took about 25–51 seconds, including the 512 MiB host. The VPS instances were destroyed after validation; there is no current permanent lab. These are historical controlled observations, not performance guarantees for every distribution, panel version, or cloud network. See [Testing](TESTING.md) and [Release readiness](READINESS.md) for the reproducible contract.

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
