# VPS Scope

VPS Scope is a read-only security audit tool for Ubuntu and Debian servers. It collects the state of a host, points out things worth reviewing, and leaves the machine untouched.

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](../LICENSE)

[中文](../README.md) · [Checks](CHECKS.md) · [Design notes](DESIGN.md) · [Testing](TESTING.md)

## Why VPS Scope exists

This project began with a hands-on review of [vernu/vps-audit](https://github.com/vernu/vps-audit). That script makes a VPS check approachable, but on real servers, reading configuration files directly, applying service or port-count thresholds, and treating failed collection as safe can produce false positives and missed findings.

VPS Scope is an independent implementation rather than a fork. It starts from effective configuration and reviewable evidence: failed collection becomes `UNKNOWN`, listeners are separated into public, private, loopback, and container-published scopes, and findings are interpreted in the context of the server's role. The original comparison used commit [`e39115f`](https://github.com/vernu/vps-audit/tree/e39115f85414073ee5cf96bea5e3b1b811375a2a), whose script SHA-256 is `db1134574f3c8df30bc9ac10821d207dda13ae22b0905964e2c0bc7cc71192e6`.

## What it looks at

The audit covers the parts of a small VPS that are easy to overlook: system resources, account and password context, effective SSH settings, listeners and active connections, firewall rules, Fail2ban/CrowdSec, login activity, pending updates, systemd services, Docker isolation, TLS certificates, file permissions, and common persistence locations.

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

Then run `sudo vps-scope`. The installer detects amd64 or arm64 automatically and verifies the release checksum before installing anything.

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
sudo ./vps-scope audit --lang zh-CN --profile proxy
sudo ./vps-scope audit --profile custom --expect-public 22/tcp,443/tcp
```

Profiles give the audit some context about the server's job. Built-in choices include `general`, `web`, `proxy`, `docker`, and `mixed`. Custom public listeners can be declared as `PORT/tcp` or `PORT/udp`; this affects exposure checks, not the rest of the audit.

## Reports

Interactive mode defaults to showing the result in the terminal and saving a full report bundle. Saved reports go to `~/vps-scope-reports/HOST/TIMESTAMP/`; `~/vps-scope-reports/latest` points to the newest one. The completion message explains each file and prints a copy-paste download command.

```bash
sudo vps-scope report show  # show the latest report again
sudo vps-scope report list  # list saved reports
sudo vps-scope report path  # print the latest report directory
```

Reports can also be written to an explicit location as JSON, plain text, Markdown, HTML, or a full bundle:

```bash
sudo ./vps-scope audit --format bundle --output ./reports/sgp
```

A bundle contains the canonical JSON report, human-readable formats, and a SHA-256 manifest. Report files are created with restrictive permissions on Linux.

JSON reports can be rendered again without reconnecting to the server:

```bash
vps-scope render report.json --lang zh-CN --format html --output report.zh-CN.html
vps-scope render report.json --lang en --format markdown --output report.en.md
```

The `redact` command replaces hostnames, addresses, domains, usernames, and key fingerprints with stable placeholders before a report is shared:

```bash
vps-scope redact report.json --format markdown --output public.md
```

VPS Scope does not copy passwords, tokens, private keys, subscription paths, or application blobs that may contain private key material into a report.

## Comparing runs

Use `diff` to see what changed on one server, or `fleet` for a quick comparison across several machines:

```bash
vps-scope diff old.json new.json
vps-scope fleet west.json sgp.json tw.json japan.json
```

Checks keep the same IDs in Chinese and English, so reports remain comparable regardless of display language.

## Other commands

```text
doctor      show which audit sources are available on this host
checks      list checks and their IDs
explain     explain a check and its recommendation
render      turn a JSON report into another language or format
redact      make a report safer to share
verify      verify the files in a report bundle
version     show build information
```

## Support

The first release targets Ubuntu and Debian on Linux `amd64` and `arm64`. Some checks use system tools such as `ss`, `journalctl`, `ufw`, `nft`, `dpkg`, `docker`, or `sqlite3`. If one is unavailable, the affected result is reported as unavailable rather than silently treated as safe.

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
