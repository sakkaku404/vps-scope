# VPS Scope

VPS Scope is a read-only security audit tool for Ubuntu and Debian servers. It collects the state of a host, points out things worth reviewing, and leaves the machine untouched.

[![CI](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml/badge.svg)](https://github.com/sakkaku404/vps-scope/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/sakkaku404/vps-scope)](https://github.com/sakkaku404/vps-scope/releases)
[![License](https://img.shields.io/github/license/sakkaku404/vps-scope)](LICENSE)

[中文](docs/README.zh-CN.md) · [Checks](docs/CHECKS.md) · [Design notes](docs/DESIGN.md) · [Testing](docs/TESTING.md)

## What it looks at

The audit covers the parts of a small VPS that are easy to overlook: effective SSH settings, listening sockets, firewall rules, login activity, pending updates, systemd services, Docker isolation, TLS certificates, file permissions, and common persistence locations.

Results are based on the state the system is actually using where possible. For example, SSH settings come from `sshd -T`, not from grepping one configuration file. Network listeners are separated into public, private, loopback, IPv4, IPv6, and container-published endpoints.

VPS Scope uses four result states:

- `PASS` — the check ran and the expected condition was met
- `RISK` — the collected evidence needs attention
- `INFO` — useful context or inventory, but not a problem by itself
- `UNKNOWN` — the check could not reach a reliable conclusion

There is no security score, and the tool does not make changes or offer an automatic fix mode.

## Install

The shortest installation command is:

```bash
curl -fsSL https://raw.githubusercontent.com/sakkaku404/vps-scope/main/install.sh | sudo bash
```

Then run `sudo vps-scope`. The installer detects amd64 or arm64 automatically and verifies the release checksum before installing anything.

To run one audit without installing the program:

```bash
curl -fsSL https://raw.githubusercontent.com/sakkaku404/vps-scope/main/run.sh | sudo bash
```

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

The default output is intended for a terminal. Reports can also be written as JSON, plain text, Markdown, or a self-contained HTML file:

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

VPS Scope is useful for reviewing a server, but it cannot prove that a machine is clean or see cloud firewall rules from inside the guest. See [the design notes](docs/DESIGN.md) for the current trust boundary and known limitations.

## Development

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/vps-scope
```

Contributions and reproducible Ubuntu/Debian fixtures are welcome. Please do not attach an unredacted server report to a public issue.

Use GitHub's private vulnerability reporting for security problems in VPS Scope itself. See [SECURITY.md](SECURITY.md) for details.

## License

MIT
