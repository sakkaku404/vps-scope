# Testing

## Local checks

```bash
go test -count=1 ./...
go test -race ./...
go vet ./...
```

Tests cover address classification, listener parsing, dpkg verification classification, explicit port intent, bilingual catalogs, redaction stability, all renderers, report manifests, tamper detection, and CLI parsing.

Proxy-specific fixtures also verify that configuration summaries never retain UUIDs, passwords, API secrets, inbound tags, SSH key comments, APT URL credentials, or complete process arguments.

## Cross compilation

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/vps-scope-linux-amd64 ./cmd/vps-scope
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/vps-scope-linux-arm64 ./cmd/vps-scope
```

## Real-host regression

Real-host tests must use disposable release candidates and explicitly chosen report paths. Read the resulting JSON and human report; a successful exit code alone is not acceptance.

The current disposable matrix includes Debian 12, Debian 13, Ubuntu 22.04, and Ubuntu 26.04 on 1 vCPU / 1 GB VPS instances. Scenarios cover S-UI, 3x-ui with its generated Xray configuration, native sing-box with Hysteria2 and Clash API, Docker loopback publication, deliberately privileged containers, expiring TLS, invalid JSON beside a still-running service, UFW, IPv6, and empty cloud-image `authorized_keys` placeholders.

Regression review should verify:

- `ss` contains listeners only, not established connections.
- loopback DNS, application, and container ports are not public exposure.
- `sshd -T` facts match the effective daemon policy.
- failed-login categories are not summed into a misleading total.
- UFW default policy and individual allow rules are both represented.
- package-owned capabilities are not automatically risks.
- normal `/etc/shadow` group-readable policy is accepted on Ubuntu/Debian.
- masked systemd symlinks are not treated as world-writable unit files.
- Docker loopback publication remains loopback.
- S-UI, 3x-ui, and x-ui management listeners are distinguished from proxy ingress.
- Resource, password-context, active-connection, firewalld, and CrowdSec parsers have deterministic fixtures.
- file-backed TLS and embedded TLS visibility are reported separately.
- JSON, text, Markdown, HTML, manifest verification, `diff`, and `fleet` agree.
- SSH fingerprint evidence excludes key material and comments; empty placeholder files are not `UNKNOWN`.
- process, persistence, and APT evidence cannot retain command-line secrets or repository credentials.
- invalid active proxy configuration is a risk even while the old process remains running.
- a public control API blocked by UFW default-deny is distinguished from an unrestricted endpoint.
- an identified container panel with an ambiguous management port remains `UNKNOWN`.
- config-to-listener relations distinguish TCP and UDP and do not treat expected public proxy ingress as a vulnerability.
- Reality, Trojan, Shadowsocks, OpenVPN, and WireGuard summaries retain semantic facts without secret-bearing values.
- the audit executable itself is excluded from temporary-directory process findings when using the one-command runner.

The latest four-host run completed the standard audit in 2.3–3.9 seconds. Deep mode completed in 27.3–36.6 seconds and ran full SUID/SGID, capability, and `dpkg --verify` checks. These timings are observations from 1 vCPU / 1 GB lab VPS instances, not performance guarantees.

Never commit real host reports. They may contain IP addresses, domains, usernames, paths, and operational evidence.
