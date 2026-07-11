# Testing

## Local checks

```bash
go test -count=1 ./...
go test -race ./...
go vet ./...
```

Tests cover address classification, listener parsing, dpkg verification classification, explicit port intent, bilingual catalogs, redaction stability, all renderers, report manifests, tamper detection, and CLI parsing.

## Cross compilation

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/vps-scope-linux-amd64 ./cmd/vps-scope
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/vps-scope-linux-arm64 ./cmd/vps-scope
```

## Real-host regression

Real-host tests must use disposable release candidates and explicitly chosen report paths. Read the resulting JSON and human report; a successful exit code alone is not acceptance.

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

Never commit real host reports. They may contain IP addresses, domains, usernames, paths, and operational evidence.
