# Contributing

Contributions are welcome, especially reproducible parser fixtures from Ubuntu or Debian. Do not submit real unredacted host reports, credentials, private keys, tokens, subscription paths, or customer infrastructure details.

Every new check should:

1. have a stable ID and Chinese/English explanation;
2. identify an authoritative evidence source;
3. return `UNKNOWN` when collection fails;
4. explain false-positive boundaries;
5. avoid system mutation and implicit privilege escalation;
6. include a parser or policy test;
7. keep secret values outside the report model.

Run `go test ./...` and `go vet ./...` before opening a pull request.

Use the issue forms for bugs, false positives, and feature requests. Security vulnerabilities in VPS Scope must be reported through GitHub private vulnerability reporting rather than a public issue.

See [docs/RELEASING.md](docs/RELEASING.md) for the maintainer release process.
