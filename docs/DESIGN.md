# Design and trust boundary

## Non-mutation invariant

Audit collectors do not invoke package managers in install mode, edit files, change modes, restart services, alter firewall rules, create users, or call `sudo`. The process never elevates itself. The only permitted write path is an output file or bundle explicitly selected by the user.

The tool has no remediation mode. Suggested commands are explanatory report text only.

## Evidence before policy

Collectors obtain typed facts. Policy evaluates those facts under an effective profile. Renderers translate stable check IDs into Chinese or English. This separation lets one canonical JSON report be rendered in either language and compared across tool versions.

Proxy and web adapters emit configured endpoints into a shared graph. Runtime listeners and normalized host-firewall facts are attached separately; active UFW is combined with the effective nftables INPUT path so workload-managed rules are not hidden by a frontend summary. Policy then evaluates configuration-to-listener ownership, TCP/UDP transport, reverse-proxy frontends and backends, path-gated management routes, exposure scope, and firewall disposition. Product parsers do not decide whether an endpoint is safe.

Network access is disabled by default. The only current opt-in path is `--external-domain`, which performs bounded DNS and TLS observations for the supplied domains. `--expect-cdn` adds an explicit policy expectation; it is never inferred from software names.

## Profiles

Built-in profiles are `general`, `proxy`, `web`, `docker`, `mixed`, and `custom`. `auto` detects a suggested profile. Profiles affect expected listeners; they never suppress SSH authentication, firewall, privilege, persistence, management-plane, or secret-permission checks.

Explicit listener intent uses `--expect-public PORT/protocol`. Supported proxy-panel management exposure remains independent even when its port is explicitly expected.

Resource use and active connections are point-in-time inventory. Proxy ingress gets per-port established TCP connection snapshots so baselines can expose changes, but counts do not become risks merely because they cross a generic threshold. Event evidence such as OOM kills, core dumps, failed services, and low disk headroom drives reliability findings.

## Privacy

Local reports retain host evidence but never intentionally collect secret values. Redaction uses stable placeholders so relationships remain readable. Private keys, passwords, tokens, subscription paths, SSH key comments, full process arguments, command-bearing persistence lines, credential-bearing repository URLs, and private-key-bearing application blobs are outside the evidence boundary. Authorized SSH keys are represented only by algorithm, size, account, and SHA-256 fingerprint.

## Known limitations

- A host-local audit cannot prove internet reachability or inspect provider security groups. Opt-in DNS/TLS observation adds evidence but still cannot replace a second network vantage point or historical DNS data.
- A clean report cannot prove that a host is uncompromised.
- Generic nftables semantics and cloud firewall policy require more context than an internal process can always obtain.
- CVE databases, rootkit signatures, active network scanning, and image-registry freshness are intentionally outside the default offline audit.
