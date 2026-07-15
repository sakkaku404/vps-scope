# Design and trust boundary

## Non-mutation invariant

Audit collectors do not invoke package managers in install mode, edit files, change modes, restart services, alter firewall rules, create users, or call `sudo`. The process never elevates itself. The only permitted write path is an output file or bundle explicitly selected by the user.

The tool has no remediation mode. Suggested commands are explanatory report text only.

## Evidence before policy

Collectors obtain typed facts. Policy evaluates those facts under an effective profile. Renderers translate stable check IDs into Chinese or English. This separation lets one canonical JSON report be rendered in either language and compared across tool versions.

The canonical JSON contract is `schema_version: 1.0` and is published in [`schemas/report-v1.schema.json`](../schemas/report-v1.schema.json). Within this schema, existing check IDs are permanent: releases may append an ID, but cannot reuse an ID for another meaning or silently remove it. Optional facts and evidence may grow without breaking older readers. A breaking field or semantic change requires a new report schema.

Each new finding also carries a language-neutral `reason_code`. The check ID states what was evaluated; the reason code states why the current status was selected. Existing reason codes are stable within report schema 1.0. Older 1.0 reports without this optional field remain valid. A history comparison reports a reason change even when the top-level status remains unchanged.

`vps-scope verify` treats transport integrity and report semantics as separate layers. For a bundle it first requires the complete allowlisted file set, rejects symlinked or undeclared payloads, and checks sizes and SHA-256 values. It then validates the canonical report: current reports must contain every known stable check ID exactly once, use valid status/severity combinations, preserve category and reason-code ownership, and carry summary counts derived from the findings. Reports from before the full v1 ID contract remain readable without pretending they contain checks that did not yet exist. A report produced by a newer tool may append well-formed IDs while retaining every ID known to the verifier, preserving report-v1 forward compatibility.

All user-selected JSON inputs and generated outputs are size-bounded. Single reports and baselines are rendered to a private temporary inode, synced, and published without replacing an existing destination. Bundle payloads and manifests are written with restrictive permissions; failed generation removes the newly reserved bundle directory. Readers require a stable regular file before consuming it so a FIFO, device, symlink, or path swap cannot turn an offline report command into an unbounded or unintended read.

Panel adapters expose a versioned adapter ID, a recognized database schema ID, a privacy-safe fingerprint made only from table and column names, and an explicit capability list. An unknown fingerprint stops schema-specific queries and produces incomplete/`UNKNOWN` evidence instead of applying a nearby version optimistically.

Proxy and web adapters emit configured endpoints into a shared graph. Runtime listeners and normalized host-firewall facts are attached separately; active UFW is combined with the effective nftables INPUT path so workload-managed rules are not hidden by a frontend summary. Policy then evaluates configuration-to-listener ownership, TCP/UDP transport, reverse-proxy frontends and backends, path-gated management routes, exposure scope, and firewall disposition. Product parsers do not decide whether an endpoint is safe.

Network access is disabled by default. The only current opt-in path is `--external-domain`, which performs bounded DNS and TLS observations for the supplied domains. `--expect-cdn` adds an explicit policy expectation; it is never inferred from software names.

## Profiles

Built-in profiles are `general`, `proxy`, `web`, `docker`, `mixed`, and `custom`. `auto` detects a suggested profile. Profiles affect expected listeners; they never suppress SSH authentication, firewall, privilege, persistence, management-plane, or secret-permission checks.

Explicit listener intent uses `--expect-public PORT/protocol`. Supported proxy-panel management exposure remains independent even when its port is explicitly expected.

Resource use and active connections are point-in-time inventory. Proxy ingress gets per-port established TCP connection snapshots so baselines can expose changes, but counts do not become risks merely because they cross a generic threshold. Event evidence such as OOM kills, core dumps, failed services, and low disk headroom drives reliability findings.

## Privacy

Local reports retain host evidence but never intentionally collect secret values. Redaction uses stable placeholders so relationships remain readable. Private keys, passwords, tokens, subscription paths, SSH key comments, full process arguments, command-bearing persistence lines, credential-bearing repository URLs, and private-key-bearing application blobs are outside the evidence boundary. Authorized SSH keys are represented only by algorithm, size, account, and SHA-256 fingerprint.

`vps-scope support REPORT.json` creates a new, non-overwriting compatibility bundle. It contains an already-redacted report, an allowlisted OS/product/panel-schema capability summary, a privacy notice, and a SHA-256 manifest. It never reads a live panel database or configuration file. Users must still review every generated file before sharing it.

## Known limitations

- A host-local audit cannot prove internet reachability or inspect provider security groups. Opt-in DNS/TLS observation adds evidence but still cannot replace a second network vantage point or historical DNS data.
- A clean report cannot prove that a host is uncompromised.
- Generic nftables semantics and cloud firewall policy require more context than an internal process can always obtain.
- CVE databases, rootkit signatures, active network scanning, and image-registry freshness are intentionally outside the default offline audit.
