# Design and trust boundary

## Non-mutation invariant

Audit collectors do not invoke package managers in install mode, edit files, change modes, restart services, alter firewall rules, create users, or call `sudo`. The process never elevates itself. The only permitted write path is an output file or bundle explicitly selected by the user.

The tool has no remediation mode. Suggested commands are explanatory report text only.

## Evidence before policy

Collectors obtain typed facts. Policy evaluates those facts under an effective profile. Renderers translate stable check IDs into Chinese or English. This separation lets one canonical JSON report be rendered in either language and compared across tool versions.

The canonical JSON contract is `schema_version: 1.0` and is published in [`schemas/report-v1.schema.json`](../schemas/report-v1.schema.json). Within this schema, existing check IDs are permanent: releases may append an ID, but cannot reuse an ID for another meaning or silently remove it. Optional facts and evidence may grow without breaking older readers. A breaking field or semantic change requires a new report schema.

Each new finding also carries a language-neutral `reason_code`. The check ID states what was evaluated; the reason code states why the current status was selected. Existing reason codes are stable within report schema 1.0. Older 1.0 reports without this optional field remain valid. A history comparison reports a reason change even when the top-level status remains unchanged.

`vps-scope verify` treats transport integrity and report semantics as separate layers. For a bundle it first requires the complete allowlisted file set, rejects symlinked or undeclared payloads, and checks sizes and SHA-256 values. It then validates the canonical report: current reports must contain every known stable check ID exactly once, use valid status/severity combinations, preserve category and reason-code ownership, and carry summary counts derived from the findings. Reports from before the full v1 ID contract remain readable without pretending they contain checks that did not yet exist. A report produced by a newer tool may append well-formed IDs while retaining every ID known to the verifier, preserving report-v1 forward compatibility.

Each of the 16 category evaluators has a panic boundary. If an unexpected runtime value causes one category to panic, the audit keeps every stable ID owned by that category and marks each one `UNKNOWN` / unavailable; the other categories continue. Panic values and stack details are withheld from report evidence because they may contain configuration data. This recovery path preserves the 51-ID semantic contract without converting an internal failure into `PASS`.

Every external command is resolved through a fixed Debian/Ubuntu system search path. Before execution, the binary and every parent directory must be root-owned and not group/other writable; the process does not trust the caller's `PATH`, a workload-provided binary, or a writable `/usr/local` shadow. Child processes receive a minimal fixed environment rather than the caller's environment, so Docker contexts, package-manager roots, dynamic-loader settings, pagers, and secret-shaped variables cannot redirect or contaminate evidence collection. Linux commands run in their own process group so a deadline terminates forked descendants and closes inherited output pipes. Standard output and standard error remain independently bounded to 8 MiB, and truncated evidence cannot become a clean result.

All user-selected JSON inputs and generated outputs are size-bounded. Single reports and baselines are rendered to a private temporary inode, synced, and published without replacing an existing destination. Bundle payloads and manifests are written with restrictive permissions; failed generation removes the newly reserved bundle directory. Bundle verification reads no more than the manifest plus the schema-wide maximum of 16 declared files before rejecting excessive directory contents. Offline report readers require a stable regular file and reject symlinks and path swaps. Live collectors open Linux paths non-blockingly, validate the opened descriptor as a regular file, and then enforce their byte limit; this still follows ordinary configuration symlinks while refusing FIFOs, devices, sockets, and directories.

Configuration discovery does not use an allocating whole-directory glob. A bounded walker processes only absolute, built-in patterns, follows a finite number of path segments, and limits both examined directory entries and unique matches. Each evidence family chooses a smaller match ceiling appropriate to its expected configuration layout. A limit, permission failure, broken matched path, or unreadable matched file invalidates completeness: the caller receives no partial match list, and dependent checks cannot remain `PASS` or ordinary `INFO`. Independently proven risks remain risks and carry an explicit `evidence_discovery_incomplete` fact rather than being hidden by a later collection failure.

Directory inventories outside configuration discovery are bounded as well. `/proc` scans reject an excessive process snapshot as unavailable, and saved-report listing has per-root plus aggregate entry ceilings. These readers return either the complete bounded snapshot or an error; callers never receive a prefix that could be mistaken for the full process or report inventory.

Docker inventory follows the same all-or-error rule. `docker ps -q` accepts at most 128 running container IDs, validates the daemon-provided ID shape, and inspects them in fixed batches of 32 rather than creating one unbounded argument list. A batch timeout, truncated output, malformed JSON, or count mismatch invalidates the complete Docker snapshot; Docker findings become `UNKNOWN` instead of reporting on an incomplete subset.

Panel adapters expose a versioned adapter ID, a recognized database schema ID, a privacy-safe fingerprint made only from table and column names, and an explicit capability list. An unknown fingerprint stops schema-specific queries and produces incomplete/`UNKNOWN` evidence instead of applying a nearby version optimistically.

The embedded SQLite reader opens panel databases read-only after a regular-file preflight. Metadata queries have a fixed deadline and explicit database, column, row, cell, and aggregate-result limits. These limits apply before any returned value becomes retained evidence, preventing a malformed or unexpectedly large database from turning a read-only audit into an unbounded resource consumer. The target host never needs the `sqlite3` command.

`vps-scope doctor` uses the same executable trust inspection as live audit commands on Linux. `TRUSTED` means the resolved binary and every parent directory are root-owned and not group/other writable; `UNTRUSTED` means the command exists but the audit will refuse it; `MISSING` means it is unavailable. The diagnostic therefore describes what the audit can safely execute rather than merely what a caller-controlled shell can locate.

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
