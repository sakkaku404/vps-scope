# Changelog

Notable changes to VPS Scope are recorded here.

The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

## 1.3.4 - 2026-07-16

### Security

- Proxy workload inventory now consumes the same bounded Docker snapshot as Docker isolation checks. It no longer bypasses the ceiling with a separate formatted `docker ps` command, and incomplete Docker or process inventory turns `WORK-003` into `UNKNOWN` instead of a clean no-workload conclusion.

### Testing

- Added proxy-inventory fixtures for Docker-backed Outline recognition and daemon collection failure propagation.

## 1.3.3 - 2026-07-16

### Security

- Docker inventory now has an explicit 128-container ceiling and uses fixed 32-container `docker inspect` batches. Oversized inventories, invalid daemon IDs, timeouts, truncated batch output, malformed JSON, and batch count mismatches yield no partial Docker snapshot; dependent Docker findings become `UNKNOWN` rather than being derived from a prefix.

### Testing

- Docker fact-store tests cover the inventory ceiling, batched successful inspection, and an incomplete first batch that must not leak a partial container list.

## 1.3.2 - 2026-07-16

### Security

- Configuration discovery now uses a bounded glob walker instead of `filepath.Glob`. Each collector has an explicit match budget, the complete discovery has a directory-entry budget, and an overflow returns incomplete evidence rather than retaining a silent prefix.
- SSH host keys, sudoers fragments, APT sources, persistence files, proxy configurations, reverse-proxy routes, certificate paths, and renewal hooks now propagate discovery and matched-file read failures. An incomplete inventory cannot remain `PASS` or ordinary `INFO`; a risk already proven by independent evidence remains visible with an explicit incompleteness marker.
- `/proc` process scans and saved-report navigation now use a shared bounded directory reader. Excessive process or report inventories fail explicitly without returning a partial list, and `report show` no longer uses an allocating glob.

### Fixed

- Hiddify generated-configuration discovery no longer truncates silently after 64 paths.
- A panel-runtime risk with an unsupported schema no longer combines `RISK` with the schema-invalid `unavailable` flag.
- TLS parsing no longer leaves a proven expiry risk in the schema-invalid `RISK` plus `unavailable` state when another certificate is unreadable.

### Testing

- File-discovery tests cover deterministic sorting and deduplication, directory symlinks, broken non-directory aliases, match-count overflow, directory-entry overflow, absence of partial results, and the `PASS`/`RISK` incomplete-evidence transition.
- Sensitive-permission and TLS-renewal tests now inject their filesystem inputs instead of inheriting panel databases or root cron entries from the host running the test binary.
- Shared directory-reader tests require invalid budgets and entry overflows to return errors without a partial directory snapshot.

## 1.3.1 - 2026-07-16

### Security

- External collector commands now receive a minimal fixed environment instead of inheriting caller-controlled values. Variables such as `DOCKER_HOST`, `DOCKER_CONTEXT`, `APT_CONFIG`, `DPKG_ROOT`, and `LD_PRELOAD` can no longer redirect local evidence collection or alter trusted command loading.
- Report-bundle verification now reads at most the schema-wide maximum of 17 directory entries. A user-supplied directory containing an excessive number of undeclared files is rejected without loading the complete directory into memory.

### Testing

- Linux command-runner tests prove that path and locale remain deterministic while evidence-changing and secret-shaped caller variables are absent from the child process.
- Bundle tests cross the directory-entry limit with a small fixture and require an explicit verification failure.

## 1.3.0 - 2026-07-16

### Security

- Built-in read-only SQLite panel queries now reject non-regular databases and bound database size, query duration, column and row counts, individual cells, and the complete retained result. A malformed or unexpectedly large panel database can no longer consume unbounded audit time or memory.

### Changed

- On Linux, `vps-scope doctor` now applies the same executable ownership and writable-parent checks as the audit runner and reports `TRUSTED`, `UNTRUSTED`, or `MISSING` instead of treating every discoverable command as safe.

### Testing

- Deterministic tests cover every doctor command state, an expired SQLite query deadline, and SQLite database, row, column, cell, and aggregate-result bounds.

## 1.2.1 - 2026-07-16

### Security

- Bounded collector reads now open Linux paths non-blockingly and validate the opened descriptor as a regular file. A FIFO, device, socket, or directory at a discovered configuration path can no longer make the audit wait for a producer or consume an unintended stream.

### Testing

- Linux tests cover an unread FIFO with no writer and a symlink to a regular configuration file; cross-platform tests reject directory reads while preserving the existing size limit.

## 1.2.0 - 2026-07-16

### Security

- Every external collector command is now resolved to an absolute path and rejected unless the executable and all parent directories are root-owned and not group/other writable. The same trust boundary previously used for proxy self-tests now also covers system inventory commands.

### Reliability

- Linux collector commands run in isolated process groups. A deadline now terminates forked descendants as well as the immediate process, preventing inherited output pipes from keeping an audit stuck after timeout.

### Testing

- Linux-specific command-runner tests cover fixed locale/PATH handling, non-zero exits, untrusted executable paths, forked-process timeouts, trusted system binaries, and the 8 MiB output cap.
- The Linux CI coverage floors now track the exercised baseline more closely: app 56%, audit 54%, redact 86%, and report 82%.

## 1.1.1 - 2026-07-16

### Fixed

- A recovered category panic now preserves every stable check ID in that category as `UNKNOWN` / unavailable, so one unexpected runtime value cannot produce a structurally invalid report or suppress unaffected categories.

### Security

- Panic values and implementation details are withheld from report errors and evidence because unexpected values may contain configuration secrets.

### Testing

- The stable-ID contract now verifies complete category ownership, and fault injection proves that a recovered workload-category panic still produces a semantically valid 51-ID report.

## 1.1.0 - 2026-07-16

### Added

- Releases now include the project license and a deterministic third-party notice generated from the dependency modules actually linked into the binary; both are checksummed and keylessly signed.
- CI regenerates the notice twice to prove deterministic output, syntax-checks every maintained Bash laboratory and release script, and exercises signed temporary-run and installation flows against the pinned public 1.0 release.
- The release workflow verifies all checksums, all five keyless signatures, and the exact ten-file staged asset set before publishing.

### Security

- `install.sh` and `run.sh` now bind Sigstore verification to the exact requested tag when a version is explicitly selected, while `latest` remains constrained to this repository's release workflow and semantic-version tags.
- Release tests and vulnerability scanning now run in a separate read-only job; write, OIDC, and attestation permissions are granted only to the dependent publishing job.

### Fixed

- The English build documentation no longer incorrectly claims that the Go source has no third-party module dependencies.

## 1.0.0 - 2026-07-16

### Stability

- VPS Scope now declares a stable 1.x compatibility policy for report schema 1.0, the existing 51 check IDs, reason codes, baseline v2, documented commands and long flags, exit behavior, and Ubuntu/Debian amd64/arm64 support.
- The 1.0 engineering gate is backed by three consecutive compatible releases (`v0.12.0` through `v0.14.0`), the fixed four-host laboratory, release-asset provenance verification, and protected repository/security-scanning state.

### Added

- CI now performs bounded fuzz runs for proxy configuration parsers and report-bundle filename boundaries instead of relying only on seed-corpus execution.
- The disposable laboratory now includes a guarded, self-cleaning report fault-injection runner for undeclared, missing, symlinked, and semantically invalid bundle payloads.

### Changed

- Report semantic validation now produces deterministic diagnostics, rejects negative semantic-version components, and reuses a single immutable category contract.
- The 1.0 readiness ledger records the three-release compatibility gate, fixed-lab evidence, public-asset verification, and repository security posture.
- The cross-host connectivity matrix now requires exact remote readiness and completed cleanup, fails on any probe or lifecycle error, and uses bounded TCP/UDP retries within the original timeout budget to avoid treating one dropped packet as a policy result.

## 0.14.0 - 2026-07-16

### Added

- `vps-scope verify` now accepts standalone JSON reports and validates the report-v1 semantic contract: stable IDs, categories, status/severity combinations, reason-code ownership, availability flags, timestamps, host context, and recomputed summary counts.
- Semantic verification preserves report-v1 forward compatibility: reports from newer tool versions may append well-formed IDs, but they cannot omit or redefine any ID already known to the verifier.
- CI and the reproducible regression script now run a complete standard Linux audit with the freshly built binary and verify the generated report bundle.

### Changed

- Single-file reports are bounded and published atomically without replacing an existing output; failed rendering leaves no partial destination.
- Baseline creation now uses the same bounded, non-overwriting atomic publication path; local JSON/report readers reject oversized, non-regular, swapped, or symlinked inputs, and Linux updates the `latest` report link atomically.
- Report and support bundles remove partial directories after generation failures, require their complete file sets, reject unsafe locales, symlinked payloads, undeclared files, unknown manifest fields, trailing JSON, oversized inputs, and incomplete manifests.
- The disposable connectivity runner now removes its capture files and verifies that no helper process, UFW rule, or runtime state file survives a scenario.

## 0.13.0 - 2026-07-15

### Added

- Optional, language-neutral `reason_code` values explain why each stable check ID produced its current state; same-status reason changes now appear in semantic diffs without breaking older report-v1 readers.
- `vps-scope support REPORT.json` creates a non-overwriting, privacy-safe compatibility bundle with a redacted report, allowlisted panel schema/capability metadata, a review notice, and a verifiable SHA-256 manifest.
- A guarded disposable-host laboratory under `scripts/lab` exercises bounded TCP/UDP IPv4/IPv6 listeners and cross-host probes with exact authorization markers, reserved ports, locks, and automatic UFW/process cleanup.
- A fixed-lab readiness contract documents the OS, panel, Docker, TLS, dual-stack, compatibility, performance, and release evidence required before 1.0.

### Changed

- Redaction now covers finding facts and errors, profile reasons, metadata, and UUIDs in addition to host identifiers and evidence text.
- TLS renewal evidence uses the latest explicit journal outcome when success and failure signals coexist; ordinary Caddy service health no longer counts as proof of certificate renewal.
- CI syntax-checks the lab shell guard and cross-builds the lab-only network helper without adding it to release assets.

## 0.12.0 - 2026-07-15

### Added

- `DOCKER-002` correlates public container publications with host INPUT policy and the effective FORWARD/DOCKER-USER path for IPv4 and IPv6; unavailable forwarding evidence is `UNKNOWN`.
- TLS renewal closure records schedules, recent success and failure signals, deployment/reload hooks, renewal methods, and a stable minimum-days fact.
- Panel adapters now expose privacy-safe database schema fingerprints and capability sets. Unknown native-panel schemas stop specialized queries and make runtime conclusions incomplete.
- `diff` emits semantic `REGRESSION`, `IMPROVEMENT`, and `CHANGE` events for panel exposure, stale ingress, Docker isolation/forwarding, TLS lifetime/renewal, SSH keys, and workload inventory.
- A published report-v1 JSON Schema, an explicit 51-ID compatibility contract, coverage ratchets, and a one-command reproducible regression suite.

### Changed

- Text, Markdown, and HTML reports begin with a plain-language overall verdict and explain that `UNKNOWN` is an evidence gap rather than a safe result.
- Firewall hook parsing is shared by INPUT and FORWARD collectors without allowing one hook to become evidence for another.
- TLS and Docker evidence collection now use typed, cached facts instead of embedding all acquisition logic in presentation checks.

## 0.11.0 - 2026-07-15

### Added

- Release binaries and checksum manifests are now keylessly signed through GitHub Actions OIDC, with GitHub artifact provenance attached to both Linux binaries. Install and run helpers verify the signature automatically when `cosign` is present; `VPS_SCOPE_REQUIRE_SIGNATURE=1` makes signature verification mandatory.
- nftables parsing now understands reachable port sets and uniform verdict maps, so common firewall compositions do not disappear from endpoint exposure analysis.
- TLS renewal evidence now includes active Caddy-managed HTTPS and user crontab locations alongside certbot and acme.sh scheduling.

### Changed

- Docker published-port evidence explicitly states that Docker inspect cannot establish cloud-firewall or effective host-forwarding exposure on its own.
- Bundle creation and verification stream report hashes with per-file safety limits instead of loading report files wholesale.

### Fixed

- Root audits no longer execute detected proxy-core or native panel binaries unless the resolved executable and every parent directory are root-owned and not group/other writable. Unsafe binaries are reported as unverified rather than executed.
- Small-file collection, including file-backed TLS certificates and panel helper scripts, now reads from the size-checked file descriptor instead of reopening a path after inspection.
- Native self-test failures no longer copy arbitrary validator stderr into reports; credential-like command diagnostics are redacted before they become evidence.

## 0.10.0 - 2026-07-13

### Added

- Management posture evidence for S-UI and 3x-ui/x-ui now includes root/default-path visibility, direct TLS state, host-firewall disposition, and public reverse-proxy reachability.
- Panel/runtime policy detects management or subscription ports reused by proxy ingress, disabled inbounds that still listen, and unexplained public listeners owned by a panel or proxy core.
- Privacy-safe panel-login, control-API, subscription-abuse, rate-limit, and web-probe signal counts, plus per-ingress established TCP connection snapshots without arbitrary count thresholds.
- Docker Compose project/service relationships, effective mount inspection, network context, restart policy, read-only-rootfs state, and explicit high-impact ambient systemd capability checks.

### Changed

- The terminal proxy overview now surfaces management posture, runtime mismatches, attack/abuse counts, reverse-proxy chains, and Compose context instead of leaving them only in verbose evidence.
- A public path-gated reverse proxy to a panel is treated as public management exposure; a non-default path can reduce scan noise but is not an access-control boundary.
- Managed panel config trees are no longer passed to single-file native self-test commands.

### Fixed

- Empty S-UI and 3x-ui path settings are distinguished from missing evidence, including database-backed path settings.
- `CapabilityBoundingSet` is no longer mistaken for a granted capability; only explicit high-impact ambient capabilities elevate service isolation risk.
- Docker socket mounts visible through both bind and effective-mount views are counted once.
- Later medium-severity panel/runtime mismatches no longer overwrite an earlier high-severity collision.
- Corrected `render` and `redact` examples so Go CLI flags precede the report path.
- Fresh 3x-ui installations now inherit the panel's built-in subscription role before database overrides are applied; explicit `subEnable=false` still removes that role.
- Public, unrestricted plaintext subscription endpoints are reported as high risk, while loopback Xray control listeners owned by 3x-ui/x-ui are classified as internal controls instead of unknown ports.
- Read-only panel database access now waits briefly for SQLite writers and retries schema probing, reducing transient `UNKNOWN` results while a panel is committing runtime changes.

## 0.9.1 - 2026-07-13

### Changed

- Terminal reports now show a privacy-safe proxy workload overview with detected components, panel versions, proxy ingress relationships, and configured control APIs when evidence is available.
- Removed the redundant system-mutation banner from terminal report headers.

## 0.9.0 - 2026-07-13

### Added

- A structured endpoint graph separating product adapters, live listeners, host-firewall facts, policy judgments, and report evidence.
- `WORK-013` for Nginx, Caddy, and HAProxy frontend-to-backend chains, including public management routes, missing endpoints, over-broad backends, and external upstream separation.
- `WORK-014` for explicitly enabled external DNS/TLS observation with optional CDN-origin address expectations; network access remains disabled by default.
- A native Outline Shadowbox container adapter that distinguishes the management API from TCP/UDP Shadowsocks ingress without retaining API prefixes, keys, or credentials.
- Policy matrices for TCP/UDP endpoint relations, reverse proxies, external observation, and native/sing-box TUIC, Trojan, Shadowsocks, and OpenVPN parsing.
- An action-oriented reading layer for terminal, Markdown, and HTML reports: confirmed priority risks, availability concerns, maintenance work, and evidence gaps are separated without changing raw finding states.

### Changed

- Official Outline and Marzban host-network containers are treated as deployment context while their effective listeners and management exposure are audited separately.
- Proxy endpoint policy now consumes a typed graph instead of combining collection, product parsing, and judgment in one loop.
- Raised the build baseline to Go 1.25.12 because opt-in TLS observation made standard-library fixes for GO-2026-5856 and GO-2026-5037 reachable.
- Active UFW evidence is now merged with the effective nftables INPUT path, avoiding false blocked-port results when a workload installs direct nftables rules.
- Firewall exposure reports collapse duplicate IPv4/IPv6 rules and flag public allow rules with no matching live listener.
- Hiddify-managed Xray/sing-box listeners, WireGuard kernel listeners, path-gated HAProxy management routes, and secret-bearing generated inbound files now receive product-aware judgments.
- Deleted proxy-core or temporary-directory executables still running are distinguished from ordinary post-upgrade interpreter processes.
- Markdown reports lead with key evidence and keep the remaining evidence in a collapsible section; JSON remains the full canonical evidence record.
- Split shared proxy endpoint vocabulary and endpoint-policy helpers out of the main proxy check implementation without changing audit IDs or schemas.

## 0.8.0 - 2026-07-13

### Added

- Managed-install adapters for Marzban and Hiddify, including allowlisted environment parsing, generated Xray/sing-box ingress, internal control endpoints, Mieru port bindings, and runtime/firewall correlation.
- Anonymous report golden fixture plus report v1 and baseline v1/v2 compatibility tests.

### Fixed

- Baseline v2 now binds to the report StableID and normalizes volatile listener PID/fd data; v1 remains readable with a weaker-identity warning.
- iptables and nftables default input policies are tracked independently for IPv4, IPv6, and inet instead of merging both address families.
- Standalone report and baseline JSON inputs have a 64 MiB limit and reject trailing JSON documents.
- Deep panel adapters now take precedence over shallow container-name detection, and cached Docker facts replace repeated `docker ps`/`docker port` calls.
- Official Marzban host networking is recorded as deployment context while privileged containers, Docker socket mounts, and unrelated host networking remain risks.

## 0.7.0 - 2026-07-13

### Added

- Normalized host-firewall facts for UFW, firewalld, nftables, and iptables/ip6tables, preserving protocol, port, source scope, address family, and action.
- Versioned native S-UI and 3x-ui/x-ui adapters with database schema probing before metadata queries.
- `baseline create` and `baseline check` for stable public listeners, SSH key fingerprints, firewall rules, panel/proxy endpoints, containers, and proxy services.

### Changed

- Split panel runtime policy, proxy parsers, and report comparison commands out of the largest audit and CLI files without changing check IDs or report schemas.

## 0.6.1 - 2026-07-12

### Fixed

- Bounded captured command output and marks completeness-sensitive checks `UNKNOWN` rather than treating truncated journals, listeners, process lists, package verification, or proxy evidence as complete.
- Refused existing report-bundle directories, added nanosecond bundle names, and hardened manifest verification against traversal, duplicate names, oversized manifests, and unexpected file names.
- Withheld sudo `NOPASSWD` command details and arguments from audit evidence while retaining the relevant privilege boundary.
- Corrected installer wording: release assets are checksum-verified, not independently signed.

### Changed

- Added cached-fact, command-output, sudo-privacy, bundle-boundary, and fuzz regression tests.
- CI and release workflows now run pinned `govulncheck` source scans.
- Raised the build baseline to Go 1.25.10 after source scanning found reachable standard-library fixes in the former Go 1.24.0 toolchain.

## 0.6.0 - 2026-07-12

### Added

- Native, privacy-safe S-UI and 3x-ui database facts, including panel role mapping and dynamic inbound metadata, through a built-in read-only SQLite reader that does not require `sqlite3` on the audited VPS.
- `WORK-012`, which compares supported panel database state, generated configuration, and live listeners without confusing management, subscription, and proxy ingress ports.

### Fixed

- Dynamic 3x-ui inbounds described by both the panel database and generated Xray configuration are deduplicated in inventory and endpoint-relation reports.
- S-UI embedded TLS record visibility uses the same built-in read-only database reader as the panel adapter.

## 0.5.0 - 2026-07-11

### Changed

- Added a shared fact snapshot so process, listener, UFW, and Docker evidence is collected once and reused consistently.
- Split routine and expensive checks: the standard audit remains fast, while `--deep` enables recursive privileged-file and package-integrity verification.
- Refined the Chinese and English project-origin wording and synchronized README examples, commands, and support details.
- Repositioned the proxy profile around sing-box, Xray, Hysteria2, management panels, control APIs, and containerized proxy workloads.
- Rebuilt the offline HTML report with status filters, search, collapsible evidence, responsive layout, print styles, and light/dark themes.
- Reduced duplicate privileged-file scanning and stopped classifying DHCP and ordinary time-daemon listeners as unexpected public applications.

### Added

- Proxy endpoint relations covering configured protocol, TCP/UDP transport, live listener/process, exposure scope, and UFW disposition (`WORK-009`).
- Privacy-safe proxy journal signal counts (`WORK-010`) and WireGuard interface/listener/handshake context (`WORK-011`).
- Reality semantic checks that retain only presence/count facts, plus native Trojan, Shadowsocks, OpenVPN, and S-UI database ingress parsing.
- Network congestion-control and queue state (`SYS-004`), temporary-directory executables (`PERSIST-002`), and inode/journal/Docker storage context (`REL-002`).
- Renewal scheduling and last-service-result evidence for file-backed TLS certificates.
- Proxy ingress inventory, native sing-box/Xray configuration self-tests, control API exposure, proxy secret-file permissions, systemd isolation context, and UDP runtime context (`WORK-003` through `WORK-008`).
- Privacy-safe SSH authorized-key fingerprints with weak-key detection (`SSH-005`).
- Container-panel discovery for Hiddify, Marzban, Outline, and containerized x-ui/S-UI; ambiguous management exposure remains `UNKNOWN`.
- Real-host regression coverage across Debian 12/13 and Ubuntu 22.04/26.04.

### Fixed

- The one-command runner executable is no longer reported as a suspicious process merely because it runs from `/tmp`.
- Full process arguments, authorized-key comments, suspicious startup commands, and credential-bearing APT URLs can no longer leak into reports.
- Empty cloud-image `authorized_keys` placeholder files no longer cause a false `UNKNOWN`.

## 0.4.0 - 2026-07-11

### Added

- A GitHub Pages one-command audit entry point at `https://sakkaku404.github.io/vps-scope/run.sh`.
- Evidence-only CPU, memory, disk, load, uptime, and established-connection inventory.
- Contextual password-policy analysis, CrowdSec enforcement checks, and firewalld zone/rule analysis.

### Changed

- Chinese is now the repository's default README; the English README lives under `docs/`.

## 0.3.0 - 2026-07-11

### Added

- Saved-report commands: `vps-scope report list`, `report show`, and `report path`.

### Changed

- Interactive audits now default to showing the terminal report and saving a full bundle under `~/vps-scope-reports`, with a `latest` link and practical viewing and download instructions.

## 0.2.0 - 2026-07-11

### Changed

- `WORK-002` now audits management-plane exposure for S-UI, 3x-ui, and x-ui instead of being S-UI-specific.

## 0.1.2 - 2026-07-11

### Fixed

- Interactive profile selection no longer prints an internal Go writer pointer before the prompt.

## 0.1.1 - 2026-07-11

### Added

- Checksum-verified one-command installer and temporary runner for Linux amd64 and arm64.

## 0.1.0 - 2026-07-11

### Added

- Read-only audits for Ubuntu and Debian across 16 system areas.
- Chinese and English terminal output and reports.
- JSON, text, Markdown, HTML, and verifiable report bundles.
- Report comparison, fleet summaries, re-rendering, and redaction.
- Linux amd64 and arm64 release builds.

[Unreleased]: https://github.com/sakkaku404/vps-scope/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/sakkaku404/vps-scope/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/sakkaku404/vps-scope/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/sakkaku404/vps-scope/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/sakkaku404/vps-scope/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/sakkaku404/vps-scope/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/sakkaku404/vps-scope/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/sakkaku404/vps-scope/compare/v0.14.0...v1.0.0
[0.14.0]: https://github.com/sakkaku404/vps-scope/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/sakkaku404/vps-scope/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/sakkaku404/vps-scope/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/sakkaku404/vps-scope/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/sakkaku404/vps-scope/compare/v0.9.1...v0.10.0
[0.9.1]: https://github.com/sakkaku404/vps-scope/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/sakkaku404/vps-scope/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/sakkaku404/vps-scope/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/sakkaku404/vps-scope/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/sakkaku404/vps-scope/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/sakkaku404/vps-scope/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/sakkaku404/vps-scope/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sakkaku404/vps-scope/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sakkaku404/vps-scope/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sakkaku404/vps-scope/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/sakkaku404/vps-scope/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sakkaku404/vps-scope/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sakkaku404/vps-scope/releases/tag/v0.1.0
