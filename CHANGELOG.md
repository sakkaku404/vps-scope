# Changelog

Notable changes to VPS Scope are recorded here.

The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

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

[Unreleased]: https://github.com/sakkaku404/vps-scope/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/sakkaku404/vps-scope/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sakkaku404/vps-scope/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sakkaku404/vps-scope/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sakkaku404/vps-scope/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/sakkaku404/vps-scope/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sakkaku404/vps-scope/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sakkaku404/vps-scope/releases/tag/v0.1.0
