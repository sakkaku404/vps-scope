# Changelog

Notable changes to VPS Scope are recorded here.

The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Refined the Chinese and English project-origin wording and synchronized README examples, commands, and support details.

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

[Unreleased]: https://github.com/sakkaku404/vps-scope/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/sakkaku404/vps-scope/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sakkaku404/vps-scope/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sakkaku404/vps-scope/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/sakkaku404/vps-scope/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sakkaku404/vps-scope/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sakkaku404/vps-scope/releases/tag/v0.1.0
