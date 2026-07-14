# Security policy

## Supported versions

Security fixes are provided for the latest published release. Users should reproduce an issue with the latest version before reporting it when possible.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Older releases | No |
| Unreleased `main` | Best effort |

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/sakkaku404/vps-scope/security/advisories/new) for vulnerabilities in VPS Scope. Do not open a public issue if a report contains an exploitable bug, credentials, private host details, or an unredacted audit report.

Include the affected version, operating system, reproduction steps, impact, and a minimal sanitized example. Do not test against systems you do not own or have permission to audit.

You should receive an initial acknowledgement within seven days. A fix and disclosure timeline will depend on severity and reproducibility.

## Scope

Security reports should concern VPS Scope itself: unsafe collection behavior, unintended mutation, secret leakage, report-redaction failures, command injection, privilege-boundary problems, or release-pipeline compromise.

A finding reported by VPS Scope about a particular server is not a vulnerability in this project. Use the false-positive issue form if the finding is incorrect, and redact the evidence before posting it.

## Release verification

Published Linux binaries are covered by SHA-256 checksums, Sigstore keyless signatures, and GitHub build provenance. The installer always checks SHA-256 and verifies the signature automatically when `cosign` is available. See [release verification](docs/SUPPLY-CHAIN.md) for the optional strict signature mode and manual verification command.
