# Release readiness and fixed laboratory

VPS Scope currently uses three disposable amd64, 1 vCPU / 1 GB hosts as the
fixed live laboratory: Debian 13 with S-UI, Debian 12 with 3x-ui/Xray, and
Ubuntu 24.04 with Docker/Nginx. They are not proof that every provider,
distribution release, architecture, panel fork, or proxy protocol behaves
identically. Older machines are historical evidence only and are not part of
the active lab inventory.

## Required matrix

- Standard audit on all three active hosts; deep audit on all three before a
  release candidate.
- Ubuntu 22.04/26.04 and other supported-version behavior remains covered by
  deterministic fixtures, CI, and retained historical evidence until a
  current disposable live host is assigned. Documentation must not describe a
  deleted host as active.
- S-UI/sing-box, native sing-box, Hiddify/Xray, and Marzban/Xray runtime discovery.
- Supported panel schema, unsupported schema fixture, stopped panel, public management plane, loopback/reverse-proxied management plane, role collision, and stale listener scenarios.
- Docker public and loopback publication, effective FORWARD/DOCKER-USER evidence, missing address-family evidence, privileged/host-network/socket-mount cases.
- TLS expiry, near-expiry, schedule-only, recent success, failure, reload-hook, embedded-material, and unavailable-evidence cases.
- Full cross-host TCP and UDP connectivity matrix plus the public `probe plan/run/import` workflow from a second host; IPv4 and IPv6 remain separate evidence families.
- Clean automatic recovery: no lab process, UFW rule, report, or credential remains after a scenario.

## Compatibility promises

- Report schema 1.0 remains readable by current commands.
- The 51 IDs published at 1.0 remain permanent and append-only; the current catalog contains 55 IDs.
- Existing reason codes do not silently change meaning.
- A new native panel adapter needs an anonymized fixture and a reproducible disposable-host case.
- Failed or incomplete collection never becomes `PASS`.

## Performance and supply chain

- Standard runs are reviewed against the established small-VPS envelope; a regression needs an identified evidence source, not a relaxed timeout.
- Linux amd64 and arm64 cross-builds are mandatory.
- Unit, scenario, race, vet, vulnerability, coverage, shell-syntax, schema-compatibility, manifest-tamper, semantic-report, and redaction tests must pass.
- The freshly built Linux amd64 executable must complete a real audit on the CI runner and verify the resulting 55-ID report; compiling or printing `version` alone is not sufficient.
- Release assets are built by GitHub Actions, checksummed, signed when configured, downloaded again, and verified before the release is considered complete.

The project used three consecutive pre-1.0 releases satisfying this contract without an ID/schema compatibility break as the engineering gate for the 1.0 label. Current releases continue to use the same contract; popularity or a large external telemetry pool is not a substitute for it.

## 1.0 evidence ledger

- `v0.12.0`, `v0.13.0`, and `v0.14.0` each shipped the same 51 stable check IDs. The only report-v1 schema growth was the optional, backward-compatible `reason_code` field in `v0.13.0`.
- The `v0.14.0` release candidate completed the required standard matrix on the then-current four-host laboratory, Debian and Ubuntu deep runs, 24/24 cross-host TCP/UDP probes, report/support-bundle fault injection, privacy scans, and zero-residue cleanup.
- The public `v0.14.0` amd64 asset was downloaded again, matched `SHA256SUMS` and GitHub provenance, identified the expected release commit, and reproduced all 51 findings on those four historical laboratory hosts without a status or reason-code regression.
- The `v1.0.0-rc.1` candidate reproduced the same 51-ID status and reason-code results on the then-current four hosts, passed deep audits on Debian and Ubuntu, completed a strict 24/24 cross-host TCP/UDP matrix with zero residue, generated and verified a privacy-scanned support bundle, and rejected four independently injected bundle faults.
- The 1.0 matrix runner verifies exact remote readiness and cleanup state and exits non-zero on any probe or lifecycle failure. TCP and UDP probes may retry only within one fixed timeout, so an isolated dropped packet does not become a policy conclusion while persistent blocking still fails the gate.
- The repository has no open code-scanning, Dependabot, or secret-scanning alerts. Main-branch protection requires current `test` and `analyze` checks, linear history, resolved conversations, and applies to administrators; force pushes and deletion are disabled.
