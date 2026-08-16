# Release readiness and disposable laboratory

The v1.1.0 release laboratory used five disposable amd64 hosts: Debian 13 with
S-UI, Debian 12 with 3x-ui/Xray, Ubuntu 24.04 with Docker/Nginx, a near-stock
Debian 13 host, and a constrained Debian 13 host with 512 MiB of memory. The
first four had 1 vCPU / 1 GiB; the constrained role had 1 vCPU / 512 MiB. They
were destroyed after validation, so there is no current live inventory.
Addresses and credentials are intentionally not recorded here. Every future
release candidate must record its newly assigned disposable inventory and must
not carry an old address or host forward as current. A small laboratory is not
proof that every provider, distribution release, architecture, panel fork, or
proxy protocol behaves identically.

## Required matrix

- Standard audit on every host assigned to that release candidate's disposable inventory;
  deep audit on every host before a release candidate.
- Every newly generated report must record zero category-contract repairs and
  zero command/file snapshot or topology budget rejections under the ordinary matrix. Its
  retained command and file bytes must remain below their documented 64 MiB
  ceilings; a deliberately over-budget fixture must become `UNKNOWN` without
  terminating the audit.
- Ubuntu 22.04/26.04 and other supported-version behavior remains covered by
  deterministic fixtures, CI, and retained historical evidence until a
  current disposable live host is assigned. Documentation must not describe a
  deleted host as active.
- S-UI/sing-box, native sing-box, Hiddify/Xray, and Marzban/Xray runtime discovery.
- Supported panel schema, unsupported schema fixture, stopped panel, public management plane, loopback/reverse-proxied management plane, role collision, and stale listener scenarios.
- Docker public and loopback publication, effective FORWARD/DOCKER-USER evidence, missing address-family evidence, privileged/host-network/socket-mount cases.
- TLS expiry, near-expiry, schedule-only, recent success, failure, reload-hook, embedded-material, and unavailable-evidence cases.
- Reliability evidence with both journal and coredump history available, plus
  deterministic missing-command and failed-command cases; neither absence may
  report zero incidents as `PASS`.
- Deleted and temporary executable scenarios must consume the same bounded
  `/proc/*/exe` snapshot, including unreadable-link and process-exit races.
- Full cross-host TCP and UDP connectivity matrix plus the public `probe plan/run/import` workflow from a second host; IPv4 and IPv6 remain separate evidence families.
- Clean automatic recovery: no lab process, UFW rule, report, or credential remains after a scenario.

## Compatibility promises

- Report schema 1.0 remains readable by current commands.
- The 55 IDs published at 1.0 remain permanent and append-only.
- Existing reason codes do not silently change meaning.
- A new native panel adapter needs an anonymized fixture and a reproducible disposable-host case.
- Failed or incomplete collection never becomes `PASS`.

## Performance and supply chain

- Standard runs are reviewed against the established small-VPS envelope; a regression needs an identified evidence source, not a relaxed timeout.
- Review the sealed full-run benchmark and real-host maximum RSS together. The
  benchmark catches allocation drift; only the disposable 1 GB laboratory can
  establish the live memory envelope.
- Linux amd64 and arm64 cross-builds are mandatory.
- Both pull-request CI and the tag-triggered release workflow must independently pass unit, scenario, race, vet, Staticcheck, Gosec, vulnerability, coverage, bounded fuzz, shell-syntax, schema-compatibility, manifest-tamper, semantic-report, and redaction tests.
- The freshly built Linux amd64 executable must complete a real audit on the CI runner and verify the resulting 55-ID report; compiling or printing `version` alone is not sufficient.
- Release binaries and bootstrap scripts are built or copied from the tagged source by GitHub Actions, checksummed, independently signed, and verified before upload. The staged set must contain exactly seven assets and seven Sigstore bundles. A draft Release is downloaded and fully reverified before publication, and the documented strict path verifies a pinned bootstrap script before execution.

The project used three consecutive pre-1.0 releases satisfying this contract without an ID/schema compatibility break as the engineering gate for the 1.0 label. Current releases continue to use the same contract; popularity or a large external telemetry pool is not a substitute for it.

## 1.0 evidence ledger

- The August 2026 evidence-architecture candidate completed two consecutive
  standard/deep/bundle/support rounds on the then-current five-host laboratory. Each
  host produced all 55 findings with zero status, severity, reason-code,
  component, or endpoint drift between rounds; all reports passed manifest and
  semantic verification, all command/file/topology budget rejection counters
  remained zero, the 32-container Docker stress case passed, and all 16
  cross-host TCP/UDP probes succeeded with verified cleanup. Deep audit duration
  ranged from about 25 to 51 seconds, including the 512 MiB role.

- `v0.12.0`, `v0.13.0`, and `v0.14.0` each shipped the same 51 stable check IDs. The only report-v1 schema growth was the optional, backward-compatible `reason_code` field in `v0.13.0`.
- The `v0.14.0` release candidate completed the required standard matrix on the then-current four-host laboratory, Debian and Ubuntu deep runs, 24/24 cross-host TCP/UDP probes, report/support-bundle fault injection, privacy scans, and zero-residue cleanup.
- The public `v0.14.0` amd64 asset was downloaded again, matched `SHA256SUMS` and GitHub provenance, identified the expected release commit, and reproduced all 51 findings on those four historical laboratory hosts without a status or reason-code regression.
- The `v1.0.0-rc.1` candidate reproduced the same 51-ID status and reason-code results on the then-current four hosts, passed deep audits on Debian and Ubuntu, completed a strict 24/24 cross-host TCP/UDP matrix with zero residue, generated and verified a privacy-scanned support bundle, and rejected four independently injected bundle faults.
- The 1.0 matrix runner verifies exact remote readiness and cleanup state and exits non-zero on any probe or lifecycle failure. TCP and UDP probes may retry only within one fixed timeout, so an isolated dropped packet does not become a policy conclusion while persistent blocking still fails the gate.
- The final `v1.0.0` contract added `NET-004`, `WORK-015`, `WORK-016`, and `WORK-017` to the 51-ID release-candidate contract, for 55 published IDs. Current validation derives the required ID set from the report's own tool version, so authentic v0.12-v0.14 reports remain readable without allowing a report to claim checks that did not yet exist.
- Post-1.0 compatible growth added the optional typed `deployment` view. The published report schema is now executed against both a legacy golden report and a complete current 55-ID report, with adverse topology cases rejected; omission remains valid for older schema-1.0 reports.
- The repository has no open code-scanning, Dependabot, or secret-scanning alerts. Main-branch protection requires current `test` and `analyze` checks, linear history, resolved conversations, and applies to administrators; force pushes and deletion are disabled.
