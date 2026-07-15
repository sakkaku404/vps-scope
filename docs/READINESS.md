# Release readiness and fixed laboratory

VPS Scope treats the four disposable Debian/Ubuntu hosts as a fixed compatibility laboratory, not as proof that every hosting provider or panel fork behaves identically. A release candidate is accepted only when the following evidence is reproducible.

## Required matrix

- Debian 12, Debian 13, Ubuntu 22.04 LTS, and the current Ubuntu development/LTS lab image.
- Standard audit on all four; deep audit on at least one Debian and one Ubuntu host.
- S-UI/sing-box, native sing-box, Hiddify/Xray, and Marzban/Xray runtime discovery.
- Supported panel schema, unsupported schema fixture, stopped panel, public management plane, loopback/reverse-proxied management plane, role collision, and stale listener scenarios.
- Docker public and loopback publication, effective FORWARD/DOCKER-USER evidence, missing address-family evidence, privileged/host-network/socket-mount cases.
- TLS expiry, near-expiry, schedule-only, recent success, failure, reload-hook, embedded-material, and unavailable-evidence cases.
- TCP and UDP external reachability from a second host; IPv4 and IPv6 remain separate evidence families.
- Clean automatic recovery: no lab process, UFW rule, report, or credential remains after a scenario.

## Compatibility promises

- Report schema 1.0 remains readable by current commands.
- The 51 existing check IDs are permanent and append-only.
- Existing reason codes do not silently change meaning.
- A new native panel adapter needs an anonymized fixture and a reproducible disposable-host case.
- Failed or incomplete collection never becomes `PASS`.

## Performance and supply chain

- Standard runs are reviewed against the established small-VPS envelope; a regression needs an identified evidence source, not a relaxed timeout.
- Linux amd64 and arm64 cross-builds are mandatory.
- Unit, scenario, race, vet, vulnerability, coverage, shell-syntax, schema-compatibility, manifest-tamper, semantic-report, and redaction tests must pass.
- The freshly built Linux amd64 executable must complete a real audit on the CI runner and verify the resulting 51-ID report; compiling or printing `version` alone is not sufficient.
- Release assets are built by GitHub Actions, checksummed, signed when configured, downloaded again, and verified before the release is considered complete.

Three consecutive releases satisfying this contract without an ID/schema compatibility break are the engineering gate for a 1.0 label. Popularity or a large external telemetry pool is not required.
