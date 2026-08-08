# Testing

## Local checks

```bash
go test -count=1 ./...
go test -race ./...
go vet ./...
staticcheck ./...
gosec -quiet ./...
govulncheck ./...
bash scripts/regression.sh
```

CI installs the pinned Staticcheck version declared in `.github/workflows/ci.yml`; local runs should use the same version when investigating a difference.

Tests cover address classification, listener parsing, dpkg verification classification, explicit port intent, bilingual catalogs, redaction stability, all renderers, report manifests, tamper detection, command-output limits, fact caching, sudo evidence privacy, and CLI parsing. CI also performs bounded fuzz runs for proxy parser panic safety and report-bundle file-name boundaries; longer local fuzz runs remain part of release-candidate review.

The offline command matrix runs both a current 55-ID typed-topology report and the retained legacy schema-1.0 golden through verification, text/Markdown/HTML/JSON rendering, redaction plus re-verification, support-bundle generation plus verification, fleet display, and self-diff in Chinese, English, Russian, and Persian. A separate non-empty diff fixture requires semantic change messages themselves—not only table headings and finding titles—to be localized in Russian and Persian; Persian HTML must retain RTL document direction. The HTML template contract rejects untranslated literal labels, including accessibility text, and the human-renderer parity test requires actionable findings to retain their IDs, evidence, and localized suggestions in terminal, Markdown, and HTML output.

The collection contract has deterministic full-run fixtures as well as parser tests. They require one complete 55-ID report from an injected Linux command/file snapshot, prove that identical command, lookup, file, link, and directory requests execute only once under concurrency, and prove that one file path remains one snapshot even when callers request different byte limits. WireGuard listener policy and workload evaluation consume the same interface/port inventory. The suite exercises cached failures and panicking evidence providers. The full-run fixture rejects every evidence-starved `PASS`; only the audit-privilege and extra-UID-0 results proven directly by its injected EUID and passwd snapshot may pass. Missing or duplicate category results must be repaired to `UNKNOWN`, while the ordinary run must record zero contract repairs. A forced internal audit deadline preserves completed evidence and fills every unrun stable ID with unavailable `UNKNOWN`; a separate test proves that operator cancellation still returns no report. Injected `/proc` directory and executable-link evidence drives both deleted-program and temporary-execution decisions without touching the developer host. Finding-budget tests cover per-run command/file/directory memory ceilings, overlong and excessive report evidence, UTF-8-safe truncation, terminal-control removal on generated reports, and fail-closed validation of unsafe imported text. Typed-topology render tests also prove that current reports do not fall back to parsing forged human-readable `key=value` evidence.

The sealed full-run fixture also injects hostname and effective UID. It checks the resulting stable host identity, requires the `SYS-001` status and EUID evidence to agree, and runs the same evidence twice to require byte-identical canonical JSON. This prevents a test from quietly inheriting its developer workstation's hostname or privilege state.

Deployment tests build a mixed sing-box, Reality, Clash API, S-UI, Nginx, and firewall fixture, then reverse the independent collector result orders. Both inputs must produce an identical validated typed topology with the same stable components, endpoints, and links. This guards the topology model against accidental slice-order identity and against reintroducing report-text parsing.

Cancellation tests cover an already-canceled audit, cancellation during a context-aware evidence command, and the no-partial-report guarantee. Linux command-runner coverage additionally checks descendant process-group termination; Windows development runs verify context propagation and leave the operating-system process-group behavior to Linux CI.

Panel adapter tests require the audit cancellation context to reach the adapter input, while SQLite tests require expired parent contexts to stop metadata queries explicitly. Probe round-trip tests reformat a valid plan before execution, proving that logical plan hashes do not depend on whitespace and that the generated observation remains importable.

`BenchmarkRunFromDeterministicIncompleteSnapshot` is a small architecture benchmark, not a VPS performance claim. It exercises all 55 IDs from sealed evidence and reports time, bytes, and allocations so large collection-layer regressions are visible during review.

CI also runs the freshly cross-built Linux amd64 binary on the GitHub Ubuntu runner, produces a complete bundle through a real standard audit, and verifies both the manifest and the report semantic contract. It additionally requires exactly 55 current findings, zero category-contract repairs, zero command/file/topology budget rejections, and the default no-workload-execution policy. This catches collector panics, missing stable IDs, malformed summaries, development-build reason-code gaps, and silent evidence-budget regressions that package-level tests alone cannot prove absent.

The release-script gate installs Cosign in a standard system path, then exercises both the temporary runner and installer against the pinned public `v1.0.0` release with signature verification required. This proves the explicit-version certificate identity, checksum path, architecture selection, installation path, and executable handoff rather than checking shell syntax alone. The tag workflow separately places the current `run.sh` and `install.sh` in `SHA256SUMS`, signs both scripts, verifies all seven signed assets, and rejects anything other than the exact fourteen-file staged set. It uploads those files to a draft Release, downloads the draft assets again, repeats the exact-set, checksum, and seven-signature verification, and publishes only after that round trip succeeds. A failed round trip removes only the still-draft Release ID created by that workflow run, leaving tags, pre-existing drafts, and published releases untouched. The third-party notice generator runs twice and must produce byte-identical output containing the linked SQLite module.

`scripts/check-coverage.sh` enforces per-package ratchets rather than one misleading repository-wide percentage. It deliberately requires Linux: standard Windows development environments skip filesystem-symlink cases that are part of the Linux audit contract, so their partial percentage is not comparable to CI. Run it in WSL/Linux or rely on the GitHub CI gate. The current Linux CI floors are app 66%, audit 68%, redact 92%, and report 85%; they may only move upward as more OS collectors gain deterministic fixtures.

`internal/app/report_contract_test.go` also compares JSON Schema count and string budgets with the executable's canonical contract constants. Changing a runtime limit without updating the published schema, or changing the schema without updating runtime validation, fails the test suite.

Proxy-specific fixtures also verify that configuration summaries never retain UUIDs, passwords, API secrets, inbound tags, SSH key comments, APT URL credentials, or complete process arguments.

## Policy scenarios

`internal/audit/scenario_test.go` provides the reusable command fixture used for policy tests. Every command used by a scenario must be declared explicitly; an undeclared command fails, so a test cannot quietly inherit facts from the developer workstation or CI runner.

The scenarios assert outcomes, not implementation details. They currently cover effective SSH policy, firewall and update evidence, journald-based SSH and sudo auditing, public panel exposure and default paths, expected public proxy ingress, public control APIs, panel/runtime and role collisions, disabled or unexplained listeners, privacy-safe abuse counts, Compose/effective mounts, ambient capabilities, unsafe Docker isolation, and truncated command output. The important safety contract is that incomplete evidence produces `UNKNOWN`, never `PASS`.

Runtime fault injection deliberately panics a category evaluator with a secret-shaped value. The test requires all stable IDs for that category to survive as unavailable `UNKNOWN` findings, requires the panic value to be absent from errors and evidence, and validates the resulting complete 55-ID report with the production semantic verifier.

Linux-only command-runner tests execute real root-owned system utilities. They prove that a caller-controlled `PATH` and locale are replaced; Docker, package-manager, dynamic-loader, and secret-shaped environment variables are not inherited; writable temporary executables are refused; non-zero exits retain bounded diagnostics; noisy output is truncated; and a timed-out shell cannot leave a forked child holding the audit open. These tests run under the race detector in CI even when development happens on Windows.

Bundle verification tests enforce both manifest file-count limits and the containing directory's 17-entry protocol limit. The verifier stops after the first excessive entry rather than enumerating an attacker-sized directory before reporting failure.

Linux file-reader tests place a FIFO at a candidate configuration path without starting a writer and require immediate refusal. They also prove that a normal symlink to a regular configuration remains readable, while common tests retain the descriptor-bound size limit and reject directories.

SQLite adapter tests create real temporary databases and enforce an expired query deadline plus the database, column, row, cell, and aggregate-result limits. Doctor fixtures separately prove trusted, untrusted, missing, and legacy availability-only command states, so diagnostics cannot silently drift away from the audit runner's executable policy.

Configuration-discovery tests use temporary directory trees to prove deterministic sorting, deduplication, ordinary directory-symlink traversal, correct handling of broken non-directory aliases, match-count limits, directory-entry limits, and all-or-error results. Fault mapping separately requires an incomplete `PASS`/`INFO` result to become unavailable `UNKNOWN`, while an independently proven `RISK` keeps its severity and records the incomplete inventory without creating an invalid status/availability combination. Tests for default sensitive-file paths and renewal schedules inject a sealed file set, so installing S-UI or adding a root cron entry on the test host cannot change their expected result.

The shared bounded directory reader is tested independently: invalid budgets and one-entry-over-limit directories must fail without returning a partial snapshot. `/proc` collectors and saved-report navigation use that same implementation, while bundle verification retains its stricter protocol-specific 17-entry test.

Docker inventory tests cover the 128-container ceiling, fixed inspect batching, and a deliberately incomplete batch. The latter must return no usable container prefix, so `DOCKER-001` and `DOCKER-002` cannot be derived from only the first successful batch.

Proxy inventory tests additionally require Docker-backed recognition to use the shared bounded snapshot and require a Docker collection failure to make `WORK-003` unavailable rather than silently reporting no proxy workload.

When adding a new decision rule, add at least one ordinary expected-state scenario and one adverse or incomplete-evidence scenario. Keep fixtures small, synthetic, and free of real host identifiers or secrets.

## Cross compilation

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/vps-scope-linux-amd64 ./cmd/vps-scope
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/vps-scope-linux-arm64 ./cmd/vps-scope
```

## Real-host regression

Real-host tests must use disposable release candidates and explicitly chosen report paths. Read the resulting JSON and human report; a successful exit code alone is not acceptance.

The current fixed live laboratory consists of five disposable amd64 VPS roles:
Debian 13 with S-UI 1.5.3, Debian 12 with 3x-ui 3.4.2 and its embedded Xray,
Ubuntu 24.04 with Docker and Nginx, a near-stock Debian 13 role, and a
constrained Debian 13 role with 512 MiB of memory. It includes public and
loopback listeners, UFW, a public Docker publication whose forwarding path
differs from host INPUT, a loopback container backend, and an Nginx
frontend/backend route. Addresses and credentials are not retained in the
repository. A release candidate must record a newly assigned disposable
inventory before documentation calls any laboratory active.

Regression review should verify:

- `ss` contains listeners only, not established connections.
- loopback DNS, application, and container ports are not public exposure.
- `sshd -T` facts match the effective daemon policy.
- failed-login categories are not summed into a misleading total.
- UFW default policy and individual allow rules are both represented; direct nftables INPUT rules are merged when another workload bypasses the UFW summary.
- nftables, iptables/ip6tables, and firewalld fixtures normalize family, protocol, port, source, and action without allowing an IPv4 rule to cover IPv6.
- nftables OUTPUT/FORWARD accepts do not become host-ingress evidence, duplicate dual-stack rules collapse in reports, and stale public allows require a missing live listener.
- package-owned capabilities are not automatically risks.
- normal `/etc/shadow` group-readable policy is accepted on Ubuntu/Debian.
- masked systemd symlinks are not treated as world-writable unit files.
- Docker loopback publication remains loopback.
- Docker public publications are evaluated through FORWARD/DOCKER-USER rather than inferred from host INPUT alone; unreadable forwarding policy is `UNKNOWN`.
- S-UI, 3x-ui, and x-ui management listeners are distinguished from proxy ingress.
- Empty/root panel paths are distinguished from unavailable path evidence, and a public path-gated reverse proxy remains management exposure.
- Management/subscription and proxy-ingress role collisions, disabled inbounds that still listen, and unexplained public panel/core listeners elevate the panel-runtime finding.
- Native S-UI and 3x-ui database facts remain available when `sqlite3` is absent from the target host.
- Native panel reports identify the selected adapter and supported database schema version; an unknown schema stops metadata queries cleanly.
- A public panel allow-rule, missing Shadowsocks UDP allow-rule, and a stopped panel each change the relevant result to `RISK` or `INFO`; none becomes a false `PASS`.
- Resource, password-context, active-connection, firewalld, and CrowdSec parsers have deterministic fixtures.
- Per-ingress TCP connection snapshots exclude peer addresses from the workload summary and never become a risk solely from a generic count threshold.
- file-backed TLS and embedded TLS visibility are reported separately.
- TLS automation distinguishes a configured schedule from a recent success, a failure signal, and a post-renewal reload hook.
- JSON, text, Markdown, HTML, manifest verification, `diff`, and `fleet` agree.
- SSH fingerprint evidence excludes key material and comments; empty placeholder files are not `UNKNOWN`.
- process, persistence, and APT evidence cannot retain command-line secrets or repository credentials.
- invalid active proxy configuration is a risk even while the old process remains running.
- a public control API blocked by UFW default-deny is distinguished from an unrestricted endpoint.
- an identified container panel with an ambiguous management port remains `UNKNOWN`.
- config-to-listener relations distinguish TCP and UDP and do not treat expected public proxy ingress as a vulnerability.
- Reality, Trojan, Shadowsocks, OpenVPN, and WireGuard summaries retain semantic facts without secret-bearing values.
- the audit executable itself is excluded from temporary-directory process findings when using the one-command runner.
- a baseline created from a report matches a later unchanged audit and rejects a different host or changed stable inventory.
- reverse-proxy policy separates local loopback backends from external camouflage upstreams and elevates unrestricted public management routes.
- Docker Compose labels are allowlisted, effective Docker socket mounts are deduplicated, and official host-network deployment context does not hide unrelated privileged containers.
- A broad `CapabilityBoundingSet` alone is not a risk; an explicit high-impact `AmbientCapabilities` grant is.
- external DNS/TLS observation stays disabled without `--external-domain`; failures are `UNKNOWN`, while an explicitly expected CDN domain that publishes the local address is `RISK`.
- deployment policy distinguishes public, restricted, blocked, TLS/path, and egress/DNS intent; an absent policy does not become compliance `PASS`.
- embedded advisory ranges are tested at vulnerable and fixed boundaries, and a full `ps` row must reach runtime version matching.
- second-vantage plans exclude DHCP clients, preserve explicit UDP uncertainty, reject changed role/exposure metadata, and import a matching TCP observation without overwriting the source report.

The July 2026 hardening regression used five disposable Debian 13, 1 vCPU / 1 GB
hosts. A full cross-host matrix completed 40/40 TCP and UDP probes. The same
candidate produced and semantically verified all four report languages, passed
a deep audit, recognized an allow reached through a custom iptables INPUT chain,
and evaluated real Docker publication plus DOCKER-USER fall-through semantics.
Cleanup checks found no residual listeners, labelled rules, containers, helper
processes, or runtime state. Host addresses and raw reports remain uncommitted.

The August 2026 evidence-architecture regression used the three-host mixed-OS
laboratory described above. Standard audits completed in 1.10 to 3.11 seconds
with maximum RSS between 63,408 and 112,356 KiB. Deep audits completed in 27.64
to 40.18 seconds without a higher memory envelope. All three bundles passed
manifest and 55-ID semantic verification; the same S-UI report was rendered in
Chinese, English, Russian, and Persian. Live review found and fixed S-UI's
omitted-root-path database default, duplicate 3x-ui/Xray advisory inventory,
and an Xray API inbound incorrectly counted as proxy ingress. Addresses and raw
reports remain uncommitted.

The same three hosts then completed a 12/12 cross-host TCP/UDP IPv4 matrix with
zero remaining UFW rules, helper processes, or runtime state. The Docker host
also passed a 32-container bounded inventory run, public-versus-loopback
publication through `DOCKER-USER`, and a reachable custom INPUT-chain test.
After adverse-state evidence was captured, public panel and subscription rules
were removed, the public Docker fixture was deleted, panel databases were set
to mode 0600, and effective SSH password authentication was disabled. A final
audit confirmed those findings changed from risk to pass while the services
remained active.

The subsequent five-role regression ran the current candidate twice on every
host. Each run produced all 55 findings, and comparisons found no change in
status, severity, reason code, components, or endpoint relationships. All
reports passed manifest and semantic verification with zero contract repairs
or command/file/topology budget rejections. The 32-container Docker inventory,
DOCKER-USER/forwarding semantics, custom INPUT-chain case, and all 16 cross-host
TCP/UDP probes passed with verified cleanup. Deep audits completed in about
25–51 seconds, including the 512 MiB role. These figures are laboratory
observations, not general performance promises.

Earlier mixed-workload standard runs completed in about 4 to 8 seconds with the
expanded workload graph. Deep runs on the two busiest lab hosts took about 37 to
54 seconds. These timings are observations from 1 vCPU / 1 GB lab VPS instances,
not performance guarantees.

Never commit real host reports. They may contain IP addresses, domains, usernames, paths, and operational evidence.

## Disposable connectivity laboratory

The opt-in helpers under `scripts/lab` are separate from the audit binary. They require an exact disposable-host marker, accept only ports 39000-39999, serialize scenarios with a lock, and remove their process and optional UFW rule on every normal or signalled exit. Existing rules on the selected port cause a refusal. `/opt/vps-scope-lab` is used for executables because a valid lab host may mount `/run` with `noexec`; `/run/vps-scope-lab` contains state only.

The fixed matrix exercises cross-host TCP/UDP IPv4 reachability and local IPv6 listener parsing. External IPv6 reachability is recorded only on hosts with a usable IPv6 route; its absence is not converted into a pass. Matrix artifacts contain aliases and outcomes, not resolved addresses, and are never committed.

The matrix requires an exact network/port readiness marker, waits for each remote cleanup, fails on every probe or lifecycle error, and checks for residual UFW rules, helpers, and state files. Its TCP/UDP retries stay inside one fixed timeout. The guarded report fault-injection runner independently proves rejection of undeclared files, missing files, symlink payloads, and manifest-consistent semantic corruption, then removes its working directory.

The Docker inventory runner is also marker-gated and uses the same host lock. It requires a cached image, creates at most 64 resource-limited paused containers carrying one exact label, runs an audit plus report verification, and deletes both containers and its report in an exit trap. The synthetic fact-store test owns the intentionally unsafe 129-container boundary; the disposable runner exercises the normal real-daemon multi-batch path without forcing a 1 GB VPS into artificial memory pressure.
