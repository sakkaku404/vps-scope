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

CI also runs the freshly cross-built Linux amd64 binary on the GitHub Ubuntu runner, produces a complete bundle through a real standard audit, and verifies both the manifest and the report semantic contract. This catches collector panics, missing stable IDs, malformed summaries, and development-build reason-code gaps that package-level tests alone cannot prove absent.

The release-script gate installs Cosign in a standard system path, then exercises both the temporary runner and installer against the pinned public `v1.0.0` release with signature verification required. This proves the explicit-version certificate identity, checksum path, architecture selection, installation path, and executable handoff rather than checking shell syntax alone. The third-party notice generator runs twice and must produce byte-identical output containing the linked SQLite module.

`scripts/check-coverage.sh` enforces per-package ratchets rather than one misleading repository-wide percentage. It deliberately requires Linux: standard Windows development environments skip filesystem-symlink cases that are part of the Linux audit contract, so their partial percentage is not comparable to CI. Run it in WSL/Linux or rely on the GitHub CI gate. The current Linux CI floors are app 56%, audit 54%, redact 86%, and report 82%; they may only move upward as more OS collectors gain deterministic fixtures.

Proxy-specific fixtures also verify that configuration summaries never retain UUIDs, passwords, API secrets, inbound tags, SSH key comments, APT URL credentials, or complete process arguments.

## Policy scenarios

`internal/audit/scenario_test.go` provides the reusable command fixture used for policy tests. Every command used by a scenario must be declared explicitly; an undeclared command fails, so a test cannot quietly inherit facts from the developer workstation or CI runner.

The scenarios assert outcomes, not implementation details. They currently cover effective SSH policy, firewall and update evidence, journald-based SSH and sudo auditing, public panel exposure and default paths, expected public proxy ingress, public control APIs, panel/runtime and role collisions, disabled or unexplained listeners, privacy-safe abuse counts, Compose/effective mounts, ambient capabilities, unsafe Docker isolation, and truncated command output. The important safety contract is that incomplete evidence produces `UNKNOWN`, never `PASS`.

Runtime fault injection deliberately panics a category evaluator with a secret-shaped value. The test requires all stable IDs for that category to survive as unavailable `UNKNOWN` findings, requires the panic value to be absent from errors and evidence, and validates the resulting complete 51-ID report with the production semantic verifier.

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

The current disposable matrix includes Debian 12, Debian 13, Ubuntu 22.04, and Ubuntu 26.04 on 1 vCPU / 1 GB VPS instances. It covers S-UI with VLESS Reality, Hysteria2, and Shadowsocks; 3x-ui v3.4.2 with VLESS Reality, Trojan TLS, Shadowsocks TCP/UDP, and VMess WS; native sing-box with Hysteria2, TUIC, Trojan, Shadowsocks, and Clash API; a two-host WireGuard tunnel; an OpenVPN 2.6 UDP server; official Outline Shadowbox; Nginx/Caddy/HAProxy management chains; Docker loopback publication; deliberately privileged containers; expiring TLS; invalid JSON beside a still-running service; UFW; IPv6; and empty cloud-image `authorized_keys` placeholders.

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

The latest four-host standard run completed in about 4 to 8 seconds with the expanded workload graph. Deep runs on the two busiest lab hosts took about 37 to 54 seconds. These timings are observations from 1 vCPU / 1 GB lab VPS instances, not performance guarantees.

Never commit real host reports. They may contain IP addresses, domains, usernames, paths, and operational evidence.

## Disposable connectivity laboratory

The opt-in helpers under `scripts/lab` are separate from the audit binary. They require an exact disposable-host marker, accept only ports 39000-39999, serialize scenarios with a lock, and remove their process and optional UFW rule on every normal or signalled exit. Existing rules on the selected port cause a refusal. `/opt/vps-scope-lab` is used for executables because a valid lab host may mount `/run` with `noexec`; `/run/vps-scope-lab` contains state only.

The fixed matrix exercises cross-host TCP/UDP IPv4 reachability and local IPv6 listener parsing. External IPv6 reachability is recorded only on hosts with a usable IPv6 route; its absence is not converted into a pass. Matrix artifacts contain aliases and outcomes, not resolved addresses, and are never committed.

The matrix requires an exact network/port readiness marker, waits for each remote cleanup, fails on every probe or lifecycle error, and checks for residual UFW rules, helpers, and state files. Its TCP/UDP retries stay inside one fixed timeout. The guarded report fault-injection runner independently proves rejection of undeclared files, missing files, symlink payloads, and manifest-consistent semantic corruption, then removes its working directory.

The Docker inventory runner is also marker-gated and uses the same host lock. It requires a cached image, creates at most 64 resource-limited paused containers carrying one exact label, runs an audit plus report verification, and deletes both containers and its report in an exit trap. The synthetic fact-store test owns the intentionally unsafe 129-container boundary; the disposable runner exercises the normal real-daemon multi-batch path without forcing a 1 GB VPS into artificial memory pressure.
