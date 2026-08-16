# Changelog

Notable changes to VPS Scope are recorded here. The project follows
[Semantic Versioning](https://semver.org/).

Only versions that were actually published as GitHub Releases appear as
release headings. The many internal version numbers used during the initial
July 2026 development sprint were never public releases and are intentionally
not presented as such.

## Unreleased

### Fixed

- The temporary runner restores the caller's working directory before starting
  the binary, so relative policy and output paths no longer point into a
  temporary directory that is deleted on exit. Explicit commands no longer
  depend on `/dev/tty`, while no-argument interactive mode opens the controlling
  terminal only after proving it is available.
- Leading flags passed through `bash -s --` are treated as `audit` flags. The
  interactive wizard rejects invalid numbered choices and requires at least one
  valid listener for the custom profile.
- Audit output formats and explicit destinations are validated before evidence
  collection. The audit help now lists the custom profile, and support bundles
  report all four files including `manifest.json`.
- Saved report guidance now leads with the stable `latest` HTML path and an
  SFTP workflow. The `scp` fallback is an explicit `<SSH_HOST>` template rather
  than a guessed `root@IP` command that may ignore the user's SSH alias, port,
  identity file, or agent; timestamped history and the five-file inventory are
  retained as secondary detail. The terminal now makes clear that `report show`
  and `verify` require an installed copy; the one-line runner keeps report files
  but removes its temporary executable.
- The four README languages now share the same user-facing contract: a real
  proxy-host example, support levels, profile behavior, report download flow,
  result semantics, and execution boundary. Russian and Persian terminology
  was rewritten to remove literal mistranslations, and tests now guard required
  sections, commands, local links, code fences, and known-bad terminology.
- `doctor`, `fleet`, semantic diff labels, support-bundle output, and report
  verification now retain localized user-facing text in Russian and Persian;
  stable machine tokens such as PASS, RISK, INFO, UNKNOWN and schema names stay
  unchanged. `explain` accepts `--lang` either before or after the check ID.
- Dated audit documents are explicitly marked as historical snapshots so old
  check counts, runner prompts, and laboratory claims are not mistaken for the
  current release contract.
- Release builds now require Go 1.25.13 or newer in the 1.25 maintenance line,
  closing the standard-library vulnerabilities that affected HTML rendering,
  TLS post-handshake processing, and certificate ASN.1 parsing.

## 1.1.0 - 2026-08-08

This is one consolidated architecture, correctness, report, and release-chain
upgrade rather than a sequence of small releases.

### Changed

- Audit evidence is sealed behind single-flight command, file, directory,
  link, process, firewall, panel, reverse-proxy, and Docker snapshots. Repeated
  checks consume one point-in-time view, and retained evidence has explicit
  memory and collection budgets.
- IPv4 and IPv6 wildcard listeners retain separate identities. Configuration,
  panel-role, firewall, and runtime relations no longer cross an address-family
  boundary merely because both addresses are public wildcards.
- Evidence gaps in existing checks are no longer flattened into reassuring
  output: keyboard-interactive SSH counts as a password path, unreadable PAM
  policy becomes `UNKNOWN`, deep capability inventory requires `getcap`, UDP
  proxy context requires the core receive/send buffer facts, and failed disk
  or journald-state reads make reliability evidence incomplete.
- `--audit-timeout` bounds the complete audit, including SQLite reads,
  external observations, and time-varying samples—not only child commands.
  When that deadline is reached, completed evidence is retained and checks that
  did not run become explicit `UNKNOWN`; operator cancellation still stops
  immediately without manufacturing a partial report.
- The 55-check contract is owned by one registry. Missing, duplicated,
  panicking, canceled, truncated, or over-budget collection results are
  repaired to explicit `UNKNOWN` outcomes instead of disappearing or becoming
  `PASS`.
- Proxy configuration, panels, live listeners, firewall paths, Docker
  publications, reverse-proxy routes, TLS bindings, and connection counts now
  produce a validated typed deployment graph. Current renderers consume that
  graph; evidence-string parsing remains only for old schema-1.0 reports.
- Offline render, redact, support, verify, fleet, diff, baseline, and probe
  workflows share semantic report validation. Diff rejects cross-host input,
  while the four-language report matrix covers current and legacy reports.
  Reports, manifests, probe documents, policy files, embedded advisories, and
  JSON proxy configurations all reject duplicate object members instead of
  inheriting ambiguous last-value-wins decoding. Hysteria2 YAML recognition
  likewise requires one valid top-level `listen` key and ignores nested keys.
- HTML and Markdown summaries link directly to stable finding anchors. Action
  totals include urgent, availability, maintenance, and evidence-gap bands.
  HTML headings, search controls, empty states, and accessibility labels are
  catalog-backed in all four languages; terminal, Markdown, and HTML contract
  tests require actionable findings to retain their evidence and suggestions.
- Equal-severity actions follow the stable 55-check registry order instead of
  incidental slice or string order, keeping reports reproducible over time.

### Security

- Audits no longer execute S-UI, 3x-ui, sing-box, Xray, Nginx, or other audited
  workload binaries by default. The explicit `--native-self-test` opt-in is
  recorded in report metadata and retains trusted-path checks.
- Panel SQLite inspection uses an owner-controlled, descriptor-anchored path,
  a bounded read-only transaction, query deadlines, and row/cell/result limits.
  The unused external `sqlite3` fallback and retry sleeps were removed; S-UI
  and x-ui schema variants now live in one declarative capability registry.
- External probe plans reject non-public targets by default, pin resolved
  addresses into the logical plan, and cannot silently re-resolve DNS into
  loopback, private, link-local, or metadata networks at execution time.
- Report and support-bundle redaction covers structured credentials,
  authorization headers, URL user information, sensitive query parameters,
  subscription paths, and private-key material. A support bundle is not written
  when a suspicious value survives redaction.
- Redacted reports retain a deterministic, non-reversible per-host pseudonym
  so diff and baseline checks still reject cross-host input. Topology IDs are
  re-keyed per host instead of retaining address-derived hashes that could be
  enumerated offline; legacy `HOST_ID_1` reports are refused for historical
  comparison because their original identity cannot be recovered.
- Markdown rendering escapes raw HTML and formatting metacharacters from
  imported evidence, preventing active attacker-controlled markup in
  permissive local viewers.
- Commands that rewrite or package a report reject optional fields that the
  running version cannot preserve and sanitize. Read-only render, verify,
  diff, and fleet workflows remain forward-compatible.
- Runner and installer downloads require HTTPS redirects, TLS 1.2 or newer,
  connection and total deadlines, and bounded retries. Release copies of both
  scripts are checksummed and independently signed.

### Fixed

- CLI duration parsing now rejects overflow and lookback windows beyond 366
  days. Explicit invalid languages, stray positional arguments, and
  `--also-terminal` without a report bundle fail instead of being silently
  ignored.
- Baselines consume typed deployment facts, reject malformed or ambiguous
  documents, and omit volatile listener PID/FD data. Semantic diff output is
  deterministic and reports severity plus material audit-context changes.
- TLS renewal evidence must be recent, expired certificates cannot round to
  zero remaining days, and future-valid certificates are reported explicitly.
  A recent renewal journal can independently close a missing systemd result
  timestamp instead of leaving a fully evidenced renewal as `UNKNOWN`.
- Component summaries canonicalize panel process names and Docker image tags,
  avoiding duplicate x-ui/S-UI and reverse-proxy products in one deployment.
- Proxy summaries no longer claim that configuration validation passed when
  only panel runtime consistency was checked and no supported core
  configuration was discovered.
- Semantic report validation selects the required check-ID contract from the
  report's own tool version. Authentic v0.12-v0.14 and v1.0.0-rc.1 51-ID
  reports remain readable; final v1.0 reports require all 55 published IDs.
- A failed draft-release round trip removes only the still-draft Release
  created by that workflow run. Existing drafts, published Releases, and Git
  tags are never selected by the cleanup path.
- Address-family-aware listener matching, complete audit cancellation, bounded
  file and command capture, deterministic evidence time, report-summary
  accounting, cross-host diff rejection, and support-bundle privacy failures
  now have direct regression tests.
- Reports, baselines, and probe documents reject duplicate JSON object members
  at every nesting level, avoiding parser-dependent first-value/last-value
  interpretations of the same signed bytes.
- Panel correlation treats `ss`'s `*` spelling as the live form of a configured
  `0.0.0.0` or `::` wildcard. A 3x-ui management socket is no longer reported
  simultaneously as missing and as an unexplained public listener.
- Shareable reports preserve non-identifying loopback and wildcard addresses,
  so exposure semantics survive redaction. Proxy assessment counts also keep
  availability findings separate from the remaining Linux baseline instead of
  presenting the same risk twice. A static-only configuration observation can
  no longer borrow a `PASS` badge from panel runtime, and report headlines
  distinguish confirmed risks from `UNKNOWN` evidence gaps.

### Release quality

- Pull-request and tag workflows independently run tests, race analysis,
  coverage ratchets, vet, Staticcheck, Gosec, vulnerability checks, bounded
  fuzzing, cross-builds, and a real 55-finding Linux audit/verify smoke test.
- Core coverage ratchets now hold app at 66%, audit at 68%, redaction at 92%,
  and report rendering at 85%, below current measured coverage but above the
  previous regression floors.
- A tag first creates a draft Release. GitHub-hosted assets are downloaded
  again, checked against the exact expected set, and have every checksum and
  Sigstore identity reverified before publication.
- The documented strict bootstrap path verifies a pinned `run.sh` or
  `install.sh` bundle before execution. The shorter `curl | bash` path states
  its bootstrap-trust boundary explicitly.

## 1.0.0 - 2026-07-24

First public release.

### Added

- Read-only Ubuntu and Debian audits with `PASS`, `RISK`, `INFO`, and `UNKNOWN`
  conclusions. Failed evidence collection never becomes `PASS`.
- A 55-check Linux and proxy-VPS contract covering host identity, accounts,
  SSH, privilege boundaries, listeners, firewall behavior, authentication,
  updates, packages, systemd, Docker, TLS, proxy workloads, persistence, OOM,
  core dumps, disk, inode, and logging reliability.
- Workload-aware inspection for S-UI, 3x-ui/x-ui, sing-box, Xray-core,
  Hysteria 2, TUIC, Trojan, Shadowsocks, Reality, WireGuard, OpenVPN, Hiddify,
  Marzban, Outline, Nginx, Caddy, HAProxy, Docker, and Docker Compose evidence.
- Relationship-based judgments that distinguish expected public proxy ingress
  from management, subscription, and control endpoints, then relate those
  roles to actual listeners, host firewall rules, Docker publication, reverse
  proxies, TLS, and service runtime state.
- Chinese, English, Russian, and Persian terminal and report output.
- Terminal, JSON, text, Markdown, HTML, and complete report-bundle output;
  saved-report discovery; semantic verification; redaction; support bundles;
  baseline, diff, fleet, and external probe workflows.
- Stable report schema 1.0, stable finding IDs and reason codes, Linux amd64 and
  arm64 builds, SHA-256 manifests, Sigstore signatures, GitHub provenance, CI,
  CodeQL, dependency review, and vulnerability scanning.

### Compatibility

- Reports from the 51-ID v0.12-v0.14 development contract and the 1.0 release
  candidate remain readable according to the contract of their declared tool
  version.
- The 55 IDs in the final v1.0.0 contract are permanent and append-only within
  1.x. Report schema 1.0 additions remain optional for older readers.
