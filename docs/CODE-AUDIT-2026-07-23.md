# Code audit — 2026-07-23

This review focused on false-safe firewall conclusions, command-execution trust,
Docker publication semantics, localization completeness, dependency health, and
whether the disposable laboratory actually exercises the production binary.

## Resolved findings

| ID | Severity | Problem | Resolution |
| --- | --- | --- | --- |
| AUD-201 | High | The host-firewall model flattened iptables rules and could miss an allow reached through a custom INPUT chain. Default policy could then produce a false safe result. | Added ordered filter-table parsing, reachable-chain traversal, RETURN/goto handling, per-family policy, and unresolved-path propagation to `UNKNOWN`. |
| AUD-202 | High | Trusted executable resolution followed the `iptables-save` symlink and executed the multi-call target directly. The target lost its original `argv[0]`, so real firewall evidence collection failed on Debian. | Trust checks still validate the resolved target, but execution preserves the requested system path. Both the original and resolved directory chains are verified. |
| AUD-203 | High | Docker firewall analysis treated a source-scoped `DOCKER-USER` allow as a restriction even when later traffic fell through to Docker's accept path. It also confused translated container ports with original published ports. | Added ordered DOCKER-USER evaluation, fall-through/RETURN semantics, condition handling, and explicit `--ctorigdstport` versus `--dport` interpretation. |
| AUD-204 | Medium | nftables rules with interface, destination, negation, or unsupported match conditions could be interpreted as unconditional evidence; map iteration also made some traversals nondeterministic. | Conditional paths now become `UNKNOWN`, reachable custom chains are traversed in rule order, and chain selection is deterministic. |
| AUD-205 | Medium | A restricted allow under default ACCEPT could be described as restricted exposure, while a restricted allow followed by a closing deny could be described as blocked. | Default-policy and terminal-rule ordering now distinguish unrestricted fall-through, source restriction, explicit block, and incomplete evidence. |
| AUD-206 | Medium | When UFW was active, direct nftables workload rules were collected but omitted from the detailed FW-002 evidence. | FW-002 now includes reachable non-UFW nftables rules while filtering generated `ufw-*` duplicates. |
| AUD-207 | Medium | Russian and Persian catalogs could silently fall back to English for interactive strings, and their README files contained stray Chinese text. | Added catalog-key parity and UI-source coverage tests, corrected prominent translations, and added a documentation leakage test. |
| AUD-208 | Low | One CLI test inherited `SSH_CONNECTION` from a real remote runner, and the Windows laboratory runner assumed the local SSH username and default key. | Tests now seal ambient SSH state. The matrix runner accepts explicit SSH user and identity-file parameters. |
| AUD-209 | Low | The embedded SQLite driver was behind the maintained release line. | Updated `modernc.org/sqlite` and its transitive modules; module verification, static analysis, vulnerability analysis, and Linux tests pass. |

## Verification performed

- Windows: package tests, `go vet`, Staticcheck, Gosec, module verification,
  PowerShell parsing, shell syntax checks, and documentation/catalog assertions.
- Linux amd64 on Debian 13: normal tests, race tests, coverage ratchets, and
  bounded fuzzing of proxy parsing, evidence parsing, and report-bundle handling.
- Five disposable Debian 13 VPS hosts: 40 TCP/UDP cross-host probes, standard
  audit runs in all four report languages, a deep audit, semantic report
  verification, a custom iptables-chain scenario, and Docker publication and
  DOCKER-USER scenarios.
- Cleanup checks verified that temporary listeners, firewall rules, labelled
  containers, helper processes, and runtime state were removed.

## Remaining trust boundaries

These are explicit boundaries rather than known false-safe defects:

- A host cannot prove an upstream cloud firewall or Internet path from local
  evidence alone. External observation is opt-in and failures remain `UNKNOWN`.
- Unknown panel database schemas and unsupported firewall expressions remain
  `UNKNOWN`; they are not guessed from process names or port numbers.
- VPS Scope audits server-side configuration and runtime evidence. It does not
  claim that a real client completed a proxy handshake or reached a blocked
  destination.
- Report evidence can contain operational metadata. Redaction is enforced, but
  users must still review a bundle before sharing it.
