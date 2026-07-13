# Check catalog

Check IDs are stable across languages and report formats. A status is separate from execution metadata: a finding can be unavailable or not applicable without silently becoming a pass.

| Domain | IDs | Primary evidence |
|---|---|---|
| System context | `SYS-001`–`SYS-004` | effective UID, `timedatectl`, `/proc`, `df`, congestion control and queue discipline |
| Accounts | `ACC-001`–`ACC-003` | `/etc/passwd`, `/etc/shadow`, effective SSH authentication, PAM |
| SSH | `SSH-001`–`SSH-005` | `sshd -T`, filesystem ownership/modes, privacy-safe SHA-256 authorized-key fingerprints |
| Privileges | `PRIV-001`–`PRIV-002` | sudoers; deep-mode SUID/SGID, `getcap`, `dpkg-query -S` |
| Network | `NET-001`–`NET-003` | listeners and established connections from `ss`, address classification, profile intent |
| Firewall | `FW-001`–`FW-002` | Effective UFW plus direct nftables INPUT policy, firewalld and iptables/ip6tables rules, address-family coverage, and stale public allows without a listener |
| Authentication | `AUTH-001`–`AUTH-003` | journald/auth.log, sudo journal, Fail2ban and CrowdSec clients |
| Updates | `UPD-001`–`UPD-002` | simulated APT upgrade, reboot marker, timers |
| Packages | `PKG-001`–`PKG-002` | APT sources; deep-mode `dpkg --verify` classification |
| Processes | `PROC-001`–`PROC-002` | failed systemd units, `/proc/*/exe` |
| Docker | `DOCKER-001` | Docker inspect isolation and port bindings |
| TLS | `TLS-001`–`TLS-002` | file-backed X.509 parsing; privacy-safe embedded-material detection |
| Workloads | `WORK-001`–`WORK-014` | proxy processes/configs, management/control exposure, native self-tests, permissions, service isolation, UDP context, config-to-listener/firewall relations, privacy-safe log counts, WireGuard runtime, panel role/runtime consistency, reverse-proxy chains, and opt-in external DNS/TLS observation |
| Filesystem | `FS-001` | sensitive paths, modes, sticky bits |
| Persistence | `PERSIST-001`–`PERSIST-002` | systemd, timers, cron, startup files, executables running from temporary directories |
| Reliability | `REL-001`–`REL-002` | kernel journal, coredumps, journal persistence and size, disk and inode state |

## Interpretation rules

- Port and service counts are inventory, never standalone risk thresholds.
- CPU, memory, load, uptime, and connection counts are snapshots for context, never standalone vulnerability thresholds.
- Password quality becomes a risk only when an SSH password path is enabled and a login account actually has a local password hash.
- Failed SSH log categories are reported separately because PAM, invalid-user, and failed-password lines can describe the same attempt.
- `PermitRootLogin prohibit-password` is contextual `INFO`, not equivalent to password-enabled root login.
- Package-owned SUID files and capabilities remain inventory; unowned privileged files elevate the finding.
- Missing documentation excluded by image minimization is separated from missing runtime package files.
- Public S-UI, 3x-ui, and x-ui management access is evaluated separately from proxy ingress and subscription endpoints.
- A public subscription endpoint is expected to be reachable, but unrestricted plaintext transport is a high risk because subscription URLs commonly carry bearer-like access material.
- A root/default panel path and disabled panel TLS strengthen the explanation of an already public management exposure; neither a random path nor HTTPS alone makes a public panel private.
- A loopback panel reached through a public Nginx, Caddy, or HAProxy route is still public management exposure.
- Management/subscription ports reused by proxy ingress, disabled inbounds that remain live, and unexplained public panel/core listeners are explicit runtime-consistency risks.
- Public proxy ingress is expected when configuration, transport, listener, process, and firewall evidence agree.
- Established TCP counts are snapshots for each configured proxy ingress, not generic attack thresholds; compare runs or baselines to identify meaningful changes.
- Reality private keys, server names, targets, and short IDs are never exported; only presence and counts are retained.
- Embedded S-UI TLS blobs are never exported merely to inspect expiry; validity remains `UNKNOWN` until a safe interface exists.
- systemd capability bounding sets are context, not grants; only explicit high-impact ambient capabilities elevate `WORK-007`.

## Standard and deep audit

The standard audit avoids recursive filesystem and full package-integrity scans. `vps-scope audit --deep` additionally runs `PRIV-002` and `PKG-002`; skipped checks are reported as not applicable, never as `PASS`.
