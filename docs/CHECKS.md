# Check catalog

Check IDs are stable across languages and report formats. A status is separate from execution metadata: a finding can be unavailable or not applicable without silently becoming a pass.

| Domain | IDs | Primary evidence |
|---|---|---|
| System context | `SYS-001`–`SYS-002` | effective UID, `timedatectl` |
| Accounts | `ACC-001`–`ACC-002` | `/etc/passwd` |
| SSH | `SSH-001`–`SSH-004` | `sshd -T`, filesystem ownership/modes |
| Privileges | `PRIV-001`–`PRIV-002` | sudoers, SUID/SGID, `getcap`, `dpkg-query -S` |
| Network | `NET-001`–`NET-002` | `ss -lntu[p]`, address classification, profile intent |
| Firewall | `FW-001`–`FW-002` | UFW verbose policy/rules; nftables and iptables inventory |
| Authentication | `AUTH-001`–`AUTH-003` | journald/auth.log, sudo journal, Fail2ban client |
| Updates | `UPD-001`–`UPD-002` | simulated APT upgrade, reboot marker, timers |
| Packages | `PKG-001`–`PKG-002` | APT sources, `dpkg --verify` classification |
| Processes | `PROC-001`–`PROC-002` | failed systemd units, `/proc/*/exe` |
| Docker | `DOCKER-001` | Docker inspect isolation and port bindings |
| TLS | `TLS-001`–`TLS-002` | file-backed X.509 parsing; privacy-safe embedded-material detection |
| Workloads | `WORK-001`–`WORK-002` | process inventory, S-UI settings, listeners and UFW |
| Filesystem | `FS-001` | sensitive paths, modes, sticky bits |
| Persistence | `PERSIST-001` | systemd units, timers, cron, rc.local, ld.so.preload |
| Reliability | `REL-001` | kernel journal, coredumps, journal persistence, disk space |

## Interpretation rules

- Port and service counts are inventory, never standalone risk thresholds.
- Failed SSH log categories are reported separately because PAM, invalid-user, and failed-password lines can describe the same attempt.
- `PermitRootLogin prohibit-password` is contextual `INFO`, not equivalent to password-enabled root login.
- Package-owned SUID files and capabilities remain inventory; unowned privileged files elevate the finding.
- Missing documentation excluded by image minimization is separated from missing runtime package files.
- Public S-UI management access is evaluated separately from proxy ingress and subscription endpoints.
- Embedded S-UI TLS blobs are never exported merely to inspect expiry; validity remains `UNKNOWN` until a safe interface exists.
