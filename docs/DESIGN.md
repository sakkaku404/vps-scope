# Design and trust boundary

## Non-mutation invariant

Audit collectors do not invoke package managers in install mode, edit files, change modes, restart services, alter firewall rules, create users, or call `sudo`. The process never elevates itself. The only permitted write path is an output file or bundle explicitly selected by the user.

No automatic remediation command will be added. Suggested commands are explanatory report text only.

## Evidence before policy

Collectors obtain typed facts. Policy evaluates those facts under an effective profile. Renderers translate stable check IDs into Chinese or English. This separation lets one canonical JSON report be rendered in either language and compared across tool versions.

## Profiles

Built-in profiles are `general`, `proxy`, `web`, `docker`, `mixed`, and `custom`. `auto` detects a suggested profile. Profiles affect expected listeners; they never suppress SSH authentication, firewall, privilege, persistence, management-plane, or secret-permission checks.

Explicit listener intent uses `--expect-public PORT/protocol`. Supported proxy-panel management exposure remains independent even when its port is explicitly expected.

## Privacy

Local reports retain host evidence but never intentionally collect secret values. Redaction uses stable placeholders so relationships remain readable. Private keys, passwords, tokens, subscription paths, and private-key-bearing application blobs are outside the evidence boundary.

## Known limitations

- A host-local audit cannot prove internet reachability or inspect provider security groups.
- A clean report cannot prove that a host is uncompromised.
- Generic nftables semantics and cloud firewall policy require more context than an internal process can always obtain.
- CVE databases, rootkit signatures, active network scanning, and image-registry freshness are intentionally outside the default offline audit.
