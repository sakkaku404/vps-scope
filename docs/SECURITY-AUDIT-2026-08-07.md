# Security audit — 2026-08-07

> Historical snapshot: this document records the v1.1.0-era boundary. Later runner behavior, toolchain fixes, and localization changes are described by the current README and CHANGELOG.

This review covers the development branch that follows `v1.0.0`. It records
security boundaries and regression evidence; it is not a claim that any audit
tool can prove a host uncompromised.

## Resolved findings

- **Workload execution:** a normal audit no longer executes S-UI, 3x-ui,
  sing-box, Xray, or Nginx binaries with the audit process's privileges.
  `--native-self-test` is an explicit opt-in and retains ownership and
  writable-path checks. Static parsing remains the default.
- **Report privacy:** support bundles use expanded credential, authorization,
  URL, subscription-path, and private-key redaction, followed by a fail-closed
  residual-secret scan before any bundle directory is created.
- **SQLite replacement races:** native panel databases are read through an
  anchored file and immediate-directory descriptor, in one bounded read-only
  transaction. WAL-backed S-UI state was verified on a live Debian 13 host.
- **Probe target safety:** second-vantage plans pin resolved addresses and
  reject loopback, private, link-local, and metadata-style targets unless the
  operator explicitly permits private targets.
- **Unbounded external work:** external domain observations accept at most 16
  names and share an overall deadline.
- **Offline report trust:** render, redact, support, baseline, diff, fleet, and
  probe workflows validate the full report semantic contract. `diff` also
  refuses reports from different stable host identities.

## Installer trust boundary

Release binaries, `install.sh`, and `run.sh` have SHA-256 manifest entries and
independent Sigstore bundles. The release workflow uploads them to a draft,
downloads the complete draft asset set again, and republishes only after all
checksums and GitHub Actions OIDC identities verify. Once started, the scripts
apply the same verification to the selected binary. If Cosign is absent,
non-interactive execution stops unless checksum-only mode was explicitly
requested; an interactive terminal must type `continue`.

The short `curl | bash` form executes its bootstrap script before that script
can verify anything. It therefore trusts the HTTPS Release download for the
bootstrap step. The strict documented path pins a tag, verifies the script's
bundle first, and only then runs it with binary signature verification required.
A checksum downloaded from the same release detects corruption but does not by
itself authenticate a compromised release account.

## Validation performed

- `go test -count=1 ./...` and `go vet ./...` passed.
- `go mod verify` passed.
- Staticcheck found no project defect after removal of an obsolete firewall
  compatibility wrapper; its existing Persian Unicode-format style warnings
  are presentation warnings, not executable-content findings.
- `govulncheck` reported no reachable vulnerabilities using the locally cached
  database dated 2026-07-27. CI must refresh and repeat the scan before release.
- Three disposable 1 vCPU / 1 GB hosts produced complete 55-ID reports and
  valid manifests. The matrix covered Debian 13 with S-UI 1.5.3, Debian 12 with
  3x-ui 3.4.2 and embedded Xray, and Ubuntu 24.04 with Docker and Nginx.
- On a live Debian host, `run.sh` refused non-interactive execution without a
  publisher signature; explicit checksum-only mode ran the signed public
  `v1.0.0` binary, and `install.sh` installed it only into a temporary path.

## Remaining boundary

VPS Scope is an evidence-driven configuration and runtime auditor, not an EDR,
malware sandbox, or proof of remote client connectivity. Compromise below the
operating system, deliberately falsified local evidence, and unrecognized
vendor schema changes remain outside what a local read-only audit can prove.
