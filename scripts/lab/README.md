# Disposable VPS laboratory

These helpers exercise TCP/UDP and IPv4/IPv6 evidence on explicitly disposable hosts. They are not installed by VPS Scope and are never included in release archives.

Safety gates:

- The remote host must contain `/var/lib/vps-scope-lab/authorized` with exactly `VPS_SCOPE_DISPOSABLE_LAB=1`.
- Only ports 39000-39999 are accepted.
- A host lock prevents concurrent scenarios.
- Every process and optional UFW rule is removed by an exit trap.
- The scripts never change SSH, accounts, panel databases, systemd units, package state, or existing firewall rules.
- UFW exposure is opt-in and uses one named rule; it is rejected when UFW is inactive.

Build the helper on the development machine:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o net-helper ./scripts/lab/net-helper.go
```

After copying it to `/run/vps-scope-lab/net-helper`, start a guarded listener:

```bash
sudo VPS_SCOPE_LAB_NETWORK=udp4 VPS_SCOPE_LAB_PORT=39082 VPS_SCOPE_LAB_DURATION=60 \
  VPS_SCOPE_LAB_HELPER=/run/vps-scope-lab/net-helper ./scripts/lab/scenario.sh
```

Probe it from another lab host:

```bash
/run/vps-scope-lab/net-helper --mode probe --network udp4 --address SERVER_ADDRESS:39082
```

Never commit lab addresses, SSH aliases, credentials, raw reports, or the authorization marker.

On a Windows development host, the bounded parallel matrix runner accepts SSH aliases as arguments and writes only alias-to-alias outcomes:

```powershell
.\scripts\lab\run-connectivity-matrix.ps1 -Hosts lab-a,lab-b,lab-c,lab-d `
  -SshUser root -IdentityFile $HOME\.ssh\vps-scope-lab -Output .\lab-result.json
```

The runner does not create the authorization marker or copy binaries. It verifies an exact network-and-port readiness marker before probing, uses bounded TCP/UDP retries within one timeout to tolerate an isolated dropped packet or connection attempt, waits for scenario cleanup, removes its bounded stdout/stderr capture files, and fails if a probe fails or a lab UFW rule, serving helper, or runtime state file remains. The target address is used only as the probe destination and is not written to the result.

The host-firewall-chain runner inserts one temporary INPUT jump to a dedicated
user chain and exposes one reserved TCP listener. It proves that an allow in a
reachable custom iptables chain is not hidden by a default-deny policy. The
listener, jump, chain, and helper log are removed by the exit trap; the verified
report remains at the selected path for semantic review:

```bash
sudo VPS_SCOPE_LAB_AUDIT_BIN=/opt/vps-scope-lab/vps-scope \
  VPS_SCOPE_LAB_REPORT=/run/vps-scope-lab/host-firewall-chain-report \
  ./scripts/lab/run-host-firewall-chain.sh
```

The guarded report fault-injection runner verifies that the candidate rejects undeclared files, missing files, symlinked payloads, and a manifest-consistent but semantically invalid report. It accepts only an existing candidate binary and report bundle, uses a fixed runtime directory, and removes every injected bundle on exit:

```bash
sudo ./scripts/lab/run-report-fault-injection.sh /path/to/vps-scope /path/to/report-bundle
```

The guarded Docker inventory runner exercises real multi-batch `docker inspect` collection without touching existing containers. It requires a locally cached image and creates only labelled, paused Alpine containers with CPU, memory, swap, and PID limits. The exit trap removes every labelled container and report even if one audit step fails:

```bash
sudo VPS_SCOPE_LAB_AUDIT_BIN=/opt/vps-scope-lab/vps-scope \
  VPS_SCOPE_LAB_DOCKER_COUNT=32 \
  ./scripts/lab/run-docker-inventory-stress.sh
```

It intentionally refuses to pull an image or create more than 64 additional containers. The unit fixtures cover the 128-container refusal path; the disposable runner exists to prove the normal multi-batch path on a real Docker daemon without exhausting a small VPS.

The advisory fixture builds a harmless sleeping process under the trusted
`sing-box` executable name and reports version `1.4.4`, the vulnerable boundary
covered by the bundled upstream advisory. The runner refuses to replace a real
binary, removes the temporary executable and process, verifies the complete
report, and requires `WORK-017` to preserve the critical advisory severity:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags '-X main.product=sing-box -X main.version=1.4.4' \
  -o sing-box-fixture ./scripts/lab/product-fixture.go
sudo VPS_SCOPE_LAB_PRODUCT_FIXTURE=/opt/vps-scope-lab/sing-box-fixture \
  ./scripts/lab/run-advisory-fixture.sh
```

The Docker firewall semantics runner creates one loopback publication, one
public host-to-container port translation, and one privileged container. It
also inserts a labelled source allow without a closing deny in `DOCKER-USER`;
the report must recognize that unrelated Internet traffic still falls through
to Docker's accept path. The rule and all three containers are removed by the
exit trap, while the verified report is retained at the explicitly selected
path for review:

```bash
sudo VPS_SCOPE_LAB_AUDIT_BIN=/opt/vps-scope-lab/vps-scope \
  VPS_SCOPE_LAB_REPORT=/run/vps-scope-lab/docker-firewall-report \
  ./scripts/lab/run-docker-firewall-semantics.sh
```
