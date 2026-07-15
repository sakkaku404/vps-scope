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
.\scripts\lab\run-connectivity-matrix.ps1 -Hosts lab-a,lab-b,lab-c,lab-d -Output .\lab-result.json
```

The runner does not create the authorization marker or copy binaries. It waits for scenario cleanup, removes its bounded stdout/stderr capture files, and fails if a lab UFW rule, serving helper, or runtime state file remains. The target address is used only as the probe destination and is not written to the result.
