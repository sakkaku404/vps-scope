#!/usr/bin/env bash
set -euo pipefail

marker=/var/lib/vps-scope-lab/authorized
runtime=/run/vps-scope-lab
audit_bin="${VPS_SCOPE_LAB_AUDIT_BIN:-/opt/vps-scope-lab/vps-scope}"
helper="${VPS_SCOPE_LAB_HELPER:-/opt/vps-scope-lab/net-helper}"
report="${VPS_SCOPE_LAB_REPORT:-$runtime/host-firewall-chain-report}"
chain=VPS-SCOPE-LAB
port=39601
pid=""
jump_added=0

die() { printf 'vps-scope lab: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "run as root on a disposable lab host"
[[ -f "$marker" ]] || die "missing disposable-lab marker $marker"
[[ "$(tr -d '\r\n' < "$marker")" == "VPS_SCOPE_DISPOSABLE_LAB=1" ]] || die "invalid disposable-lab marker"
[[ -x "$audit_bin" && -x "$helper" ]] || die "candidate or helper is not executable"
command -v iptables >/dev/null || die "iptables is unavailable"
iptables -S "$chain" >/dev/null 2>&1 && die "lab chain already exists"
[[ ! -e "$report" ]] || die "report path already exists: $report"

mkdir -p -m 0700 "$runtime"
exec 9>"$runtime/lock"
flock -n 9 || die "another lab scenario is active"
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  if (( jump_added )); then iptables -D INPUT -j "$chain" >/dev/null 2>&1 || true; fi
  iptables -F "$chain" >/dev/null 2>&1 || true
  iptables -X "$chain" >/dev/null 2>&1 || true
  rm -f "$runtime/host-firewall-helper.log"
}
trap cleanup EXIT INT TERM HUP

iptables -N "$chain"
iptables -I INPUT 1 -j "$chain"
jump_added=1
iptables -A "$chain" -p tcp --dport "$port" -m comment --comment vps-scope-host-firewall-lab -j ACCEPT

"$helper" --mode serve --network tcp4 --address "0.0.0.0:$port" >"$runtime/host-firewall-helper.log" 2>&1 &
pid=$!
for _ in {1..50}; do
  grep -q '^READY ' "$runtime/host-firewall-helper.log" 2>/dev/null && break
  kill -0 "$pid" 2>/dev/null || die "helper exited before readiness"
  sleep 0.1
done
grep -q '^READY ' "$runtime/host-firewall-helper.log" || die "helper readiness timeout"

"$audit_bin" audit --lang en --profile proxy --format bundle --output "$report" --quiet
"$audit_bin" verify "$report"
printf 'PASS host firewall chain: report=%s listener=%s/tcp\n' "$report" "$port"
