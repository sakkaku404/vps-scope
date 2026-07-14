#!/usr/bin/env bash
set -euo pipefail

marker=/var/lib/vps-scope-lab/authorized
runtime=/run/vps-scope-lab
port="${VPS_SCOPE_LAB_PORT:-39081}"
network="${VPS_SCOPE_LAB_NETWORK:-tcp4}"
helper="${VPS_SCOPE_LAB_HELPER:-$runtime/net-helper}"
duration="${VPS_SCOPE_LAB_DURATION:-90}"
open_firewall="${VPS_SCOPE_LAB_OPEN_FIREWALL:-0}"

die() { printf 'vps-scope lab: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "run as root on a disposable lab host"
[[ -f "$marker" ]] || die "missing disposable-lab marker $marker"
[[ "$(tr -d '\r\n' < "$marker")" == "VPS_SCOPE_DISPOSABLE_LAB=1" ]] || die "invalid disposable-lab marker"
[[ "$port" =~ ^39[0-9]{3}$ ]] || die "port must be in the reserved lab range 39000-39999"
[[ "$network" =~ ^(tcp4|tcp6|udp4|udp6)$ ]] || die "unsupported network"
[[ "$duration" =~ ^[0-9]+$ ]] && (( duration >= 5 && duration <= 600 )) || die "duration must be 5-600 seconds"
[[ -x "$helper" ]] || die "helper is not executable: $helper"

mkdir -p -m 0700 "$runtime"
exec 9>"$runtime/lock"
flock -n 9 || die "another lab scenario is active"

pid=""
rule_added=0
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  if (( rule_added )); then ufw --force delete allow "$port/$([[ "$network" == udp* ]] && printf udp || printf tcp)" >/dev/null 2>&1 || true; fi
  rm -f "$runtime/ready" "$runtime/helper.log" "$runtime/helper.pid"
}
trap cleanup EXIT INT TERM HUP

proto=tcp
[[ "$network" == udp* ]] && proto=udp
address=0.0.0.0:"$port"
[[ "$network" == *6 ]] && address="[::]:$port"
if [[ "$open_firewall" == 1 ]]; then
  command -v ufw >/dev/null || die "UFW requested but unavailable"
  ufw status | grep -q '^Status: active' || die "UFW requested but inactive"
  if ufw status | grep -Eq "(^|[[:space:]])${port}(/${proto})?([[:space:]]|$)"; then
    die "refusing to alter a port that already has a UFW rule"
  fi
  ufw allow "$port/$proto" comment 'vps-scope disposable lab' >/dev/null
  rule_added=1
fi

"$helper" --mode serve --network "$network" --address "$address" >"$runtime/helper.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$runtime/helper.pid"
for _ in {1..50}; do
  if grep -q '^READY ' "$runtime/helper.log" 2>/dev/null; then touch "$runtime/ready"; break; fi
  kill -0 "$pid" 2>/dev/null || { cat "$runtime/helper.log" >&2; die "helper exited before becoming ready"; }
  sleep 0.1
done
[[ -f "$runtime/ready" ]] || die "helper readiness timeout"
printf 'READY network=%s port=%s pid=%s duration=%ss firewall_rule=%s\n' "$network" "$port" "$pid" "$duration" "$rule_added"
sleep "$duration"
