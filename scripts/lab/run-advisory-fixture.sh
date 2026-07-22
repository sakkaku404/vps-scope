#!/usr/bin/env bash
set -euo pipefail

marker=/var/lib/vps-scope-lab/authorized
audit_bin="${VPS_SCOPE_LAB_AUDIT_BIN:-/opt/vps-scope-lab/vps-scope}"
fixture="${VPS_SCOPE_LAB_PRODUCT_FIXTURE:-/opt/vps-scope-lab/sing-box-fixture}"
report="${VPS_SCOPE_LAB_REPORT:-/run/vps-scope-lab/advisory-report.json}"
target=/usr/local/bin/sing-box

die() { printf 'vps-scope advisory lab: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "run as root"
[[ -f "$marker" ]] && [[ "$(tr -d '\r\n' < "$marker")" == "VPS_SCOPE_DISPOSABLE_LAB=1" ]] || die "disposable-lab marker missing or invalid"
[[ -x "$audit_bin" ]] || die "audit binary is unavailable"
[[ -x "$fixture" ]] || die "product fixture is unavailable"
[[ ! -e "$target" ]] || die "refusing to replace existing $target"
[[ ! -e "$report" ]] || die "report path already exists"

pid=""
cleanup() {
  if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
  rm -f -- "$target"
}
trap cleanup EXIT INT TERM HUP

install -o root -g root -m 0755 "$fixture" "$target"
[[ "$("$target" version)" == "sing-box version 1.4.4" ]] || die "fixture version is not the expected vulnerable boundary"
"$target" &
pid=$!
sleep 0.2
"$audit_bin" audit --lang en --profile proxy --format json --output "$report"
"$audit_bin" verify "$report"
grep -A 6 '"id": "WORK-017"' "$report" | grep -q '"status": "RISK"' || die "WORK-017 did not report RISK"
grep -A 8 '"id": "WORK-017"' "$report" | grep -q '"severity": "critical"' || die "WORK-017 did not preserve advisory severity"
printf 'advisory fixture passed: %s\n' "$report"
