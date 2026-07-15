#!/usr/bin/env bash
set -euo pipefail

marker=/var/lib/vps-scope-lab/authorized
work=/run/vps-scope-lab/report-fault-injection
binary="${1:-}"
source_bundle="${2:-}"

die() { printf 'vps-scope lab: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "run as root on a disposable lab host"
[[ -f "$marker" ]] || die "missing disposable-lab marker"
[[ "$(tr -d '\r\n' < "$marker")" == "VPS_SCOPE_DISPOSABLE_LAB=1" ]] || die "invalid disposable-lab marker"
[[ -x "$binary" ]] || die "candidate binary is not executable"
[[ -f "$source_bundle/manifest.json" && -f "$source_bundle/report.json" ]] || die "source is not a report bundle"

rm -rf -- "$work"
mkdir -p -m 0700 "$work"
trap 'rm -rf -- "$work"' EXIT INT TERM HUP

copy_case() {
  local name=$1
  mkdir -m 0700 "$work/$name"
  cp -a -- "$source_bundle"/. "$work/$name"/
}

expect_rejected() {
  local name=$1 pattern=$2
  shift 2
  if "$@" >"$work/$name.out" 2>&1; then
    die "$name was incorrectly accepted"
  fi
  grep -Eq "$pattern" "$work/$name.out" || {
    sed -n '1,12p' "$work/$name.out" >&2
    die "$name failed for an unexpected reason"
  }
  printf 'PASS rejected %s\n' "$name"
}

copy_case undeclared
printf 'unexpected\n' >"$work/undeclared/unexpected.txt"
expect_rejected undeclared 'not declared in manifest' "$binary" verify "$work/undeclared"

copy_case missing
rm -f -- "$work/missing/report.en.md"
expect_rejected missing '(no such file|cannot open|missing)' "$binary" verify "$work/missing"

copy_case symlink
rm -f -- "$work/symlink/report.en.md"
ln -s report.en.txt "$work/symlink/report.en.md"
expect_rejected symlink '(not a regular file|symlink)' "$binary" verify "$work/symlink"

copy_case semantic
jq '.summary.pass += 1' "$work/semantic/report.json" >"$work/semantic/report.json.new"
mv -f -- "$work/semantic/report.json.new" "$work/semantic/report.json"
sha=$(sha256sum "$work/semantic/report.json" | awk '{print $1}')
size=$(stat -c %s "$work/semantic/report.json")
jq --arg sha "$sha" --argjson size "$size" \
  '(.files[] | select(.name == "report.json") | .sha256) = $sha | (.files[] | select(.name == "report.json") | .size) = $size' \
  "$work/semantic/manifest.json" >"$work/semantic/manifest.json.new"
mv -f -- "$work/semantic/manifest.json.new" "$work/semantic/manifest.json"
expect_rejected semantic 'summary does not match findings' "$binary" verify "$work/semantic"

printf 'report fault injection complete: 4/4 invalid bundles rejected\n'
