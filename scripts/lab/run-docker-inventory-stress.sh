#!/usr/bin/env bash
set -euo pipefail

marker=/var/lib/vps-scope-lab/authorized
runtime=/run/vps-scope-lab
work="$runtime/docker-inventory-stress"
audit_bin="${VPS_SCOPE_LAB_AUDIT_BIN:-}"
image="${VPS_SCOPE_LAB_DOCKER_IMAGE:-alpine:3.22}"
count="${VPS_SCOPE_LAB_DOCKER_COUNT:-32}"
label_key=vps-scope-lab
label_value=docker-inventory-stress
label="$label_key=$label_value"

die() { printf 'vps-scope lab: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" == 0 ]] || die "run as root on a disposable lab host"
[[ -f "$marker" ]] || die "missing disposable-lab marker $marker"
[[ "$(tr -d '\r\n' < "$marker")" == "VPS_SCOPE_DISPOSABLE_LAB=1" ]] || die "invalid disposable-lab marker"
[[ -n "$audit_bin" && -x "$audit_bin" ]] || die "set VPS_SCOPE_LAB_AUDIT_BIN to an executable candidate"
[[ "$count" =~ ^[0-9]+$ ]] && (( count >= 1 && count <= 64 )) || die "VPS_SCOPE_LAB_DOCKER_COUNT must be 1-64"
command -v docker >/dev/null || die "docker is unavailable"
command -v timeout >/dev/null || die "timeout is unavailable"
docker image inspect "$image" >/dev/null 2>&1 || die "refusing to pull an image; pre-load $image first"

mkdir -p -m 0700 "$runtime"
exec 9>"$runtime/lock"
flock -n 9 || die "another lab scenario is active"

remaining=()
mapfile -t remaining < <(docker ps -aq --filter "label=$label")
((${#remaining[@]} == 0)) || die "refusing to reuse existing Docker lab containers"

cleanup() {
  local id actual
  mapfile -t remaining < <(docker ps -aq --filter "label=$label")
  for id in "${remaining[@]}"; do
    actual="$(docker inspect -f "{{ index .Config.Labels \"$label_key\" }}" "$id" 2>/dev/null || true)"
    [[ "$actual" == "$label_value" ]] || { printf 'vps-scope lab: refusing unexpected container %s\n' "$id" >&2; continue; }
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  rm -rf -- "$work"
}
trap cleanup EXIT INT TERM HUP

for i in $(seq 1 "$count"); do
  name="vps-scope-lab-docker-inventory-$i"
  timeout 20s docker run -d --name "$name" --label "$label" \
    --pids-limit 16 --memory 16m --memory-swap 16m --cpus 0.01 \
    "$image" sleep 300 >/dev/null
  timeout 20s docker pause "$name" >/dev/null
done

"$audit_bin" audit --lang en --profile proxy --format bundle --output "$work/report" --quiet
"$audit_bin" verify "$work/report"
printf 'PASS docker inventory stress: extra_containers=%s image=%s\n' "$count" "$image"
