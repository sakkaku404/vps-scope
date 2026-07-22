#!/usr/bin/env bash
set -euo pipefail

marker=/var/lib/vps-scope-lab/authorized
runtime=/run/vps-scope-lab
audit_bin="${VPS_SCOPE_LAB_AUDIT_BIN:-/opt/vps-scope-lab/vps-scope}"
image="${VPS_SCOPE_LAB_DOCKER_IMAGE:-alpine:3.22}"
report="${VPS_SCOPE_LAB_REPORT:-$runtime/docker-firewall-report}"
comment=vps-scope-docker-firewall-lab
label=vps-scope.lab=docker-firewall-semantics
containers=(vps-scope-lab-loopback vps-scope-lab-public vps-scope-lab-privileged)
rule_added=0

die() { printf 'vps-scope lab: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die "run as root on a disposable lab host"
[[ -f "$marker" ]] || die "missing disposable-lab marker $marker"
[[ "$(tr -d '\r\n' < "$marker")" == "VPS_SCOPE_DISPOSABLE_LAB=1" ]] || die "invalid disposable-lab marker"
[[ -x "$audit_bin" ]] || die "candidate audit binary is not executable"
command -v docker >/dev/null || die "docker is unavailable"
command -v iptables >/dev/null || die "iptables is unavailable"
docker image inspect "$image" >/dev/null 2>&1 || die "refusing to pull image; pre-load $image"

mkdir -p -m 0700 "$runtime"
exec 9>"$runtime/lock"
flock -n 9 || die "another lab scenario is active"
iptables -S DOCKER-USER >/dev/null 2>&1 || die "DOCKER-USER is unavailable"
iptables -S DOCKER-USER | grep -q -- "$comment" && die "lab firewall rule already exists"
for name in "${containers[@]}"; do
  docker container inspect "$name" >/dev/null 2>&1 && die "container name already exists: $name"
done
[[ ! -e "$report" ]] || die "report path already exists: $report"

cleanup() {
  if (( rule_added )); then
    iptables -D DOCKER-USER -p tcp -s 203.0.113.0/24 --dport 80 -m comment --comment "$comment" -j ACCEPT >/dev/null 2>&1 || true
  fi
  for name in "${containers[@]}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT INT TERM HUP

docker run -d --name "${containers[0]}" --label "$label" --memory 32m --pids-limit 32 \
  -p 127.0.0.1:39443:80 "$image" sleep 600 >/dev/null
docker run -d --name "${containers[1]}" --label "$label" --memory 32m --pids-limit 32 \
  -p 0.0.0.0:39543:80 "$image" sleep 600 >/dev/null
docker run -d --name "${containers[2]}" --label "$label" --memory 32m --pids-limit 32 \
  --privileged --network none "$image" sleep 600 >/dev/null

# This rule intentionally allows one source without a closing deny. Other
# sources still fall through to Docker's own accept path; an audit must not
# describe the public publication as source-restricted.
iptables -I DOCKER-USER 1 -p tcp -s 203.0.113.0/24 --dport 80 -m comment --comment "$comment" -j ACCEPT
rule_added=1

"$audit_bin" audit --lang en --profile proxy --format bundle --output "$report" --quiet
"$audit_bin" verify "$report"
printf 'PASS docker firewall semantics: report=%s public=39543/tcp target=80/tcp\n' "$report"
